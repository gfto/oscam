#include "globals.h"

#define REQ_SIZE	4

static int camd33_send(uchar *buf, int ml)
{
  int l;
  if (!cur_client()->pfd) return(-1);
  l=boundary(4, ml);
  memset(buf+ml, 0, l-ml);
  cs_ddump_mask(D_CLIENT, buf, l, "send %d bytes to client", l);
  if (cur_client()->crypted)
    aes_encrypt(buf, l);
  return(send(cur_client()->pfd, buf, l, 0));
}

static int camd33_recv(struct s_client * client, uchar *buf, int l)
{
  int n;
  if (!client->pfd) return(-1);
  if ((n=recv(client->pfd, buf, l, 0))>0)
  {
    client->last=time((time_t *) 0);
    if (client->crypted)
      aes_decrypt(buf, n);
  }
  cs_ddump_mask(D_CLIENT, buf, n, "received %d bytes from client", n);
  return(n);
}

static void camd33_request_emm()
{
  uchar mbuf[20];
	struct s_reader *aureader = NULL, *rdr = NULL;

	//TODO: just take the first reader in list
	LL_ITER *itr = ll_iter_create(cur_client()->aureader_list);
	while ((rdr = ll_iter_next(itr))) {
		aureader=rdr;
		break;
	}
	ll_iter_release(itr);

	if (!aureader) return;

  if (aureader->hexserial[0])
  {
    log_emm_request(aureader);
    mbuf[0]=0;
    mbuf[1]=aureader->caid>>8;
    mbuf[2]=aureader->caid&0xff;
    memcpy(mbuf+3, aureader->hexserial, 4);
    memcpy(mbuf+7, &aureader->prid[0][1], 3);
    memcpy(mbuf+10, &aureader->prid[2][1], 3);
    camd33_send(mbuf, 13);
  }
}

static void camd33_auth_client()
{
  int i, rc;
  uchar *usr=NULL, *pwd=NULL;
  struct s_auth *account;
  uchar mbuf[1024];

  cur_client()->crypted=cfg.c33_crypted;
  if (cur_client()->crypted)
  {
    struct s_ip *p_ip;
    for (p_ip=cfg.c33_plain; (p_ip) && (cur_client()->crypted); p_ip=p_ip->next)
      if ((cur_client()->ip>=p_ip->ip[0]) && (cur_client()->ip<=p_ip->ip[1]))
        cur_client()->crypted=0;
  }
  if (cur_client()->crypted)
    aes_set_key((char *) cfg.c33_key);

  mbuf[0]=0;
  camd33_send(mbuf, 1);	// send login-request

  for (rc=0, cur_client()->camdbug[0]=0, mbuf[0]=1; (rc<2) && (mbuf[0]); rc++)
  {
    i=process_input(mbuf, sizeof(mbuf), 1);
    if ((i>0) && (!mbuf[0]))
    {
      usr=mbuf+1;
      pwd=usr+strlen((char *)usr)+2;
    }
    else
      memcpy(cur_client()->camdbug+1, mbuf, cur_client()->camdbug[0]=i);
  }
  for (rc=-1, account=cfg.account; (usr) && (account) && (rc<0); account=account->next)
    if ((!strcmp((char *)usr, account->usr)) && (!strcmp((char *)pwd, account->pwd)))
      rc=cs_auth_client(cur_client(), account, NULL);
  if (!rc)
    camd33_request_emm();
  else
  {
    if (rc<0) cs_auth_client(cur_client(), 0, usr ? "invalid account" : "no user given");
    cs_exit(0);
  }
}

static int get_request(uchar *buf, int n)
{
  int rc, w;
  struct s_client *cur_cl = cur_client();

  if (cur_cl->camdbug[0])
  {
    memcpy(buf, cur_cl->camdbug+1, rc=cur_cl->camdbug[0]);
    cur_cl->camdbug[0]=0;
    return(rc);
  }
  for (rc=w=0; !rc;)
  {
    switch (rc=process_input(buf, 16, (w) ? cfg.ctimeout : cfg.cmaxidle))
    {
      case -9:
        rc=0;
      case  0:
        if ((w) || cfg.c33_passive)
          rc=-1;
        else
        {
          buf[0]=0;
          camd33_send(buf, 1);
          w++;
        }
      case -1:
        break;
      default:
        if (cur_cl->account && !memcmp(buf+1, cur_cl->account->usr, strlen(cur_cl->account->usr)))
        {
          cs_log("%s still alive", cs_inet_ntoa(cur_cl->ip));
          rc=w=0;
        }
	      else
        {
          switch (buf[0])
          {
            case  2:
            case  3: w=boundary(4, buf[9]+10); break;
            default: w=n;	// garbage ?
          }
          w=process_input(buf+16, w-16, 0);
          if (w>0) rc+=w;
        }
    }
  }
  if (rc<0) rc=0;
  return(rc);
}

static void camd33_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
  uchar mbuf[1024];
  mbuf[0]=2;
  memcpy(mbuf+1, client->req+(er->cpti*REQ_SIZE), 4);	// get pin
  memcpy(mbuf+5, er->cw, 16);
  camd33_send(mbuf, 21);
  if (!cfg.c33_passive)
    camd33_request_emm();
}

static void camd33_process_ecm(uchar *buf, int l)
{
  ECM_REQUEST *er;
  if (!(er=get_ecmtask()))
    return;
  memcpy(cur_client()->req+(er->cpti*REQ_SIZE), buf+3, 4);	// save pin
  er->l=l-7;
  er->caid=b2i(2, buf+1);
  memcpy(er->ecm , buf+7, er->l);
  get_cw(cur_client(), er);
}

static void camd33_process_emm(uchar *buf, int l)
{
  EMM_PACKET epg;
  memset(&epg, 0, sizeof(epg));
  epg.l=l-7;
  memcpy(epg.caid     , buf+1, 2);
  memcpy(epg.hexserial, buf+3, 4);
  memcpy(epg.emm      , buf+7, epg.l);
  do_emm(cur_client(), &epg);
}

static void * camd33_server(void* cli)
{
  int n;
  uchar mbuf[1024];

  struct s_client * client = (struct s_client *) cli;
  client->thread=pthread_self();
  pthread_setspecific(getclient, cli);

  client->req=(uchar *)malloc(CS_MAXPENDING*REQ_SIZE);
  if (!client->req)
  {
    cs_log("Cannot allocate memory (errno=%d)", errno);
    cs_exit(1);
  }
  memset(client->req, 0, CS_MAXPENDING*REQ_SIZE);

  camd33_auth_client();

  while ((n=get_request(mbuf, sizeof(mbuf)))>0)
  {
    switch(mbuf[0])
    {
      case 2:
        camd33_process_ecm(mbuf, n);
        break;
      case 3:
        camd33_process_emm(mbuf, n);
        break;
      default:
        cs_debug_mask(D_CLIENT, "unknown command !");
    }
  }
  cs_disconnect_client(client);
  return NULL;
}

void module_camd33(struct s_module *ph)
{
  static PTAB ptab; //since there is always only 1 camd33 server running, this is threadsafe
  ptab.ports[0].s_port = cfg.c33_port;
  ph->ptab = &ptab;
  ph->ptab->nports = 1;

  strcpy(ph->desc, "camd33");
  ph->type=MOD_CONN_TCP;
  ph->logtxt=cfg.c33_crypted ? ", crypted" : ", UNCRYPTED!";
  ph->multi=1;
  ph->watchdog=1;
  ph->s_ip=cfg.c33_srvip;
  ph->s_handler=camd33_server;
  ph->recv=camd33_recv;
  ph->send_dcw=camd33_send_dcw;
  ph->num=R_CAMD33;
}
