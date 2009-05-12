#include "globals.h"

static int radegast_send(uchar *buf)
{
  int l=buf[1]+2;
  return(send(pfd, buf, l, 0));
}

static int radegast_recv(uchar *buf, int l)
{
  int i, n;
  if (!pfd) return(-1);
  if ((n=recv(pfd, buf, l, 0))>0)
    client[cs_idx].last=time((time_t *) 0);
  return(n);
}

static void radegast_auth_client(in_addr_t ip)
{
  int ok;
  struct s_auth *account;
  struct s_ip *p_ip;
  for (ok=0, p_ip=cfg->rad_allowed; (p_ip) && (!ok); p_ip=p_ip->next)
    ok=((ip>=p_ip->ip[0]) && (ip<=p_ip->ip[1]));
  if (!ok)
  {
    cs_auth_client((struct s_auth *)0, NULL);
    cs_exit(0);
  }
  for (ok=0, account=cfg->account; (cfg->rad_usr[0]) && (account) && (!ok); account=account->next)
    if (ok=(!strcmp(cfg->rad_usr, account->usr)))
      if (cs_auth_client(account, NULL))
        cs_exit(0);
  if (!ok)
    cs_auth_client((struct s_auth *)(-1), NULL);
}

static int get_request(uchar *buf)
{
  int n, rc=0;
  if ((n=process_input(buf, 2, cfg->cmaxidle))==2)
  {
    if ((n=process_input(buf+2, buf[1], 0))>=0)
      n+=2;
    if (n-2==buf[1])
      rc=n;
    else
      cs_log("WARNING: protocol error (garbage)");
  }
  if (n>0)
    cs_ddump(buf, n, "received %d bytes from client", n);
  return(rc);
}

static void radegast_send_dcw(ECM_REQUEST *er)
{
  mbuf[0]=0x02;		// DCW
  if (er->rc<4)
  {
    mbuf[1]=0x12;	// len (overall)
    mbuf[2]=0x05;	// ACCESS
    mbuf[3]=0x10;	// len
    memcpy(mbuf+4, er->cw, 16);
  }
  else
  {
    mbuf[1]=0x02;	// len (overall)
    mbuf[2]=0x04;	// NO ACCESS
    mbuf[3]=0x00;	// len
  }
  radegast_send(mbuf);
}

static void radegast_process_ecm(uchar *buf, int l)
{
  int i, n, sl;
  ECM_REQUEST *er;

  if (!(er=get_ecmtask()))
    return;
  for (i=0; i<l; i+=(sl+2))
  {
    sl=buf[i+1];
    switch(buf[i])
    {
      case  2:		// CAID (upper byte only, oldstyle)
        er->caid=buf[i+2]<<8;
        break;
      case 10:		// CAID
        er->caid=b2i(2, buf+i+2);
        break;
      case  3:		// ECM DATA
        er->l=sl;
        memcpy(er->ecm, buf+i+2, er->l);
        break;
      case  6:		// PROVID (ASCII)
        n=(sl>6) ? 3 : (sl>>1);
        er->prid=cs_atoi((char *) buf+i+2+sl-(n<<1), n, 0);
        break;
      case  7:		// KEYNR (ASCII), not needed
        break;
      case  8:		// ECM PROCESS PID ?? don't know, not needed
        break;
    }
  }
  if (l!=i)
    cs_log("WARNING: ECM-request corrupt");
  else
    get_cw(er);
}

static void radegast_process_unknown(uchar *buf)
{
  uchar answer[2]={0x81, 0x00};
  radegast_send(answer);
  cs_log("unknown request %02X, len=%d", buf[0], buf[1]);
}

static void radegast_server()
{
  int n;

  radegast_auth_client(client[cs_idx].ip);
  while ((n=get_request(mbuf))>0)
  {
    switch(mbuf[0])
    {
      case 1:
        radegast_process_ecm(mbuf+2, mbuf[1]);
        break;
      default:
        radegast_process_unknown(mbuf);
    }
  }
  cs_disconnect_client();
}

void module_radegast(struct s_module *ph)
{
  static PTAB ptab;
  ptab.ports[0].s_port = cfg->rad_port;
  ph->ptab = &ptab;
  ph->ptab->nports = 1;

  strcpy(ph->desc, "radegast");
  ph->type=MOD_CONN_TCP;
  ph->multi=0;
  ph->watchdog=1;
  ph->s_ip=cfg->rad_srvip;
  ph->s_handler=radegast_server;
  ph->recv=radegast_recv;
  ph->send_dcw=radegast_send_dcw;
}
