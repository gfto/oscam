#include "globals.h"

static int32_t radegast_send(struct s_client * client, uchar *buf)
{
  int32_t l=buf[1]+2;
  return(send(client->pfd, buf, l, 0));
}

static int32_t radegast_recv(struct s_client *client, uchar *buf, int32_t l)
{
  int32_t n;
  if (!client->pfd) return(-1);
  if (client->typ == 'c') {  // server code
    if ((n=recv(client->pfd, buf, l, 0))>0)
      client->last=time((time_t *) 0);
  } else {  // client code
    if ((n=recv(client->pfd, buf, l, 0))>0) {
      cs_ddump_mask(D_CLIENT, buf, n, "radegast: received %d bytes from %s", n, remote_txt());
      client->last = time((time_t *) 0);

      if (buf[0] == 2) {  // dcw received
        if (buf[3] != 0x10) {  // dcw ok
          cs_log("radegast: no dcw");
          n = -1;
        }
      }
    }
  }
  return(n);
}

static int32_t radegast_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t UNUSED(n))
{
  if ((buf[0] == 2) && (buf[1] == 0x12)) {
  	tmp_dbg(33);
    memcpy(dcw, buf+4, 16);
    cs_debug_mask(D_CLIENT, "radegast: recv chk - %s", cs_hexdump(0, dcw, 16, tmp_dbg, sizeof(tmp_dbg)));
    *rc = 1;
    return(client->reader->msg_idx);
  }

  return (-1);
}

static void radegast_auth_client(in_addr_t ip)
{
  int32_t ok;
  struct s_auth *account;

  ok = check_ip(cfg.rad_allowed, ip);

  if (!ok)
  {
    cs_auth_client(cur_client(), (struct s_auth *)0, NULL);
    cs_exit(0);
  }

  for (ok=0, account=cfg.account; (cfg.rad_usr[0]) && (account) && (!ok); account=account->next)
  {
    ok=(!strcmp(cfg.rad_usr, account->usr));
    if (ok && cs_auth_client(cur_client(), account, NULL))
      cs_exit(0);
  }

  if (!ok)
    cs_auth_client(cur_client(), (struct s_auth *)(-1), NULL);
}

static int32_t get_request(uchar *buf)
{
  int32_t n, rc=0;
  if ((n=process_input(buf, 2, cfg.cmaxidle))==2)
  {
    if ((n=process_input(buf+2, buf[1], 0))>=0)
      n+=2;
    if (n-2==buf[1])
      rc=n;
    else
      cs_log("WARNING: protocol error (garbage)");
  }
  if (n>0)
  {
    cs_ddump_mask(D_CLIENT, buf, n, "received %d bytes from client", n);
  }
  return(rc);
}

static void radegast_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
  uchar mbuf[1024];
  mbuf[0]=0x02;		// DCW
  if (er->rc < E_NOTFOUND)
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
  radegast_send(client, mbuf);
}

static void radegast_process_ecm(uchar *buf, int32_t l)
{
  int32_t i, n, sl;
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
    get_cw(cur_client(), er);
}

static void radegast_process_unknown(uchar *buf)
{
  uchar answer[2]={0x81, 0x00};
  radegast_send(cur_client(), answer);
  cs_log("unknown request %02X, len=%d", buf[0], buf[1]);
}

static void * radegast_server(struct s_client * client, uchar *mbuf, int n)
{

	if (!client->init_done) {
		radegast_auth_client(cur_client()->ip);
		client->init_done=1;
	}

	switch(mbuf[0]) {
		case 1:
			radegast_process_ecm(mbuf+2, mbuf[1]);
			break;
		default:
			radegast_process_unknown(mbuf);
	}

	return NULL;
}

static int32_t radegast_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *UNUSED(buf))
{
  int32_t n;
  uchar provid_buf[8];
  uchar header[22] = "\x02\x01\x00\x06\x08\x30\x30\x30\x30\x30\x30\x30\x30\x07\x04\x30\x30\x30\x38\x08\x01\x02";  
  uchar *ecmbuf;
  if(!cs_malloc(&ecmbuf,er->l + 30, -1)) return -1;

  ecmbuf[0] = 1;
  ecmbuf[1] = er->l + 30 - 2;
  memcpy(ecmbuf + 2, header, sizeof(header));
  for(n = 0; n < 4; n++) {
    snprintf((char*)provid_buf+(n*2), sizeof(provid_buf)-(n*2), "%02X", ((uchar *)(&er->prid))[4 - 1 - n]);
  }
  ecmbuf[7] = provid_buf[0];
  ecmbuf[8] = provid_buf[1];
  ecmbuf[9] = provid_buf[2];
  ecmbuf[10] = provid_buf[3];
  ecmbuf[11] = provid_buf[4];
  ecmbuf[12] = provid_buf[5];
  ecmbuf[13] = provid_buf[6];
  ecmbuf[14] = provid_buf[7];
  ecmbuf[2 + sizeof(header)] = 0xa;
  ecmbuf[3 + sizeof(header)] = 2;
  ecmbuf[4 + sizeof(header)] = er->caid >> 8;
  ecmbuf[5 + sizeof(header)] = er->caid & 0xff;
  ecmbuf[6 + sizeof(header)] = 3;
  ecmbuf[7 + sizeof(header)] = er->l;
  memcpy(ecmbuf + 8 + sizeof(header), er->ecm, er->l);
  ecmbuf[4] = er->caid >> 8;

  client->reader->msg_idx = er->idx;
  n = send(client->pfd, ecmbuf, er->l + 30, 0);

  cs_log("radegast: sending ecm");
  cs_ddump_mask(D_CLIENT, ecmbuf, er->l + 30, "ecm:");

  free(ecmbuf);

  return 0;
}

int32_t radegast_cli_init(struct s_client *cl)
{
  *cl = *cl; //prevent compiler warning
  int32_t handle;

  cs_log("radegast: proxy %s:%d (fd=%d)",
  cur_client()->reader->device, cur_client()->reader->r_port, cur_client()->udp_fd);

  handle = network_tcp_connection_open(cl->reader);
  if(handle < 0) return -1;

  cur_client()->reader->tcp_connected = 2;
  cur_client()->reader->card_status = CARD_INSERTED;
  cur_client()->reader->last_g = cur_client()->reader->last_s = time((time_t *)0);

  cs_debug_mask(D_CLIENT, "radegast: last_s=%d, last_g=%d", cur_client()->reader->last_s, cur_client()->reader->last_g);

  cur_client()->pfd=cur_client()->udp_fd;

  return(0);
}

void module_radegast(struct s_module *ph)
{
  static PTAB ptab; //since there is always only 1 radegast server running, this is threadsafe
  ptab.ports[0].s_port = cfg.rad_port;
  ph->ptab = &ptab;
  ph->ptab->nports = 1;

  cs_strncpy(ph->desc, "radegast", sizeof(ph->desc));
  ph->type=MOD_CONN_TCP;
  ph->listenertype = LIS_RADEGAST;
  ph->multi=0;
  ph->watchdog=1;
  ph->s_ip=cfg.rad_srvip;
  ph->s_handler=radegast_server;
  ph->recv=radegast_recv;
  ph->send_dcw=radegast_send_dcw;
  ph->c_multi=0;
  ph->c_init=radegast_cli_init;
  ph->c_recv_chk=radegast_recv_chk;
  ph->c_send_ecm=radegast_send_ecm;
  ph->num=R_RADEGAST;
}
