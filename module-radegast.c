#include "globals.h"
extern struct s_reader * reader;

static int radegast_send(uchar *buf)
{
  int l=buf[1]+2;
  return(send(client[cs_idx].pfd, buf, l, 0));
}

static int radegast_recv(uchar *buf, int l)
{
  int n;
  if (!client[cs_idx].pfd) return(-1);
  if (client[cs_idx].is_server) {  // server code
    if ((n=recv(client[cs_idx].pfd, buf, l, 0))>0)
      client[cs_idx].last=time((time_t *) 0);
  } else {  // client code
    if ((n=recv(client[cs_idx].pfd, buf, l, 0))>0) {
      cs_ddump(buf, n, "radegast: received %d bytes from %s", n, remote_txt());
      client[cs_idx].last = time((time_t *) 0);

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

static int radegast_recv_chk(uchar *dcw, int *rc, uchar *buf)
{
  if ((buf[0] == 2) && (buf[1] == 0x12)) {
    memcpy(dcw, buf+4, 16);
    cs_debug("radegast: recv chk - %s", cs_hexdump(0, dcw, 16));
    *rc = 1;
    return(reader[client[cs_idx].ridx].msg_idx);
  }

  return (-1);
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
  {
    ok=(!strcmp(cfg->rad_usr, account->usr));
    if (ok && cs_auth_client(account, NULL))
      cs_exit(0);
  }

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
  uchar mbuf[1024];
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

static void * radegast_server(void *cli)
{
  int n;
  uchar mbuf[1024];

	struct s_client * client = (struct s_client *) cli;
  client->thread=pthread_self();

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
  return NULL;
}

static int radegast_send_ecm(ECM_REQUEST *er)
{
  int n;
  uchar provid_buf[8];
  uchar header[22] = "\x02\x01\x00\x06\x08\x30\x30\x30\x30\x30\x30\x30\x30\x07\x04\x30\x30\x30\x38\x08\x01\x02";
  uchar *ecmbuf = malloc(er->l + 30);
  memset(ecmbuf, 0, er->l + 30);

  ecmbuf[0] = 1;
  ecmbuf[1] = er->l + 30 - 2;
  memcpy(ecmbuf + 2, header, sizeof(header));
  for(n = 0; n < 4; n++) {
    sprintf((char*)provid_buf+(n*2), "%02X", ((uchar *)(&er->prid))[4 - 1 - n]);
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

  reader[client[cs_idx].ridx].msg_idx = er->idx;
  n = send(client[cs_idx].pfd, ecmbuf, er->l + 30, 0);

  cs_log("radegast: sending ecm");
  cs_ddump(ecmbuf, er->l + 30, "ecm:");

  free(ecmbuf);

  return 0;
}

int radegast_cli_init(void)
{
  struct sockaddr_in loc_sa;
  struct protoent *ptrp;
  int p_proto, handle;

  client[cs_idx].pfd=0;
  if (reader[client[cs_idx].ridx].r_port<=0)
  {
    cs_log("radegast: invalid port %d for server %s", reader[client[cs_idx].ridx].r_port, reader[client[cs_idx].ridx].device);
    return(1);
  }
  if( (ptrp=getprotobyname("tcp")) )
    p_proto=ptrp->p_proto;
  else
    p_proto=6;

  client[cs_idx].ip=0;
  memset((char *)&loc_sa,0,sizeof(loc_sa));
  loc_sa.sin_family = AF_INET;
#ifdef LALL
  if (cfg->serverip[0])
    loc_sa.sin_addr.s_addr = inet_addr(cfg->serverip);
  else
#endif
    loc_sa.sin_addr.s_addr = INADDR_ANY;
  loc_sa.sin_port = htons(reader[client[cs_idx].ridx].l_port);

  if ((client[cs_idx].udp_fd=socket(PF_INET, SOCK_STREAM, p_proto))<0)
  {
    cs_log("radegast: Socket creation failed (errno=%d)", errno);
    cs_exit(1);
  }

#ifdef SO_PRIORITY
  if (cfg->netprio)
    setsockopt(client[cs_idx].udp_fd, SOL_SOCKET, SO_PRIORITY,
               (void *)&cfg->netprio, sizeof(ulong));
#endif
  if (!reader[client[cs_idx].ridx].tcp_ito) {
    ulong keep_alive = reader[client[cs_idx].ridx].tcp_ito?1:0;
    setsockopt(client[cs_idx].udp_fd, SOL_SOCKET, SO_KEEPALIVE,
    (void *)&keep_alive, sizeof(ulong));
  }

  memset((char *)&client[cs_idx].udp_sa,0,sizeof(client[cs_idx].udp_sa));
  client[cs_idx].udp_sa.sin_family = AF_INET;
  client[cs_idx].udp_sa.sin_port = htons((u_short)reader[client[cs_idx].ridx].r_port);

  cs_log("radegast: proxy %s:%d (fd=%d)",
  reader[client[cs_idx].ridx].device, reader[client[cs_idx].ridx].r_port, client[cs_idx].udp_fd);

  handle = network_tcp_connection_open();
  if(handle < 0) return -1;

  reader[client[cs_idx].ridx].tcp_connected = 2;
  reader[client[cs_idx].ridx].card_status = CARD_INSERTED;
  reader[client[cs_idx].ridx].last_g = reader[client[cs_idx].ridx].last_s = time((time_t *)0);

  cs_debug("radegast: last_s=%d, last_g=%d", reader[client[cs_idx].ridx].last_s, reader[client[cs_idx].ridx].last_g);

  client[cs_idx].pfd=client[cs_idx].udp_fd;

  return(0);
}

void module_radegast(struct s_module *ph)
{
  static PTAB ptab; //since there is always only 1 radegast server running, this is threadsafe
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
  ph->c_multi=0;
  ph->c_init=radegast_cli_init;
  ph->c_recv_chk=radegast_recv_chk;
  ph->c_send_ecm=radegast_send_ecm;
  ph->num=R_RADEGAST;
}
