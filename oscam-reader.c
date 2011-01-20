#include "globals.h"

int logfd=0;

void reader_do_idle(struct s_reader * reader);

void cs_ri_brk(struct s_reader * reader, int flag)
{
  if (flag)
    reader->brk_pos=reader->init_history_pos;
  else
    reader->init_history_pos=reader->brk_pos;
}

void cs_ri_log(struct s_reader * reader, char *fmt,...)
{
	char txt[256];

	va_list params;
	va_start(params, fmt);
	vsprintf(txt, fmt, params);
	va_end(params);
	cs_log("%s", txt);

	if (cfg->saveinithistory) {
		FILE *fp;
		char filename[256];
		char *buffer;
		int filelen = 0;
		sprintf(filename, "%s/reader%d", get_tmp_dir(), get_ridx(reader));
		int size = reader->init_history_pos+strlen(txt)+1;
		buffer = malloc(size+1);

		if (buffer == NULL)
			return;

		memset(buffer, 32, size);

		fp = fopen(filename, "r");

		if (fp) {
			filelen = fread(buffer, 1, reader->init_history_pos, fp);
			fclose(fp);
		}

		sprintf(buffer + filelen, "%s\n", txt);

		fp = fopen(filename, "w");
		if (fp) {
			fwrite(buffer, 1, filelen + strlen(txt)+1, fp);
			fclose(fp);
		}

		free(buffer);
	}
	reader->init_history_pos+=strlen(txt)+1;
}

static void casc_check_dcw(struct s_reader * reader, int idx, int rc, uchar *cw)
{
  int i;
  struct s_client *cl = reader->client;
  for (i=0; i<CS_MAXPENDING; i++)
  {
    if ((cl->ecmtask[i].rc>=10) &&
        (!memcmp(cl->ecmtask[i].ecmd5, cl->ecmtask[idx].ecmd5, CS_ECMSTORESIZE)))
    {
      if (rc)
      {
        cl->ecmtask[i].rc=(i==idx) ? 1 : 2;
#ifdef CS_WITH_GBOX
        if(cl->ecmtask[i].gbxRidx)cl->ecmtask[i].rc=0;
#endif
        memcpy(cl->ecmtask[i].cw, cw, 16);
      }
      else
        cl->ecmtask[i].rc=0;    
      write_ecm_answer(reader, &cl->ecmtask[i]);
      cl->ecmtask[i].idx=0;
    }
  }
}

int casc_recv_timer(struct s_reader * reader, uchar *buf, int l, int msec)
{
  struct timeval tv;
  fd_set fds;
  int rc;
  struct s_client *cl = reader->client;

  if (!cl->pfd) return(-1);
  tv.tv_sec = msec/1000;
  tv.tv_usec = (msec%1000)*1000;
  FD_ZERO(&fds);
  FD_SET(cl->pfd, &fds);
  select(cl->pfd+1, &fds, 0, 0, &tv);
  rc=0;
  if (FD_ISSET(cl->pfd, &fds))
    if (!(rc=reader->ph.recv(cl, buf, l)))
      rc=-1;

  return(rc);
}

#define MSTIMEOUT                 0x800000 
#define DEFAULT_CONNECT_TIMEOUT   500
  
int network_select(int forRead, int timeout) 
{ 
   int sd = cur_client()->udp_fd; 
   if(sd>=0) { 
       fd_set fds; 
       FD_ZERO(&fds); FD_SET(sd,&fds); 
       struct timeval tv; 
       if(timeout&MSTIMEOUT) { tv.tv_sec=0; tv.tv_usec=(timeout&~MSTIMEOUT)*1000; } 
       else { tv.tv_sec=0; tv.tv_usec=timeout*1000; } 
       int r=select(sd+1,forRead ? &fds:0,forRead ? 0:&fds,0,&tv); 
       if(r>0) return 1; 
       else if(r<0) { 
         cs_debug_mask(D_READER, "socket: select failed: %s",strerror(errno)); 
         return -1; 
       } 
       else { 
         if(timeout>0) {
           cs_debug_mask(D_READER, "socket: select timed out (%d %s)",timeout&~MSTIMEOUT,(timeout&MSTIMEOUT)?"ms":"secs");
         }
         errno=ETIMEDOUT;
         return 0; 
       } 
   } 
   return -1; 
} 

// according to documentation getaddrinfo() is thread safe
int hostResolve(struct s_reader *rdr)
{
   int result = 0;
   struct s_client *cl = rdr->client;
   
   pthread_mutex_lock(&gethostbyname_lock);
   
   in_addr_t last_ip = cl->ip;
   
   if (cfg->resolve_gethostbyname) { //Resolve with gethostbyname:
     struct hostent *rht = gethostbyname(rdr->device);
     if (!rht) {
       cs_log("can't resolve %s", rdr->device);
       result = 0;
     } else {
       memcpy(&cl->udp_sa.sin_addr, rht->h_addr, sizeof(cl->udp_sa.sin_addr));
       cl->ip=cs_inet_order(cl->udp_sa.sin_addr.s_addr);
       result = 1;
     }
   }
   else { //Resolve with getaddrinfo:
     struct addrinfo hints, *res = NULL;
     memset(&hints, 0, sizeof(hints));
     hints.ai_socktype = SOCK_STREAM;
     hints.ai_family = cl->udp_sa.sin_family;
     hints.ai_protocol = IPPROTO_TCP;

     int err = getaddrinfo(rdr->device, NULL, &hints, &res);
     if (err != 0 || !res || !res->ai_addr) {
       cs_log("can't resolve %s, error: %s", rdr->device, err ? gai_strerror(err) : "unknown");
       result = 0;
     } else {
       cl->udp_sa.sin_addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
       cl->ip = cs_inet_order(cl->udp_sa.sin_addr.s_addr);
       result = 1;
     }
     if (res) freeaddrinfo(res);
   }

   if (!result) {
     cl->udp_sa.sin_addr.s_addr = 0;
     cl->ip = 0;
   } else if (cl->ip != last_ip) {
     cs_log("%s: resolved ip=%s", rdr->device, cs_inet_ntoa(cl->ip));
   }

   pthread_mutex_unlock(&gethostbyname_lock);

   return result;
}

void clear_block_delay(struct s_reader *rdr) {
   rdr->tcp_block_delay = 100;
   cs_ftime(&rdr->tcp_block_connect_till);
}

void block_connect(struct s_reader *rdr) {
  if (!rdr->tcp_block_delay)
  	rdr->tcp_block_delay = 100; //starting blocking time, 100ms
  rdr->tcp_block_connect_till.time += rdr->tcp_block_delay / 1000;
  rdr->tcp_block_connect_till.millitm += rdr->tcp_block_delay % 1000;
  rdr->tcp_block_delay *= 2; //increment timeouts
  if (rdr->tcp_block_delay >= 60*1000)
    rdr->tcp_block_delay = 60*1000; //max 1min, todo config
  cs_debug_mask(D_TRACE, "tcp connect blocking delay for %s set to %d", rdr->label, rdr->tcp_block_delay);
}

int is_connect_blocked(struct s_reader *rdr) {
  struct timeb cur_time;
  cs_ftime(&cur_time);
  return (comp_timeb(&cur_time, &rdr->tcp_block_connect_till) < 0);
}
                
int network_tcp_connection_open()
{
  struct s_client *cl = cur_client();
  struct s_reader *rdr = cl->reader;
  cs_log("connecting to %s", rdr->device);

  in_addr_t last_ip = cl->ip;
  if (!hostResolve(rdr))
     return -1;

  if (last_ip != cl->ip) //clean blocking delay on ip change:
    clear_block_delay(rdr);
  if (is_connect_blocked(rdr)) { //inside of blocking delay, do not connect!
    cs_log("tcp connect blocking delay asserted for %s", rdr->label);
    return -1;
  }
  
  int flag = 1;
  setsockopt(cl->udp_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
  
  int sd = cl->udp_fd;
  int fl = fcntl(sd, F_GETFL);
  fcntl(sd, F_SETFL, O_NONBLOCK); //set to nonblocking mode to avoid "endless" connecting loops and pipe-overflows:
  int res =connect(sd, (struct sockaddr *)&cl->udp_sa, sizeof(cl->udp_sa));
  if (res == 0) { 
     fcntl(sd, F_SETFL, fl); //connect sucessfull, restore blocking mode
     clear_block_delay(rdr);
     return sd;
  }

  if (errno == EINPROGRESS || errno == EALREADY) {
     if (network_select(0, DEFAULT_CONNECT_TIMEOUT) > 0) { //if connect is in progress, wait apr. 500ms
        int r = -1;
        uint l = sizeof(r);
        if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &r, (socklen_t*)&l) == 0) {
           if (r == 0) {
              fcntl(sd, F_SETFL, fl);
              clear_block_delay(rdr);
              return sd; //now we are connected
           }
	}
     }
  }
  //else we are not connected - or already connected:
  else if (errno == EISCONN) {
    cs_log("already connected!");
    fcntl(sd, F_SETFL, fl);
    clear_block_delay(rdr);
    return sd;
  }

  if (errno == EBADF || errno == ENOTSOCK) {
    cs_log("connect failed: bad socket/descriptor %d", sd);
  }
  else if (errno == ETIMEDOUT) {
    cs_log("connect failed: timeout");
  }
  else if (errno == ECONNREFUSED) {
    cs_log("connection refused");
  }
  else if (errno == ENETUNREACH) {
    cs_log("connect failed: network unreachable!");
  }
  else if (errno == EADDRINUSE) {
    cs_log("connect failed: address in use!");
  }
  else                                                 
    cs_log("connect(fd=%d) failed: (errno=%d: %s)", sd, errno, strerror(errno));

  fcntl(sd, F_SETFL, fl); //restore blocking mode
  
  //connect has failed. Block connect for a while:
  block_connect(rdr);
      
  return -1; 
}

void network_tcp_connection_close(struct s_client *cl, int fd)
{
	if(!cl) return;
	struct s_reader *reader = cl->reader;
	cs_debug_mask(D_READER, "tcp_conn_close(): fd=%d, cl->typ == 'c'=%d", fd, cl->typ == 'c');

	if (fd) {
		close(fd);
		if (fd == cl->udp_fd)
			cl->udp_fd = 0;
		if (fd == cl->pfd)
			cl->pfd = 0;

		if(reader)
			clear_block_delay(reader);
	}


  if (cl->typ != 'c')
  {
    int i;
    //cl->pfd = 0;
    if(reader)
        reader->tcp_connected = 0;

    if (cl->ecmtask) {
	for (i = 0; i < CS_MAXPENDING; i++) {
	   cl->ecmtask[i].idx = 0;
	   cl->ecmtask[i].rc = 0;
	}
    }

    if(reader) {
        reader->ncd_msgid=0;
        reader->last_s=reader->last_g=0;
        
        if (reader->ph.c_init(cl)) {
            cs_debug_mask(D_READER, "network_tcp_connection_close() exit(1);");
            cs_exit(1);
        }
    }
  }
}

static void casc_do_sock_log(struct s_reader * reader)
{
  int i, idx;
  ushort caid, srvid;
  ulong provid;
  struct s_client *cl = reader->client;

  idx=reader->ph.c_recv_log(&caid, &provid, &srvid);
  cl->last=time((time_t)0);
  if (idx<0) return;        // no dcw-msg received

  for (i=0; i<CS_MAXPENDING; i++)
  {
    if (  (cl->ecmtask[i].rc>=10)
       && (cl->ecmtask[i].idx==idx)
       && (cl->ecmtask[i].caid==caid)
       && (cl->ecmtask[i].prid==provid)
       && (cl->ecmtask[i].srvid==srvid))
    {
      casc_check_dcw(reader, i, 0, cl->ecmtask[i].cw);  // send "not found"
      break;
    }
  }
}

static void casc_do_sock(struct s_reader * reader, int w)
{
  int i, n, idx, rc, j;
  uchar buf[1024];
  uchar dcw[16];
  struct s_client *cl = reader->client; 

  if ((n=casc_recv_timer(reader, buf, sizeof(buf), w))<=0)
  {
    if (reader->ph.type==MOD_CONN_TCP && reader->typ != R_RADEGAST)
    {
      if (reader->ph.c_idle)
      	reader_do_idle(reader);
      else {
        cs_debug_mask(D_READER, "casc_do_sock: close connection");
        network_tcp_connection_close(reader->client, cl->udp_fd);
      }
      return;
    }
  }
  cl->last=time((time_t)0);
  idx=reader->ph.c_recv_chk(cl, dcw, &rc, buf, n);

  if (idx<0) return;  // no dcw received
  reader->last_g=time((time_t*)0); // for reconnect timeout
//cs_log("casc_do_sock: last_s=%d, last_g=%d", reader->last_s, reader->last_g);
  if (!idx) idx=cl->last_idx;
  j=0;
  for (i=0; i<CS_MAXPENDING; i++)
  {

   if (cl->ecmtask[i].idx==idx)
    {
      casc_check_dcw(reader, i, rc, dcw);
      j=1;
      break;
    }
  }
}

static void casc_get_dcw(struct s_reader * reader, int n)
{
  int w;
  struct timeb tps, tpe;
  struct s_client *cl = reader->client;
  tpe=cl->ecmtask[n].tps;
  //tpe.millitm+=1500;    // TODO: timeout of 1500 should be config

  tpe.time += cfg->srtimeout/1000;
  tpe.millitm += cfg->srtimeout%1000;
  
  cs_ftime(&tps);
  while (((w=1000*(tpe.time-tps.time)+tpe.millitm-tps.millitm)>0)
          && (cl->ecmtask[n].rc>=10))
  {
    casc_do_sock(reader, w);
    cs_ftime(&tps);
  }
  if (cl->ecmtask[n].rc>=10)
    casc_check_dcw(reader, n, 0, cl->ecmtask[n].cw);  // simulate "not found"
}



int casc_process_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  int rc, n, i, sflag;
  time_t t;//, tls;
  struct s_client *cl = reader->client;
  
  uchar buf[512];

  t=time((time_t *)0);
  for (n=-1, i=0, sflag=1; i<CS_MAXPENDING; i++)
  {
    if ((t-(ulong)cl->ecmtask[i].tps.time > ((cfg->ctimeout + 500) / 1000) + 1) &&
        (cl->ecmtask[i].rc>=10))      // drop timeouts
        {
          cl->ecmtask[i].rc=0;
        }
    if (n<0 && (cl->ecmtask[i].rc<10))   // free slot found
      n=i;
    if ((cl->ecmtask[i].rc>=10) &&      // ecm already pending
        (!memcmp(er->ecmd5, cl->ecmtask[i].ecmd5, CS_ECMSTORESIZE)) &&
        (er->level<=cl->ecmtask[i].level))    // ... this level at least
      sflag=0;
  }
  if (n<0)
  {
    cs_log("WARNING: ecm pending table overflow !!");
    return(-2);
  }
  memcpy(&cl->ecmtask[n], er, sizeof(ECM_REQUEST));
  cl->ecmtask[n].matching_rdr = NULL; //This avoids double free of matching_rdr!
  if( reader->typ == R_NEWCAMD )
    cl->ecmtask[n].idx=(reader->ncd_msgid==0)?2:reader->ncd_msgid+1;
  else
    cl->ecmtask[n].idx=cl->idx++;
  cl->ecmtask[n].rc=10;
  cs_debug_mask(D_READER, "---- ecm_task %d, idx %d, sflag=%d, level=%d", 
           n, cl->ecmtask[n].idx, sflag, er->level);

  if( reader->ph.type==MOD_CONN_TCP && reader->tcp_rto )
  {
    int rto = abs(reader->last_s - reader->last_g);
    if (rto >= (reader->tcp_rto*60))
    {
      if (reader->ph.c_idle)
      	reader_do_idle(reader);
      else {
        cs_debug_mask(D_READER, "rto=%d", rto);
        network_tcp_connection_close(reader->client, cl->udp_fd);
      }
    }
  }

  cs_ddump_mask(D_ATR, er->ecm, er->l, "casc ecm:");
  rc=0;
  if (sflag)
  {
    if ((rc=reader->ph.c_send_ecm(cl, &cl->ecmtask[n], buf)))
      casc_check_dcw(reader, n, 0, cl->ecmtask[n].cw);  // simulate "not found"
    else
      cl->last_idx = cl->ecmtask[n].idx;
    reader->last_s = t;   // used for inactive_timeout and reconnect_timeout in TCP reader

    if (!reader->ph.c_multi)
      casc_get_dcw(reader, n);
  }

//cs_log("casc_process_ecm 1: last_s=%d, last_g=%d", reader->last_s, reader->last_g);

  if (cl->idx>0x1ffe) cl->idx=1;
  return(rc);
}

static int reader_store_emm(uchar *emm, uchar type)
{
  int rc;
  struct s_client *cl = cur_client();
  memcpy(cl->emmcache[cl->rotate].emmd5, MD5(emm, emm[2], cl->dump), CS_EMMSTORESIZE);
  cl->emmcache[cl->rotate].type=type;
  cl->emmcache[cl->rotate].count=1;
//  cs_debug_mask(D_READER, "EMM stored (index %d)", rotate);
  rc=cl->rotate;
  cl->rotate=(++cl->rotate < CS_EMMCACHESIZE)?cl->rotate:0;
  return(rc);
}

static void reader_get_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  //cs_log("hallo idx:%d rc:%d caid:%04X",er->idx,er->rc,er->caid);
  if ((er->rc<E_NOCARD) ) //FIXME should this not be <= E_STOPPED?
    {
      send_dcw(reader->client, er);
      return;
    }
  
  er->ocaid=er->caid;
  if (!chk_bcaid(er, &reader->ctab))
  {
    cs_debug_mask(D_READER, "caid %04X filtered", er->caid);
    er->rcEx=E2_CAID;
    er->rc = E_RDR_NOTFOUND;
    write_ecm_answer(reader, er);
    return;
  }
  // cache2
  if (check_cwcache2(er, er->client->grp))
  {
    er->rc = E_CACHE2;
    write_ecm_answer(reader, er);
    return;
  }
  if (reader->typ & R_IS_CASCADING)
  {
    struct s_client *cl = reader->client;
    cl->last_srvid=er->srvid;
    cl->last_caid=er->caid;
    casc_process_ecm(reader, er);
    return;
  }
#ifdef WITH_CARDREADER
  if (reader->ratelimitecm) {
	cs_debug_mask(D_READER, "ratelimit idx:%d rc:%d caid:%04X srvid:%04X",er->idx,er->rc,er->caid,er->srvid);
	int foundspace=-1;
	int h;
	for (h=0;h<reader->ratelimitecm;h++) {
		if (reader->rlecmh[h].srvid == er->srvid) {
			foundspace=h;
			cs_debug_mask(D_READER, "ratelimit found srvid in use at pos: %d",h);
			break;
		} 
	}
	if (foundspace<0) {
		for (h=0;h<reader->ratelimitecm;h++) {
			if ((reader->rlecmh[h].last ==- 1) || ((time(NULL)-reader->rlecmh[h].last) > reader->ratelimitseconds)) {
				foundspace=h;
				cs_debug_mask(D_READER, "ratelimit found space at pos: %d old seconds %d",h,reader->rlecmh[h].last);
				break;
			} 
		}
	}
	if (foundspace<0) {
		//drop
		cs_debug_mask(D_READER, "ratelimit could not find space for srvid %04X. Dropping.",er->srvid);
		er->rcEx=32;
		er->rc = E_RDR_NOTFOUND;
		int clcw;
		for (clcw=0;clcw<16;clcw++) er->cw[clcw]=(uchar)0;
		snprintf( er->msglog, MSGLOGSIZE, "ECMratelimit no space for srvid" );
		write_ecm_answer(reader, er);
		return;
	} else {
		reader->rlecmh[foundspace].last=time(NULL);
		reader->rlecmh[foundspace].srvid=er->srvid;
	}

  }
  cs_ddump_mask(D_ATR, er->ecm, er->l, "ecm:");
  er->msglog[0] = 0;
  struct timeb tps, tpe;
  cs_ftime(&tps);
  er->rc=reader_ecm(reader, er);
  cs_ftime(&tpe);
  if (cs_dblevel) {
	ushort lc, *lp;
	for (lp=(ushort *)er->ecm+(er->l>>2), lc=0; lp>=(ushort *)er->ecm; lp--)
		lc^=*lp;
	cs_debug_mask(D_TRACE, "reader: %s ecm: %04X real time: %d ms", reader->label, lc, 1000*(tpe.time-tps.time)+tpe.millitm-tps.millitm);
  }
  write_ecm_answer(reader, er);
  reader_post_process(reader);
#endif
}

static int reader_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  int i, no, rc, ecs;
  char *rtxt[] = { "error", (reader->typ & R_IS_CASCADING) ? "sent" : "written", "skipped", "blocked" };
  char *typedesc[]= { "unknown", "unique", "shared", "global" };
  struct timeb tps, tpe;
  struct s_client *cl = reader->client;

  cs_ftime(&tps);

	MD5(ep->emm, ep->emm[2], cl->dump);

	no=0;
	for (i=ecs=0; (i<CS_EMMCACHESIZE) && (!ecs); i++) {
       	if (!memcmp(cl->emmcache[i].emmd5, cl->dump, CS_EMMSTORESIZE)) {
			if (reader->cachemm)
				ecs=(reader->rewritemm > cl->emmcache[i].count) ? 1 : 2;
			else
				ecs=1;
			no=++cl->emmcache[i].count;
			i--;
		}
	}

  if ((rc=ecs)<2)
  {
          if (reader->typ & R_IS_CASCADING) {
                  cs_debug_mask(D_READER, "network emm reader: %s" ,reader->label);

                  if (reader->ph.c_send_emm) {
                          rc=reader->ph.c_send_emm(ep);
                  } else {
                          cs_debug_mask(D_READER, "send_emm() support missing");
                          rc=0;
                  }
          } else {
                  cs_debug_mask(D_READER, "local emm reader: %s" ,reader->label);
#ifdef WITH_CARDREADER
                  rc=reader_emm(reader, ep);
#else
                  rc=0;
#endif
          }

          if (!ecs)
          {
                  i=reader_store_emm(ep->emm, ep->type);
                  no=1;
          }
  }

  if (rc) cl->lastemm=time((time_t)0);

#ifdef CS_LED
  if (rc) cs_switch_led(LED3, LED_BLINK_ON);
#endif

  if (reader->logemm & (1 << rc))
  {
    cs_ftime(&tpe);

    cs_log("%s emmtype=%s, len=%d, idx=%d, cnt=%d: %s (%d ms) by %s",
           username(ep->client), typedesc[cl->emmcache[i].type], ep->emm[2],
           i, no, rtxt[rc], 1000*(tpe.time-tps.time)+tpe.millitm-tps.millitm, reader->label); //FIXME not sure why emmtyp must come from ep->client and typedesc can be of cur_client
  }

#ifdef WEBIF
  //counting results
  switch(rc){
	  case 0:
		  reader->emmerror[ep->type]++;
		  break;
	  case 1:
		  reader->emmwritten[ep->type]++;
		  break;
	  case 2:
		  reader->emmskipped[ep->type]++;
		  break;
	  case 3:
		  reader->emmblocked[ep->type]++;
		  break;
  }
#endif

#ifdef QBOXHD_LED
  if (rc) qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,QBOXHD_LED_BLINK_MEDIUM);
#endif


  return(rc);
}

static int reader_listen(struct s_reader * reader, int fd1, int fd2)
{
  int fdmax, tcp_toflag, use_tv=(!(reader->typ & R_IS_CASCADING));
  int is_tcp=(reader->ph.type==MOD_CONN_TCP);
  fd_set fds;
  struct timeval tv;

#ifdef CS_WITH_GBOX 
  if(reader->typ==R_GBOX) {
    struct timeb tpe;
    int x;
    ulong ms;
    cs_ftime(&tpe);
    for(x=0;x<CS_MAXPENDING;x++){
      ms=1000*(tpe.time-cl->ecmtask[x].tps.time)+tpe.millitm-cl->ecmtask[x].tps.millitm;
      if(cl->ecmtask[x].rc == 10 && ms > cfg->ctimeout && cl->ridx == cl->ecmtask[x].gbxRidx) {
        //cs_log("hello rc=%d idx:%d x:%d ridx%d ridx:%d",cl->ecmtask[x].rc,cl->ecmtask[x].idx,x,ridx,cl->ecmtask[x].gbxRidx);
        cl->ecmtask[x].rc=5;
        send_dcw(cl, &cl->ecmtask[x]);
      }
    }
  }
#endif

  tcp_toflag=(fd2 && is_tcp && reader->tcp_ito && reader->tcp_connected);
  tv.tv_sec = 0;
  tv.tv_usec = 100000L;
  if (tcp_toflag)
  {
    tv.tv_sec = reader->tcp_ito*60;
    tv.tv_usec = 0;
    use_tv = 1;
  } 
  FD_ZERO(&fds);
  FD_SET(fd1, &fds);
  if (fd2) FD_SET(fd2, &fds);
  if (logfd) FD_SET(logfd, &fds);
  fdmax=(fd1>fd2) ? fd1 : fd2;
  fdmax=(fdmax>logfd) ? fdmax : logfd;
  if (select(fdmax+1, &fds, 0, 0, (use_tv) ? &tv : 0)<0) return(0);

  if ((logfd) && (FD_ISSET(logfd, &fds)))
  {
    cs_debug_mask(D_READER, "select: log-socket ist set");
    return(3);
  }

  if ((fd2) && (FD_ISSET(fd2, &fds)))
  {
    cs_debug_mask(D_READER, "select: socket is set");
    return(2);
  }

  if (FD_ISSET(fd1, &fds))
  {
    if (tcp_toflag)
    {
      time_t now;
      int time_diff;
      time(&now);
      time_diff = abs(now-reader->last_s);
      if (time_diff>(reader->tcp_ito*60))
      {
        if (reader->ph.c_idle)
          reader_do_idle(reader);
        else {
          cs_debug_mask(D_READER, "%s inactive_timeout (%d), close connection (fd=%d)", 
                  reader->ph.desc, time_diff, fd2);
          network_tcp_connection_close(reader->client, fd2);
        }
      }
    }
    cs_debug_mask(D_READER, "select: pipe is set");
    return(1);
  }

  if (tcp_toflag)
  {
    if (reader->ph.c_idle)
      reader_do_idle(reader);
    else {
      cs_debug_mask(D_READER, "%s inactive_timeout (%d), close connection (fd=%d)", 
             reader->ph.desc, tv.tv_sec, fd2);
      network_tcp_connection_close(reader->client, fd2);
    }
    return(0);
  }

#ifdef WITH_CARDREADER
  if (!(reader->typ & R_IS_CASCADING)) reader_checkhealth(reader);
#endif
  return(0);
}

void reader_do_card_info(struct s_reader * reader)
{
#ifdef WITH_CARDREADER
      reader_card_info(reader); 
#endif
      if (reader->ph.c_card_info)
      	reader->ph.c_card_info();
}

void clear_reader_pipe(struct s_reader * reader)
{
	uchar *ptr;
	int pipeCmd;
	while (reader && reader->client && reader->client->fd_m2c_c)
	{
		pipeCmd = read_from_pipe(reader->client->fd_m2c_c, &ptr, 0);
		if (ptr) free(ptr);
		if (pipeCmd==PIP_ID_ERR || pipeCmd==PIP_ID_NUL)
			break;
	}
}

static void reader_do_pipe(struct s_reader * reader)
{
  uchar *ptr;
  int pipeCmd = read_from_pipe(reader->client->fd_m2c_c, &ptr, 0);

  switch(pipeCmd)
  {
    case PIP_ID_ECM:
      reader_get_ecm(reader, (ECM_REQUEST *)ptr);
      break;
    case PIP_ID_EMM:
      reader_do_emm(reader, (EMM_PACKET *)ptr);
      break;
    case PIP_ID_CIN: 
      reader_do_card_info(reader);
      break;
    case PIP_ID_ERR:
      cs_exit(1);
      break;
    default:
       cs_log("unhandled pipe message %d (reader %s)", pipeCmd, reader->label);
       break;
  }
  if (ptr) free(ptr);
}

void reader_do_idle(struct s_reader * reader)
{
  if (reader->ph.c_idle) 
    reader->ph.c_idle();
}

static void reader_main(struct s_reader * reader)
{
  while (1)
  {
    switch(reader_listen(reader, reader->client->fd_m2c_c, reader->client->pfd))
    {
      case 0: reader_do_idle(reader); break;
      case 1: reader_do_pipe(reader)  ; break;
      case 2: casc_do_sock(reader, 0)   ; break;
      case 3: casc_do_sock_log(reader); break;
    }
  }
}

void * start_cardreader(void * rdr)
{
	struct s_reader * reader = (struct s_reader *) rdr;

	reader->client->thread=pthread_self();
	pthread_setspecific(getclient, reader->client);

  if (reader->typ & R_IS_CASCADING)
  {
    reader->client->typ='p';
    reader->client->port=reader->r_port;
    cs_log("proxy thread started  (thread=%8X, label=%s, server=%s)",pthread_self(), reader->label, reader->device);
    
    if (!(reader->ph.c_init)) {
      cs_log("FATAL: %s-protocol not supporting cascading", reader->ph.desc);
      cs_sleepms(1000);
      cs_exit(1);
    }
    
	if (reader->ph.c_init(reader->client)) {
		//proxy reader start failed
		cs_exit(1);
	}
    
    if ((reader->log_port) && (reader->ph.c_init_log))
      reader->ph.c_init_log();
  }
#ifdef WITH_CARDREADER
  else
  {
    reader->client->ip=cs_inet_addr("127.0.0.1");
    cs_log("reader thread started (thread=%8X, label=%s, device=%s, detect=%s%s, mhz=%d, cardmhz=%d)", pthread_self(), reader->label,
        reader->device, reader->detect&0x80 ? "!" : "",RDR_CD_TXT[reader->detect&0x7f], reader->mhz,reader->cardmhz);
   	while (reader_device_init(reader)==2)
     	cs_sleepms(60000); // wait 60 secs and try again
  }

#endif
  reader->client->emmcache=(struct s_emm *)malloc(CS_EMMCACHESIZE*(sizeof(struct s_emm)));
  if (!reader->client->emmcache)
  {
    cs_log("Cannot allocate memory (errno=%d)", errno);
    cs_exit(1);
  }
  memset(reader->client->emmcache, 0, CS_EMMCACHESIZE*(sizeof(struct s_emm)));

  reader->client->ecmtask=(ECM_REQUEST *)malloc(CS_MAXPENDING*(sizeof(ECM_REQUEST)));
  if (!reader->client->ecmtask)
  {
    cs_log("Cannot allocate memory (errno=%d)", errno);
    cs_exit(1);
  }
  memset(reader->client->ecmtask, 0, CS_MAXPENDING*(sizeof(ECM_REQUEST)));
  reader_main(reader);
  cs_exit(0);
	return NULL; //dummy to prevent compiler error
}

