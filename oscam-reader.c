#include "globals.h"
#include "reader-common.h"

int32_t logfd=0;

void reader_do_idle(struct s_reader * reader);

void cs_ri_brk(struct s_reader * reader, int32_t flag)
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
	vsnprintf(txt, sizeof(txt), fmt, params);
	va_end(params);
	cs_log("%s", txt);

	if (cfg.saveinithistory) {
		int32_t size = reader->init_history_pos+strlen(txt)+2;

		cs_realloc(&reader->init_history, size, -1);

		if (!reader->init_history)
			return;

		snprintf(reader->init_history+reader->init_history_pos, strlen(txt)+2, "%s\n", txt);
		reader->init_history_pos+=strlen(txt)+1;
	}
}

void casc_check_dcw(struct s_reader * reader, int32_t idx, int32_t rc, uchar *cw)
{
	int32_t i, pending=0;
	time_t t = time(NULL);
	ECM_REQUEST *ecm;
	struct s_client *cl = reader->client;

	if(!cl) return; 
  
	for (i=0; i<CS_MAXPENDING; i++) {
		ecm = &cl->ecmtask[i];
		if ((ecm->rc>=10) && ecm->caid == cl->ecmtask[idx].caid && (!memcmp(ecm->ecmd5, cl->ecmtask[idx].ecmd5, CS_ECMSTORESIZE))) {
			if (rc) {
				ecm->rc=(i==idx) ? 1 : 2;
				memcpy(ecm->cw, cw, 16);
			} else
				ecm->rc=0;
			write_ecm_answer(reader, ecm);
			ecm->idx=0;
		}

		if (ecm->rc>=10 && (t-(uint32_t)ecm->tps.time > ((cfg.ctimeout + 500) / 1000) + 1)) { // drop timeouts
			ecm->rc=0;
#ifdef WITH_LB
			send_reader_stat(reader, ecm, E_TIMEOUT);
#endif
		}

		if (ecm->rc >= 10)
			pending++;
	}
	cl->pending=pending;
}

int32_t hostResolve(struct s_reader *rdr){
   struct s_client *cl = rdr->client;
   
   if(!cl) return 0;
    
   in_addr_t last_ip = cl->ip;
   cl->ip = cs_getIPfromHost(rdr->device);
   cl->udp_sa.sin_addr.s_addr = cl->ip;
   
   if (cl->ip != last_ip) {
     cs_log("%s: resolved ip=%s", rdr->device, cs_inet_ntoa(cl->ip));
   }

   return cl->ip?1:0;
}

void clear_block_delay(struct s_reader *rdr) {
   rdr->tcp_block_delay = 0;
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

int32_t is_connect_blocked(struct s_reader *rdr) {
  struct timeb cur_time;
  cs_ftime(&cur_time);
  return (rdr->tcp_block_delay && comp_timeb(&cur_time, &rdr->tcp_block_connect_till) < 0);
}
                
int32_t network_tcp_connection_open(struct s_reader *rdr)
{
	if (!rdr) return -1;
	struct s_client *client = rdr->client;
	cs_log("connecting to %s:%d", rdr->device, rdr->r_port);
	struct sockaddr_in loc_sa;

	memset((char *)&client->udp_sa, 0, sizeof(client->udp_sa));

	in_addr_t last_ip = client->ip;
	if (!hostResolve(rdr))
		return -1;

	if (last_ip != client->ip) //clean blocking delay on ip change:
		clear_block_delay(rdr);

	if (is_connect_blocked(rdr)) { //inside of blocking delay, do not connect!
		cs_debug_mask(D_TRACE, "tcp connect blocking delay asserted for %s", rdr->label);
		return -1;
	}

	client->pfd=0;
	if (client->reader->r_port<=0) {
		cs_log("invalid port %d for server %s", client->reader->r_port, client->reader->device);
		return(1);
	}

	client->is_udp=(rdr->typ==R_CAMD35);

	client->ip=0;
	memset((char *)&loc_sa,0,sizeof(loc_sa));
	loc_sa.sin_family = AF_INET;
#ifdef LALL
	if (cfg.serverip[0])
		loc_sa.sin_addr.s_addr = inet_addr(cfg.serverip);
	else
#endif
		loc_sa.sin_addr.s_addr = INADDR_ANY;

	loc_sa.sin_port = htons(client->reader->l_port);

	if ((client->udp_fd=socket(PF_INET, client->is_udp ? SOCK_DGRAM : SOCK_STREAM, client->is_udp ? IPPROTO_UDP : IPPROTO_TCP))<0) {
		cs_log("Socket creation failed (errno=%d %s)", errno, strerror(errno));
		return 1;
	}

#ifdef SO_PRIORITY
	if (cfg.netprio)
		setsockopt(client->udp_fd, SOL_SOCKET, SO_PRIORITY, (void *)&cfg.netprio, sizeof(uintptr_t));
#endif

	int32_t keep_alive = 1;
	setsockopt(client->udp_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keep_alive, sizeof(keep_alive));

	if (!client->reader->tcp_ito) { 
		uint32_t keep_alive = client->reader->tcp_ito?1:0;
		setsockopt(client->udp_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keep_alive, sizeof(uintptr_t));
	}

	if (client->reader->l_port>0) {
		if (bind(client->udp_fd, (struct sockaddr *)&loc_sa, sizeof (loc_sa))<0) {
			cs_log("bind failed (errno=%d %s)", errno, strerror(errno));
			close(client->udp_fd);
			return 1;
		}
	}

	client->udp_sa.sin_family = AF_INET;
	client->udp_sa.sin_port = htons((uint16_t)client->reader->r_port);

	cs_log("socket open for %s fd=%d", rdr->ph.desc, client->udp_fd);

	if (client->is_udp) {
		rdr->tcp_connected = 1;
		return client->udp_fd;
	}
  
	//int32_t flag = 1;
	//setsockopt(cl->udp_fd, IPPROTO_TCP, SO_DEBUG, (char *) &flag, sizeof(int));

	int32_t sd = client->udp_fd;

	int32_t res = connect(sd, (struct sockaddr *)&client->udp_sa, sizeof(client->udp_sa));
	if (res == -1) {
		cs_log("connect(fd=%d) failed: (errno=%d %s)", sd, errno, strerror(errno));
		//connect has failed. Block connect for a while:
		block_connect(rdr);
      
		return -1; 
	}

	setTCPTimeouts(sd);
	clear_block_delay(rdr);
	client->pfd = client->udp_fd;
	rdr->tcp_connected = 1;
	cs_log("connect succesfull %s fd=%d", rdr->ph.desc, client->udp_fd);
	return sd;
}

void network_tcp_connection_close(struct s_reader *reader)
{
	struct s_client *cl = reader->client;
	if(!cl) return;
	int32_t fd = cl->udp_fd;

	cs_log("tcp_conn_close(): fd=%d, cl->typ == '%c' is_udp %d", fd, cl->typ, cl->is_udp);
	int32_t i;

	if (!reader || cl->typ != 'p') {
		//only proxy reader should call this, client connections are closed on thread cleanup
		cs_log("invalid client tcp_conn_close()");
		cs_exit(0);
	}

	if (fd) {
		close(fd);

		cl->udp_fd = 0;
		cl->pfd = 0;
	}

	reader->tcp_connected = 0;

	if (cl->ecmtask) {
		for (i = 0; i < CS_MAXPENDING; i++) {
			cl->ecmtask[i].idx = 0;
			cl->ecmtask[i].rc = 0;
		}
	}
}

void casc_do_sock_log(struct s_reader * reader)
{
  int32_t i, idx;
  uint16_t caid, srvid;
  uint32_t provid;
  struct s_client *cl = reader->client;
  
  if(!cl) return;

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

int32_t casc_process_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
	int32_t rc, n, i, sflag, pending=0;
	time_t t;//, tls;
	struct s_client *cl = reader->client;
  
	if(!cl) return -1;
  
	uchar buf[512];

	t=time((time_t *)0);
	ECM_REQUEST *ecm;
	for (n=-1, i=0, sflag=1; i<CS_MAXPENDING; i++) {
		ecm = &cl->ecmtask[i];
		if ((ecm->rc>=10) && (t-(uint32_t)ecm->tps.time > ((cfg.ctimeout + 500) / 1000) + 1)) { // drop timeouts
			ecm->rc=0;
#ifdef WITH_LB
			send_reader_stat(reader, ecm, E_TIMEOUT);
#endif
		}
		if (n<0 && (ecm->rc<10))   // free slot found
			n=i;

		if ((ecm->rc>=10) &&      // ecm already pending
		 er->caid == ecm->caid &&
		 (!memcmp(er->ecmd5, ecm->ecmd5, CS_ECMSTORESIZE)) &&
		 (er->level<=ecm->level))    // ... this level at least
			sflag=0;
      
		if (ecm->rc >=10) 
			pending++;
	}
	cl->pending=pending;

	if (n<0) {
		cs_log("WARNING: ecm pending table overflow !!");
		return(-2);
	}

	memcpy(&cl->ecmtask[n], er, sizeof(ECM_REQUEST));
	cl->ecmtask[n].matching_rdr = NULL; //This avoids double free of matching_rdr!

	if( reader->typ == R_NEWCAMD )
		cl->ecmtask[n].idx=(reader->ncd_msgid==0)?2:reader->ncd_msgid+1;
	else {
		if (!cl->idx)
    			cl->idx = 1;
		cl->ecmtask[n].idx=cl->idx++;
	}

	cl->ecmtask[n].rc=10;
	cs_debug_mask(D_READER, "---- ecm_task %d, idx %d, sflag=%d, level=%d", n, cl->ecmtask[n].idx, sflag, er->level);

	cs_ddump_mask(D_ATR, er->ecm, er->l, "casc ecm:");
	rc=0;
	if (sflag) {
		if ((rc=reader->ph.c_send_ecm(cl, &cl->ecmtask[n], buf)))
			casc_check_dcw(reader, n, 0, cl->ecmtask[n].cw);  // simulate "not found"
		else
			cl->last_idx = cl->ecmtask[n].idx;
		reader->last_s = t;   // used for inactive_timeout and reconnect_timeout in TCP reader
	}

//cs_log("casc_process_ecm 1: last_s=%d, last_g=%d", reader->last_s, reader->last_g);

	if (cl->idx>0x1ffe) cl->idx=1;

	return(rc);
}

static int32_t reader_store_emm(uchar *emm, uchar type)
{
  int32_t rc;
  unsigned char md5tmp[MD5_DIGEST_LENGTH];
  struct s_client *cl = cur_client();
  memcpy(cl->emmcache[cl->rotate].emmd5, MD5(emm, emm[2], md5tmp), CS_EMMSTORESIZE);
  cl->emmcache[cl->rotate].type=type;
  cl->emmcache[cl->rotate].count=1;
//  cs_debug_mask(D_READER, "EMM stored (index %d)", rotate);
  rc=cl->rotate;
  cl->rotate=(++cl->rotate < CS_EMMCACHESIZE)?cl->rotate:0;
  return(rc);
}

void reader_get_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
  //cs_log("hallo idx:%d rc:%d caid:%04X",er->idx,er->rc,er->caid);
  if (er->rc<=E_STOPPED)
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
  if (check_cwcache2(er, reader->grp))
  {
    er->rc = E_CACHE2;
    write_ecm_answer(reader, er);
    return;
  }
  if (reader->typ & R_IS_CASCADING)
  {
    struct s_client *cl = reader->client;
    if(!cl) return;
    cl->last_srvid=er->srvid;
    cl->last_caid=er->caid;
    casc_process_ecm(reader, er);
    return;
  }
#ifdef WITH_CARDREADER
  if (reader->ratelimitecm) {
	cs_debug_mask(D_READER, "ratelimit idx:%d rc:%d caid:%04X srvid:%04X",er->idx,er->rc,er->caid,er->srvid);
	int32_t foundspace=-1;
	int32_t h;
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
		int32_t clcw;
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
  if(er->rc == ERROR){
  	char buf[32];
  	cs_log("Error processing ecm for caid %04X, srvid %04X (servicename: %s) on reader %s.", er->caid, er->srvid, get_servicename(reader->client, er->srvid, er->caid, buf), reader->label);  	
  }
  cs_ftime(&tpe);
  if (cs_dblevel) {
	uint16_t lc, *lp;
	for (lp=(uint16_t *)er->ecm+(er->l>>2), lc=0; lp>=(uint16_t *)er->ecm; lp--)
		lc^=*lp;
	cs_debug_mask(D_TRACE, "reader: %s ecm: %04X real time: %d ms", reader->label, lc, 1000*(tpe.time-tps.time)+tpe.millitm-tps.millitm);
  }
  write_ecm_answer(reader, er);
  reader_post_process(reader);
#endif
}

int32_t reader_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
  int32_t i, no, rc, ecs;
  unsigned char md5tmp[MD5_DIGEST_LENGTH];
  char *rtxt[] = { "error", (reader->typ & R_IS_CASCADING) ? "sent" : "written", "skipped", "blocked" };
  char *typedesc[]= { "unknown", "unique", "shared", "global" };
  struct timeb tps, tpe;
  struct s_client *cl = reader->client;
  
  if(!cl) return 0;

  cs_ftime(&tps);

	MD5(ep->emm, ep->emm[2], md5tmp);

	no=0;
	for (i=ecs=0; (i<CS_EMMCACHESIZE) && (!ecs); i++) {
       	if (!memcmp(cl->emmcache[i].emmd5, md5tmp, CS_EMMSTORESIZE)) {
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

void reader_do_card_info(struct s_reader * reader)
{
#ifdef WITH_CARDREADER
      reader_card_info(reader); 
#endif
      if (reader->ph.c_card_info)
      	reader->ph.c_card_info();
}

void reader_do_idle(struct s_reader * reader)
{
	if (reader->ph.c_idle)
		reader->ph.c_idle();
	else {
		if (reader->client && reader->client->pfd && reader->tcp_connected) {
			cs_debug_mask(D_READER, "%s inactive_timeout, close connection (fd=%d)", reader->ph.desc, reader->client->pfd);
			network_tcp_connection_close(reader);
		}
	}
}

void reader_init(struct s_reader *reader) {
	struct s_client *client = reader->client;

	if (reader->typ & R_IS_CASCADING) {
		client->typ='p';
		client->port=reader->r_port;
		cs_log("proxy thread started  (thread=%8X, label=%s, server=%s)",pthread_self(), reader->label, reader->device);

		if (!(reader->ph.c_init)) {
			cs_log("FATAL: %s-protocol not supporting cascading", reader->ph.desc);
			cs_sleepms(1000);
			cs_exit(1);
		}

		if (reader->ph.c_init(client)) {
			//proxy reader start failed
			cs_exit(1);
		}

		if ((reader->log_port) && (reader->ph.c_init_log))
			reader->ph.c_init_log();
	}
#ifdef WITH_CARDREADER
	else {
		client->ip=cs_inet_addr("127.0.0.1");
		cs_log("reader thread started (thread=%8X, label=%s, device=%s, detect=%s%s, mhz=%d, cardmhz=%d)", pthread_self(), reader->label,
			reader->device, reader->detect&0x80 ? "!" : "",RDR_CD_TXT[reader->detect&0x7f], reader->mhz,reader->cardmhz);
		while (reader_device_init(reader)==2)
			cs_sleepms(60000); // wait 60 secs and try again
	}
#endif

	cs_malloc(&client->emmcache,CS_EMMCACHESIZE*(sizeof(struct s_emm)), 1);
	cs_malloc(&client->ecmtask,CS_MAXPENDING*(sizeof(ECM_REQUEST)), 1);
}
