#include "globals.h"
#include "module-cccam.h"
#include "module-led.h"
#include "module-stat.h"
#include "oscam-client.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "reader-common.h"

/**
 * add one entitlement item to entitlements of reader.
 **/
void cs_add_entitlement(struct s_reader *rdr, uint16_t caid, uint32_t provid, uint64_t id, uint32_t class, time_t start, time_t end, uint8_t type)
{
	if (!rdr->ll_entitlements) rdr->ll_entitlements = ll_create("ll_entitlements");

	S_ENTITLEMENT *item;
	if (cs_malloc(&item, sizeof(S_ENTITLEMENT))) {

		// fill item
		item->caid = caid;
		item->provid = provid;
		item->id = id;
		item->class = class;
		item->start = start;
		item->end = end;
		item->type = type;

		//add item
		ll_append(rdr->ll_entitlements, item);

	  // cs_debug_mask(D_TRACE, "entitlement: Add caid %4X id %4X %s - %s ", item->caid, item->id, item->start, item->end);
	}

}

/**
 * clears entitlements of reader.
 **/
void cs_clear_entitlement(struct s_reader *rdr)
{
	if (!rdr->ll_entitlements)
		return;

	ll_clear_data(rdr->ll_entitlements);
}


void casc_check_dcw(struct s_reader * reader, int32_t idx, int32_t rc, uchar *cw)
{
	int32_t i, pending=0;
	time_t t = time(NULL);
	ECM_REQUEST *ecm;
	struct s_client *cl = reader->client;

	if(!cl) return;

	for (i = 0; i < cfg.max_pending; i++) {
		ecm = &cl->ecmtask[i];
		if ((ecm->rc>=10) && ecm->caid == cl->ecmtask[idx].caid && (!memcmp(ecm->ecmd5, cl->ecmtask[idx].ecmd5, CS_ECMSTORESIZE))) {
			if (rc) {
				write_ecm_answer(reader, ecm, (i==idx) ? E_FOUND : E_CACHE2, 0, cw, NULL); 
			} else {
				write_ecm_answer(reader, ecm, E_NOTFOUND, 0 , NULL, NULL);
			}
			ecm->idx=0;
			ecm->rc=0;
		}

		if (ecm->rc>=10 && (t-(uint32_t)ecm->tps.time > ((cfg.ctimeout + 500) / 1000) + 1)) { // drop timeouts
			ecm->rc=0;
			send_reader_stat(reader, ecm, NULL, E_TIMEOUT);
		}

		if (ecm->rc >= 10)
			pending++;
	}
	cl->pending=pending;
}

int32_t hostResolve(struct s_reader *rdr){
   struct s_client *cl = rdr->client;

   if(!cl) return 0;

   IN_ADDR_T last_ip;
   IP_ASSIGN(last_ip, cl->ip);
   cs_resolve(rdr->device, &cl->ip, &cl->udp_sa, &cl->udp_sa_len);
   IP_ASSIGN(SIN_GET_ADDR(cl->udp_sa), cl->ip);

   if (!IP_EQUAL(cl->ip, last_ip)) {
     cs_log("%s: resolved ip=%s", rdr->device, cs_inet_ntoa(cl->ip));
   }

   return IP_ISSET(cl->ip);
}

void clear_block_delay(struct s_reader *rdr) {
   rdr->tcp_block_delay = 0;
   cs_ftime(&rdr->tcp_block_connect_till);
}

void block_connect(struct s_reader *rdr) {
  if (!rdr->tcp_block_delay)
  	rdr->tcp_block_delay = 100; //starting blocking time, 100ms
  cs_ftime(&rdr->tcp_block_connect_till);
  rdr->tcp_block_connect_till.time += rdr->tcp_block_delay / 1000;
  rdr->tcp_block_connect_till.millitm += rdr->tcp_block_delay % 1000;
  rdr->tcp_block_delay *= 4; //increment timeouts
  if (rdr->tcp_block_delay >= 60*1000)
    rdr->tcp_block_delay = 60*1000; //max 1min, todo config
  rdr_debug_mask(rdr, D_TRACE, "tcp connect blocking delay set to %d", rdr->tcp_block_delay);
}

int32_t is_connect_blocked(struct s_reader *rdr) {
  struct timeb cur_time;
  cs_ftime(&cur_time);
  int32_t blocked = (rdr->tcp_block_delay && comp_timeb(&cur_time, &rdr->tcp_block_connect_till) < 0);
  if (blocked) {
		int32_t ts = 1000*(rdr->tcp_block_connect_till.time-cur_time.time)
				+rdr->tcp_block_connect_till.millitm-cur_time.millitm;
		rdr_debug_mask(rdr, D_TRACE, "connection blocked, retrying in %ds", ts/1000);
  }
  return blocked;
}

int32_t network_tcp_connection_open(struct s_reader *rdr)
{
	if (!rdr) return -1;
	struct s_client *client = rdr->client;
	struct sockaddr_in loc_sa;

	memset((char *)&client->udp_sa, 0, sizeof(client->udp_sa));

	IN_ADDR_T last_ip;
	IP_ASSIGN(last_ip, client->ip);
	if (!hostResolve(rdr))
		return -1;

	if (!IP_EQUAL(last_ip, client->ip)) //clean blocking delay on ip change:
		clear_block_delay(rdr);

	if (is_connect_blocked(rdr)) { //inside of blocking delay, do not connect!
		return -1;
	}

	if (client->reader->r_port<=0) {
		rdr_log(client->reader, "invalid port %d for server %s", client->reader->r_port, client->reader->device);
		return -1;
	}

	client->is_udp=(rdr->typ==R_CAMD35);

	rdr_log(rdr, "connecting to %s:%d", rdr->device, rdr->r_port);

	if (client->udp_fd)
		rdr_log(rdr, "WARNING: client->udp_fd was not 0");

	int s_domain = PF_INET;
#ifdef IPV6SUPPORT
	if (!IN6_IS_ADDR_V4MAPPED(&rdr->client->ip) && !IN6_IS_ADDR_V4COMPAT(&rdr->client->ip))
		s_domain = PF_INET6;
#endif
	int s_type   = client->is_udp ? SOCK_DGRAM : SOCK_STREAM;
	int s_proto  = client->is_udp ? IPPROTO_UDP : IPPROTO_TCP;

	if ((client->udp_fd = socket(s_domain, s_type, s_proto)) < 0) {
		rdr_log(rdr, "Socket creation failed (errno=%d %s)", errno, strerror(errno));
		client->udp_fd = 0;
		block_connect(rdr);
		return -1;
	}

	set_socket_priority(client->udp_fd, cfg.netprio);

	int32_t keep_alive = 1;
	setsockopt(client->udp_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keep_alive, sizeof(keep_alive));

	int32_t flag = 1;
	setsockopt(client->udp_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flag, sizeof(flag));

	if (client->reader->l_port>0) {
		memset((char *)&loc_sa,0,sizeof(loc_sa));
		loc_sa.sin_family = AF_INET;
		if (IP_ISSET(cfg.srvip))
			IP_ASSIGN(SIN_GET_ADDR(loc_sa), cfg.srvip);
		else
			loc_sa.sin_addr.s_addr = INADDR_ANY;

		loc_sa.sin_port = htons(client->reader->l_port);
		if (bind(client->udp_fd, (struct sockaddr *)&loc_sa, sizeof (loc_sa))<0) {
			rdr_log(rdr, "bind failed (errno=%d %s)", errno, strerror(errno));
			close(client->udp_fd);
			client->udp_fd = 0;
			block_connect(rdr);
			return -1;
		}
	}

#ifdef IPV6SUPPORT
	if (IN6_IS_ADDR_V4MAPPED(&rdr->client->ip) || IN6_IS_ADDR_V4COMPAT(&rdr->client->ip)) {
		((struct sockaddr_in *)(&client->udp_sa))->sin_family = AF_INET;
		((struct sockaddr_in *)(&client->udp_sa))->sin_port = htons((uint16_t)client->reader->r_port);
	} else {
		((struct sockaddr_in6 *)(&client->udp_sa))->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)(&client->udp_sa))->sin6_port = htons((uint16_t)client->reader->r_port);
	}
#else
	client->udp_sa.sin_family = AF_INET;
	client->udp_sa.sin_port = htons((uint16_t)client->reader->r_port);
#endif

	rdr_debug_mask(rdr, D_TRACE, "socket open for %s fd=%d", rdr->ph.desc, client->udp_fd);

	if (client->is_udp) {
		rdr->tcp_connected = 1;
		return client->udp_fd;
	}

       int32_t fl = fcntl(client->udp_fd, F_GETFL);
	fcntl(client->udp_fd, F_SETFL, O_NONBLOCK);

	int32_t res = connect(client->udp_fd, (struct sockaddr *)&client->udp_sa, client->udp_sa_len);
	if (res == -1) {
		int32_t r = -1;
		if (errno == EINPROGRESS || errno == EALREADY) {
			struct pollfd pfd;
			pfd.fd = client->udp_fd;
			pfd.events = POLLOUT;
			int32_t rc = poll(&pfd, 1, 3000);
			if (rc > 0) {
				uint32_t l = sizeof(r);
				if (getsockopt(client->udp_fd, SOL_SOCKET, SO_ERROR, &r, (socklen_t*)&l) != 0)
					r = -1;
				else
					errno = r;
			} else {
				errno = ETIMEDOUT;
			}
		}
		if (r != 0) {
			rdr_log(rdr, "connect failed: %s", strerror(errno));
			block_connect(rdr); //connect has failed. Block connect for a while
			close(client->udp_fd);
			client->udp_fd = 0;
			return -1;
		}
	}

	fcntl(client->udp_fd, F_SETFL, fl); //restore blocking mode

	setTCPTimeouts(client->udp_fd);
	clear_block_delay(rdr);
	client->last=client->login=time((time_t*)0);
	client->last_caid=client->last_srvid=0;
	client->pfd = client->udp_fd;
	rdr->tcp_connected = 1;
	rdr_debug_mask(rdr, D_TRACE, "connect succesfull fd=%d", client->udp_fd);
	return client->udp_fd;
}

void network_tcp_connection_close(struct s_reader *reader, char *reason)
{
	if (!reader) {
		//only proxy reader should call this, client connections are closed on thread cleanup
		cs_log("WARNING: invalid client");
		cs_disconnect_client(cur_client());
		return;
	}

	struct s_client *cl = reader->client;
	if(!cl) return;
	int32_t fd = cl->udp_fd;

	int32_t i;

	if (fd) {
		rdr_log(reader, "disconnected: reason %s", reason ? reason : "undef");
		close(fd);

		cl->udp_fd = 0;
		cl->pfd = 0;
	}

	reader->tcp_connected = 0;
	reader->card_status = UNKNOWN;
	cl->logout=time((time_t *)0);

	if (cl->ecmtask) {
		for (i = 0; i < cfg.max_pending; i++) {
			cl->ecmtask[i].idx = 0;
			cl->ecmtask[i].rc = 0;
		}
	}
	// newcamd message ids are stored as a reference in ecmtask[].idx 
 	// so we need to reset them aswell 
	if (reader->typ == R_NEWCAMD) 
		cl->ncd_msgid = 0; 
}

void casc_do_sock_log(struct s_reader * reader)
{
  int32_t i, idx;
  uint16_t caid, srvid;
  uint32_t provid;
  struct s_client *cl = reader->client;

  if(!cl) return;

  idx=reader->ph.c_recv_log(&caid, &provid, &srvid);
  cl->last=time((time_t*)0);
  if (idx<0) return;        // no dcw-msg received

  if(!cl->ecmtask) {
    rdr_log(reader, "WARNING: ecmtask not a available");
    return;
  }

  for (i = 0; i < cfg.max_pending; i++)
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

	if(!cl || !cl->ecmtask) {
		rdr_log(reader, "WARNING: ecmtask not a available");
		return -1;
	}

	uchar buf[512];

	t=time((time_t *)0);
	ECM_REQUEST *ecm;
	for (i = 0; i < cfg.max_pending; i++) {
		ecm = &cl->ecmtask[i];
		if ((ecm->rc>=10) && (t-(uint32_t)ecm->tps.time > ((cfg.ctimeout + 500) / 1000) + 1)) { // drop timeouts
			ecm->rc=0;
			send_reader_stat(reader, ecm, NULL, E_TIMEOUT);
		}
	}

	for (n = -1, i = 0, sflag = 1; i < cfg.max_pending; i++) {
		ecm = &cl->ecmtask[i];
		if (n<0 && (ecm->rc<10))   // free slot found
			n=i;

		// ecm already pending
		// ... this level at least
		if ((ecm->rc>=10) &&  er->caid == ecm->caid && (!memcmp(er->ecmd5, ecm->ecmd5, CS_ECMSTORESIZE)))
			sflag=0;

		if (ecm->rc >=10)
			pending++;
	}
	cl->pending=pending;

	if (n<0) {
		rdr_log(reader, "WARNING: reader ecm pending table overflow !!");
		return(-2);
	}

	memcpy(&cl->ecmtask[n], er, sizeof(ECM_REQUEST));
	cl->ecmtask[n].matching_rdr = NULL; //This avoids double free of matching_rdr!
#ifdef CS_CACHEEX
	cl->ecmtask[n].csp_lastnodes = NULL; //This avoids double free of csp_lastnodes!
#endif
	cl->ecmtask[n].parent = er;

	if( reader->typ == R_NEWCAMD )
		cl->ecmtask[n].idx=(cl->ncd_msgid==0)?2:cl->ncd_msgid+1;
	else {
		if (!cl->idx)
    			cl->idx = 1;
		cl->ecmtask[n].idx=cl->idx++;
	}

	cl->ecmtask[n].rc=10;
	cs_debug_mask(D_TRACE, "---- ecm_task %d, idx %d, sflag=%d", n, cl->ecmtask[n].idx, sflag);

	cs_ddump_mask(D_ATR, er->ecm, er->ecmlen, "casc ecm (%s):", (reader)?reader->label:"n/a");
	rc=0;
	if (sflag) {
		if ((rc=reader->ph.c_send_ecm(cl, &cl->ecmtask[n], buf)))
			casc_check_dcw(reader, n, 0, cl->ecmtask[n].cw);  // simulate "not found"
		else
			cl->last_idx = cl->ecmtask[n].idx;
		reader->last_s = t;   // used for inactive_timeout and reconnect_timeout in TCP reader
	}

	if (cl->idx>0x1ffe) cl->idx=1;

	return(rc);
}

void reader_get_ecm(struct s_reader * reader, ECM_REQUEST *er)
{
	struct s_client *cl = reader->client;
	if(!cl) return;
	if (er->rc<=E_STOPPED) {
		//TODO: not sure what this is for, but it was in mpcs too.
		// ecm request was already answered when the request was started (this ECM_REQUEST is a copy of client->ecmtask[] ECM_REQUEST).
		// send_dcw is a client function but reader_get_ecm is only called from reader functions where client->ctyp is not set and so send_dcw() will segfault.
		// so we could use send_dcw(er->client, er) or write_ecm_answer(reader, er), but send_dcw wont be threadsafe from here cause there may be multiple threads accessing same s_client struct.
		// maybe rc should be checked before request is sent to reader but i could not find the reason why this is happening now and not in v1.10 (zetack)
		//send_dcw(cl, er);
		char ecmd5[17*3];                
        cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
		rdr_debug_mask(reader, D_TRACE, "skip ecmhash %s, rc=%d", ecmd5, er->rc);
		return;
	}

	if (!chk_bcaid(er, &reader->ctab)) {
		rdr_debug_mask(reader, D_READER, "caid %04X filtered", er->caid);
		write_ecm_answer(reader, er, E_NOTFOUND, E2_CAID, NULL, NULL);
		return;
	}

	// cache2
	struct ecm_request_t *ecm = check_cwcache(er, cl);
	if (ecm && ecm->rc <= E_NOTFOUND) {
		char ecmd5[17*3];                
        cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
		rdr_debug_mask(reader, D_TRACE, "ecmhash %s answer from cache", ecmd5);
		write_ecm_answer(reader, er, E_CACHE2, 0, ecm->cw, NULL);
		return;
	}

	if (is_cascading_reader(reader)) {
		cl->last_srvid=er->srvid;
		cl->last_caid=er->caid;
		casc_process_ecm(reader, er);
		cl->lastecm=time((time_t*)0);
		return;
	}

	cardreader_process_ecm(reader, cl, er);
}

void reader_do_card_info(struct s_reader * reader)
{
	cardreader_get_card_info(reader);
	if (reader->ph.c_card_info)
		reader->ph.c_card_info();
}

void reader_do_idle(struct s_reader * reader)
{
	if (reader->ph.c_idle)
		reader->ph.c_idle();
	else {
		time_t now;
		int32_t time_diff;
		time(&now);
		time_diff = abs(now - reader->last_s);
		if (time_diff>(reader->tcp_ito*60)) {
			struct s_client *cl = reader->client;
			if (cl && reader->tcp_connected && reader->ph.type==MOD_CONN_TCP) {
				cs_debug_mask(D_READER, "%s inactive_timeout, close connection (fd=%d)", reader->ph.desc, cl->pfd);
				network_tcp_connection_close(reader, "inactivity");
			} else
				reader->last_s = now;
		}
	}
}

int32_t reader_init(struct s_reader *reader) {
	struct s_client *client = reader->client;

	if (is_cascading_reader(reader)) {
		client->typ='p';
		client->port=reader->r_port;
		set_null_ip(&client->ip);

		if (!(reader->ph.c_init)) {
			rdr_log(reader, "FATAL: %s-protocol not supporting cascading", reader->ph.desc);
			return 0;
		}

		if (reader->ph.c_init(client)) {
			//proxy reader start failed
			return 0;
		}

		if ((reader->log_port) && (reader->ph.c_init_log))
			reader->ph.c_init_log();

		if (!cs_malloc(&client->ecmtask, cfg.max_pending * sizeof(ECM_REQUEST)))
			return 0;

		rdr_log(reader, "proxy initialized, server %s:%d", reader->device, reader->r_port);
	} else {
		if (!cardreader_init(reader))
			return 0;
	}

	if (!cs_malloc(&client->emmcache, CS_EMMCACHESIZE * sizeof(struct s_emm))) {
		NULLFREE(client->ecmtask);
		return 0;
	}

	client->login=time((time_t*)0);
	client->init_done=1;

	return 1;
}

#if !defined(WITH_CARDREADER) && defined(WITH_STAPI)
/* Dummy function stub for stapi compiles without cardreader as libstapi needs it. */
int32_t ATR_InitFromArray(ATR *atr, const unsigned char atr_buffer[ATR_MAX_SIZE], uint32_t length) {
	return 0;
}
#endif

char *reader_get_type_desc(struct s_reader * rdr, int32_t extended)
{
	char *desc = "unknown";
	if (rdr->crdr.desc)
		return rdr->crdr.desc;
	if (is_network_reader(rdr) || rdr->typ == R_SERIAL) {
		if (rdr->ph.desc)
			desc = rdr->ph.desc;
	}
	if (rdr->typ == R_NEWCAMD && rdr->ncd_proto == NCD_524)
		desc = "newcamd524";
	else if (extended && rdr->typ == R_CCCAM && cccam_client_extended_mode(rdr->client)) {
		desc = "cccam ext";
	}
	return desc;
}

void hexserial_to_newcamd(uchar *source, uchar *dest, uint16_t caid)
{
	if (caid == 0x5581 || caid == 0x4aee) { // Bulcrypt
		dest[0] = 0x00;
		dest[1] = 0x00;
		memcpy(dest + 2, source, 4);
		return;
	}
	caid = caid >> 8;
	if (caid == 0x17 || caid == 0x06) { // Betacrypt or Irdeto
		// only 4 Bytes Hexserial for newcamd clients (Hex Base + Hex Serial)
		// first 2 Byte always 00
		dest[0]=0x00; //serial only 4 bytes
		dest[1]=0x00; //serial only 4 bytes
		// 1 Byte Hex Base (see reader-irdeto.c how this is stored in "source")
		dest[2]=source[3];
		// 3 Bytes Hex Serial (see reader-irdeto.c how this is stored in "source")
		dest[3]=source[0];
		dest[4]=source[1];
		dest[5]=source[2];
	} else if (caid == 0x05 || caid == 0x0D) {
		dest[0] = 0x00;
		memcpy(dest + 1, source, 5);
	} else {
		memcpy(dest, source, 6);
	}
}

void newcamd_to_hexserial(uchar *source, uchar *dest, uint16_t caid)
{
	caid = caid >> 8;
	if (caid == 0x17 || caid == 0x06) { // Betacrypt or Irdeto
		memcpy(dest, source+3, 3);
		dest[3] = source[2];
		dest[4] = 0;
		dest[5] = 0;
	} else if (caid == 0x05 || caid == 0x0D) {
		memcpy(dest, source+1, 5);
		dest[5] = 0;
	} else {
		memcpy(dest, source, 6);
	}
}

struct s_reader *get_reader_by_label(char *lbl)
{
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(&itr))) {
		if (streq(lbl, rdr->label))
			break;
	}
	return rdr;
}

bool hexserialset(struct s_reader *rdr)
{
	int i;
	if (!rdr)
		return false;
	for (i = 0; i < 8; i++) {
		if (rdr->hexserial[i])
			return true;
	}
	return false;
}
