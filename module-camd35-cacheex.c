#define MODULE_LOG_PREFIX "camd35"

#include "globals.h"

#if defined(CS_CACHEEX) && (defined(MODULE_CAMD35) || defined(MODULE_CAMD35_TCP))

#include "module-cacheex.h"
#include "module-camd35.h"
#include "module-camd35-cacheex.h"
#include "oscam-cache.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-string.h"
#include "oscam-reader.h"

uint8_t camd35_node_id[8];

/**
 * send push filter
 */
void camd35_cacheex_send_push_filter(struct s_client *cl, uint8_t mode)
{
	struct s_reader *rdr = cl->reader;
	int i = 20, j;
	CECSPVALUETAB *filter;
	//maximum size: 20+255
	uint8_t buf[20+242];
	memset(buf, 0, sizeof(buf));
	buf[0] = 0x3c;
	buf[1] = 0xf2;

	//mode==2 send filters from rdr
	if(mode == 2 && rdr)
	{
		filter = &rdr->cacheex.filter_caidtab;
	}
	//mode==3 send filters from acc
	else if(mode == 3 && cl->typ == 'c' && cl->account)
	{
		filter = &cl->account->cacheex.filter_caidtab;
	}
	else {
		return;
	}

	i2b_buf(2, filter->n, buf + i);
	i += 2;

	int32_t max_filters = 15;
	for(j=0; j<max_filters; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			i2b_buf(4, filter->caid[j], buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters && j<CS_MAXCAIDTAB; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			i2b_buf(4, filter->cmask[j], buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters && j<CS_MAXCAIDTAB; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			i2b_buf(4, filter->prid[j], buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters && j<CS_MAXCAIDTAB; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			i2b_buf(4, filter->srvid[j], buf + i);
		}
		i += 4;
	}

	cs_log_dbg(D_CACHEEX, "cacheex: sending push filter request to %s", username(cl));
	camd35_send_without_timeout(cl, buf, 242); //send adds +20
}

/**
 * store received push filter
 */
static void camd35_cacheex_push_filter(struct s_client *cl, uint8_t *buf, uint8_t mode)
{
	struct s_reader *rdr = cl->reader;
	int i = 20, j;
	CECSPVALUETAB *filter;

	//mode==2 write filters to acc
	if(mode == 2 && cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 2
		&& cl->account->cacheex.allow_filter == 1)
	{
		filter = &cl->account->cacheex.filter_caidtab;
	}
	//mode==3 write filters to rdr
	else if(mode == 3 && rdr && rdr->cacheex.allow_filter == 1)
	{
		filter = &rdr->cacheex.filter_caidtab;
	}
	else {
		return;
	}

	filter->n = b2i(2, buf + i);
	i += 2;
	if(filter->n > CS_MAXCAIDTAB)
	{
		filter->n = CS_MAXCAIDTAB;
	}

	int32_t max_filters = 15;
	for(j=0; j<max_filters; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->caid[j] = b2i(4, buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters && j<CS_MAXCAIDTAB; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->cmask[j] = b2i(4, buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters && j<CS_MAXCAIDTAB; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->prid[j] = b2i(4, buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters && j<CS_MAXCAIDTAB; j++)
	{
		if(j<CS_MAXCAIDTAB)
		{
			filter->srvid[j] = b2i(4, buf + i);
		}
		i += 4;
	}

	cs_log_dbg(D_CACHEEX, "cacheex: received push filter request from %s", username(cl));
}

static int32_t camd35_cacheex_push_chk(struct s_client *cl, ECM_REQUEST *er)
{
	if(ll_count(er->csp_lastnodes) >= cacheex_maxhop(cl))    //check max 10 nodes to push:
	{
		cs_log_dbg(D_CACHEEX, "cacheex: nodelist reached %d nodes, no push", cacheex_maxhop(cl));
		return 0;
	}

	if(cl->reader)
	{
		if(!cl->reader->tcp_connected)
		{
			cs_log_dbg(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
			return 0;
		}
	}

	//if(chk_is_null_nodeid(remote_node,8)){
	if(!cl->ncd_skey[8])
	{
		cs_log_dbg(D_CACHEEX, "cacheex: NO peer_node_id got yet, skip!");
		return 0;
	}

	uint8_t *remote_node = cl->ncd_skey; //it is sended by reader(mode 2) or client (mode 3) each 30s using keepalive msgs

	//search existing peer nodes:
	LL_LOCKITER *li = ll_li_create(er->csp_lastnodes, 0);
	uint8_t *node;
	while((node = ll_li_next(li)))
	{
		cs_log_dbg(D_CACHEEX, "cacheex: check node %" PRIu64 "X == %" PRIu64 "X ?", cacheex_node_id(node), cacheex_node_id(remote_node));
		if(memcmp(node, remote_node, 8) == 0)
		{
			break;
		}
	}
	ll_li_destroy(li);

	//node found, so we got it from there, do not push:
	if(node)
	{
		cs_log_dbg(D_CACHEEX,
					  "cacheex: node %" PRIu64 "X found in list => skip push!", cacheex_node_id(node));
		return 0;
	}

	//check if cw is already pushed
	if(check_is_pushed(er->cw_cache, cl))
		{ return 0; }

	cs_log_dbg(D_CACHEEX, "cacheex: push ok %" PRIu64 "X to %" PRIu64 "X %s", cacheex_node_id(camd35_node_id), cacheex_node_id(remote_node), username(cl));

	return 1;
}

static int32_t camd35_cacheex_push_out(struct s_client *cl, struct ecm_request_t *er)
{
	int8_t rc = (er->rc < E_NOTFOUND) ? E_FOUND : er->rc;
	if(rc != E_FOUND && rc != E_UNHANDLED) { return -1; }  //Maybe later we could support other rcs

	//E_FOUND     : we have the CW,
	//E_UNHANDLED : incoming ECM request

	if(cl->reader)
	{
		if(!camd35_tcp_connect(cl))
		{
			cs_log_dbg(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
			return (-1);
		}
	}

	uint32_t size = sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw) + sizeof(uint8_t) +
					(ll_count(er->csp_lastnodes) + 1) * 8;
	unsigned char *buf;
	if(!cs_malloc(&buf, size + 20))  //camd35_send() adds +20
		{ return -1; }

	buf[0] = 0x3f; //New Command: Cache-push
	buf[1] = size & 0xff;
	buf[2] = size >> 8;
	buf[3] = rc;

	i2b_buf(2, er->srvid, buf + 8);
	i2b_buf(2, er->caid, buf + 10);
	i2b_buf(4, er->prid, buf + 12);
	//i2b_buf(2, er->idx, buf + 16); // Not relevant...?

	if(er->cwc_cycletime && er->cwc_next_cw_cycle < 2)
	{
		buf[18] = er->cwc_cycletime; // contains cwc stage3 cycletime
		if(er->cwc_next_cw_cycle == 1)
		{ buf[18] = (buf[18] | 0x80); } // set bit 8 to high

		if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
			{ cl->account->cwc_info++; }
		else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
			{ cl->cwc_info++; }

		cs_log_dbg(D_CWC, "CWC (CE) push to %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
	}

	buf[19] = er->ecm[0] != 0x80 && er->ecm[0] != 0x81 ? 0 : er->ecm[0];

	uint8_t *ofs = buf + 20;

	//write oscam ecmd5:
	memcpy(ofs, er->ecmd5, sizeof(er->ecmd5)); //16
	ofs += sizeof(er->ecmd5);

	//write csp hashcode:
	i2b_buf(4, htonl(er->csp_hash), ofs);
	ofs += 4;

	//write cw:
	memcpy(ofs, er->cw, sizeof(er->cw)); //16
	ofs += sizeof(er->cw);

	//write node count:
	*ofs = ll_count(er->csp_lastnodes) + 1;
	ofs++;

	//write own node:
	memcpy(ofs, camd35_node_id, 8);
	ofs += 8;

	//write other nodes:
	LL_LOCKITER *li = ll_li_create(er->csp_lastnodes, 0);
	uint8_t *node;
	while((node = ll_li_next(li)))
	{
		memcpy(ofs, node, 8);
		ofs += 8;
	}
	ll_li_destroy(li);

	int32_t res = camd35_send(cl, buf, size);
	NULLFREE(buf);
	return res;
}

static void camd35_cacheex_push_in(struct s_client *cl, uchar *buf)
{
	int8_t rc = buf[3];
	if(rc != E_FOUND && rc != E_UNHANDLED)  //Maybe later we could support other rcs
		{ return; }

	ECM_REQUEST *er;
	uint16_t size = buf[1] | (buf[2] << 8);
	if(size < sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw))
	{
		cs_log_dbg(D_CACHEEX, "cacheex: %s received old cash-push format! data ignored!", username(cl));
		return;
	}

	if(!(er = get_ecmtask()))
		{ return; }

	er->srvid = b2i(2, buf + 8);
	er->caid = b2i(2, buf + 10);
	er->prid = b2i(4, buf + 12);
	er->pid  = b2i(2, buf + 16);
	er->ecm[0] = buf[19]!=0x80 && buf[19]!=0x81 ? 0 : buf[19]; //odd/even byte, usefull to send it over CSP and to check cw for swapping
	er->rc = rc;

	er->ecmlen = 0;

	if(buf[18])
	{
		if(buf[18] & (0x01 << 7))
		{
			er->cwc_cycletime = (buf[18] & 0x7F); // remove bit 8 to get cycletime
			er->cwc_next_cw_cycle = 1;
		}
		else
		{
			er->cwc_cycletime = buf[18];
			er->cwc_next_cw_cycle = 0;
		}
	}

	if (er->cwc_cycletime && er->cwc_next_cw_cycle < 2)
	{
		if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
			{ cl->account->cwc_info++; }
		else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
			{ cl->cwc_info++; }
		cs_log_dbg(D_CWC, "CWC (CE) received from %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
	}

	uint8_t *ofs = buf + 20;

	//Read ecmd5
	memcpy(er->ecmd5, ofs, sizeof(er->ecmd5)); //16
	ofs += sizeof(er->ecmd5);

	if(!check_cacheex_filter(cl, er))
		{ return; }

	//Read csp_hash:
	er->csp_hash = ntohl(b2i(4, ofs));
	ofs += 4;

	//Read cw:
	memcpy(er->cw, ofs, sizeof(er->cw)); //16
	ofs += sizeof(er->cw);

	//Check auf neues Format:
	uint8_t *data;
	if(size > (sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw)))
	{

		//Read lastnodes:
		uint8_t count = *ofs;
		ofs++;

		//check max nodes:
		if(count > cacheex_maxhop(cl))
		{
			cs_log_dbg(D_CACHEEX, "cacheex: received %d nodes (max=%d), ignored! %s", (int32_t)count, cacheex_maxhop(cl), username(cl));
			NULLFREE(er);
			return;
		}
		cs_log_dbg(D_CACHEEX, "cacheex: received %d nodes %s", (int32_t)count, username(cl));
		if (er){
			er->csp_lastnodes = ll_create("csp_lastnodes");
		}
		while(count)
		{
			if(!cs_malloc(&data, 8))
				{ break; }
			memcpy(data, ofs, 8);
			ofs += 8;
			ll_append(er->csp_lastnodes, data);
			count--;
			cs_log_dbg(D_CACHEEX, "cacheex: received node %" PRIu64 "X %s", cacheex_node_id(data), username(cl));
		}
	}
	else
	{
		cs_log_dbg(D_CACHEEX, "cacheex: received old cachex from %s", username(cl));
		er->csp_lastnodes = ll_create("csp_lastnodes");
	}

	//store remote node id if we got one. The remote node is the first node in the node list
	data = ll_has_elements(er->csp_lastnodes);
	if(data && !cl->ncd_skey[8])    //Ok, this is tricky, we use newcamd key storage for saving the remote node
	{
		memcpy(cl->ncd_skey, data, 8);
		cl->ncd_skey[8] = 1; //Mark as valid node
	}
	cs_log_dbg(D_CACHEEX, "cacheex: received cacheex from remote node id %" PRIu64 "X", cacheex_node_id(cl->ncd_skey));

	//for compatibility: add peer node if no node received (not working now, maybe later):
	if(!ll_count(er->csp_lastnodes) && cl->ncd_skey[8])
	{
		if(!cs_malloc(&data, 8))
			{ return; }
		memcpy(data, cl->ncd_skey, 8);
		ll_append(er->csp_lastnodes, data);
		cs_log_dbg(D_CACHEEX, "cacheex: added missing remote node id %" PRIu64 "X", cacheex_node_id(data));
	}

	cacheex_add_to_cache(cl, er);
}

void camd35_cacheex_recv_ce1_cwc_info(struct s_client *cl, uchar *buf, int32_t idx)
{
	if(!(buf[0] == 0x01 && buf[18] < 0xFF && buf[18] > 0x00)) // cwc info ; normal camd3 ecms send 0xFF but we need no cycletime of 255 ;)
		return;

	ECM_REQUEST *er = NULL;
	int32_t i;

	for(i = 0; i < cfg.max_pending; i++)
	{
		if (cl->ecmtask[i].idx == idx)
		{
			er = &cl->ecmtask[i];
			break;
		}
	}

	if(!er)
	{ return; }

	int8_t rc = buf[3];
	if(rc != E_FOUND)
		{ return; }

	if(buf[18])
	{
		if(buf[18] & (0x01 << 7))
		{
			er->cwc_cycletime = (buf[18] & 0x7F); // remove bit 8 to get cycletime
			er->parent->cwc_cycletime = er->cwc_cycletime;
			er->cwc_next_cw_cycle = 1;
			er->parent->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
		}
		else
		{
			er->cwc_cycletime = buf[18];
			er->parent->cwc_cycletime = er->cwc_cycletime;
			er->cwc_next_cw_cycle = 0;
			er->parent->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
		}
	}

	if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
		{ cl->account->cwc_info++; }
	else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
		{ cl->cwc_info++; }

	cs_log_dbg(D_CWC, "CWC (CE1) received from %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);

}


/**
 * when a server client connects
 */
static void camd35_server_client_init(struct s_client *cl)
{
	if(!cl->init_done)
	{
		cl->cacheex_needfilter = 1;
	}
}

/**
 * store received remote id
 */
static void camd35_cacheex_push_receive_remote_id(struct s_client *cl, uint8_t *buf)
{

	memcpy(cl->ncd_skey, buf + 20, 8);
	cl->ncd_skey[8] = 1;
	cs_log_dbg(D_CACHEEX, "cacheex: received id answer from %s: %" PRIu64 "X", username(cl), cacheex_node_id(cl->ncd_skey));
}


void camd35_cacheex_init_dcw(struct s_client *client, ECM_REQUEST *er)
{
	uint8_t *buf = er->src_data; // get orig request

	if(((client->typ == 'c' && client->account && client->account->cacheex.mode)
		|| ((client->typ == 'p' || client->typ == 'r') && (client->reader && client->reader->cacheex.mode)))
		&& er->cwc_cycletime && er->cwc_next_cw_cycle < 2)  // ce1
	{
		buf[18] = er->cwc_cycletime; // contains cwc stage3 cycletime
		if(er->cwc_next_cw_cycle == 1)
			{ buf[18] = (buf[18] | 0x80); } // set bit 8 to high
		if(client->typ == 'c' && client->account && client->account->cacheex.mode)
			{ client->account->cwc_info++; }
		else if((client->typ == 'p' || client->typ == 'r') && (client->reader && client->reader->cacheex.mode))
			{ client->cwc_info++; }
		cs_log_dbg(D_CWC, "CWC (CE1) push to %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(client), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
		buf[19] = er->ecm[0];
	}
}

/**
 * send own id
 */
void camd35_cacheex_push_send_own_id(struct s_client *cl, uint8_t *mbuf)
{
	uint8_t rbuf[32]; //minimal size
	if(!cl->crypted) { return; }
	cs_log_dbg(D_CACHEEX, "cacheex: received id request from node %" PRIu64 "X %s", cacheex_node_id(mbuf + 20), username(cl));
	memset(rbuf, 0, sizeof(rbuf));
	rbuf[0] = 0x3e;
	rbuf[1] = 12;
	rbuf[2] = 0;
	memcpy(rbuf + 20, camd35_node_id, 8);
	cs_log_dbg(D_CACHEEX, "cacheex: sending own id %" PRIu64 "X request %s", cacheex_node_id(camd35_node_id), username(cl));
	camd35_send(cl, rbuf, 12); //send adds +20
}

bool camd35_cacheex_server(struct s_client *client, uint8_t *mbuf)
{
	switch(mbuf[0])
	{
	case 0x3c:  // Cache-push filter request
		if(client->account && client->account->cacheex.mode==2){
			camd35_cacheex_push_filter(client, mbuf, 2);
		}
		break;
	case 0x3d:  // Cache-push id request
		camd35_cacheex_push_receive_remote_id(client, mbuf); //reader send request id with its nodeid, so we save it!
		camd35_cacheex_push_send_own_id(client, mbuf);
		if(client->cacheex_needfilter && client->account && client->account->cacheex.mode==3){
			camd35_cacheex_send_push_filter(client, 3);
			client->cacheex_needfilter = 0;
		}
		break;
	case 0x3e:  // Cache-push id answer
		camd35_cacheex_push_receive_remote_id(client, mbuf);
		break;
	case 0x3f:  // Cache-push
		camd35_cacheex_push_in(client, mbuf);
		break;
	default:
		return 0; // Not processed by cacheex
	}
	return 1; // Processed by cacheex
}

bool camd35_cacheex_recv_chk(struct s_client *client, uint8_t *buf)
{
	struct s_reader *rdr = client->reader;
	switch(buf[0])
	{
	case 0x3c:    // Cache-push filter request
		if(rdr->cacheex.mode==3){
			camd35_cacheex_push_filter(client, buf, 3);
		}
		break;
	case 0x3d:    // Cache-push id request
		camd35_cacheex_push_receive_remote_id(client, buf); //client send request id with its nodeid, so we save it!
		camd35_cacheex_push_send_own_id(client, buf);
		break;
	case 0x3e:     // Cache-push id answer
		camd35_cacheex_push_receive_remote_id(client, buf);
		break;
	case 0x3f:    //cache-push
		camd35_cacheex_push_in(client, buf);
		break;
	default:
		return 0; // Not processed by cacheex
	}
	return 1; // Processed by cacheex
}

/**
 * request remote id
 */
void camd35_cacheex_push_request_remote_id(struct s_client *cl)
{
	uint8_t rbuf[32];//minimal size
	memset(rbuf, 0, sizeof(rbuf));
	rbuf[0] = 0x3d;
	rbuf[1] = 12;
	rbuf[2] = 0;
	memcpy(rbuf + 20, camd35_node_id, 8);
	cs_log_dbg(D_CACHEEX, "cacheex: sending id request to %s", username(cl));
	camd35_send(cl, rbuf, 12); //send adds +20
}

void camd35_cacheex_module_init(struct s_module *ph)
{
	ph->c_cache_push = camd35_cacheex_push_out;
	ph->c_cache_push_chk = camd35_cacheex_push_chk;
	ph->s_init = camd35_server_client_init;
}

#endif
