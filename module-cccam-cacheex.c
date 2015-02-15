#define MODULE_LOG_PREFIX "cccam"

#include "globals.h"

#if defined(CS_CACHEEX) && defined(MODULE_CCCAM)

#include "module-cacheex.h"
#include "module-cccam-data.h"
#include "module-cccam-cacheex.h"
#include "oscam-cache.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-string.h"
#include "oscam-chk.h"
#include "oscam-reader.h"

extern int32_t cc_cli_connect(struct s_client *cl);
extern int32_t cc_cmd_send(struct s_client *cl, uint8_t *buf, int32_t len, cc_msg_type_t cmd);

void cc_cacheex_filter_out(struct s_client *cl)
{
	struct s_reader *rdr = (cl->typ == 'c') ? NULL : cl->reader;
	int i = 0, j;
	CECSPVALUETAB *filter;
	//minimal size, keep it <= 512 for max UDP packet size without fragmentation
	int32_t size = 482;
	uint8_t buf[482];
	memset(buf, 0, sizeof(buf));

	//mode==2 send filters from rdr
	if(rdr && rdr->cacheex.mode == 2)
	{
		filter = &rdr->cacheex.filter_caidtab;
	}
	//mode==3 send filters from acc
	else if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 3)
	{
		filter = &cl->account->cacheex.filter_caidtab;
	}
	else {
		return;
	}

	i2b_buf(2, filter->n, buf + i);
	i += 2;

	int32_t max_filters = 30;
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
	cc_cmd_send(cl, buf, size, MSG_CACHE_FILTER);
}

void cc_cacheex_filter_in(struct s_client *cl, uchar *buf)
{
	struct s_reader *rdr = (cl->typ == 'c') ? NULL : cl->reader;
	int i = 0, j;
	CECSPVALUETAB *filter;

	//mode==2 write filters to acc
	if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 2
		&& cl->account->cacheex.allow_filter == 1)
	{
		filter = &cl->account->cacheex.filter_caidtab;
	}
	//mode==3 write filters to rdr
	else if(rdr && rdr->cacheex.mode == 3 && rdr->cacheex.allow_filter == 1)
	{
		filter = &rdr->cacheex.filter_caidtab;
	}
	else {
		return;
	}

	filter->n = b2i(2, buf + i);
	i += 2;

	int32_t max_filters = 30;
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

static int32_t cc_cacheex_push_chk(struct s_client *cl, struct ecm_request_t *er)
{
	struct cc_data *cc = cl->cc;
	if(chk_is_null_nodeid(cc->peer_node_id,8))
	{
		cs_log_dbg(D_CACHEEX, "cacheex: NO peer_node_id got yet, skip!");
		return 0;
	}

	if(ll_count(er->csp_lastnodes) >= cacheex_maxhop(cl))    //check max 10 nodes to push:
	{
		cs_log_dbg(D_CACHEEX, "cacheex: nodelist reached %d nodes, no push", cacheex_maxhop(cl));
		return 0;
	}

	uint8_t *remote_node = cc->peer_node_id;

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

	if(!cl->cc)
	{
		if(cl->reader && !cl->reader->tcp_connected)
		{
			cc_cli_connect(cl);
		}
	}

	if(!cc || !cl->udp_fd)
	{
		cs_log_dbg(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
		return 0;
	}

	//check if cw is already pushed
	if(check_is_pushed(er->cw_cache, cl))
		{ return 0; }

	return 1;
}

static int32_t cc_cacheex_push_out(struct s_client *cl, struct ecm_request_t *er)
{
	int8_t rc = (er->rc < E_NOTFOUND) ? E_FOUND : er->rc;
	if(rc != E_FOUND && rc != E_UNHANDLED) { return -1; }  //Maybe later we could support other rcs

	if(cl->reader)
	{
		if(!cl->reader->tcp_connected)
			{ cc_cli_connect(cl); }
	}

	struct cc_data *cc = cl->cc;
	if(!cc || !cl->udp_fd)
	{
		cs_log_dbg(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
		return (-1);
	}

	uint32_t size = sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw) + sizeof(uint8_t) +
					(ll_count(er->csp_lastnodes) + 1) * 8;

	unsigned char *buf;
	if(!cs_malloc(&buf, size + 20))  //camd35_send() adds +20
		{ return -1; }

	// build ecm message
	//buf[0] = er->caid >> 8;
	//buf[1] = er->caid & 0xff;
	//buf[2] = er->prid >> 24;
	//buf[3] = er->prid >> 16;
	//buf[4] = er->prid >> 8;
	//buf[5] = er->prid & 0xff;
	//buf[10] = er->srvid >> 8;
	//buf[11] = er->srvid & 0xff;
	buf[12] = (sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw)) & 0xff;
	buf[13] = (sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw)) >> 8;
	//buf[12] = 0;
	//buf[13] = 0;
	buf[14] = rc;

	i2b_buf(2, er->caid, buf + 0);
	i2b_buf(4, er->prid, buf + 2);
	i2b_buf(2, er->srvid, buf + 10);

	if(er->cwc_cycletime && er->cwc_next_cw_cycle < 2)
	{
		buf[18] = er->cwc_cycletime; // contains cwc stage3 cycletime
		if(er->cwc_next_cw_cycle == 1)
		{ buf[18] = (buf[18] | 0x80); } // set bit 8 to high

		if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
			{ cl->account->cwc_info++; }
		else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
			{ cl->cwc_info++; }
		cs_log_dbg(D_CWC, "CWC (CE) push to %s cycletime: %isek - nextcwcycle: CW%i for %04X:%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
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
	memcpy(ofs, cc->node_id, 8);
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

	int32_t res = cc_cmd_send(cl, buf, size + 20, MSG_CACHE_PUSH);
	if(res > 0)   // cache-ex is pushing out, so no receive but last_g should be updated otherwise disconnect!
	{
		if(cl->reader)
			{ cl->reader->last_s = cl->reader->last_g = time((time_t *)0); } // correct
		if(cl) { cl->last = time(NULL); }
	}
	NULLFREE(buf);
	return res;
}

void cc_cacheex_push_in(struct s_client *cl, uchar *buf)
{
	struct cc_data *cc = cl->cc;
	ECM_REQUEST *er;
	if(!cc) { return; }

	if(cl->reader)
		{ cl->reader->last_s = cl->reader->last_g = time((time_t *)0); }
	if(cl) { cl->last = time(NULL); }

	int8_t rc = buf[14];
	if(rc != E_FOUND && rc != E_UNHANDLED)  //Maybe later we could support other rcs
		{ return; }
	uint16_t size = buf[12] | (buf[13] << 8);
	if(size != sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw))
	{
		cs_log_dbg(D_CACHEEX, "cacheex: %s received old cash-push format! data ignored!", username(cl));
		return;
	}
	if(!(er = get_ecmtask()))
		{ return; }

	er->caid = b2i(2, buf + 0);
	er->prid = b2i(4, buf + 2);
	er->srvid = b2i(2, buf + 10);
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
		cs_log_dbg(D_CWC, "CWC (CE) received from %s cycletime: %isek - nextcwcycle: CW%i for %04X:%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
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

	//Read lastnode count:
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
	//Read lastnodes:
	uint8_t *data;
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

	//for compatibility: add peer node if no node received:
	if(!ll_count(er->csp_lastnodes))
	{
		if(!cs_malloc(&data, 8))
			{ return; }
		memcpy(data, cc->peer_node_id, 8);
		ll_append(er->csp_lastnodes, data);
		cs_log_dbg(D_CACHEEX, "cacheex: added missing remote node id %" PRIu64 "X", cacheex_node_id(data));
	}

	cacheex_add_to_cache(cl, er);
}

void cc_cacheex_module_init(struct s_module *ph)
{
	ph->c_cache_push = cc_cacheex_push_out;
	ph->c_cache_push_chk = cc_cacheex_push_chk;
}

#endif
