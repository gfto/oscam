#include "globals.h"

#ifdef CS_CACHEEX

#include "cscrypt/md5.h"
#include "module-cacheex.h"
#include "module-cw-cycle-check.h"
#include "oscam-cache.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-conf.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"

#define cs_cacheex_matcher "oscam.cacheex"

extern uint8_t cc_node_id[8];
extern uint8_t camd35_node_id[8];

uint8_t cacheex_peer_id[8];

extern CS_MUTEX_LOCK ecm_pushed_deleted_lock;
extern struct ecm_request_t	*ecm_pushed_deleted;
extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;


static void *chkcache_process(void)
{
	set_thread_name(__func__);

	time_t timeout;
	struct ecm_request_t *er, *ecm;
#ifdef CS_CACHEEX
	uint8_t add_hitcache_er;
	struct s_reader *cl_rdr;
	struct s_reader *rdr;
	struct s_ecm_answer *ea;
	struct s_client *cex_src=NULL;
#endif
	struct s_write_from_cache *wfc=NULL;

	while(1)
	{
		cs_readlock(&ecmcache_lock);
		for(er = ecmcwcache; er; er = er->next)
		{
			timeout = time(NULL)-((cfg.ctimeout+500)/1000+1);
			if(er->tps.time < timeout)
				{ break; }

			if(er->rc<E_UNHANDLED || er->readers_timeout_check)  //already answered
				{ continue; }

			//********  CHECK IF FOUND ECM IN CACHE
			ecm = check_cache(er, er->client);
			if(ecm)     //found in cache
			{

#ifdef CS_CACHEEX
				//check for add_hitcache
				if(ecm->cacheex_src)   //cw from cacheex
				{
					if((er->cacheex_wait_time && !er->cacheex_wait_time_expired) || !er->cacheex_wait_time)   //only when no wait_time expires (or not wait_time)
					{

						//add_hitcache already called, but we check if we have to call it for these (er) caid|prid|srvid
						if(ecm->prid!=er->prid || ecm->srvid!=er->srvid)
						{
							cex_src = ecm->cacheex_src && is_valid_client(ecm->cacheex_src) && !ecm->cacheex_src->kill ?  ecm->cacheex_src : NULL; //here we should be sure cex client has not been freed!
							if(cex_src){  //add_hitcache only if client is really active
								add_hitcache_er=1;
								cl_rdr = cex_src->reader;
								if(cl_rdr && cl_rdr->cacheex.mode == 2)
								{
									for(ea = er->matching_rdr; ea; ea = ea->next)
									{
										rdr = ea->reader;
										if(cl_rdr == rdr && ((ea->status & REQUEST_ANSWERED) == REQUEST_ANSWERED))
										{
											cs_debug_mask(D_CACHEEX|D_CSP|D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [CACHEEX] skip ADD self request!", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid);
											add_hitcache_er=0; //don't add hit cache, reader requested self
										}
									}
								}

								if(add_hitcache_er)
									{ add_hitcache(cex_src, er); }  //USE cacheex client (to get correct group) and ecm from requesting client (to get correct caid|prid|srvid)!!!
							}
						}

					}
					else
					{
						//add_hitcache already called, but we have to remove it because cacheex not coming before wait_time
						if(ecm->prid==er->prid && ecm->srvid==er->srvid)
							{ del_hitcache(ecm); }
					}
				}
				//END check for add_hitcache
#endif

				if(check_client(er->client))
				{

					wfc=NULL;
					if(!cs_malloc(&wfc, sizeof(struct s_write_from_cache)))
					{
						free(ecm);
						continue;
					}

					wfc->er_new=er;
					wfc->er_cache=ecm;

					if(!add_job(er->client, ACTION_ECM_ANSWER_CACHE, wfc, sizeof(struct s_write_from_cache)))   //write_ecm_answer_fromcache
					{
						free(ecm);
						continue;
					}
				}
				else
					{ free(ecm); }
			}
		}
		cs_readunlock(&ecmcache_lock);

		cs_sleepms(10);
	}

	return NULL;
}

void checkcache_process_thread_start(void)
{
	start_thread((void *) &chkcache_process, "chkcache_process");
}

void cacheex_init(void)
{
	// Init random node id
	get_random_bytes(cacheex_peer_id, 8);
#ifdef MODULE_CCCAM
	memcpy(cacheex_peer_id, cc_node_id, 8);
#endif
#ifdef MODULE_CAMD35_TCP
	memcpy(camd35_node_id, cacheex_peer_id, 8);
#endif
}

void cacheex_clear_account_stats(struct s_auth *account)
{
	account->cwcacheexgot = 0;
	account->cwcacheexpush = 0;
	account->cwcacheexhit = 0;
}

void cacheex_clear_client_stats(struct s_client *client)
{
	client->cwcacheexgot = 0;
	client->cwcacheexpush = 0;
	client->cwcacheexhit = 0;
}

int32_t cacheex_add_stats(struct s_client *cl, uint16_t caid, uint16_t srvid, uint32_t prid, uint8_t direction)
{
	if(!cfg.cacheex_enable_stats)
		{ return -1; }

	// create list if doesn't exist
	if(!cl->ll_cacheex_stats)
		{ cl->ll_cacheex_stats = ll_create("ll_cacheex_stats"); }

	time_t now = time((time_t *)0);
	LL_ITER itr = ll_iter_create(cl->ll_cacheex_stats);
	S_CACHEEX_STAT_ENTRY *cacheex_stats_entry;

	// check for existing entry
	while((cacheex_stats_entry = ll_iter_next(&itr)))
	{
		if(cacheex_stats_entry->cache_srvid == srvid &&
				cacheex_stats_entry->cache_caid == caid &&
				cacheex_stats_entry->cache_prid == prid &&
				cacheex_stats_entry->cache_direction == direction)
		{
			// we already have this entry - just add count and time
			cacheex_stats_entry->cache_count++;
			cacheex_stats_entry->cache_last = now;
			return cacheex_stats_entry->cache_count;
		}
	}

	// if we land here we have to add a new entry
	if(cs_malloc(&cacheex_stats_entry, sizeof(S_CACHEEX_STAT_ENTRY)))
	{
		cacheex_stats_entry->cache_caid = caid;
		cacheex_stats_entry->cache_srvid = srvid;
		cacheex_stats_entry->cache_prid = prid;
		cacheex_stats_entry->cache_count = 1;
		cacheex_stats_entry->cache_last = now;
		cacheex_stats_entry->cache_direction = direction;
		ll_iter_insert(&itr, cacheex_stats_entry);
		return 1;
	}
	return 0;
}


int8_t cacheex_maxhop(struct s_client *cl)
{
	int maxhop = 10;
	if(cl->reader && cl->reader->cacheex.maxhop)
		{ maxhop = cl->reader->cacheex.maxhop; }
	else if(cl->account && cl->account->cacheex.maxhop)
		{ maxhop = cl->account->cacheex.maxhop; }
	return maxhop;
}

static void cacheex_cache_push_to_client(struct s_client *cl, ECM_REQUEST *er)
{
	add_job(cl, ACTION_CACHE_PUSH_OUT, er, 0);
}

/**
 * cacheex modes:
 *
 * cacheex=1 CACHE PULL:
 * Situation: oscam A reader1 has cacheex=1, oscam B account1 has cacheex=1
 *   oscam A gets a ECM request, reader1 send this request to oscam B, oscam B checks his cache
 *   a. not found in cache: return NOK
 *   a. found in cache: return OK+CW
 *   b. not found in cache, but found pending request: wait max cacheexwaittime and check again
 *   oscam B never requests new ECMs
 *
 *   CW-flow: B->A
 *
 * cacheex=2 CACHE PUSH:
 * Situation: oscam A reader1 has cacheex=2, oscam B account1 has cacheex=2
 *   if oscam B gets a CW, its pushed to oscam A
 *   reader has normal functionality and can request ECMs
 *
 *   Problem: oscam B can only push if oscam A is connected
 *   Problem or feature?: oscam A reader can request ecms from oscam B
 *
 *   CW-flow: B->A
 *
 */
void cacheex_cache_push(ECM_REQUEST *er)
{
	if(er->rc >= E_NOTFOUND) { return; }

	//cacheex=2 mode: push (server->remote)
	struct s_client *cl;
	cs_readlock(&clientlist_lock);
	for(cl = first_client->next; cl; cl = cl->next)
	{
		if(check_client(cl) && er->cacheex_src != cl)
		{
			if(get_module(cl)->num == R_CSP)    // always send to csp cl
			{
				if(!er->cacheex_src || cfg.csp.allow_reforward) { cacheex_cache_push_to_client(cl, er); }  // but not if the origin was cacheex (might loop)
			}
			else if(cl->typ == 'c' && !cl->dup && cl->account && cl->account->cacheex.mode == 2)      //send cache over user
			{
				if(get_module(cl)->c_cache_push  // cache-push able
						&& (!er->grp || (cl->grp & er->grp)) //Group-check
						/****  OUTGOING FILTER CHECK ***/
						&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_name || strcmp(username(cl), er->selected_reader->label)) //check reader mode-1 loopback by same name
						&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_ip || (check_client(er->selected_reader->client) && !IP_EQUAL(cl->ip, er->selected_reader->client->ip))) //check reader mode-1 loopback by same ip
						&& (!cl->account->cacheex.drop_csp || checkECMD5(er))  //cacheex_drop_csp-check
						&& chk_ctab(er->caid, &cl->ctab)  					 //Caid-check
						&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &cl->ftab))	 	 //Ident-check (not for csp: prid=0 always!)
						&& chk_srvid(cl, er) //Service-check
				  )
				{
					cacheex_cache_push_to_client(cl, er);
				}
			}
		}
	}
	cs_readunlock(&clientlist_lock);


	//cacheex=3 mode: reverse push (reader->server)
	cs_readlock(&readerlist_lock);
	cs_readlock(&clientlist_lock);
	struct s_reader *rdr;
	for(rdr = first_active_reader; rdr; rdr = rdr->next)
	{
		cl = rdr->client;
		if(check_client(cl) && er->cacheex_src != cl && rdr->cacheex.mode == 3)    //send cache over reader
		{
			if(rdr->ph.c_cache_push     // cache-push able
					&& (!er->grp || (rdr->grp & er->grp)) //Group-check
					/****  OUTGOING FILTER CHECK ***/
					&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_name || strcmp(username(cl), er->selected_reader->label)) //check reader mode-1 loopback by same name
					&& (!er->selected_reader || !cacheex_reader(er->selected_reader) || !cfg.block_same_ip || (check_client(er->selected_reader->client) && !IP_EQUAL(cl->ip, er->selected_reader->client->ip))) //check reader mode-1 loopback by same ip
					&& (!rdr->cacheex.drop_csp || checkECMD5(er))  		 //cacheex_drop_csp-check
					&& chk_ctab(er->caid, &rdr->ctab)  					 //Caid-check
					&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &rdr->ftab))	 	 //Ident-check (not for csp: prid=0 always!)
					&& chk_srvid(cl, er) //Service-check
			  )
			{
				cacheex_cache_push_to_client(cl, er);
			}
		}
	}
	cs_readunlock(&clientlist_lock);
	cs_readunlock(&readerlist_lock);
}


/****  INCOMING FILTER CHECK ***/
uint8_t check_cacheex_filter(struct s_client *cl, ECM_REQUEST *er)
{

	if(check_client(cl) && cl->typ == 'p' && cl->reader && cl->reader->cacheex.mode==2
			&& (!cl->reader->cacheex.drop_csp || checkECMD5(er))                              //cacheex_drop_csp-check
			&& chk_ctab(er->caid, &cl->reader->ctab)  			                              //Caid-check
			&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &cl->reader->ftab))	  //Ident-check (not for csp: prid=0 always!)
			&& chk_srvid(cl, er) 								                              //Service-check
			&& chk_csp_ctab(er, &cl->reader->cacheex.filter_caidtab)	                      //cacheex_ecm_filter -> for compatibility with old oscam
	  )
		{ return 1; }

	if(check_client(cl) && cl->typ == 'c' && cl->account && cl->account->cacheex.mode==3
			&& (!cl->account->cacheex.drop_csp || checkECMD5(er))                    //cacheex_drop_csp-check
			&& chk_ctab(er->caid, &cl->ctab)                                         //Caid-check
			&& (!checkECMD5(er) || chk_ident_filter(er->caid, er->prid, &cl->ftab))	 //Ident-check (not for csp: prid=0 always!)
			&& chk_srvid(cl, er)                                                     //Service-check
			&& chk_csp_ctab(er, &cl->account->cacheex.filter_caidtab)                //cacheex_ecm_filter -> for compatibility with old oscam
	  )
		{ return 1; }

	free(er);
	return 0;
}



static inline struct s_cacheex_matcher *is_cacheex_matcher_matching(ECM_REQUEST *from_er, ECM_REQUEST *to_er)
{
	struct s_cacheex_matcher *entry = cfg.cacheex_matcher;
	int8_t v_ok = (from_er && to_er) ? 2 : 1;
	while(entry)
	{
		int8_t ok = 0;
		if(from_er
				&& (!entry->caid || entry->caid == from_er->caid)
				&& (!entry->provid || entry->provid == from_er->prid)
				&& (!entry->srvid || entry->srvid == from_er->srvid)
				&& (!entry->chid || entry->chid == from_er->chid)
				&& (!entry->pid || entry->pid == from_er->pid)
				&& (!entry->ecmlen || entry->ecmlen == from_er->ecmlen))
			{ ok++; }

		if(to_er
				&& (!entry->to_caid || entry->to_caid == to_er->caid)
				&& (!entry->to_provid || entry->to_provid == to_er->prid)
				&& (!entry->to_srvid || entry->to_srvid == to_er->srvid)
				&& (!entry->to_chid || entry->to_chid == to_er->chid)
				&& (!entry->to_pid || entry->to_pid == to_er->pid)
				&& (!entry->to_ecmlen || entry->to_ecmlen == to_er->ecmlen))
			{ ok++; }

		if(ok == v_ok)
		{
			if(!from_er || !to_er || from_er->srvid == to_er->srvid)
				{ return entry; }
		}
		entry = entry->next;
	}
	return NULL;
}

bool cacheex_is_match_alias(struct s_client *cl, ECM_REQUEST *er)
{
	return check_client(cl) && cl->account && cl->account->cacheex.mode == 1 && is_cacheex_matcher_matching(NULL, er);
}

inline int8_t cacheex_match_alias(struct s_client *cl, ECM_REQUEST *er, ECM_REQUEST *ecm)
{
	if(check_client(cl) && cl->account && cl->account->cacheex.mode == 1)
	{
		struct s_cacheex_matcher *entry = is_cacheex_matcher_matching(ecm, er);
		if(entry)
		{
			int32_t diff = comp_timeb(&er->tps, &ecm->tps);
			if(diff > entry->valid_from && diff < entry->valid_to)
			{
#ifdef WITH_DEBUG
				if(D_CACHEEX & cs_dblevel)
				{
					char result[CXM_FMT_LEN] = { 0 };
					int32_t s, size = CXM_FMT_LEN;
					s = ecmfmt(entry->caid, 0, entry->provid, entry->chid, entry->pid, entry->srvid, entry->ecmlen, 0, 0, 0, result, size, 0, 0);
					s += snprintf(result + s, size - s, " = ");
					s += ecmfmt(entry->to_caid, 0, entry->to_provid, entry->to_chid, entry->to_pid, entry->to_srvid, entry->to_ecmlen, 0, 0, 0, result + s, size - s, 0, 0);
					s += snprintf(result + s, size - s, " valid %d/%d", entry->valid_from, entry->valid_to);
					cs_debug_mask(D_CACHEEX, "cacheex-matching for: %s", result);
				}
#endif
				return 1;
			}
		}
	}
	return 0;
}

static int32_t cacheex_add_to_cache_int(struct s_client *cl, ECM_REQUEST *er, int8_t csp)
{
	if(er->rc >= E_NOTFOUND) { return 0; }

	if(!cl)
		{ return 0; }
	if(!csp && cl->reader && cl->reader->cacheex.mode != 2)  //from reader
	{
		cs_debug_mask(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if(!csp && !cl->reader && cl->account && cl->account->cacheex.mode != 3)  //from user
	{
		cs_debug_mask(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if(!csp && !cl->reader && !cl->account)    //not active!
	{
		cs_debug_mask(D_CACHEEX, "CACHEX received, but invalid client state %s", username(cl));
		return 0;
	}

	uint8_t i, c;
	uint8_t null = 0;
	for(i = 0; i < 16; i += 4)
	{
		c = ((er->cw[i] + er->cw[i + 1] + er->cw[i + 2]) & 0xff);
		null |= (er->cw[i] | er->cw[i + 1] | er->cw[i + 2]);
		if(er->cw[i + 3] != c)
		{
			cs_ddump_mask(D_CACHEEX, er->cw, 16, "push received cw with chksum error from %s", csp ? "csp" : username(cl));
			cl->cwcacheexerr++;
			if(cl->account)
				{ cl->account->cwcacheexerr++; }
			return 0;
		}
	}

	if(null == 0 || chk_is_null_CW(er->cw))
	{
		cs_ddump_mask(D_CACHEEX, er->cw, 16, "push received null cw from %s", csp ? "csp" : username(cl));
		cl->cwcacheexerr++;
		if(cl->account)
			{ cl->account->cwcacheexerr++; }
		return 0;
	}

	er->grp |= cl->grp;  //ok for mode2 reader too: cl->reader->grp
	er->rc = E_CACHEEX;
	er->cacheex_src = cl;
	er->selected_reader = cl->reader;
	er->client = NULL; //No Owner! So no fallback!

	if(check_client(cl))
	{
		cl->cwcacheexgot++;
		if(cl->account)
			{ cl->account->cwcacheexgot++; }
		first_client->cwcacheexgot++;
	}

	add_hitcache(cl, er);  //we have to call it before add_cache, because in chk_process we could remove it!
	add_cache(er);
	cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 1);

	cs_writelock(&ecm_pushed_deleted_lock);
	er->next = ecm_pushed_deleted;
	ecm_pushed_deleted = er;
	cs_writeunlock(&ecm_pushed_deleted_lock);

	return 1;  //NO free, we have to wait cache push out stuff ends.
}


void cacheex_add_to_cache(struct s_client *cl, ECM_REQUEST *er)
{
	er->from_cacheex = 1;
	if(!cacheex_add_to_cache_int(cl, er, 0))
		{ free_push_in_ecm(er); }
}

void cacheex_add_to_cache_from_csp(struct s_client *cl, ECM_REQUEST *er)
{
	if(!cacheex_add_to_cache_int(cl, er, 1))
		{ free_push_in_ecm(er); }
}

//Format:
//caid:prov:srvid:pid:chid:ecmlen=caid:prov:srvid:pid:chid:ecmlen[,validfrom,validto]
//validfrom: default=-2000
//validto: default=4000
//valid time if found in cache
static struct s_cacheex_matcher *cacheex_matcher_read_int(void)
{
	FILE *fp = open_config_file(cs_cacheex_matcher);
	if(!fp)
		{ return NULL; }

	char token[1024];
	unsigned char type;
	int32_t i, ret, count = 0;
	struct s_cacheex_matcher *new_cacheex_matcher = NULL, *entry, *last = NULL;
	uint32_t line = 0;

	while(fgets(token, sizeof(token), fp))
	{
		line++;
		if(strlen(token) <= 1) { continue; }
		if(token[0] == '#' || token[0] == '/') { continue; }
		if(strlen(token) > 100) { continue; }

		for(i = 0; i < (int)strlen(token); i++)
		{
			if((token[i] == ':' || token[i] == ' ') && token[i + 1] == ':')
			{
				memmove(token + i + 2, token + i + 1, strlen(token) - i + 1);
				token[i + 1] = '0';
			}
			if(token[i] == '#' || token[i] == '/')
			{
				token[i] = '\0';
				break;
			}
		}

		type = 'm';
		uint32_t caid = 0, provid = 0, srvid = 0, pid = 0, chid = 0, ecmlen = 0;
		uint32_t to_caid = 0, to_provid = 0, to_srvid = 0, to_pid = 0, to_chid = 0, to_ecmlen = 0;
		int32_t valid_from = -2000, valid_to = 4000;

		ret = sscanf(token, "%c:%4x:%6x:%4x:%4x:%4x:%4X=%4x:%6x:%4x:%4x:%4x:%4X,%4d,%4d",
					 &type,
					 &caid, &provid, &srvid, &pid, &chid, &ecmlen,
					 &to_caid, &to_provid, &to_srvid, &to_pid, &to_chid, &to_ecmlen,
					 &valid_from, &valid_to);

		type = tolower(type);

		if(ret < 7 || type != 'm')
			{ continue; }

		if(!cs_malloc(&entry, sizeof(struct s_cacheex_matcher)))
		{
			fclose(fp);
			return new_cacheex_matcher;
		}
		count++;
		entry->line = line;
		entry->type = type;
		entry->caid = caid;
		entry->provid = provid;
		entry->srvid = srvid;
		entry->pid = pid;
		entry->chid = chid;
		entry->ecmlen = ecmlen;
		entry->to_caid = to_caid;
		entry->to_provid = to_provid;
		entry->to_srvid = to_srvid;
		entry->to_pid = to_pid;
		entry->to_chid = to_chid;
		entry->to_ecmlen = to_ecmlen;
		entry->valid_from = valid_from;
		entry->valid_to = valid_to;

		cs_debug_mask(D_TRACE, "cacheex-matcher: %c: %04X:%06X:%04X:%04X:%04X:%02X = %04X:%06X:%04X:%04X:%04X:%02X valid %d/%d",
					  entry->type, entry->caid, entry->provid, entry->srvid, entry->pid, entry->chid, entry->ecmlen,
					  entry->to_caid, entry->to_provid, entry->to_srvid, entry->to_pid, entry->to_chid, entry->to_ecmlen,
					  entry->valid_from, entry->valid_to);

		if(!new_cacheex_matcher)
		{
			new_cacheex_matcher = entry;
			last = new_cacheex_matcher;
		}
		else
		{
			last->next = entry;
			last = entry;
		}
	}

	if(count)
		{ cs_log("%d entries read from %s", count, cs_cacheex_matcher); }

	fclose(fp);

	return new_cacheex_matcher;
}

void cacheex_load_config_file(void)
{
	struct s_cacheex_matcher *entry, *old_list;

	old_list = cfg.cacheex_matcher;
	cfg.cacheex_matcher = cacheex_matcher_read_int();

	while(old_list)
	{
		entry = old_list->next;
		free(old_list);
		old_list = entry;
	}
}

uint32_t get_cacheex_wait_time(ECM_REQUEST *er, struct s_client *cl)
{
	int32_t i, dwtime = -1, awtime = -1;

	for(i = 0; i < cfg.cacheex_wait_timetab.n; i++)
	{
		if(i == 0 && cfg.cacheex_wait_timetab.caid[i] <= 0)
		{
			dwtime = cfg.cacheex_wait_timetab.dwtime[i];
			awtime = cfg.cacheex_wait_timetab.awtime[i];
			continue; //check other, only valid for unset
		}

		if(cfg.cacheex_wait_timetab.caid[i] == er->caid || cfg.cacheex_wait_timetab.caid[i] == er->caid >> 8 || ((cfg.cacheex_wait_timetab.cmask[i] >= 0 && (er->caid & cfg.cacheex_wait_timetab.cmask[i]) == cfg.cacheex_wait_timetab.caid[i]) || cfg.cacheex_wait_timetab.caid[i] == -1))
		{
			if((cfg.cacheex_wait_timetab.prid[i] >= 0 && cfg.cacheex_wait_timetab.prid[i] == (int32_t)er->prid) || cfg.cacheex_wait_timetab.prid[i] == -1)
			{
				if((cfg.cacheex_wait_timetab.srvid[i] >= 0 && cfg.cacheex_wait_timetab.srvid[i] == er->srvid) || cfg.cacheex_wait_timetab.srvid[i] == -1)
				{
					dwtime = cfg.cacheex_wait_timetab.dwtime[i];
					awtime = cfg.cacheex_wait_timetab.awtime[i];
					break;
				}
			}

		};

	}
	if(awtime > 0 && dwtime <= 0)
	{
		return awtime;
	}
	if(cl == NULL)
	{
		if(dwtime < 0)
			{ dwtime = 0; }
		return dwtime;
	}
	if(awtime > 0 || dwtime > 0)
	{
		//if found last in cache return dynwaittime else alwayswaittime
		if(check_hitcache(er,cl))
			{ return dwtime >= awtime ? dwtime : awtime; }
		else
			{ return awtime > 0 ? awtime : 0; }
	}
	return 0;
}

int32_t chk_csp_ctab(ECM_REQUEST *er, CECSPVALUETAB *tab)
{
	if(!er->caid || !tab->n)
		{ return 1; } // nothing setup we add all
	int32_t i;
	for(i = 0; i < tab->n; i++)
	{

		if(tab->caid[i] > 0)
		{
			if(tab->caid[i] == er->caid || tab->caid[i] == er->caid >> 8 || ((tab->cmask[i] >= 0 && (er->caid & tab->cmask[i]) == tab->caid[i]) || tab->caid[i] == -1))
			{
				if((tab->prid[i] >= 0 && tab->prid[i] == (int32_t)er->prid) || tab->prid[i] == -1)
				{
					if((tab->srvid[i] >= 0 && tab->srvid[i] == er->srvid) || tab->srvid[i] == -1)
					{
						return 1;
					}
				}
			}
		}
	}
	return 0;
}

#endif
