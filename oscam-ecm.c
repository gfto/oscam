#define MODULE_LOG_PREFIX "ecm"

#include "globals.h"
#include "cscrypt/md5.h"
#include "module-anticasc.h"
#include "module-cacheex.h"
#include "module-led.h"
#include "module-stat.h"
#include "module-webif.h"
#include "module-ird-guess.h"
#include "module-cw-cycle-check.h"
#include "module-gbox.h"
#include "oscam-cache.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-ecm.h"
#include "oscam-garbage.h"
#include "oscam-failban.h"
#include "oscam-net.h"
#include "oscam-time.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-work.h"
#include "reader-common.h"

extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;
extern uint16_t len4caid[256];
extern uint32_t ecmcwcache_size;
extern int32_t exit_oscam;

extern CS_MUTEX_LOCK ecm_pushed_deleted_lock;
extern struct ecm_request_t	*ecm_pushed_deleted;

static pthread_mutex_t cw_process_sleep_cond_mutex;
static pthread_cond_t cw_process_sleep_cond;
static int cw_process_wakeups;

void fallback_timeout(ECM_REQUEST *er)
{
	if(er->rc >= E_UNHANDLED && er->stage < 4)
	{
		cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} fallback timeout! (stage: %d)", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, er->stage);
		debug_ecm(D_TRACE, "fallback for %s %s", username(er->client), buf);
		while(er->stage < 4)  //if preferlocalcards=1 and no answer from locals, initial stage will be 2! We need to reach stage=4 to call fallback's.
		{
			request_cw_from_readers(er, 0);
		}
	}
}

void ecm_timeout(ECM_REQUEST *er)
{
	if(!er->readers_timeout_check)
	{
		er->readers_timeout_check = 1;

		if(check_client(er->client) && er->rc >= E_UNHANDLED)
		{
			debug_ecm(D_TRACE, "timeout for %s %s", username(er->client), buf);


			//set timeout for readers not answering
			struct s_ecm_answer *ea_list;
			for(ea_list = er->matching_rdr; ea_list; ea_list = ea_list->next)
			{
				if((ea_list->status & (REQUEST_SENT | REQUEST_ANSWERED)) == REQUEST_SENT)  //Request sent, but no answer!
				{
					write_ecm_answer(ea_list->reader, er, E_TIMEOUT, 0, NULL, NULL); //set timeout for readers not answered!
				}
			}

			//send timeout to client!
			cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} client timeout! ", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid);
			er->rc = E_TIMEOUT;
			er->rcEx = 0;
			send_dcw(er->client, er);
		}
	}
}

void increment_n_request(struct s_client *cl){
	if(check_client(cl)){
		cl->n_request[1]++;
		first_client->n_request[1]++;
	}
}

void update_n_request(void){
	struct s_client *cl;

	cs_readlock(&clientlist_lock);
	for(cl = first_client->next; cl; cl = cl->next)
	{
#ifdef CS_CACHEEX
		if(check_client(cl) && get_module(cl)->num != R_CSP && cl->typ == 'c' && !cl->dup && cl->account && cl->account->cacheex.mode<=1) //no cacheex 2/3 client
#else
		if(check_client(cl) && get_module(cl)->num != R_CSP && cl->typ == 'c' && !cl->dup)
#endif
		{
			cl->n_request[0]=cl->n_request[1];
			cl->n_request[1]=0;
		}else{
			cl->n_request[0]=0;
			cl->n_request[1]=0;
		}
	}

	first_client->n_request[0]=first_client->n_request[1];
	first_client->n_request[1]=0;

	cs_readunlock(&clientlist_lock);
}

static void *cw_process(void)
{
	set_thread_name(__func__);
	int64_t time_to_check_fbtimeout, time_to_check_ctimeout, next_check, ecmc_next, cache_next, n_request_next, msec_wait = 3000;
	struct timeb t_now, tbc, ecmc_time, cache_time, n_request_time;
	ECM_REQUEST *er = NULL;
	time_t ecm_maxcachetime;

#ifdef CS_CACHEEX
	int64_t time_to_check_cacheex_wait_time;
	int64_t time_to_check_cacheex_mode1_delay;
#endif

	cs_pthread_cond_init(&cw_process_sleep_cond_mutex, &cw_process_sleep_cond);

#ifdef CS_ANTICASC
	int32_t ac_next;
	struct timeb ac_time;
	cs_ftime(&ac_time);
	add_ms_to_timeb(&ac_time, cfg.ac_stime * 60 * 1000);
#endif

	cs_ftime(&ecmc_time);
	add_ms_to_timeb(&ecmc_time, 1000);
	cs_ftime(&cache_time);
	add_ms_to_timeb(&cache_time, 3000);
	cs_ftime(&n_request_time);
	add_ms_to_timeb(&n_request_time, 60 * 1000);

	while(!exit_oscam)
	{
		if(cw_process_wakeups == 0)    // No waiting wakeups, proceed to sleep
		{
			sleepms_on_cond(&cw_process_sleep_cond_mutex, &cw_process_sleep_cond, msec_wait);
		}
		cw_process_wakeups = 0; // We've been woken up, reset the counter
		if(exit_oscam)
			{ break; }

		next_check = 0;
#ifdef CS_ANTICASC
		ac_next = 0;
#endif
		ecmc_next = 0;
		cache_next = 0;
		msec_wait = 0;

		cs_ftime(&t_now);
		cs_readlock(&ecmcache_lock);
		for(er = ecmcwcache; er; er = er->next)
		{

			if(
				(er->from_cacheex || er->from_csp)                  //ignore ecms from cacheex/csp
				||
				er->readers_timeout_check                           //ignore already checked
				||
				!check_client(er->client)                           //ignore ecm of killed clients
			)
				{ continue; }

			if(er->rc >= E_UNHANDLED)
			{

#ifdef CS_CACHEEX
				//cacheex_wait_time
				if(er->cacheex_wait_time && !er->cacheex_wait_time_expired)
				{
					tbc = er->tps;
					time_to_check_cacheex_mode1_delay = 0;
					time_to_check_cacheex_wait_time = add_ms_to_timeb_diff(&tbc, lb_auto_timeout(er, er->cacheex_wait_time));
					if(comp_timeb(&t_now, &tbc) >= 0)
					{
						add_job(er->client, ACTION_CACHEEX_TIMEOUT, (void *)er, 0);
						time_to_check_cacheex_wait_time = 0;

					}else if(er->cacheex_mode1_delay && !er->stage && er->cacheex_reader_count>0){
						//check for cacheex_mode1_delay
						tbc = er->tps;
						time_to_check_cacheex_mode1_delay = add_ms_to_timeb_diff(&tbc, lb_auto_timeout(er, er->cacheex_mode1_delay));
						if(comp_timeb(&t_now, &tbc) >= 0)
						{
							add_job(er->client, ACTION_CACHEEX1_DELAY, (void *)er, 0);
							time_to_check_cacheex_mode1_delay = 0;
						}
					}
					if(!next_check || (time_to_check_cacheex_wait_time > 0 && time_to_check_cacheex_wait_time < next_check))
						{ next_check = time_to_check_cacheex_wait_time; }
					if(!next_check || (time_to_check_cacheex_mode1_delay > 0 && time_to_check_cacheex_mode1_delay < next_check))
						{ next_check = time_to_check_cacheex_mode1_delay; }
				}
#endif
				if(er->stage < 4)
				{
					//fbtimeout
					tbc = er->tps;
					time_to_check_fbtimeout = add_ms_to_timeb_diff(&tbc, lb_auto_timeout(er, get_fallbacktimeout(er->caid)));
					if(comp_timeb(&t_now, &tbc) >= 0)
					{
						add_job(er->client, ACTION_FALLBACK_TIMEOUT, (void *)er, 0);
						time_to_check_fbtimeout = 0;
					}
					if(!next_check || (time_to_check_fbtimeout > 0 && time_to_check_fbtimeout < next_check))
						{ next_check = time_to_check_fbtimeout; }
				}
			}


			//clienttimeout
			if(!er->readers_timeout_check)  //ecm stays in cache at least ctimeout+2seconds!
			{
				tbc = er->tps;
				time_to_check_ctimeout = add_ms_to_timeb_diff(&tbc, lb_auto_timeout(er, cfg.ctimeout));
				if(comp_timeb(&t_now, &tbc) >= 0)
				{
					add_job(er->client, ACTION_CLIENT_TIMEOUT, (void *)er, 0);
					time_to_check_ctimeout = 0;
				}
				if(!next_check || (time_to_check_ctimeout > 0 && time_to_check_ctimeout < next_check))
					{ next_check = time_to_check_ctimeout; }
			}
		}
		cs_readunlock(&ecmcache_lock);
#ifdef CS_ANTICASC
		if(cfg.ac_enabled && (ac_next = comp_timeb(&ac_time, &t_now)) <= 10)
		{
			ac_do_stat();
			cs_ftime(&ac_time);
			ac_next = add_ms_to_timeb_diff(&ac_time, cfg.ac_stime * 60 * 1000);
		}
#endif
		if((ecmc_next = comp_timeb(&ecmc_time, &t_now)) <= 10)
		{
			uint32_t count = 0;
			struct ecm_request_t *ecm, *ecmt = NULL, *prv;

			cs_readlock(&ecmcache_lock);
			for(ecm = ecmcwcache, prv = NULL; ecm; prv = ecm, ecm = ecm->next, count++)
			{
				ecm_maxcachetime = t_now.time - ((cfg.ctimeout+500)/1000+3);  //to be sure no more access er!

				if(ecm->tps.time < ecm_maxcachetime)
				{
					cs_readunlock(&ecmcache_lock);
					cs_writelock(&ecmcache_lock);
					ecmt = ecm;
					if(prv)
						{ prv->next = NULL; }
					else
						{ ecmcwcache = NULL; }
					cs_writeunlock(&ecmcache_lock);
					break;
				}
			}
			if(!ecmt)
				{ cs_readunlock(&ecmcache_lock); }
			ecmcwcache_size = count;

			while(ecmt)
			{
				ecm = ecmt->next;
				free_ecm(ecmt);
				ecmt = ecm;
			}

#ifdef CS_CACHEEX
			ecmt=NULL;
			cs_readlock(&ecm_pushed_deleted_lock);
			for(ecm = ecm_pushed_deleted, prv = NULL; ecm; prv = ecm, ecm = ecm->next)
			{
				ecm_maxcachetime = t_now.time - ((cfg.ctimeout+500)/1000+3);
				if(ecm->tps.time < ecm_maxcachetime)
				{
					cs_readunlock(&ecm_pushed_deleted_lock);
					cs_writelock(&ecm_pushed_deleted_lock);
					ecmt = ecm;
					if(prv)
						{ prv->next = NULL; }
					else
						{ ecm_pushed_deleted = NULL; }
					cs_writeunlock(&ecm_pushed_deleted_lock);
					break;
				}
			}
			if(!ecmt)
				{ cs_readunlock(&ecm_pushed_deleted_lock); }

			while(ecmt)
			{
				ecm = ecmt->next;
				free_push_in_ecm(ecmt);
				ecmt = ecm;
			}
#endif

			cs_ftime(&ecmc_time);
			ecmc_next = add_ms_to_timeb_diff(&ecmc_time, 1000);
		}


		if((cache_next = comp_timeb(&cache_time, &t_now)) <= 10)
		{


			cleanup_cache();
			cacheex_cleanup_hitcache();

			cs_ftime(&cache_time);
			cache_next = add_ms_to_timeb_diff(&cache_time, 3000);
		}

		if((n_request_next = comp_timeb(&n_request_time, &t_now)) <= 10)
		{
			update_n_request();
			cs_ftime(&n_request_time);
			n_request_next = add_ms_to_timeb_diff(&n_request_time, 60 * 1000);
		}


		msec_wait = next_check;
#ifdef CS_ANTICASC
		if(!msec_wait || (ac_next > 0 && ac_next < msec_wait))
			{ msec_wait = ac_next; }
#endif
		if(!msec_wait || (ecmc_next > 0 && ecmc_next < msec_wait))
			{ msec_wait = ecmc_next; }

		if(!msec_wait || (cache_next > 0 && cache_next < msec_wait))
			{ msec_wait = cache_next; }

		if(!msec_wait || (n_request_next > 0 && n_request_next < msec_wait))
			{ msec_wait = n_request_next; }

		if(!msec_wait)
			{ msec_wait = 3000; }

		cleanupcwcycle();
	}

	return NULL;
}

void cw_process_thread_start(void)
{
	start_thread((void *) &cw_process, "cw_process");
}

void cw_process_thread_wakeup(void)
{
	cw_process_wakeups++; // Do not sleep...
	pthread_cond_signal(&cw_process_sleep_cond);
}

void convert_to_beta(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto)
{
	static uint8_t headerN3[10] = {0xc7, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x87, 0x12};
	static uint8_t headerN2[10] = {0xc9, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x48, 0x12};

	er->ocaid = er->caid;
	er->caid = caidto;
	er->prid = 0;
	er->ecmlen = er->ecm[2] + 3;

	memmove(er->ecm + 13, er->ecm + 3, er->ecmlen - 3);

	if(er->ecmlen > 0x88)
	{
		memcpy(er->ecm + 3, headerN3, 10);
		if(er->ecm[0] == 0x81)
			{ er->ecm[12] += 1; }
		er->ecm[1] = 0x70;
	}
	else
	{
		memcpy(er->ecm + 3, headerN2, 10);
	}

	er->ecmlen += 10;
	er->ecm[2] = er->ecmlen - 3;
	er->btun = 1;

	cl->cwtun++;
	cl->account->cwtun++;
	first_client->cwtun++;

	cs_log_dbg(D_TRACE, "ECM converted ocaid from 0x%04X to BetaCrypt caid 0x%04X for service id 0x%04X",
				  er->ocaid, caidto, er->srvid);
}

void convert_to_nagra(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto)
{
	cs_log_dbg(D_TRACE, "convert_to_nagra");
	er->ocaid = er->caid;
	er->caid = caidto;
	er->prid = 0;
	er->ecmlen = er->ecm[2] + 3;

	//not sure
	if(er->ecmlen < 0x52)
		{ er->ecm[1] = 0x30; }

	memmove(er->ecm + 3, er->ecm + 13, er->ecmlen - 3);

	er->ecmlen -= 10;
	er->ecm[2] = er->ecmlen - 3;
	er->btun = 1;

	cl->cwtun++;
	cl->account->cwtun++;
	first_client->cwtun++;

	cs_log_dbg(D_TRACE, "ECM converted ocaid from: 0x%04X to Nagra: 0x04%X for service id:0x04%X",
				  er->ocaid, caidto, er->srvid);
}

void cs_betatunnel(ECM_REQUEST *er)
{
	int32_t n;
	struct s_client *cl = cur_client();
	uint32_t mask_all = 0xFFFF;

	TUNTAB *ttab;
	ttab = &cl->ttab;

	for(n = 0; n < ttab->n; n++)
	{
		if((er->caid == ttab->bt_caidfrom[n]) && ((er->srvid == ttab->bt_srvid[n]) || (ttab->bt_srvid[n]) == mask_all))
		{
			if(chk_is_betatunnel_caid(er->caid) == 1 && er->ocaid == 0x0000)
			{
				convert_to_nagra(cl, er, ttab->bt_caidto[n]);
			}
			else if(er->ocaid == 0x0000)
			{
				convert_to_beta(cl, er, ttab->bt_caidto[n]);
			}
			return;
		}
	}
}

static void remove_ecm_from_reader(ECM_REQUEST *ecm)
{
	int32_t i;
	struct s_ecm_answer *ea = ecm->matching_rdr;
	while(ea)
	{
		if((ea->status & REQUEST_SENT) && !(ea->status & REQUEST_ANSWERED))
		{
			//we found a outstanding reader, clean it:
			struct s_reader *rdr = ea->reader;
			if(rdr)
			{
				struct s_client *cl = rdr->client;
				if(check_client(cl))
				{
					ECM_REQUEST *ecmtask = cl->ecmtask;
					if(ecmtask)
					{
						for(i = 0; i < cfg.max_pending; ++i)
						{
							if(ecmtask[i].parent == ecm)
							{
								ecmtask[i].client = NULL;
								cacheex_set_csp_lastnode(&ecmtask[i]);
							}
						}
					}
				}
			}
		}
		ea = ea->next;
	}
}

void free_ecm(ECM_REQUEST *ecm)
{
	struct s_ecm_answer *ea, *nxt;
	cacheex_free_csp_lastnodes(ecm);
	gbox_free_cards_pending(ecm);
	//remove this ecm from reader queue to avoid segfault on very late answers (when ecm is already disposed)
	//first check for outstanding answers:
	remove_ecm_from_reader(ecm);
	//free matching_rdr list:
	ea = ecm->matching_rdr;
	ecm->matching_rdr = NULL;
	while(ea)
	{
		nxt = ea->next;
		cs_lock_destroy(&ea->ecmanswer_lock);
		add_garbage(ea);
		ea = nxt;
	}
	if(ecm->src_data)
		{ add_garbage(ecm->src_data); }
	add_garbage(ecm);
}


void free_push_in_ecm(ECM_REQUEST *ecm)
{
	cacheex_free_csp_lastnodes(ecm);
	gbox_free_cards_pending(ecm);
	if(ecm->src_data)
		{ NULLFREE(ecm->src_data); }
	NULLFREE(ecm);
}


ECM_REQUEST *get_ecmtask(void)
{
	ECM_REQUEST *er = NULL;
	struct s_client *cl = cur_client();
	if(!cl)
		{ return NULL; }
	if(!cs_malloc(&er, sizeof(ECM_REQUEST)))
		{ return NULL; }
	cs_ftime(&er->tps);
	er->rc     = E_UNHANDLED;
	er->client = cl;
	er->grp    = 0;  //no readers/cacheex-clients answers yet
	//cs_log("client %s ECMTASK %d module %s", username(cl), n, get_module(cl)->desc);
	return er;
}

void cleanup_ecmtasks(struct s_client *cl)
{
	if(cl && !cl->account->usr) { return; }  //not for anonymous users!

	ECM_REQUEST *ecm;

	//remove this clients ecm from queue. because of cache, just null the client:
	cs_readlock(&ecmcache_lock);
	for(ecm = ecmcwcache; ecm; ecm = ecm->next)
	{
		if(ecm->client == cl)
		{
			ecm->client = NULL;
		}
	}
	cs_readunlock(&ecmcache_lock);

	//remove client from rdr ecm-queue:
	cs_readlock(&readerlist_lock);
	struct s_reader *rdr = first_active_reader;
	while(rdr)
	{
		if(check_client(rdr->client) && rdr->client->ecmtask)
		{
			int i;
			for(i = 0; i < cfg.max_pending; i++)
			{
				ecm = &rdr->client->ecmtask[i];
				if(ecm->client == cl)
				{
					ecm->client = NULL;
				}
			}
		}
		rdr = rdr->next;
	}
	cs_readunlock(&readerlist_lock);

}


static void add_cascade_data(struct s_client *client, ECM_REQUEST *er)
{
	if(!client->cascadeusers)
		{ client->cascadeusers = ll_create("cascade_data"); }
	LLIST *l = client->cascadeusers;
	LL_ITER it = ll_iter_create(l);
	time_t now = time(NULL);
	struct s_cascadeuser *cu;
	int8_t found = 0;
	while((cu = ll_iter_next(&it)))
	{
		if(er->caid == cu->caid && er->prid == cu->prid && er->srvid == cu->srvid)  //found it
		{
			if(cu->time < now)
				{ cu->cwrate = now - cu->time; }
			cu->time = now;
			found = 1;
		}
		else if(cu->time + 60 < now)  //  old
			{ ll_iter_remove_data(&it); }
	}
	if(!found)    //add it if not found
	{
		if(!cs_malloc(&cu, sizeof(struct s_cascadeuser)))
			{ return; }
		cu->caid = er->caid;
		cu->prid = er->prid;
		cu->srvid = er->srvid;
		cu->time = now;
		ll_append(l, cu);
	}
}

static int32_t is_double_check_caid(ECM_REQUEST *er)
{
	if(!cfg.double_check_caid.caid[0])  //no caids defined: Check all
		{ return 1; }
	int32_t i;
	for(i = 0; i < CS_MAXCAIDTAB; i++)
	{
		uint16_t tcaid = cfg.double_check_caid.caid[i];
		if(!tcaid)
			{ break; }
		if(tcaid == er->caid || (tcaid < 0x0100 && (er->caid >> 8) == tcaid))
		{
			return 1;
		}
	}
	return 0;
}

struct s_ecm_answer *get_ecm_answer(struct s_reader *reader, ECM_REQUEST *er)
{
	if(!er || !reader) { return NULL; }

	struct s_ecm_answer *ea;

	for(ea = er->matching_rdr; ea; ea = ea->next)
	{
		if(ea->reader == reader)
		{
			return ea;
		}
	}
	return NULL;
}


void distribute_ea(struct s_ecm_answer *ea)
{

	struct s_ecm_answer *ea_temp;

	for(ea_temp = ea->pending; ea_temp; ea_temp = ea_temp->pending_next)
	{
		cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [distribute_ea] send ea (%s) by reader %s answering for client %s", (check_client(ea_temp->er->client) ? ea_temp->er->client->account->usr : "-"), ea_temp->er->caid, ea_temp->er->prid, ea_temp->er->srvid, ea->rc==E_FOUND?"OK":"NOK", ea_temp->reader->label, (check_client(ea->er->client) ? ea->er->client->account->usr : "-"));

		//e.g. we cannot send timeout, because "ea_temp->er->client" could wait/ask other readers! Simply set not_found if different from E_FOUND!
		write_ecm_answer(ea_temp->reader, ea_temp->er, (ea->rc==E_FOUND? E_FOUND : E_NOTFOUND), ea->rcEx, ea->cw, NULL);
	}
}

int32_t send_dcw(struct s_client *client, ECM_REQUEST *er)
{
	if(!check_client(client) || client->typ != 'c')
		{ return 0; }

	cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [send_dcw] rc %d from reader %s", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, er->rc, er->selected_reader ? er->selected_reader->label : "-");

	static const char stageTxt[] = {'0', 'C', 'L', 'P', 'F', 'X'};
	static const char *stxt[] = {"found", "cache1", "cache2", "cache3",
								 "not found", "timeout", "sleeping",
								 "fake", "invalid", "corrupt", "no card", "expdate", "disabled", "stopped"
								};
	static const char *stxtEx[16] = {"", "group", "caid", "ident", "class", "chid", "queue", "peer", "sid", "", "", "", "", "", "", ""};
	static const char *stxtWh[16] = {"", "user ", "reader ", "server ", "lserver ", "", "", "", "", "", "", "", "" , "" , "", ""};
	char sby[100] = "", sreason[32] = "", scwcinfo[32] = "", schaninfo[32] = "", srealecmtime[50]="";
	char erEx[32] = "";
	char usrname[38] = "";
	char channame[32];
	struct timeb tpe;

	snprintf(usrname, sizeof(usrname) - 1, "%s", username(client));

#ifdef WITH_DEBUG
	if(cs_dblevel & D_CLIENTECM)
	{
		char buf[ECM_FMT_LEN];
		char ecmd5[17 * 3];
		char cwstr[17 * 3];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
		cs_hexdump(0, er->cw, 16, cwstr, sizeof(cwstr));
#ifdef CS_CACHEEX
		char csphash[5 * 3];
		cs_hexdump(0, (void *)&er->csp_hash, 4, csphash, sizeof(csphash));
		cs_log_dbg(D_CLIENTECM, "Client %s csphash %s cw %s rc %d %s", username(client), csphash, cwstr, er->rc, buf);
#else
		cs_log_dbg(D_CLIENTECM, "Client %s cw %s rc %d %s", username(client), cwstr, er->rc, buf);
#endif
	}
#endif

	struct s_reader *er_reader = er->selected_reader; //responding reader
	struct s_ecm_answer *ea_orig = get_ecm_answer(er_reader, er);


	//check if ecm_answer from pending's
	if(ea_orig && ea_orig->is_pending && er->rc == E_FOUND)
		{ er->rc = E_CACHE2; }


	//check if answer from cacheex-1 reader
	if(er->rc == E_FOUND && er_reader && cacheex_reader(er_reader))  //so add hit to cacheex mode 1 readers
	{
		er->rc = E_CACHEEX;
	}

	//real ecm time
	if(ea_orig && !ea_orig->is_pending && er->rc == E_FOUND
	   &&
	   (
#ifdef CS_CACHEEX
		  er->cacheex_wait_time ||
#endif
	     (ea_orig->status & READER_FALLBACK))
	 )
	{
		snprintf(srealecmtime, sizeof(srealecmtime) - 1, " (real %d ms)", ea_orig->ecm_time);
	}


	if(er->rc == E_TIMEOUT)
	{
#ifdef CS_CACHEEX
		if(!er->from_cacheex1_client){  //cosmetic: show "by" readers only for "normal" clients
#endif
		struct s_ecm_answer *ea_list;
		int32_t ofs = 0;
		for(ea_list = er->matching_rdr; ea_list; ea_list = ea_list->next)
		{
			if(ea_list->reader && ofs < (int32_t)sizeof(sby) && ((ea_list->status & REQUEST_SENT) && (ea_list->rc == E_TIMEOUT || ea_list->rc >= E_99)))   //Request send, but no cw answered!
			{
				ofs += snprintf(sby + ofs, sizeof(sby) - ofs - 1, "%s%s", ofs ? "," : " by ", ea_list->reader->label);
			}
		}
		if(er->ocaid && ofs < (int32_t)sizeof(sby))
			{ ofs += snprintf(sby + ofs, sizeof(sby) - ofs - 1, "(btun %04X)", er->ocaid); }

#ifdef CS_CACHEEX
		}
#endif
	}
	else if(er_reader)
	{
		// add marker to reader if ECM_REQUEST was betatunneled
		if(er->ocaid)
			{ snprintf(sby, sizeof(sby) - 1, " by %s(btun %04X)", er_reader->label, er->ocaid); }
		else
			{ snprintf(sby, sizeof(sby) - 1, " by %s", er_reader->label); }
	}
#ifdef CS_CACHEEX
	else if(er->cacheex_src)   //only for cacheex mode-3 clients (no mode-1 or mode-2 because reader is set!) and csp
	{
		char *cex_name = "-";
		if(check_client(er->cacheex_src) && er->cacheex_src->account){
			if(er->cacheex_src->account->usr[0] != '\0')
				cex_name = er->cacheex_src->account->usr;
			else
				cex_name = "csp";
		}

		if(er->ocaid){
			snprintf(sby, sizeof(sby) - 1, " by %s(btun %04X)", cex_name, er->ocaid);
		}else{
			snprintf(sby, sizeof(sby) - 1, " by %s", cex_name);
		}
	}
#endif


	if(er->rc < E_NOTFOUND)
	{ 
		er->rcEx = 0;
		memset(er->msglog, 0, MSGLOGSIZE); // remove reader msglog from previous requests that failed, founds never give back msglog!
	}

	if(er->rcEx)
		{ snprintf(erEx, sizeof(erEx) - 1, "rejected %s%s", stxtWh[er->rcEx >> 4], stxtEx[er->rcEx & 0xf]); }

	get_servicename_or_null(client, er->srvid, er->caid, channame);
	if(!channame[0])
		{ schaninfo[0] = '\0'; }
	else
		{ snprintf(schaninfo, sizeof(schaninfo) - 1, " - %s", channame); }

	if(er->msglog[0])
		{ snprintf(sreason, sizeof(sreason) - 1, " (%s)", er->msglog); }
#ifdef CW_CYCLE_CHECK
	if(er->cwc_msg_log[0])
		{ snprintf(scwcinfo, sizeof(scwcinfo) - 1, " (%s)", er->cwc_msg_log); }
#endif

	cs_ftime(&tpe);

#ifdef CS_CACHEEX
	int cx = 0;
	if(er->rc >= E_CACHEEX && er->cacheex_wait_time && er->cacheex_wait_time_expired){
		cx = snprintf ( sreason, sizeof sreason, " (wait_time over)");
	}
	if(er->cw_count>1){
		snprintf ( sreason+cx, (sizeof sreason)-cx, " (cw count %d)", er->cw_count);
	}
#endif

	client->cwlastresptime = comp_timeb(&tpe, &er->tps);

	time_t now = time(NULL);
	webif_client_add_lastresponsetime(client, client->cwlastresptime, now, er->rc); // add to ringbuffer

	if(er_reader)
	{
		struct s_client *er_cl = er_reader->client;
		if(check_client(er_cl))
		{
			er_cl->cwlastresptime = client->cwlastresptime;
			webif_client_add_lastresponsetime(er_cl, client->cwlastresptime, now, er->rc);
			er_cl->last_srvidptr = client->last_srvidptr;
		}
	}

	webif_client_init_lastreader(client, er, er_reader, stxt);

	client->last = now;

	//cs_log_dbg(D_TRACE, "CHECK rc=%d er->cacheex_src=%s", er->rc, username(er->cacheex_src));
	switch(er->rc)
	{
	case E_FOUND:
	{
		client->cwfound++;
		client->account->cwfound++;
		first_client->cwfound++;
		break;
	}
	case E_CACHE1:
	case E_CACHE2:
	case E_CACHEEX:
	{
		client->cwcache++;
		client->account->cwcache++;
		first_client->cwcache++;
#ifdef CS_CACHEEX
		if(check_client(er->cacheex_src))
		{
			first_client->cwcacheexhit++;
			er->cacheex_src->cwcacheexhit++;
			if(er->cacheex_src->account)
				{ er->cacheex_src->account->cwcacheexhit++; }
		}
#endif
		break;
	}
	case E_NOTFOUND:
	case E_CORRUPT:
	case E_NOCARD:
	{
		if(er->rcEx)
		{
			client->cwignored++;
			client->account->cwignored++;
			first_client->cwignored++;
		}
		else
		{
			client->cwnot++;
			client->account->cwnot++;
			first_client->cwnot++;
		}
		break;
	}
	case E_TIMEOUT:
	{
		client->cwtout++;
		client->account->cwtout++;
		first_client->cwtout++;
		break;
	}
	default:
	{
		client->cwignored++;
		client->account->cwignored++;
		first_client->cwignored++;
	}
	}

#ifdef CS_ANTICASC
// [zaplist] ACoSC anticascading
	if(cfg.acosc_enabled)
	{
		int8_t max_active_sids = 0;
		int8_t zap_limit = 0;
		int8_t penalty = 0;
		int32_t penalty_duration = 0;
		int32_t delay = 0;
		char *info1 = NULL;
		char *info2 = NULL;
		char *info3 = NULL;
		char *info4 = NULL;
		char *info5 = NULL;


  	//**global or user value?
		cs_writelock(&clientlist_lock);

		max_active_sids = client->account->acosc_max_active_sids == -1 ? cfg.acosc_max_active_sids : client->account->acosc_max_active_sids;
		info1 = client->account->acosc_max_active_sids == -1 ? "Globalvalue" : "Uservalue";

		zap_limit = client->account->acosc_zap_limit == -1 ? cfg.acosc_zap_limit : client->account->acosc_zap_limit;
		info5 = client->account->acosc_zap_limit == -1 ? "Globalvalue" : "Uservalue";

		penalty = client->account->acosc_penalty == -1 ? cfg.acosc_penalty : client->account->acosc_penalty;
		info2 = client->account->acosc_penalty == -1 ? "Globalvalue" : "Uservalue";

		penalty_duration = client->account->acosc_penalty_duration == -1 ? cfg.acosc_penalty_duration : client->account->acosc_penalty_duration;
		info3 = client->account->acosc_penalty_duration == -1 ? "Globalvalue" : "Uservalue";

		delay = client->account->acosc_delay == -1 ? cfg.acosc_delay : client->account->acosc_delay;
		info4 = client->account->acosc_delay == -1 ? "Globalvalue" : "Uservalue";

	  //**

		if((er->rc < E_NOTFOUND && max_active_sids > 0) || zap_limit > 0)
		{
			int8_t k = 0;
			int8_t active_sid_count = 0;
			time_t zaptime = time(NULL);

			if(client->account->acosc_penalty_active == 3 && client->account->acosc_penalty_until <= zaptime) // reset penalty_active
			{
				client->account->acosc_penalty_active = 0;
				client->account->acosc_penalty_until = 0;
			}

			if(client->account->acosc_penalty_active == 0 && max_active_sids > 0)
			{
				for(k=0; k<15 ; k++)
				{
					if(zaptime-30 < client->client_zap_list[k].lasttime && client->client_zap_list[k].request_stage == 10)
					{
						cs_log_dbg(D_TRACE, "[zaplist] ACoSC for Client: %s  more then 10 ECM's for %04X@%06X/%04X/%04X", username(client),  client->client_zap_list[k].caid, client->client_zap_list[k].provid, client->client_zap_list[k].chid, client->client_zap_list[k].sid);
						active_sid_count ++;
					}
				}
				cs_log_dbg(D_TRACE, "[zaplist] ACoSC for Client: %s  active_sid_count= %i with more than 10 followed ECM's (mas:%i (%s))", username(client), active_sid_count, max_active_sids, info1);
			}
			if(client->account->acosc_penalty_active == 0 && max_active_sids > 0 && active_sid_count > max_active_sids) //max_active_sids reached
			{
				client->account->acosc_penalty_active = 1;
				client->account->acosc_penalty_until = zaptime + penalty_duration;
			}

			if(client->account->acosc_penalty_active == 0 && zap_limit > 0 && client->account->acosc_user_zap_count > zap_limit) // zap_limit reached
			{
				client->account->acosc_penalty_active = 2;
				client->account->acosc_penalty_until = zaptime + penalty_duration;
			}

			if(client->account->acosc_penalty_active > 0)
			{
				if(client->account->acosc_penalty_active == 3)
					{ cs_log("[zaplist] ACoSC for Client: %s  penalty_duration: %ld seconds left(%s)", username(client), client->account->acosc_penalty_until - zaptime, info3); }

				int16_t lt = get_module(client)->listenertype;
				switch(penalty)
				{
					case 1: // NULL CW
						er->rc = E_FAKE; //E_FAKE give only a status fake not a NULL cw
						er->rcEx = E2_WRONG_CHKSUM;
						if(client->account->acosc_penalty_active == 1)
							{ cs_log("[zaplist] ACoSC for Client: %s  max_activ_sids reached: %i:%i(%s) penalty: 1(%s) send null CW", username(client), active_sid_count, max_active_sids, info1, info2); }
						if(client->account->acosc_penalty_active == 2)
							{ cs_log("[zaplist] ACoSC for Client: %s  zap_limit reached: %i:%i(%s) penalty: 1(%s) send null CW", username(client), client->account->acosc_user_zap_count, zap_limit, info5, info2); }
						
						break;
					case 2: // ban
						if(lt != LIS_DVBAPI)
						{
							if(client->account->acosc_penalty_active == 1)
								{ cs_log("[zaplist] ACoSC for Client: %s  max_activ_sids reached: %i:%i(%s) penalty: 2(%s) BAN Client - Kill and set Client to failban list for %i sec.", username(client), active_sid_count, max_active_sids, info1, info2, penalty_duration); }
							if(client->account->acosc_penalty_active == 2)
								{ cs_log("[zaplist] ACoSC for Client: %s  zap_limit reached: %i:%i(%s) penalty: 2(%s) BAN Client - Kill and set Client to failban list for %i sec.", username(client), client->account->acosc_user_zap_count, zap_limit, info5, info2, penalty_duration); }

							cs_add_violation_acosc(client, client->account->usr, penalty_duration);
							add_job(client, ACTION_CLIENT_KILL, NULL, 0);
						}
						else
						{
							cs_log("[zaplist] ACoSC for Client: %s  %i:%i(%s) penalty: 2(%s) BAN Client - don't Ban dvbapi user only stop decoding", username(client), active_sid_count, max_active_sids, info1, info2);
						}
						er->rc = E_DISABLED;
						break;
					case 3: // delay
						if(client->account->acosc_penalty_active == 1)
							{ cs_log("[zaplist] ACoSC for Client: %s  max_activ_sids reached: %i:%i(%s) penalty: 3(%s) delay CW: %ims(%s)", username(client), active_sid_count, max_active_sids, info1, info2, delay, info4); }
						if(client->account->acosc_penalty_active == 2)
							{ cs_log("[zaplist] ACoSC for Client: %s  zap_limit reached: %i:%i(%s) penalty: 3(%s) delay CW: %ims(%s)", username(client), client->account->acosc_user_zap_count, zap_limit, info5, info2, delay, info4);	}
						cs_writeunlock(&clientlist_lock);
						cs_sleepms(delay);
						cs_writelock(&clientlist_lock);
						client->cwlastresptime += delay;
						snprintf(sreason, sizeof(sreason)-1, " (%d ms penalty delay)", delay);
						break;
					default: // logging
						if(client->account->acosc_penalty_active == 1)
							{ cs_log("[zaplist] ACoSC for Client: %s  max_activ_sids reached: %i:%i(%s) penalty: 0(%s) only logging", username(client), active_sid_count, max_active_sids, info1, info2); }
						if(client->account->acosc_penalty_active == 2)
							{ cs_log("[zaplist] ACoSC for Client: %s  zap_limit reached: %i:%i(%s) penalty: 0(%s) only logging", username(client), client->account->acosc_user_zap_count, zap_limit, info5, info2);	}

						break;
				}
				client->account->acosc_user_zap_count = 0; // we got already a penalty
				client->account->acosc_penalty_active = 3;
			}
		}
		cs_writeunlock(&clientlist_lock);
	}
#endif

	ac_chk(client, er, 1);
	int32_t is_fake = 0;
	if(er->rc == E_FAKE)
	{
		is_fake = 1;
		er->rc = E_FOUND;
	}

	if(cfg.double_check &&  er->rc == E_FOUND && er->selected_reader && is_double_check_caid(er))
	{
		if(er->checked == 0)   //First CW, save it and wait for next one
		{
			er->checked = 1;
			er->origin_reader = er->selected_reader;
			memcpy(er->cw_checked, er->cw, sizeof(er->cw));
			cs_log("DOUBLE CHECK FIRST CW by %s idx %d cpti %d", er->origin_reader->label, er->idx, er->msgid);
		}
		else if(er->origin_reader != er->selected_reader)      //Second (or third and so on) cw. We have to compare
		{
			if(memcmp(er->cw_checked, er->cw, sizeof(er->cw)) == 0)
			{
				er->checked++;
				cs_log("DOUBLE CHECKED! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->msgid);
			}
			else
			{
				cs_log("DOUBLE CHECKED NONMATCHING! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->msgid);
			}
		}
		if(er->checked < 2)    //less as two same cw? mark as pending!
		{
			er->rc = E_UNHANDLED;
			goto ESC;
		}
	}

	get_module(client)->send_dcw(client, er);

	add_cascade_data(client, er);

	if(is_fake)
		{ er->rc = E_FAKE; }

	if(!(er->rc == E_SLEEPING && client->cwlastresptime == 0))
	{
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		if(er->reader_avail == 1 || er->stage == 0)
		{
			cs_log("%s (%s): %s (%d ms)%s%s%s%s",
				   usrname, buf,
				   er->rcEx ? erEx : stxt[er->rc], client->cwlastresptime, sby, schaninfo, sreason, scwcinfo);
		}
		else
		{
			cs_log("%s (%s): %s (%d ms)%s (%c/%d/%d/%d)%s%s%s%s",
				   usrname, buf,
				   er->rcEx ? erEx : stxt[er->rc],
				   client->cwlastresptime, sby,
				   stageTxt[er->stage], er->reader_requested, (er->reader_count + er->fallback_reader_count), er->reader_avail,
				   schaninfo, srealecmtime, sreason, scwcinfo);
		}
	}

	cs_log_dump_dbg(D_ATR, er->cw, 16, "cw:");
	led_status_cw_not_found(er);

ESC:

	return 0;
}

/*
 * write_ecm_request():
 */
static int32_t write_ecm_request(struct s_reader *rdr, ECM_REQUEST *er)
{
	add_job(rdr->client, ACTION_READER_ECM_REQUEST, (void *)er, 0);
	return 1;
}


/**
 * sends the ecm request to the readers
 * ECM_REQUEST er : the ecm
 * er->stage: 0 = no reader asked yet
 *            2 = ask only local reader (skipped without preferlocalcards)
 *            3 = ask any non fallback reader
 *            4 = ask fallback reader
 **/
void request_cw_from_readers(ECM_REQUEST *er, uint8_t stop_stage)
{
	struct s_ecm_answer *ea;
	int8_t sent = 0;

	if(er->stage >= 4) { return; }

	while(1)
	{
		if(stop_stage && er->stage >= stop_stage) { return; }

		er->stage++;

#ifdef CS_CACHEEX
		if(er->stage == 1 && er->preferlocalcards==2)
			{ er->stage++; }
#else
		if(er->stage == 1)
			{ er->stage++; }
#endif

		if(er->stage == 2 && !er->preferlocalcards)
			{ er->stage++; }

		for(ea = er->matching_rdr; ea; ea = ea->next)
		{
			switch(er->stage)
			{
#ifdef CS_CACHEEX
			case 1:
			{
				// Cache-Exchange
				if((ea->status & REQUEST_SENT) ||
						(ea->status & (READER_CACHEEX | READER_ACTIVE)) != (READER_CACHEEX | READER_ACTIVE))
					{ continue; }
				break;
			}
#endif
			case 2:
			{
				// only local reader
				if((ea->status & REQUEST_SENT) ||
						(ea->status & (READER_ACTIVE | READER_FALLBACK | READER_LOCAL)) != (READER_ACTIVE | READER_LOCAL))
					{ continue; }
				break;
			}
			case 3:
			{
				// any non fallback reader not asked yet
				if((ea->status & REQUEST_SENT) ||
						(ea->status & (READER_ACTIVE | READER_FALLBACK)) != READER_ACTIVE)
					{ continue; }
				break;
			}
			default:
			{
				// only fallbacks
				if((ea->status & REQUEST_SENT) ||
						(ea->status & (READER_ACTIVE | READER_FALLBACK)) != (READER_ACTIVE | READER_FALLBACK))
					{ continue; }
				break;
			}
			}

			struct s_reader *rdr = ea->reader;
			char ecmd5[17 * 3];
			cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
			cs_log_dbg(D_TRACE | D_CSP, "request_cw stage=%d to reader %s ecm hash=%s", er->stage, rdr ? rdr->label : "", ecmd5);

			ea->status |= REQUEST_SENT;
			cs_ftime(&ea->time_request_sent);

			er->reader_requested++;

			write_ecm_request(ea->reader, er);

			//set sent=1 only if reader is active/connected. If not, switch to next stage!
			if(!sent && rdr)
			{
				struct s_client *rcl = rdr->client;
				if(check_client(rcl))
				{
					if(rcl->typ == 'r' && rdr->card_status == CARD_INSERTED)
						{ sent = 1; }
					else if(rcl->typ == 'p' && (rdr->card_status == CARD_INSERTED || rdr->tcp_connected))
						{ sent = 1; }
				}
			}

			cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_request] reader %s --> SENT %d", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, rdr ? ea->reader->label : "-", sent);
		}
		if(sent || er->stage >= 4)
			{ break; }
	}
}


void add_cache_from_reader(ECM_REQUEST *er, struct s_reader *rdr, int32_t csp_hash, uchar *ecmd5, uchar *cw, int16_t caid, int32_t prid, int16_t srvid ){
	ECM_REQUEST *ecm;
	if (cs_malloc(&ecm, sizeof(ECM_REQUEST))){
		cs_ftime(&ecm->tps);

		ecm->cwc_cycletime = er->cwc_cycletime;
		ecm->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
		memcpy(ecm->ecm, er->ecm, sizeof(ecm->ecm));  // ecm[0] is pushed to cacheexclients so we need a copy from it
		ecm->caid = caid;
		ecm->prid = prid;
		ecm->srvid = srvid;
		memcpy(ecm->ecmd5, ecmd5, CS_ECMSTORESIZE);
		ecm->csp_hash = csp_hash;
		ecm->rc = E_FOUND;
		memcpy(ecm->cw, cw, sizeof(ecm->cw));
		ecm->grp = rdr->grp;
		ecm->selected_reader = rdr;
#ifdef CS_CACHEEX
		if(rdr && cacheex_reader(rdr))
			{ ecm->cacheex_src = rdr->client; } //so adds hits to reader
#endif

		add_cache(ecm); //add cw to cache

#ifdef CS_CACHEEX
		cs_writelock(&ecm_pushed_deleted_lock);
		ecm->next = ecm_pushed_deleted;
		ecm_pushed_deleted = ecm;
		cs_writeunlock(&ecm_pushed_deleted_lock);
#else
		NULLFREE(ecm);
#endif
	}
}


void chk_dcw(struct s_ecm_answer *ea)
{
	if(!ea || !ea->er)
		{ return; }

	ECM_REQUEST *ert = ea->er;
	struct s_ecm_answer *ea_list;
	struct s_reader *eardr = ea->reader;
	if(!ert)
		{ return; }

	//ecm request already answered!
	if(ert->rc < E_99)
	{
#ifdef CS_CACHEEX
		if(ea && ert->rc < E_NOTFOUND && ea->rc < E_NOTFOUND && memcmp(ea->cw, ert->cw, sizeof(ert->cw)) != 0)
		{
			char cw1[16 * 3 + 2], cw2[16 * 3 + 2];
			cs_hexdump(0, ea->cw, 16, cw1, sizeof(cw1));
			cs_hexdump(0, ert->cw, 16, cw2, sizeof(cw2));

			char ip1[20] = "", ip2[20] = "";
			if(ea->reader && check_client(ea->reader->client)) { cs_strncpy(ip1, cs_inet_ntoa(ea->reader->client->ip), sizeof(ip1)); }
			if(ert->cacheex_src) { cs_strncpy(ip2, cs_inet_ntoa(ert->cacheex_src->ip), sizeof(ip2)); }
			else if(ert->selected_reader && check_client(ert->selected_reader->client)) { cs_strncpy(ip2, cs_inet_ntoa(ert->selected_reader->client->ip), sizeof(ip2)); }

			ECM_REQUEST *er = ert;
			debug_ecm(D_TRACE, "WARNING2: Different CWs %s from %s(%s)<>%s(%s): %s<>%s", buf,
					  username(ea->reader ? ea->reader->client : ert->client), ip1,
					  er->cacheex_src ? username(er->cacheex_src) : (ea->reader ? ea->reader->label : "unknown/csp"), ip2,
					  cw1, cw2);
		}
#endif

		return;
	}


#ifdef CS_CACHEEX
	/* if answer from cacheex-1 reader, not send answer to client! thread check_cache will check counter and send answer to client!
	 * Anyway, we should check if we have to go to oher stage (>1)
	 */

	if(eardr && cacheex_reader(eardr)){

		// if wait_time, and not wait_time expired and wait_time due to hitcache(or awtime>0), we have to wait cacheex timeout before call other readers (stage>1)
		if(cacheex_reader(eardr) && !ert->cacheex_wait_time_expired && ert->cacheex_hitcache)
			{ return; }

		int8_t cacheex_left = 0;
		uint8_t has_cacheex = 0;
		if(ert->stage==1){
			for(ea_list = ert->matching_rdr; ea_list; ea_list = ea_list->next)
			{
				cs_readlock(&ea_list->ecmanswer_lock);
				if(((ea_list->status & (READER_CACHEEX | READER_FALLBACK | READER_ACTIVE))) == (READER_CACHEEX | READER_ACTIVE))
					{ has_cacheex = 1; }
				if((!(ea_list->status & READER_FALLBACK)  && ((ea_list->status & (REQUEST_SENT | REQUEST_ANSWERED | READER_CACHEEX | READER_ACTIVE)) == (REQUEST_SENT | READER_CACHEEX | READER_ACTIVE))) || ea_list->rc < E_NOTFOUND)
					{ cacheex_left++; }
				cs_readunlock(&ea_list->ecmanswer_lock);
			}

			if(has_cacheex && !cacheex_left) { request_cw_from_readers(ert, 0); }
		}

		return;
	}
#endif


	int32_t reader_left = 0, local_left = 0, reader_not_flb_left = 0, has_not_fallback = 0, has_local = 0;
	ert->selected_reader = eardr;

	switch(ea->rc)
	{
	case E_FOUND:
		memcpy(ert->cw, ea->cw, 16);
		ert->rcEx = 0;
		ert->rc = ea->rc;
		ert->grp |= eardr->grp;

		break;
	case E_INVALID:
	case E_NOTFOUND:
	{

		//check if there are other readers to ask, and if not send NOT_FOUND to client
		ert->rcEx = ea->rcEx;
		cs_strncpy(ert->msglog, ea->msglog, sizeof(ert->msglog));

		for(ea_list = ert->matching_rdr; ea_list; ea_list = ea_list->next)
		{
			cs_readlock(&ea_list->ecmanswer_lock);

			if((!(ea_list->status & READER_FALLBACK)  && ((ea_list->status & (REQUEST_SENT | REQUEST_ANSWERED | READER_LOCAL | READER_ACTIVE)) == (REQUEST_SENT | READER_LOCAL | READER_ACTIVE))) || ea_list->rc < E_NOTFOUND)
				{ local_left++; }

			if((!(ea_list->status & READER_FALLBACK)  && ((ea_list->status & (REQUEST_SENT | REQUEST_ANSWERED | READER_ACTIVE)) == (REQUEST_SENT | READER_ACTIVE))) || ea_list->rc < E_NOTFOUND)
				{ reader_not_flb_left++; }

			if(((ea_list->status & (REQUEST_ANSWERED | READER_ACTIVE)) == (READER_ACTIVE)) || ea_list->rc < E_NOTFOUND)
				{ reader_left++; }

			if(((ea_list->status & (READER_FALLBACK | READER_ACTIVE))) == (READER_ACTIVE))
				{ has_not_fallback = 1; }
			if(((ea_list->status & (READER_LOCAL | READER_FALLBACK | READER_ACTIVE))) == (READER_LOCAL | READER_ACTIVE))
				{ has_local = 1; }

			cs_readunlock(&ea_list->ecmanswer_lock);
		}

		switch(ert->stage)
		{
		case 2:   // only local reader (used only if preferlocalcards=1)
		{
			if(has_local && !local_left) { request_cw_from_readers(ert, 0); }
			break;
		}
		case 3:
		{
			// any fallback reader not asked yet
			if(has_not_fallback && !reader_not_flb_left) { request_cw_from_readers(ert, 0); }
			break;
		}
		}

		if(!reader_left  // no more matching reader
#ifdef CS_CACHEEX
		  && !cfg.wait_until_ctimeout
#endif
		  )
			{ ert->rc = E_NOTFOUND; } //so we set the return code

		break;
	}
	case E_TIMEOUT:   // if timeout, we have to send timeout to client: this is done by ecm_timeout callback
		return;
		break;
	case E_UNHANDLED:
		return;
		break;
	default:
		cs_log("unexpected ecm answer rc=%d.", ea->rc);
		return;
		break;
	}

	if(ert->rc < E_99)
		send_dcw(ert->client, ert);
}

uint32_t chk_provid(uint8_t *ecm, uint16_t caid)
{
	int32_t i, len, descriptor_length = 0;
	uint32_t provid = 0;

	switch(caid >> 8)
	{
	case 0x01:
		// seca
		provid = b2i(2, ecm + 3);
		break;
	case 0x05:
		// viaccess
		i = (ecm[4] == 0xD2) ? ecm[5] + 2 : 0; // skip d2 nano
		if((ecm[5 + i] == 3) && ((ecm[4 + i] == 0x90) || (ecm[4 + i] == 0x40)))
			{ provid = (b2i(3, ecm + 6 + i) & 0xFFFFF0); }

		i = (ecm[6] == 0xD2) ? ecm[7] + 2 : 0; // skip d2 nano long ecm
		if((ecm[7 + i] == 7) && ((ecm[6 + i] == 0x90) || (ecm[6 + i] == 0x40)))
			{ provid = (b2i(3, ecm + 8 + i) & 0xFFFFF0); }

		break;
	case 0x0D:
		// cryptoworks
		len = (((ecm[1] & 0xf) << 8) | ecm[2]) + 3;
		for(i = 8; i < len; i += descriptor_length + 2)
		{
			descriptor_length = ecm[i + 1];
			if(ecm[i] == 0x83)
			{
				provid = (uint32_t)ecm[i + 2] & 0xFE;
				break;
			}
		}
		break;
		
	case 0x18:
		// nagra2
		if (caid == 0x1801) // more safety
			provid = b2i(2, ecm + 5);
		break;
	}

	return provid;
}

void update_chid(ECM_REQUEST *er)
{
	er->chid = get_subid(er);
}

/*
 * This function writes the current CW from ECM struct to a cwl file.
 * The filename is re-calculated and file re-opened every time.
 * This will consume a bit cpu time, but nothing has to be stored between
 * each call. If not file exists, a header is prepended
 */
static void logCWtoFile(ECM_REQUEST *er, uchar *cw)
{
	FILE *pfCWL;
	char srvname[128];
	/* %s / %s   _I  %04X  _  %s  .cwl  */
	char buf[256 + sizeof(srvname)];
	char date[9];
	unsigned char  i, parity, writeheader = 0;
	struct tm timeinfo;

	/*
	* search service name for that id and change characters
	* causing problems in file name
	*/

	get_servicename(cur_client(), er->srvid, er->caid, srvname);

	for(i = 0; srvname[i]; i++)
		if(srvname[i] == ' ') { srvname[i] = '_'; }

	/* calc log file name */
	time_t walltime = cs_time();
	localtime_r(&walltime, &timeinfo);
	strftime(date, sizeof(date), "%Y%m%d", &timeinfo);
	snprintf(buf, sizeof(buf), "%s/%s_I%04X_%s.cwl", cfg.cwlogdir, date, er->srvid, srvname);

	/* open failed, assuming file does not exist, yet */
	if((pfCWL = fopen(buf, "r")) == NULL)
	{
		writeheader = 1;
	}
	else
	{
		/* we need to close the file if it was opened correctly */
		fclose(pfCWL);
	}

	if((pfCWL = fopen(buf, "a+")) == NULL)
	{
		/* maybe this fails because the subdir does not exist. Is there a common function to create it?
		    for the moment do not print32_t to log on every ecm
		    cs_log(""error opening cw logfile for writing: %s (errno=%d %s)", buf, errno, strerror(errno)); */
		return;
	}
	if(writeheader)
	{
		/* no global macro for cardserver name :( */
		fprintf(pfCWL, "# OSCam cardserver v%s - http://www.streamboard.tv/oscam/\n", CS_VERSION);
		fprintf(pfCWL, "# control word log file for use with tsdec offline decrypter\n");
		strftime(buf, sizeof(buf), "DATE %Y-%m-%d, TIME %H:%M:%S, TZ %Z\n", &timeinfo);
		fprintf(pfCWL, "# %s", buf);
		fprintf(pfCWL, "# CAID 0x%04X, SID 0x%04X, SERVICE \"%s\"\n", er->caid, er->srvid, srvname);
	}

	parity = er->ecm[0] & 1;
	fprintf(pfCWL, "%d ", parity);
	for(i = parity * 8; i < 8 + parity * 8; i++)
		{ fprintf(pfCWL, "%02X ", cw[i]); }
	/* better use incoming time er->tps rather than current time? */
	strftime(buf, sizeof(buf), "%H:%M:%S\n", &timeinfo);
	fprintf(pfCWL, "# %s", buf);
	fflush(pfCWL);
	fclose(pfCWL);
}

int32_t write_ecm_answer(struct s_reader *reader, ECM_REQUEST *er, int8_t rc, uint8_t rcEx, uint8_t *cw, char *msglog)
{
	if(!reader || !er || !er->tps.time) { return 0; }

	// drop too late answers, to avoid seg fault --> only answer until tps.time+((cfg.ctimeout+500)/1000+1) is accepted
	time_t timeout = time(NULL) - ((cfg.ctimeout+500)/1000+1);
	if(er->tps.time < timeout)   //< and NOT <=
		{ return 0; }

	int32_t i;
	uint8_t c;
	struct timeb now;
	cs_ftime(&now);

	if(er && er->parent)
	{
		// parent is only set on reader->client->ecmtask[], but we want original er
		ECM_REQUEST *er_reader_cp = er;
		er = er->parent;        //Now er is "original" ecm, before it was the reader-copy
		er_reader_cp->rc = rc;
		er_reader_cp->idx = 0;

		timeout = time(NULL) - ((cfg.ctimeout+500)/1000+1);
		if(er->tps.time < timeout)
			{ return 0; }
	}

	struct s_ecm_answer *ea = get_ecm_answer(reader, er);
	if(!ea) { return 0; }

	cs_writelock(&ea->ecmanswer_lock);

	if((ea->status & REQUEST_ANSWERED))
	{
		cs_log_dbg(D_READER, "Reader %s already answer, skip this ecm answer!", reader ? reader->label : "-");
		cs_writeunlock(&ea->ecmanswer_lock);
		return 0;
	}

	//SPECIAL CHECKs for rc
	if(rc < E_NOTFOUND && cw && chk_is_null_CW(cw))    //if cw=0 by anticascading
	{
		rc = E_NOTFOUND;
		cs_log_dbg(D_TRACE | D_LB, "WARNING: reader %s send fake cw, set rc=E_NOTFOUND!", reader ? reader->label : "-");
	}

	if(rc < E_NOTFOUND && cw && !chk_halfCW(er,cw)){
		rc = E_NOTFOUND;
		cs_log_dbg(D_TRACE | D_LB, "WARNING: reader %s send wrong swapped NDS cw, set rc=E_NOTFOUND!", reader ? reader->label : "-");
	}

	if(reader && cw && rc < E_NOTFOUND)
	{
		if(reader->disablecrccws == 0)
		{
			for(i = 0; i < 16; i += 4)
			{
				c = ((cw[i] + cw[i + 1] + cw[i + 2]) & 0xff);
				if(cw[i + 3] != c)
				{
					unsigned char nano = 0x00;
					if(er->caid == 0x100 && er->ecm[5] > 0x00)
					{
						nano = er->ecm[5]; // seca nano protection
					}	
						
					if(reader->dropbadcws && !nano) // only drop controlword if no cw encryption is applied
					{
						rc = E_NOTFOUND;
						rcEx = E2_WRONG_CHKSUM;
						break;
					}
					else
					{
						if(!nano) // only fix checksum if no cw encryption is applied (nano = 0)
						{
							cs_log_dbg(D_TRACE, "notice: changed dcw checksum byte cw[%i] from %02x to %02x", i + 3, cw[i + 3], c);
							cw[i + 3] = c;
						}
						else
						{
							if(i==12) // there are servers delivering correct controlwords but with failing last cw checksum (on purpose?!)
							{
								cs_log_dbg(D_TRACE,"NANO%02d: BAD PEER DETECTED, oscam has fixed the last cw crc that wasn't matching!", nano);
								cw[i + 3] = c; // fix the last controlword
							}
							else
							{
								cs_log_dbg(D_TRACE,"NANO%02d: not fixing the crc of this cw since its still encrypted!", nano);
								break; // crc failed so stop!
							}
						}
					}
				}
			}
		}
		else
		{
			cs_log_dbg(D_TRACE, "notice: CW checksum check disabled");
		}
	}

#ifdef CW_CYCLE_CHECK
	uint8_t cwc_ct = er->cwc_cycletime > 0 ? er->cwc_cycletime : 0;
	uint8_t cwc_ncwc = er->cwc_next_cw_cycle < 2 ? er->cwc_next_cw_cycle : 2;
	if(!checkcwcycle(er->client, er, reader, cw, rc, cwc_ct, cwc_ncwc))
	{
		rc = E_NOTFOUND;
		rcEx = E2_WRONG_CHKSUM;
		cs_log_dbg(D_CACHEEX | D_CWC | D_LB, "{client %s, caid %04X, srvid %04X} [write_ecm_answer] cyclecheck failed! Reader: %s set rc: %i", (er->client ? er->client->account->usr : "-"), er->caid, er->srvid, reader ? reader->label : "-", rc);
	}
	else { cs_log_dbg(D_CACHEEX | D_CWC | D_LB, "{client %s, caid %04X, srvid %04X} [write_ecm_answer] cyclecheck passed! Reader: %s rc: %i", (er->client ? er->client->account->usr : "-"), er->caid, er->srvid, reader ? reader->label : "-", rc); }
#endif
	//END -- SPECIAL CHECKs for rc


	ea->status |= REQUEST_ANSWERED;
	ea->rc = rc;
	ea->ecm_time = comp_timeb(&now, &ea->time_request_sent);
	if(ea->ecm_time < 1) { ea->ecm_time = 1; }  //set ecm_time 1 if answer immediately
	ea->rcEx = rcEx;
	if(cw) { memcpy(ea->cw, cw, 16); }
	if(msglog) { memcpy(ea->msglog, msglog, MSGLOGSIZE); }

	cs_writeunlock(&ea->ecmanswer_lock);

	struct timeb tpe;
	cs_ftime(&tpe);
	int32_t ntime = comp_timeb(&tpe, &er->tps);
	if(ntime < 1) { ntime = 1; }
	cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_answer] reader %s rc %d, ecm time %d ms (%d ms)", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, reader ? reader->label : "-", rc, ea->ecm_time, ntime);

	//send ea for ecm request
	int32_t res = 0;
	struct s_client *cl = er->client;
	if(check_client(cl))
	{
		res = 1;
		add_job(er->client, ACTION_ECM_ANSWER_READER, ea, 0); //chk_dcw
	}

	//distribute ea for pendings
	if(ea->pending)  //has pending ea
		{ distribute_ea(ea); }


	if(!ea->is_pending)   //not for pending ea - only once for ea
	{
		//cache update
		if(ea && ea->rc < E_NOTFOUND && ea->cw)
			add_cache_from_reader(er, reader, er->csp_hash, er->ecmd5, ea->cw, er->caid, er->prid, er->srvid );

		//readers stats for LB
		send_reader_stat(reader, er, ea, ea->rc);

		//reader checks
		char ecmd5[17 * 3];
		cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
		rdr_log_dbg(reader, D_TRACE, "ecm answer for ecm hash %s rc=%d", ecmd5, ea->rc);

		//Update reader stats:
		if(ea->rc == E_FOUND)
		{
			if(cfg.cwlogdir != NULL)
				{ logCWtoFile(er, ea->cw); } /* CWL logging only if cwlogdir is set in config */

			reader->ecmsok++;
#ifdef CS_CACHEEX
			struct s_client *eacl = reader->client;
			if(cacheex_reader(reader) && check_client(eacl))
			{
				eacl->cwcacheexgot++;
				cacheex_add_stats(eacl, ea->er->caid, ea->er->srvid, ea->er->prid, 1);
				first_client->cwcacheexgot++;
			}
#endif
		}
		else if(ea->rc == E_NOTFOUND)
		{
			reader->ecmsnok++;
			if(reader->ecmnotfoundlimit && reader->ecmsnok >= reader->ecmnotfoundlimit)
			{
				rdr_log(reader, "ECM not found limit reached %u. Restarting the reader.",
						reader->ecmsnok);
				reader->ecmsnok = 0; // Reset the variable
				reader->ecmshealthnok = 0; // Reset the variable
				add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
			}
		}

		//Reader ECMs Health Try (by Pickser)
		if(reader->ecmsok != 0 || reader->ecmsnok != 0)
		{
			reader->ecmshealthok = ((double) reader->ecmsok / (reader->ecmsok + reader->ecmsnok)) * 100;
			reader->ecmshealthnok = ((double) reader->ecmsnok / (reader->ecmsok + reader->ecmsnok)) * 100;
		}

		if(rc == E_FOUND && reader->resetcycle > 0)
		{
			reader->resetcounter++;
			if(reader->resetcounter > reader->resetcycle)
			{
				reader->resetcounter = 0;
				rdr_log(reader, "Resetting reader, resetcyle of %d ecms reached", reader->resetcycle);
				reader->card_status = CARD_NEED_INIT;
				cardreader_reset(cl);
			}
		}
	}

	return res;
}

static void guess_cardsystem(ECM_REQUEST *er)
{
	uint16_t last_hope = 0;

	// viaccess - check by provid-search
	if((er->prid = chk_provid(er->ecm, 0x500)))
		{ er->caid = 0x500; }

	// nagra
	// is ecm[1] always 0x30 ?
	// is ecm[3] always 0x07 ?
	if((er->ecm[6] == 1) && (er->ecm[4] == er->ecm[2] - 2))
		{ er->caid = 0x1801; }

	// seca2 - very poor
	if((er->ecm[8] == 0x10) && ((er->ecm[9] & 0xF1) == 1))
		{ last_hope = 0x100; }

	// is cryptoworks, but which caid ?
	if((er->ecm[3] == 0x81) && (er->ecm[4] == 0xFF) &&
			(!er->ecm[5]) && (!er->ecm[6]) && (er->ecm[7] == er->ecm[2] - 5))
	{
		last_hope = 0xd00;
	}

	if(!er->caid && er->ecm[2] == 0x31 && er->ecm[0x0b] == 0x28)
		{ guess_irdeto(er); }

	if(!er->caid)  // guess by len ..
		{ er->caid = len4caid[er->ecm[2] + 3]; }

	if(!er->caid)
		{ er->caid = last_hope; }
}

//chid calculation from module stat to here
//to improve the quickfix concerning ecm chid info and extend it to all client requests wereby the chid is known in module stat

uint32_t get_subid(ECM_REQUEST *er)
{
	if(!er->ecmlen)
		{ return 0; }

	uint32_t id = 0;
	switch(er->caid >> 8)
	{
	case 0x01:
		id = b2i(2, er->ecm + 7);
		break; // seca
	case 0x05:
		id = b2i(2, er->ecm + 8);
		break; // viaccess
	case 0x06:
		id = b2i(2, er->ecm + 6);
		break; // irdeto
	case 0x09:
		id = b2i(2, er->ecm + 11);
		break; // videoguard
	case 0x4A: // DRE-Crypt, Bulcrypt, Tongfang and others?
		if(!(er->caid == 0x4AEE))  // Bulcrypt excluded for now
			{ id = b2i(2, er->ecm + 6); }
		break;
	}
	return id;
}


static void set_readers_counter(ECM_REQUEST *er)
{
	struct s_ecm_answer *ea;

	er->reader_count = 0;
	er->fallback_reader_count = 0;
	er->localreader_count = 0;
	er->cacheex_reader_count = 0;

	for(ea = er->matching_rdr; ea; ea = ea->next)
	{
		if(ea->status & READER_ACTIVE)
		{
			if(!(ea->status & READER_FALLBACK))
				{ er->reader_count++; }
			else
				{ er->fallback_reader_count++; }

			if(cacheex_reader(ea->reader))
				{ er->cacheex_reader_count++; }
			else if(is_localreader(ea->reader, er))
				{  er->localreader_count++; }
		}
	}
}


void write_ecm_answer_fromcache(struct s_write_from_cache *wfc)
{
	ECM_REQUEST *er = NULL;
	ECM_REQUEST *ecm = NULL;

	er = wfc->er_new;
	ecm = wfc->er_cache;

	int8_t rc_orig = er->rc;

	er->grp |= ecm->grp;  //update group
#ifdef CS_CACHEEX
	if(ecm->from_csp) { er->csp_answered = 1; }  //update er as answered by csp (csp have no group)
#endif

	if(er->rc >= E_NOTFOUND)
	{
#ifdef CS_CACHEEX
		if(ecm->cacheex_src)      //from cacheex or csp
			{
				er->rc = E_CACHEEX;
			}
		else
#endif
			{ er->rc=E_CACHE1; }      //from normal readers

		memcpy(er->cw, ecm->cw, 16);
		er->selected_reader = ecm->selected_reader;
		er->cw_count = ecm->cw_count;

#ifdef CS_CACHEEX
		if(ecm->cacheex_src && is_valid_client(ecm->cacheex_src) && !ecm->cacheex_src->kill){ //here we should be sure cex client has not been freed!
			er->cacheex_src = ecm->cacheex_src;
			er->cwc_cycletime = ecm->cwc_cycletime;
			er->cwc_next_cw_cycle = ecm->cwc_next_cw_cycle;
		}else{
			er->cacheex_src = NULL;
	    }

		int8_t cacheex = check_client(er->client) && er->client->account ? er->client->account->cacheex.mode : 0;
		if(cacheex == 1 && check_client(er->client))
		{
			cacheex_add_stats(er->client, er->caid, er->srvid, er->prid, 0);
			er->client->cwcacheexpush++;
			if(er->client->account)
				{ er->client->account->cwcacheexpush++; }
			first_client->cwcacheexpush++;
		}
#endif

#ifdef CS_CACHEEX
		if(cfg.delay && cacheex!=1)  //No delay on cacheexchange mode 1 client!
			{ cs_sleepms(cfg.delay); }
#else
		if(cfg.delay)
			{ cs_sleepms(cfg.delay); }
#endif

		if(rc_orig == E_UNHANDLED)
		{
			cs_log_dbg(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_answer_fromcache] found cw in CACHE (count %d)!", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, er->cw_count);
			send_dcw(er->client, er);
		}
	}
}

void get_cw(struct s_client *client, ECM_REQUEST *er)
{
	cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] NEW REQUEST!", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid);
	increment_n_request(client);

	int32_t i, j, m;
	time_t now = time((time_t *)0);
	uint32_t line = 0;

	er->client = client;
	er->rc = E_UNHANDLED; // set default rc status to unhandled
	er->cwc_next_cw_cycle = 2; //set it to: we dont know
	if(now - client->lastecm > cfg.hideclient_to) { client->lastswitch = 0; }       // user was on freetv or didn't request for some time so we reset lastswitch to get correct stats/webif display
	client->lastecm = now;

	if(client == first_client || !client ->account || client->account == first_client->account)
	{
		//DVBApi+serial is allowed to request anonymous accounts:
		int16_t listenertype = get_module(client)->listenertype;
		if(listenertype != LIS_DVBAPI && listenertype != LIS_SERIAL)
		{
			er->rc = E_INVALID;
			er->rcEx = E2_GLOBAL;
			snprintf(er->msglog, sizeof(er->msglog), "invalid user account %s", username(client));
		}
	}

	if(er->ecmlen > MAX_ECM_SIZE)
	{
		er->rc = E_INVALID;
		er->rcEx = E2_GLOBAL;
		snprintf(er->msglog, sizeof(er->msglog), "ECM size %d > Max Ecm size %d, ignored! client %s", er->ecmlen, MAX_ECM_SIZE, username(client));
	}

	if(!client->grp)
	{
		er->rc = E_INVALID;
		er->rcEx = E2_GROUP;
		snprintf(er->msglog, sizeof(er->msglog), "invalid user group %s", username(client));
	}


	if(!er->caid)
		{ guess_cardsystem(er); }

	/* Quickfix Area */

	// add chid for all client requests as in module stat
	update_chid(er);

	// quickfix for 0100:000065
	if(er->caid == 0x100 && er->prid == 0x65 && er->srvid == 0)
		{ er->srvid = 0x0642; }

	// Quickfixes for Opticum/Globo HD9500
	// Quickfix for 0500:030300
	if(er->caid == 0x500 && er->prid == 0x030300)
		{ er->prid = 0x030600; }

	// Quickfix for 0500:D20200
	if(er->caid == 0x500 && er->prid == 0xD20200)
		{ er->prid = 0x030600; }

	//betacrypt ecm with nagra header
	if(chk_is_betatunnel_caid(er->caid) == 1 && (er->ecmlen == 0x89 || er->ecmlen == 0x4A) && er->ecm[3] == 0x07 && (er->ecm[4] == 0x84 || er->ecm[4] == 0x45))
	{
		if(er->caid == 0x1702)
		{
			er->caid = 0x1833;
		}
		else
		{
			check_lb_auto_betatunnel_mode(er);
		}
		cs_log_dbg(D_TRACE, "Quickfix remap beta->nagra: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[3], er->ecm[4]);
	}

	//nagra ecm with betacrypt header 1801, 1833, 1834, 1835
	if(chk_is_betatunnel_caid(er->caid) == 2 && (er->ecmlen == 0x93 || er->ecmlen == 0x54) && er->ecm[13] == 0x07 && (er->ecm[14] == 0x84 || er->ecm[14] == 0x45))
	{
		if(er->caid == 0x1833)
		{
			er->caid = 0x1702;
		}
		else
		{
			er->caid = 0x1722;
		}
		cs_log_dbg(D_TRACE, "Quickfix remap nagra->beta: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[13], er->ecm[44]);
	}

	//Ariva quickfix (invalid nagra provider)
	if(((er->caid & 0xFF00) == 0x1800) && er->prid > 0x00FFFF)
		{ er->prid = 0; }

	//Check for invalid provider, extract provider out of ecm:
	uint32_t prid = chk_provid(er->ecm, er->caid);
	if(!er->prid)
	{
		er->prid = prid;
	}
	else
	{
		if(prid && prid != er->prid)
		{
			cs_log_dbg(D_TRACE, "provider fixed: %04X:%06X to %04X:%06X", er->caid, er->prid, er->caid, prid);
			er->prid = prid;
		}
	}

#ifdef MODULE_NEWCAMD
	// Set providerid for newcamd clients if none is given
	if(!er->prid && client->ncd_server)
	{
		int32_t pi = client->port_idx;
		if(pi >= 0 && cfg.ncd_ptab.nports && cfg.ncd_ptab.nports >= pi && cfg.ncd_ptab.ports[pi].ncd)
			{ er->prid = cfg.ncd_ptab.ports[pi].ncd->ncd_ftab.filts[0].prids[0]; }
	}
#endif

	// CAID not supported or found
	if(!er->caid)
	{
		er->rc = E_INVALID;
		er->rcEx = E2_CAID;
		snprintf(er->msglog, MSGLOGSIZE, "CAID not supported or found");
	}

	// user expired
	if(client->expirationdate && client->expirationdate < client->lastecm)
		{ er->rc = E_EXPDATE; }

	// out of timeframe
	if(client->allowedtimeframe[0] && client->allowedtimeframe[1])
	{
		struct tm acttm;
		localtime_r(&now, &acttm);
		int32_t curtime = (acttm.tm_hour * 60) + acttm.tm_min;
		int32_t mintime = client->allowedtimeframe[0];
		int32_t maxtime = client->allowedtimeframe[1];
		if(!((mintime <= maxtime && curtime > mintime && curtime < maxtime) || (mintime > maxtime && (curtime > mintime || curtime < maxtime))))
		{
			er->rc = E_EXPDATE;
		}
		cs_log_dbg(D_TRACE, "Check Timeframe - result: %d, start: %d, current: %d, end: %d\n", er->rc, mintime, curtime, maxtime);
	}

	// user disabled
	if(client->disabled != 0)
	{
		if(client->failban & BAN_DISABLED)
		{
			cs_add_violation(client, client->account->usr);
			cs_disconnect_client(client);
		}
		er->rc = E_DISABLED;
	}

	if(!chk_global_whitelist(er, &line))
	{
		debug_ecm(D_TRACE, "whitelist filtered: %s (%s) line %d", username(client), buf, line);
		er->rc = E_INVALID;
	}

#ifdef CS_CACHEEX
	if(client->account && client->account->cacheex.mode==2 && !client->account->cacheex.allow_request)
	{
		er->rc = E_INVALID;
		snprintf(er->msglog, MSGLOGSIZE, "invalid request form cacheex-2 client");
	}
#endif


	// rc<100 -> ecm error
	if(er->rc >= E_UNHANDLED)
	{
		m = er->caid;
		i = er->srvid;

		if(i != client->last_srvid || !client->lastswitch)
		{
			if(cfg.usrfileflag)
				{ cs_statistics(client); }
			client->lastswitch = now;
		}

		// user sleeping
		if(client->tosleep && (now - client->lastswitch > client->tosleep))
		{
			if(client->failban & BAN_SLEEPING)
			{
				cs_add_violation(client, client->account->usr);
				cs_disconnect_client(client);
			}
			if(client->c35_sleepsend != 0)
			{
				er->rc = E_STOPPED; // send sleep command CMD08 {00 255}
			}
			else
			{
				er->rc = E_SLEEPING;
			}
		}

		client->last_srvid = i;
		client->last_caid = m;

		int32_t ecm_len = (((er->ecm[1] & 0x0F) << 8) | er->ecm[2]) + 3;

		for(j = 0; (j < 6) && (er->rc >= E_UNHANDLED); j++)
		{
			switch(j)
			{
			case 0:
				// fake (uniq)
				if(client->dup)
					{ er->rc = E_FAKE; }
				break;
			case 1:
				// invalid (caid)
				if(!chk_bcaid(er, &client->ctab))
				{
					er->rc = E_INVALID;
					er->rcEx = E2_CAID;
					snprintf(er->msglog, MSGLOGSIZE, "invalid caid 0x%04X", er->caid);
				}
				break;
			case 2:
				// invalid (srvid)
				// matching srvids (or 0000) specified in betatunnel will bypass this filter
				if(!chk_srvid(client, er))
				{
					if(!chk_on_btun(SRVID_ZERO, client, er))
					{
						er->rc = E_INVALID;
						snprintf(er->msglog, MSGLOGSIZE, "invalid SID");
					}
				}
				break;
			case 3:
				// invalid (ufilters)
				if(!chk_ufilters(er))
					{ er->rc = E_INVALID; }
				break;
			case 4:
				// invalid (sfilter)
				if(!chk_sfilter(er, &get_module(client)->ptab))
					{ er->rc = E_INVALID; }
				break;
			case 5:
				// corrupt
				if((i = er->ecmlen - ecm_len))
				{
					if(i > 0)
					{
						cs_log_dbg(D_TRACE, "warning: ecm size adjusted from %d to %d", er->ecmlen, ecm_len);
						er->ecmlen = ecm_len;
					}
					else
						{ er->rc = E_CORRUPT; }
				}
				break;
			}
		}
	}

	//checks for odd/even byte 
	if(er->caid>>8 != 0x26 && er->caid != 0xFFFF && get_odd_even(er)==0){
		cs_log_dbg(D_TRACE, "warning: ecm with null odd/even byte from %s", (check_client(er->client)?er->client->account->usr:"-"));
		er->rc = E_INVALID;
	}

	//not continue, send rc to client
	if(er->rc < E_UNHANDLED)
	{
		send_dcw(client, er);
		free_ecm(er);
		return;
	}


#ifdef CS_CACHEEX
	int8_t cacheex = client->account ? client->account->cacheex.mode : 0;
	er->from_cacheex1_client = 0;
	if(cacheex == 1) {er->from_cacheex1_client = 1;}
#endif


	//set preferlocalcards for this ecm request (actually, paramter is per user based, maybe in fiture it will be caid based too)
	er->preferlocalcards = cfg.preferlocalcards;
	if(client->account && client->account->preferlocalcards > -1){
		er->preferlocalcards = client->account->preferlocalcards;
	}
	if(er->preferlocalcards <0 || er->preferlocalcards >2) {er->preferlocalcards=0;}


	if(chk_is_betatunnel_caid(er->caid) && client->ttab.n)
	{
		cs_log_dump_dbg(D_TRACE, er->ecm, 13, "betatunnel? ecmlen=%d", er->ecmlen);
		cs_betatunnel(er);
	}


	// ignore ecm ...
	int32_t offset = 3;
	// ... and betacrypt header for cache md5 calculation
	if((er->caid >> 8) == 0x17)
		{ offset = 13; }
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	// store ECM in cache
	memcpy(er->ecmd5, MD5(er->ecm + offset, er->ecmlen - offset, md5tmp), CS_ECMSTORESIZE);
	cacheex_update_hash(er);
	ac_chk(client, er, 0);


	//********  CHECK IF FOUND ECM IN CACHE
	struct ecm_request_t *ecm = NULL;
	ecm = check_cache(er, client);
	if(ecm)     //found in cache
	{
		cs_log_dbg(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] cw found immediately in cache! ", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid);

		struct s_write_from_cache *wfc = NULL;
		if(!cs_malloc(&wfc, sizeof(struct s_write_from_cache)))
		{
			NULLFREE(ecm);
			free_ecm(er);
			return;
		}

		wfc->er_new = er;
		wfc->er_cache = ecm;
		write_ecm_answer_fromcache(wfc);
		NULLFREE(wfc);
		NULLFREE(ecm);
	  	free_ecm(er);

		return;
	}


// zaplist ACoSC
#ifdef CS_ANTICASC
	if(cfg.acosc_enabled)
	{
		cs_writelock(&clientlist_lock);
		insert_zaplist(er, client);
		cs_writeunlock(&clientlist_lock);
	}
#endif


	er->reader_avail = 0;
	er->readers = 0;

	struct s_ecm_answer *ea, *prv = NULL;
	struct s_reader *rdr;

	cs_readlock(&readerlist_lock);
	cs_readlock(&clientlist_lock);

	for(rdr = first_active_reader; rdr; rdr = rdr->next)
	{
		uint8_t is_fallback = chk_is_fixed_fallback(rdr, er);
		int8_t match = matching_reader(er, rdr);

		if(!match) // if this reader does not match, check betatunnel for it
			match = lb_check_auto_betatunnel(er, rdr);

		if(match)
		{
			er->reader_avail++;

#ifdef CS_CACHEEX
			if(cacheex == 1 && !cacheex_reader(rdr))  //ex1-cl only ask ex1-rdr
				{ continue; }
#endif

			if(!cs_malloc(&ea, sizeof(struct s_ecm_answer)))
				{ goto OUT; }

			er->readers++;

			ea->reader = rdr;
			ea->er = er;
			ea->rc = E_UNHANDLED;
			if(prv)
				{ prv->next = ea; }
			else
				{ er->matching_rdr = ea; }
			prv = ea;

			ea->status = READER_ACTIVE;
			if(cacheex_reader(rdr))
				{ ea->status |= READER_CACHEEX; }
			else if(is_localreader(rdr, er))
				{ ea->status |= READER_LOCAL; }

			if(is_fallback && (!is_localreader(rdr, er) || (is_localreader(rdr, er) && !er->preferlocalcards)))
				{ ea->status |= READER_FALLBACK; }

			ea->pending = NULL;
			ea->is_pending = false;
			cs_lock_create(&ea->ecmanswer_lock, "ecmanswer_lock", 5000);
		}
	}

OUT:
	cs_readunlock(&clientlist_lock);
	cs_readunlock(&readerlist_lock);

	lb_set_best_reader(er);

	//set reader_count and fallback_reader_count
	set_readers_counter(er);

	//if preferlocalcards>0, check if we have local readers selected: if not, switch to preferlocalcards=0 for this ecm
	if(er->preferlocalcards>0){
		if(er->localreader_count == 0){
			er->preferlocalcards=0;
			cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} NO local readers, set preferlocalcards = %d", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, er->preferlocalcards);
		}
	}


#ifdef CS_CACHEEX
	//WAIT_TIME
	uint32_t cacheex_wait_time = 0;
	uint32_t wait_time_no_hitcache = 0;
	uint32_t wait_time_hitcache = 0;

	if(client->account && !client->account->no_wait_time && er->preferlocalcards<2)
	{
		wait_time_no_hitcache = get_cacheex_wait_time(er,NULL);   //NO check hitcache. Wait_time is dwtime, or, if 0, awtime.
		wait_time_hitcache = get_cacheex_wait_time(er,client);  //check hitcache for calculating wait_time! If hitcache wait_time is biggest value between dwtime and awtime, else it's awtime.

		if(
			//If "normal" client and ex1-rdr>0, we cannot use hitcache for calculating wait_time because we cannot know if cw is available or not on ex1 server!
			(cacheex != 1 && er->cacheex_reader_count)
			||
				/* Cw for ex1-cl comes from: INT. cache by "normal" readers (normal clients that ask normal readers), ex1-rdr and ex2-rdr and ex3-rdr.
			 * If readers, we have to wait cws generating by normal clients asking normal readers and answers by ex1-rdr (cannot use hitcache).
			 * If no readers, use hitcache for calculating wait_time.
			 */
			(cacheex == 1 && er->reader_avail)
		)
			{ cacheex_wait_time = wait_time_no_hitcache; }
		else
			{ cacheex_wait_time = wait_time_hitcache; }
	}

	cs_log_dbg(D_TRACE | D_CACHEEX, "[GET_CW] wait_time %d caid %04X prov %06X srvid %04X rc %d cacheex cl mode %d ex1rdr %d", cacheex_wait_time, er->caid, er->prid, er->srvid, er->rc, cacheex, er->cacheex_reader_count);
	cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] wait_time %d - client cacheex mode %d, reader avail for ecm %d, hitcache %d, preferlocalcards %d", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, cacheex_wait_time, cacheex == 1 ? 1 : 0, er->reader_avail, wait_time_hitcache ? 1 : 0, er->preferlocalcards);
	//END WAIT_TIME calculation

	if(!cacheex_wait_time && (er->reader_count + er->fallback_reader_count) == 0)
#else
	if((er->reader_count + er->fallback_reader_count) == 0)
#endif
	{
		er->rc = E_NOTFOUND;
		if(!er->rcEx)
			{ er->rcEx = E2_GROUP; }
		snprintf(er->msglog, MSGLOGSIZE, "no matching reader");
		cs_log_dbg(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] NO Readers and NO wait_time... not_found! ", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid);
		send_dcw(client, er);
		free_ecm(er);
		return;
	}


	//insert it in ecmcwcache!
	cs_writelock(&ecmcache_lock);
	er->next = ecmcwcache;
	ecmcwcache = er;
	ecmcwcache_size++;
	cs_writeunlock(&ecmcache_lock);


	er->rcEx = 0;
#ifdef CS_CACHEEX
	er->cacheex_wait_time = 0;
	er->cacheex_wait_time_expired = 1;
	er->cacheex_hitcache = 0;
	er->cacheex_mode1_delay = 0;

	if(cacheex_wait_time)      //wait time for cacheex
	{
		er->cacheex_wait_time = cacheex_wait_time;
		er->cacheex_wait_time_expired = 0;
		er->cacheex_hitcache = wait_time_hitcache ? 1 : 0; //usefull only when cacheex mode 1 readers answers before wait_time and we have to decide if we have to wait until wait_time expires.
		er->cacheex_mode1_delay = get_cacheex_mode1_delay(er);

		if(!er->cacheex_mode1_delay && er->cacheex_reader_count > 0)
		{
			request_cw_from_readers(er, 1); // setting stop_stage=1, we request only cacheex mode 1 readers. Others are requested at cacheex timeout!
		}
	}
	else
#endif
		request_cw_from_readers(er, 0);


#ifdef WITH_DEBUG
	if(D_CLIENTECM & cs_dblevel)
	{
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_log_dump_dbg(D_CLIENTECM, er->ecm, er->ecmlen, "Client %s ECM dump %s", username(client), buf);
	}
#endif

	cw_process_thread_wakeup();
}


int32_t ecmfmt(uint16_t caid, uint16_t onid, uint32_t prid, uint16_t chid, uint16_t pid, uint16_t srvid, uint16_t l, char *ecmd5hex, char *csphash, char *cw, char *result, size_t size, uint16_t origin_peer, uint8_t distance)
{
	if(!cfg.ecmfmt)
		{ return snprintf(result, size, "%04X&%06X/%04X/%04X/%02X:%s", caid, prid, chid, srvid, l, ecmd5hex); }

	uint32_t s = 0, zero = 0, flen = 0, value = 0;
	char *c = cfg.ecmfmt, fmt[5] = "%04X";
	while(*c)
	{
		switch(*c)
		{
		case '0':
			zero = 1;
			value = 0;
			break;
		case 'c':
			flen = 4;
			value = caid;
			break;
		case 'o':
			flen = 4;
			value = onid;
			break;
		case 'p':
			flen = 6;
			value = prid;
			break;
		case 'i':
			flen = 4;
			value = chid;
			break;
		case 'd':
			flen = 4;
			value = pid;
			break;
		case 's':
			flen = 4;
			value = srvid;
			break;
		case 'l':
			flen = 2;
			value = l;
			break;
		case 'h':
			flen = CS_ECMSTORESIZE;
			break;
		case 'e':
			flen = 5;
			break;
		case 'w':
			flen = 17;
			break;
		case 'j':
			flen = 2;
			value = distance;
			break;
		case 'g':
			flen = 4;
			value = origin_peer;
			break;
		case '\\':
			c++;
			flen = 0;
			value = *c;
			break;
		default:
			flen = 0;
			value = *c;
			break;
		}
		if(value)
			{ zero = 0; }

		if(!zero)
		{
			//fmt[0] = '%';
			if(flen)    //Build %04X / %06X / %02X
			{
				fmt[1] = '0';
				fmt[2] = flen + '0';
				fmt[3] = 'X';
				fmt[4] = 0;
			}
			else
			{
				fmt[1] = 'c';
				fmt[2] = 0;
			}
			if(flen == CS_ECMSTORESIZE) { s += snprintf(result + s, size - s , "%s", ecmd5hex); }
			else if(flen == 5)          { s += snprintf(result + s, size - s , "%s", csphash); }
			else if(flen == 17)         { s += snprintf(result + s, size - s , "%s", cw); }
			else                         { s += snprintf(result + s, size - s, fmt, value); }
		}
		c++;
	}
	return s;
}

uint8_t checkCWpart(uchar *cw, int8_t part)
{
	uint8_t eo = part ? 8 : 0;
	int8_t i;
	for(i = 0; i < 8; i++)
		if(cw[i + eo]) { return 1; }
	return 0;
}

int32_t format_ecm(ECM_REQUEST *ecm, char *result, size_t size)
{
	char ecmd5hex[17 * 3];
	char csphash[5 * 3] = { 0 };
	char cwhex[17 * 3];
	cs_hexdump(0, ecm->ecmd5, 16, ecmd5hex, sizeof(ecmd5hex));
#ifdef CS_CACHEEX
	cs_hexdump(0, (void *)&ecm->csp_hash, 4, csphash, sizeof(csphash));
#endif
	cs_hexdump(0, ecm->cw, 16, cwhex, sizeof(cwhex));
#ifdef MODULE_GBOX
	struct gbox_ecm_request_ext *ere = ecm->src_data;
	if(ere && check_client(ecm->client) && get_module(ecm->client)->num == R_GBOX && ere->gbox_hops)
		{ return ecmfmt(ecm->caid, ecm->onid, ecm->prid, ecm->chid, ecm->pid, ecm->srvid, ecm->ecmlen, ecmd5hex, csphash, cwhex, result, size, ere->gbox_peer, ere->gbox_hops); }
	else if (ecm->selected_reader && ecm->selected_reader->typ == R_GBOX && ecm->gbox_ecm_id)
		{ return ecmfmt(ecm->caid, ecm->onid, ecm->prid, ecm->chid, ecm->pid, ecm->srvid, ecm->ecmlen, ecmd5hex, csphash, cwhex, result, size, ecm->gbox_ecm_id, 0); }
	else
#endif
		return ecmfmt(ecm->caid, ecm->onid, ecm->prid, ecm->chid, ecm->pid, ecm->srvid, ecm->ecmlen, ecmd5hex, csphash, cwhex, result, size, 0, 0);
}

