#define MODULE_LOG_PREFIX "cache"

#include "globals.h"
#include "module-cacheex.h"
#include "module-cw-cycle-check.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-hashtable.h"


// CACHE functions **************************************************************+
struct s_pushclient {
	struct s_client *cl;
	struct s_pushclient	*next_push;
};

typedef struct cw_t {
	uchar			cw[16];
	uint8_t			odd_even;			//odd/even byte (0x80 0x81)
	uint8_t			cwc_cycletime;
	uint8_t			cwc_next_cw_cycle;
	uint8_t			got_bad_cwc;		//used by cycle check
	uint16_t		caid;				//first caid received
	uint32_t		prid;				//first prid received
	uint16_t		srvid;				//first srvid received
	struct s_reader	*selected_reader;   //first answering: reader
	struct s_client *cacheex_src;  		//first answering: cacheex client

	uint64_t		grp;				//updated grp
	uint8_t			csp; 				//updated if answer from csp
	uint8_t			cacheex; 			//updated if answer from cacheex
	uint8_t			localcards;			//updated if answer from local cards (or proxy using localcards option)
	uint8_t			proxy;				//updated if answer from local reader

	uint32_t 		count;				//count of same cws receved

	//for push out
	pthread_rwlock_t    pushout_client_lock;
	struct s_pushclient *pushout_client;	//list of clients that pushing cw
	//end push out

	node		    ht_node;  //node for hash table
	node		    ll_node;  //node for linked list
} CW;

typedef struct cache_t {
	hash_table 		ht_cw;
	list 			ll_cw;
	struct timeb	upd_time; //updated time. Update time at each cw got
	struct timeb	first_recv_time;  //time of first cw received
	int32_t			csp_hash;

	node		    ht_node;  //node for hash table
	node		    ll_node;  //node for linked list
} ECMHASH;


pthread_rwlock_t cache_lock;
hash_table ht_cache;
list ll_cache;

void init_cache(void){
	init_hash_table(&ht_cache, &ll_cache);
	if (pthread_rwlock_init(&cache_lock,NULL) != 0)
		cs_log("Error creating lock cache_lock!");
}

uint32_t cache_size(void){
	return count_hash_table(&ht_cache);
}

uint8_t count_sort(CW *a, CW *b){
	if (a->count == b->count) return 0;
	return (a->count > b->count) ? -1 : 1; 	//DESC order by count
}

uint8_t check_is_pushed(CW *cw, struct s_client *cl){

	struct s_pushclient *cl_tmp;
	bool pushed=false;

	pthread_rwlock_rdlock(&cw->pushout_client_lock);
	for (cl_tmp = cw->pushout_client; cl_tmp; cl_tmp = cl_tmp->next_push) {
		if(cl_tmp->cl==cl){
			pushed=true;
			break;
		}
	}

	if(!pushed){
		pthread_rwlock_unlock(&cw->pushout_client_lock);
		pthread_rwlock_wrlock(&cw->pushout_client_lock);

		struct s_pushclient *new_push_client;
		if(cs_malloc(&new_push_client, sizeof(struct s_pushclient))){
			new_push_client->cl=cl;

			new_push_client->next_push=cw->pushout_client;
			cw->pushout_client=new_push_client;
		}

		pthread_rwlock_unlock(&cw->pushout_client_lock);
		return 0;
	}else{
		pthread_rwlock_unlock(&cw->pushout_client_lock);
		return 1;
	}
}

uint8_t get_odd_even(ECM_REQUEST *er){
	return (er->ecm[0] != 0x80 && er->ecm[0] != 0x81 ? 0 : er->ecm[0]);
}


CW *get_first_cw(ECMHASH *ecmhash, ECM_REQUEST *er){
	if(!ecmhash) return NULL;

	node *j;
	CW *cw;

	j = get_first_node_list(&ecmhash->ll_cw);
	while (j) {
		cw = get_data_from_node(j);

		if(cw && cw->odd_even == get_odd_even(er) && !cw->got_bad_cwc)
			return cw;

		j = j->next;
	}

	return NULL;
}

int compare_csp_hash(const void *arg, const void *obj){
	int32_t h = ((const ECMHASH*)obj)->csp_hash;
	return memcmp(arg, &h, 4);
}

int compare_cw(const void *arg, const void *obj){
	return memcmp(arg, ((const CW*)obj)->cw, 16);
}


/*
 * This function returns cw (mostly received) in cache for er, or NULL if not found.
 * IMPORTANT:
 * 		- If found, DON'T forget to free returned ecm, because it is a copy useful to get data
 * 		- If found, and cacheex_src client of returned ecm is not NULL, and we want to access it,
 *        remember to check for its validity (client structure is still existent)
 *        E.g.: if(ecm->cacheex_src && is_valid_client(ecm->cacheex_src) && !ecm->cacheex_src->kill)
 *        We don't want make this stuff here to avoid useless cpu time if outside function we would not access to it.
 */
struct ecm_request_t *check_cache(ECM_REQUEST *er, struct s_client *cl)
{
	if(!er->csp_hash) return NULL;

	ECM_REQUEST *ecm = NULL;
	ECMHASH *result;
	CW *cw;
	uint64_t grp = cl?cl->grp:0;

	pthread_rwlock_rdlock(&cache_lock);

	result = find_hash_table(&ht_cache, &er->csp_hash, sizeof(int32_t),&compare_csp_hash);
	cw = get_first_cw(result, er);

	if(
		cw
		&&
	    (
			cw->csp    //csp have no grp!
			||
			!grp		   			     //csp client(no grp) searching for cache
			||
			(
			  grp
			  &&
			  cw->grp  //ecm group --> only when readers/ex-clients answer (e_found) it
			  && (grp & cw->grp)
			)
		 )
	){


#ifdef CS_CACHEEX

		//if preferlocalcards=2 for this ecm request, we can server ONLY cw from localcards readers until stage<3
		if(er->preferlocalcards==2 && !cw->localcards && er->stage<3){
		    pthread_rwlock_unlock(&cache_lock);
		    return NULL;
		}

		CWCHECK check_cw = get_cwcheck(er);
		if((!cw->proxy && !cw->localcards)  //cw received from ONLY cacheex/csp peers
		   && check_cw.counter>1
		   && cw->count < check_cw.counter
		   && (check_cw.mode || !er->cacheex_wait_time_expired)
		){
		    pthread_rwlock_unlock(&cache_lock);
		    return NULL;
		}
#endif


#ifdef CW_CYCLE_CHECK
		uint8_t cwc_ct = cw->cwc_cycletime > 0 ? cw->cwc_cycletime : 0;
		uint8_t cwc_ncwc = cw->cwc_next_cw_cycle < 2 ? cw->cwc_next_cw_cycle : 2;
		if(cw->got_bad_cwc)
		{
			pthread_rwlock_unlock(&cache_lock);
			return NULL;
		}
		if(checkcwcycle(cl, er, NULL, cw->cw, 0, cwc_ct, cwc_ncwc) != 0){
			cs_log_dbg(D_CWC | D_LB, "{client %s, caid %04X, srvid %04X} [check_cache] cyclecheck passed ecm in INT. cache, ecm->rc %d", (cl ? cl->account->usr : "-"), er->caid, er->srvid, ecm ? ecm->rc : -1);
		}else{
			cs_log_dbg(D_CWC, "cyclecheck [BAD CW Cycle] from Int. Cache detected.. {client %s, caid %04X, srvid %04X} [check_cache] -> skip cache answer", (cl ? cl->account->usr : "-"), er->caid, er->srvid);
			cw->got_bad_cwc = 1; // no need to check it again
			pthread_rwlock_unlock(&cache_lock);
			return NULL;
		}
#endif

		if (cs_malloc(&ecm, sizeof(ECM_REQUEST))){
			ecm->rc = E_FOUND;
			ecm->rcEx = 0;
			memcpy(ecm->cw, cw->cw, 16);
			ecm->grp = cw->grp;
			ecm->selected_reader = cw->selected_reader;
			ecm->cwc_cycletime = cw->cwc_cycletime;
			ecm->cwc_next_cw_cycle = cw->cwc_next_cw_cycle;
			ecm->cacheex_src = cw->cacheex_src;
			ecm->cw_count = cw->count;
		}
	}

    pthread_rwlock_unlock(&cache_lock);
    return ecm;
}


void add_cache(ECM_REQUEST *er){
	if(!er->csp_hash) return;

	ECMHASH *result = NULL;
	CW *cw = NULL;
#ifdef CS_CACHEEX
	bool add_new_cw=false;
#endif

	pthread_rwlock_wrlock(&cache_lock);

	//add csp_hash to cache
	result = find_hash_table(&ht_cache, &er->csp_hash, sizeof(int32_t), &compare_csp_hash);
	if(!result){
		if(cs_malloc(&result, sizeof(ECMHASH))){
			result->csp_hash = er->csp_hash;
			init_hash_table(&result->ht_cw, &result->ll_cw);
			cs_ftime(&result->first_recv_time);

			add_hash_table(&ht_cache, &result->ht_node, &ll_cache, &result->ll_node, result, &result->csp_hash, sizeof(int32_t));

		}else{
			pthread_rwlock_unlock(&cache_lock);
			cs_log("ERROR: NO added HASH to cache!!");
			return;
		}
	}

	cs_ftime(&result->upd_time);   //need to be updated at each cw! We use it for deleting this hash when no more cws arrive inside max_cache_time!


	//add cw to this csp hash
	cw = find_hash_table(&result->ht_cw, er->cw, sizeof(er->cw), &compare_cw);

	if(!cw){

		if(count_hash_table(&result->ht_cw)>=10){  //max 10 different cws stored
			pthread_rwlock_unlock(&cache_lock);
			return;
		}

		while(1){
			if(cs_malloc(&cw, sizeof(CW))){
				memcpy(cw->cw, er->cw, sizeof(er->cw));
				cw->odd_even = get_odd_even(er);
				cw->cwc_cycletime = er->cwc_cycletime;
				cw->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
				cw->count= 0;
				cw->csp = 0;
				cw->cacheex = 0;
				cw->localcards=0;
				cw->proxy=0;
				cw->grp = 0;
				cw->caid = er->caid;
				cw->prid = er->prid;
				cw->srvid = er->srvid;
				cw->selected_reader=er->selected_reader;
				cw->cacheex_src=er->cacheex_src;
				cw->pushout_client = NULL;

				while(1){
					if (pthread_rwlock_init(&cw->pushout_client_lock, NULL) == 0)
						break;

					cs_log("Error creating lock pushout_client_lock!");
					cs_sleepms(1);
				}


				add_hash_table(&result->ht_cw, &cw->ht_node, &result->ll_cw, &cw->ll_node, cw, cw->cw, sizeof(er->cw));

	#ifdef CS_CACHEEX
				add_new_cw=true;
	#endif
				break;
			}

			cs_log("ERROR: NO added CW to cache!! Re-trying...");
			cs_sleepms(1);
		}
	}

	//update if answered from csp/cacheex/local_proxy
	if(er->from_cacheex) cw->cacheex = 1;
	if(er->from_csp) cw->csp = 1;
	if(!er->cacheex_src){
		if(is_localreader(er->selected_reader, er)) cw->localcards=1;
		else cw->proxy = 1;
	}

	//always update group and counter
	cw->grp |= er->grp;
	cw->count++;

	//sort cw_list by counter (DESC order)
	if(cw->count>1)
		sort_list(&result->ll_cw, count_sort);

	pthread_rwlock_unlock(&cache_lock);


#ifdef CS_CACHEEX

	er->cw_cache=cw;
	cacheex_cache_push(er);


	//cacheex debug log lines and cw diff stuff
	if(check_client(er->cacheex_src)){
		if(add_new_cw){
			debug_ecm(D_CACHEEX|D_CSP, "got pushed ECM %s from %s", buf, er->from_csp ? "csp" : username(er->cacheex_src));

			CW *cw_first = get_first_cw(result, er);

			if(er && cw_first){
			
			//compare er cw with mostly counted cached cw
			if(memcmp(er->cw, cw_first->cw, sizeof(er->cw)) != 0) {
				er->cacheex_src->cwcacheexerrcw++;
				if (er->cacheex_src->account)
					er->cacheex_src->account->cwcacheexerrcw++;

				if (((0x0200| 0x0800) & cs_dblevel)) { //avoid useless operations if debug is not enabled
					char cw1[16*3+2], cw2[16*3+2];
					cs_hexdump(0, er->cw, 16, cw1, sizeof(cw1));
					cs_hexdump(0, cw_first->cw, 16, cw2, sizeof(cw2));

					char ip1[20]="", ip2[20]="";
					if (check_client(er->cacheex_src))
						cs_strncpy(ip1, cs_inet_ntoa(er->cacheex_src->ip), sizeof(ip1));
					if (check_client(cw_first->cacheex_src))
						cs_strncpy(ip2, cs_inet_ntoa(cw_first->cacheex_src->ip), sizeof(ip2));
					else if (cw_first->selected_reader && check_client(cw_first->selected_reader->client))
						cs_strncpy(ip2, cs_inet_ntoa(cw_first->selected_reader->client->ip), sizeof(ip2));

					debug_ecm(D_CACHEEX| D_CSP, "WARNING: Different CWs %s from %s(%s)<>%s(%s): %s<>%s ", buf,
						er->from_csp ? "csp" : username(er->cacheex_src), ip1,
						check_client(cw_first->cacheex_src)?username(cw_first->cacheex_src):(cw_first->selected_reader?cw_first->selected_reader->label:"unknown/csp"), ip2,
						cw1, cw2);
				}
			}

		}
		}else
			debug_ecm(D_CACHEEX| D_CSP, "got duplicate pushed ECM %s from %s", buf, er->from_csp ? "csp" : username(er->cacheex_src));
	}

#endif
}

void cleanup_cache(void){
	ECMHASH *ecmhash;
	CW *cw;
	struct s_pushclient *pc, *nxt;
	node *i,*i_next,*j,*j_next;

	struct timeb now;
	int64_t gone_first, gone_upd;


	pthread_rwlock_wrlock(&cache_lock);

	i = get_first_node_list(&ll_cache);
	while (i) {
	    i_next = i->next;
	    ecmhash = get_data_from_node(i);

	    cs_ftime(&now);
	    gone_first = comp_timeb(&now, &ecmhash->first_recv_time);
	    gone_upd = comp_timeb(&now, &ecmhash->upd_time);

    	if(ecmhash && gone_first<=(cfg.max_cache_time*1000)){ //not continue, useless check for nexts one!
    		break;
    	}

    	if(ecmhash && gone_upd>(cfg.max_cache_time*1000)){

    		j = get_first_node_list(&ecmhash->ll_cw);
    		while (j) {
    			j_next = j->next;

    			cw = get_data_from_node(j);
    			if(cw){
					pthread_rwlock_destroy(&cw->pushout_client_lock);
					pc = cw->pushout_client;
					cw->pushout_client=NULL;
					while (pc) {
						nxt = pc->next_push;
						NULLFREE(pc);
						pc = nxt;
					}

					remove_elem_list(&ecmhash->ll_cw, &cw->ll_node);
					remove_elem_hash_table(&ecmhash->ht_cw, &cw->ht_node);
					NULLFREE(cw);
    			}

				j = j_next;
    		}

    		deinitialize_hash_table(&ecmhash->ht_cw);
    		remove_elem_list(&ll_cache, &ecmhash->ll_node);
    		remove_elem_hash_table(&ht_cache, &ecmhash->ht_node);
	    NULLFREE(ecmhash);
    	}

	    i = i_next;
	}

	pthread_rwlock_unlock(&cache_lock);
}
