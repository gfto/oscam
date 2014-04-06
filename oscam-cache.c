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
#ifdef CW_CYCLE_CHECK
	uint8_t			got_bad_cwc;
#endif
	uint16_t		caid;				//first caid receved
	uint32_t		prid;				//first prid receved
	uint16_t		srvid;				//first srvid receved
	struct s_reader	*selected_reader;   //first answering reader
	struct s_client *cacheex_src;  		//first answering cacheex client

	uint64_t		grp;				//updated grp
	uint8_t			csp; 				//updated if answer from csp

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


CW *get_first_cw(ECMHASH *ecmhash){
	return get_first_elem_list(&ecmhash->ll_cw);
}

int compare_csp_hash(const void *arg, const void *obj){
	return *(const int32_t*)arg != ((const ECMHASH*)obj)->csp_hash;
}

int compare_cw(const void *arg, const void *obj){
	return memcmp(arg, ((const CW*)obj)->cw, 16);
}

uint8_t get_odd_even(ECM_REQUEST *er){
	return (er->ecm[0] != 0x80 && er->ecm[0] != 0x81 ? 0 : er->ecm[0]);
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
	uint64_t grp = cl?cl->grp:0;

	pthread_rwlock_rdlock(&cache_lock);

	result = find_hash_table(&ht_cache, &er->csp_hash, sizeof(int32_t),&compare_csp_hash);
	if(
		   result
		   && get_first_cw(result)
		   &&
		   (
				get_first_cw(result)->csp    //csp have no grp!
				||
				!grp		   			     //csp client(no grp) searching for cache
				||
				(
				  grp
				  &&
				  get_first_cw(result)->grp  //ecm group --> only when readers/ex-clients answer (e_found) it
				  && (grp & get_first_cw(result)->grp)
				)
			)
	){

#ifdef CS_CACHEEX
		CWCHECK check_cw = get_cwcheck(er);

		if(get_first_cw(result)->cacheex_src
		   && check_cw.counter>1
		   && get_first_cw(result)->count < check_cw.counter
		   && (check_cw.mode || !er->cacheex_wait_time_expired)
		){
		    pthread_rwlock_unlock(&cache_lock);
		    return NULL;
		}
#endif


#ifdef CW_CYCLE_CHECK

		uint8_t cwc_ct = get_first_cw(result)->cwc_cycletime > 0 ? get_first_cw(result)->cwc_cycletime : 0;
		uint8_t cwc_ncwc = get_first_cw(result)->cwc_next_cw_cycle < 2 ? get_first_cw(result)->cwc_next_cw_cycle : 2;
		if(get_first_cw(result)->got_bad_cwc)
		{
			pthread_rwlock_unlock(&cache_lock);
			return NULL;
		}
		if(checkcwcycle(cl, er, NULL, get_first_cw(result)->cw, 0, cwc_ct, cwc_ncwc) != 0){
			cs_debug_mask(D_CWC | D_LB, "{client %s, caid %04X, srvid %04X} [check_cache] cyclecheck passed ecm in INT. cache, ecm->rc %d", (cl ? cl->account->usr : "-"), er->caid, er->srvid, ecm ? ecm->rc : -1);
		}else{
			cs_debug_mask(D_CWC, "cyclecheck [BAD CW Cycle] from Int. Cache detected.. {client %s, caid %04X, srvid %04X} [check_cache] -> skip cache answer", (cl ? cl->account->usr : "-"), er->caid, er->srvid);
			get_first_cw(result)->got_bad_cwc = 1; // no need to check it again
			pthread_rwlock_unlock(&cache_lock);
			return NULL;
		}
#endif

		if (cs_malloc(&ecm, sizeof(ECM_REQUEST))){
			ecm->rc = E_FOUND;
			ecm->rcEx = 0;

			//checks for ecm[0] odd/even byte, if we need swapp cw (all this stuff could be removed when we'll include ecm[0] to csp_hash)
			if(get_first_cw(result)->odd_even != 0 && get_odd_even(er) != get_first_cw(result)->odd_even){  //swapp it
				memcpy(ecm->cw, get_first_cw(result)->cw+8, 8);
				memcpy(ecm->cw+8, get_first_cw(result)->cw, 8);
			}else{
				memcpy(ecm->cw, get_first_cw(result)->cw, 16);
			}

			ecm->grp = get_first_cw(result)->grp;
			ecm->selected_reader = get_first_cw(result)->selected_reader;
			ecm->cwc_cycletime = get_first_cw(result)->cwc_cycletime;
			ecm->cwc_next_cw_cycle = get_first_cw(result)->cwc_next_cw_cycle;
#ifdef CS_CACHEEX
			ecm->cacheex_src = get_first_cw(result)->cacheex_src;
#endif
			ecm->cw_count = (get_first_cw(result)->count%1000) + ((int)(get_first_cw(result)->count/1000));  //set correct cw_count, removing trick from "normal" reader!
		}
	}

    pthread_rwlock_unlock(&cache_lock);
    return ecm;
}


void add_cache(ECM_REQUEST *er){
	if(!er->csp_hash) return;
	if(chk_is_null_CW(er->cw)) return;

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

	//checks for same hash but cw swapped (all this stuff could be removed when we'll include ecm[0] in csp_hash calcultaion)
	if(!cw){  //search for cw swapped
		uchar cw_swap[16];
		memcpy(cw_swap, er->cw+8, 8);
		memcpy(cw_swap+8, er->cw, 8);
		cw = find_hash_table(&result->ht_cw, cw_swap, sizeof(er->cw), &compare_cw);
		if(cw) memcpy(er->cw, cw_swap, 16); //so we have correct cw for checking cw diff
	}
	//end checks

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
				cw->grp = 0;
				cw->caid = er->caid;
				cw->prid = er->prid;
				cw->srvid = er->srvid;
				cw->selected_reader=er->selected_reader;
	#ifdef CS_CACHEEX
				cw->cacheex_src=er->cacheex_src;
	#endif
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

	//always update group and counter
	cw->grp |= er->grp;
	if(er->from_csp) cw->csp = 1;

	//if cw from normal reader, give it priority respect cacheex src, moving cw at first position!
#ifdef CS_CACHEEX
	if(er->cacheex_src)
		cw->count++;
	else
#endif
	cw->count+=1000;  //trick from "normal" reader to increase priority respect cacheex src

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

			if(er->cw && get_first_cw(result)->cw)
			
			//compare er cw with mostly counted cached cw
			if(memcmp(er->cw, get_first_cw(result)->cw, sizeof(er->cw)) != 0) {
				er->cacheex_src->cwcacheexerrcw++;
				if (er->cacheex_src->account)
					er->cacheex_src->account->cwcacheexerrcw++;

				if (((0x0200| 0x0800) & cs_dblevel)) { //avoid useless operations if debug is not enabled
					char cw1[16*3+2], cw2[16*3+2];
					cs_hexdump(0, er->cw, 16, cw1, sizeof(cw1));
					cs_hexdump(0, get_first_cw(result)->cw, 16, cw2, sizeof(cw2));

					char ip1[20]="", ip2[20]="";
					if (check_client(er->cacheex_src))
						cs_strncpy(ip1, cs_inet_ntoa(er->cacheex_src->ip), sizeof(ip1));
					if (check_client(get_first_cw(result)->cacheex_src))
						cs_strncpy(ip2, cs_inet_ntoa(get_first_cw(result)->cacheex_src->ip), sizeof(ip2));
					else if (get_first_cw(result)->selected_reader && check_client(get_first_cw(result)->selected_reader->client))
						cs_strncpy(ip2, cs_inet_ntoa(get_first_cw(result)->selected_reader->client->ip), sizeof(ip2));

					debug_ecm(D_CACHEEX| D_CSP, "WARNING: Different CWs %s from %s(%s)<>%s(%s): %s<>%s ", buf,
						er->from_csp ? "csp" : username(er->cacheex_src), ip1,
						check_client(get_first_cw(result)->cacheex_src)?username(get_first_cw(result)->cacheex_src):(get_first_cw(result)->selected_reader?get_first_cw(result)->selected_reader->label:"unknown/csp"), ip2,
						cw1, cw2);
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
	int32_t gone_first, gone_upd;


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

#ifdef CS_CACHEEX
// HIT CACHE functions **************************************************************

typedef struct hit_key_t {
	uint16_t		caid;
	uint32_t		prid;
	uint16_t		srvid;
} HIT_KEY;

typedef struct cache_hit_t {
	HIT_KEY			key;
	struct timeb	time;
	uint64_t		grp;

	node		    ht_node;
	node		    ll_node;
} CACHE_HIT;


pthread_rwlock_t hitcache_lock;
hash_table ht_hitcache;
list ll_hitcache;

void init_hitcache(void){
	init_hash_table(&ht_hitcache, &ll_hitcache);
	if (pthread_rwlock_init(&hitcache_lock,NULL) != 0)
		cs_log("Error creating lock hitcache_lock!");
}

uint32_t hitcache_size(void){
	return count_hash_table(&ht_hitcache);
}

int compare_hitkey(const void *arg, const void *obj){
	if(   ((const HIT_KEY*)arg)->caid==((const CACHE_HIT*)obj)->key.caid
		   && ((const HIT_KEY*)arg)->prid==((const CACHE_HIT*)obj)->key.prid
		   && ((const HIT_KEY*)arg)->srvid==((const CACHE_HIT*)obj)->key.srvid	)
		return 0;
	return 1;
}

int32_t check_hitcache(ECM_REQUEST *er, struct s_client *cl) {
	CACHE_HIT *result;
	HIT_KEY search;

	memset(&search, 0, sizeof(HIT_KEY));
	search.caid = er->caid;
	search.prid = er->prid;
	search.srvid = er->srvid;

	pthread_rwlock_rdlock(&hitcache_lock);
	result = find_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &compare_hitkey);
    if(result){

    	struct timeb now;
	    cs_ftime(&now);
	    int32_t gone = comp_timeb(&now, &result->time);
    	uint64_t grp = cl?cl->grp:0;

    	if(
    		gone <= (cfg.max_hitcache_time*1000)
    		&&
    		(!grp || !result->grp || (grp & result->grp))
    	){
    	    pthread_rwlock_unlock(&hitcache_lock);
    		return 1;
    	}
    }

    pthread_rwlock_unlock(&hitcache_lock);
    return 0;
}


void add_hitcache(struct s_client *cl, ECM_REQUEST *er) {
	if (!cfg.cacheex_wait_timetab.n)
		return;
	uint32_t cacheex_wait_time = get_cacheex_wait_time(er,NULL);
	if (!cacheex_wait_time)
		return;

	CACHE_HIT *result;
	HIT_KEY search;

	memset(&search, 0, sizeof(HIT_KEY));
	search.caid = er->caid;
	search.prid = er->prid;
	search.srvid = er->srvid;

	pthread_rwlock_wrlock(&hitcache_lock);

    result = find_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &compare_hitkey);
    if(!result){  //not found, add it!

    	if(cs_malloc(&result, sizeof(CACHE_HIT))){
    	    memset(result, 0, sizeof(CACHE_HIT));
    	    result->key.caid = er->caid;
    	    result->key.prid = er->prid;
    	    result->key.srvid = er->srvid;

    		add_hash_table(&ht_hitcache, &result->ht_node, &ll_hitcache, &result->ll_node, result, &result->key, sizeof(HIT_KEY));
    	}
    }

    if(result){
		if(cl) result->grp |= cl->grp;
		cs_ftime(&result->time); //always update time;
    }

    pthread_rwlock_unlock(&hitcache_lock);
}


void del_hitcache(ECM_REQUEST *er) {
	HIT_KEY search;

	memset(&search, 0, sizeof(HIT_KEY));
	search.caid = er->caid;
	search.prid = er->prid;
	search.srvid = er->srvid;

	pthread_rwlock_wrlock(&hitcache_lock);
	search_remove_elem_hash_table(&ht_hitcache, &search, sizeof(HIT_KEY), &compare_hitkey);
    pthread_rwlock_unlock(&hitcache_lock);
}


void cleanup_hitcache(void) {
	CACHE_HIT *cachehit;
	node *i,*i_next;
	struct timeb now;
	int32_t gone;

	int32_t timeout = (cfg.max_hitcache_time + (cfg.max_hitcache_time / 2))*1000;  //1,5

	pthread_rwlock_wrlock(&hitcache_lock);

	i = get_first_node_list(&ll_hitcache);
	while (i) {
	    i_next = i->next;
	    cachehit = get_data_from_node(i);

	    cs_ftime(&now);
	    gone = comp_timeb(&now, &cachehit->time);

	    if(cachehit && gone>timeout){
    		remove_elem_list(&ll_hitcache, &cachehit->ll_node);
    		remove_elem_hash_table(&ht_hitcache, &cachehit->ht_node);
	    NULLFREE(cachehit);
    	}

	    i = i_next;
	}

	pthread_rwlock_unlock(&hitcache_lock);
}
#endif


// CSP HASH functions **************************************************************
static int32_t cacheex_ecm_hash_calc(uchar *buf, int32_t n)
{
	int32_t i, h = 0;
	for(i = 0; i < n; i++)
	{
		h = 31 * h + buf[i];
	}
	return h;
}

void cacheex_update_hash(ECM_REQUEST *er)
{
	er->csp_hash = cacheex_ecm_hash_calc(er->ecm + 3, er->ecmlen - 3);
}
