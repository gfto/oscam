#include "module-stat.h"
#include "module-cccam.h"

#define UNDEF_AVG_TIME 80000
#define MAX_ECM_SEND_CACHE 16

#define LB_REOPEN_MODE_STANDARD 0
#define LB_REOPEN_MODE_FAST 1

static int stat_load_save;
static struct timeb nulltime;
static time_t last_housekeeping = 0;

void init_stat()
{
	cs_ftime(&nulltime);
	stat_load_save = -100;

	//checking config
	if (cfg.lb_nbest_readers < 2)
		cfg.lb_nbest_readers = DEFAULT_NBEST;
	if (cfg.lb_nfb_readers < 2)
		cfg.lb_nfb_readers = DEFAULT_NFB;
	if (cfg.lb_min_ecmcount < 2)
		cfg.lb_min_ecmcount = DEFAULT_MIN_ECM_COUNT;
	if (cfg.lb_max_ecmcount < 3)
		cfg.lb_max_ecmcount = DEFAULT_MAX_ECM_COUNT;
	if (cfg.lb_reopen_seconds < 10)
		cfg.lb_reopen_seconds = DEFAULT_REOPEN_SECONDS;
	if (cfg.lb_retrylimit <= 0)
		cfg.lb_retrylimit = DEFAULT_RETRYLIMIT;
	if (cfg.lb_stat_cleanup <= 0)
		cfg.lb_stat_cleanup = DEFAULT_LB_STAT_CLEANUP;
}

void load_stat_from_file()
{
	stat_load_save = 0;
	char buf[256];
	char *fname;
	FILE *file;
	if (!cfg.lb_savepath || !cfg.lb_savepath[0]) {
		snprintf(buf, sizeof(buf), "%s/stat", get_tmp_dir());
		fname = buf;
	}
	else
		fname = cfg.lb_savepath;
		
	file = fopen(fname, "r");
		
	if (!file) {
		cs_log("loadbalancer: can't read from file %s", fname);
		return;
	}
	cs_debug_mask(D_TRACE, "loadbalancer: load statistics from %s", fname);
	
	struct s_reader *rdr = NULL;
	READER_STAT *stat, *dup;
		
	int i=1;
	int count=0;
	do
	{
		stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		i = fscanf(file, "%s rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d last %ld fail %d len %02hX\n",
			buf, &stat->rc, &stat->caid, &stat->prid, &stat->srvid, 
			&stat->time_avg, &stat->ecm_count, &stat->last_received, &stat->fail_factor, &stat->ecmlen);
			
		
		if (i > 5) {
			if (rdr == NULL || strcmp(buf, rdr->label) != 0) {
				LL_ITER *itr = ll_iter_create(configured_readers);
				while ((rdr=ll_iter_next(itr))) {
					if (strcmp(rdr->label, buf) == 0) {
						break;
					}
				}
				ll_iter_release(itr);
			}
			
			if (rdr != NULL && strcmp(buf, rdr->label) == 0) {
				if (!rdr->lb_stat)
					rdr->lb_stat = ll_create();
					
				//Duplicate check:
				dup = get_stat(rdr, stat->caid, stat->prid, stat->srvid, stat->ecmlen);
				if (dup)
					free(stat); //already loaded
				else {
				
					ll_append(rdr->lb_stat, stat);
					count++;
				}
			}
			else 
			{
				cs_log("loadbalancer: statistics could not be loaded for %s", buf);
				free(stat);
			}
		}
		else if (i!=EOF && i>0)
		{
			cs_debug_mask(D_TRACE, "loadbalancer: statistics ERROR  %s rc=%d i=%d", buf, stat->rc, i);
			free(stat);
		}
		else
			free(stat);
	} while(i!=EOF && i>0);
	fclose(file);
	cs_debug_mask(D_TRACE, "loadbalancer: statistic loaded %d records", count);
}
/**
 * get statistic values for reader ridx and caid/prid/srvid/ecmlen
 */
READER_STAT *get_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid, short ecmlen)
{
	if (!rdr->lb_stat)
		rdr->lb_stat = ll_create();

	int i;
	for (i=0;i<CS_MAXCAIDTAB;i++) {
		ushort tcaid = cfg.lb_noproviderforcaid.caid[i];
		if (!tcaid) break;
		if (tcaid == caid) {
			prid = 0;
			break;
		}
	}
	
	LL_ITER *it = ll_iter_create(rdr->lb_stat);
	READER_STAT *stat = NULL;
	while ((stat = ll_iter_next(it))) {
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid) {
			if (stat->ecmlen == ecmlen)
				break;
			if (!stat->ecmlen) {
				stat->ecmlen = ecmlen;
				break;
			}
		}
	}
	ll_iter_release(it);
	return stat;
}

/**
 * removes caid/prid/srvid/ecmlen from stat-list of reader ridx
 */
int remove_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid, short ecmlen)
{
	if (!rdr->lb_stat)
		return 0;

	int c = 0;
	LL_ITER *it = ll_iter_create(rdr->lb_stat);
	READER_STAT *stat;
	while ((stat = ll_iter_next(it))) {
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid) {
			if (!stat->ecmlen || stat->ecmlen == ecmlen) {
				ll_iter_remove_data(it);
				c++;
			}
		}
	}
	ll_iter_release(it);
	return c;
}

/**
 * Calculates average time
 */
void calc_stat(READER_STAT *stat)
{
	int i;
	int c=0;
	long t = 0;
	for (i = 0; i < LB_MAX_STAT_TIME; i++) {
		if (stat->time_stat[i] > 0) {
			t += (long)stat->time_stat[i];
			c++;
		}
	}
	if (!c)
		stat->time_avg = UNDEF_AVG_TIME;
	else
		stat->time_avg = t / c;
}

/**
 * Saves statistik to /tmp/.oscam/stat.n where n is reader-index
 */
void save_stat_to_file_thread()
{
	stat_load_save = 0;
	char buf[256];
	char *fname;
	if (!cfg.lb_savepath || !cfg.lb_savepath[0]) {
		snprintf(buf, sizeof(buf), "%s/stat", get_tmp_dir());
		fname = buf;
	}
	else
		fname = cfg.lb_savepath;
		
	FILE *file = fopen(fname, "w");
	
	if (!file) {
		cs_log("can't write to file %s", fname);
		return;
	}

	int count=0;
	struct s_reader *rdr;
	LL_ITER *itr = ll_iter_create(configured_readers);
	while ((rdr=ll_iter_next(itr))) {
		
		if (rdr->lb_stat) {
			LL_ITER *it = ll_iter_create(rdr->lb_stat);
			READER_STAT *stat;
			while ((stat = ll_iter_next(it))) {
				
				fprintf(file, "%s rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d last %ld fail %d len %02hX\n",
					rdr->label, stat->rc, stat->caid, stat->prid, 
					stat->srvid, stat->time_avg, stat->ecm_count, stat->last_received, stat->fail_factor, stat->ecmlen);
				count++;
			}
			ll_iter_release(it);
		}
	}
	ll_iter_release(itr);
	
	fclose(file);
	cs_log("loadbalancer: statistic saved %d records to %s", count, fname);
}

void save_stat_to_file(int thread)
{
	stat_load_save = 0;
	if (thread)
		start_thread((void*)&save_stat_to_file_thread, "save lb stats");
	else
		save_stat_to_file_thread();
}

/**
 * Adds caid/prid/srvid/ecmlen to stat-list for reader ridx with time/rc
 */
void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int ecm_time, int rc)
{
	if (!rdr || !er || !cfg.lb_mode)
		return;
	READER_STAT *stat = get_stat(rdr, er->caid, er->prid, er->srvid, er->l);
	if (!stat) {
		stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		stat->caid = er->caid;
		stat->prid = er->prid;
		stat->srvid = er->srvid;
		stat->ecmlen = er->l;
		stat->time_avg = UNDEF_AVG_TIME; //dummy placeholder
		ll_append(rdr->lb_stat, stat);
	}

	//inc ecm_count if found, drop to 0 if not found:
	// rc codes:
	// 0 = found       +
	// 1 = cache1      #
	// 2 = cache2      #
	// 3 = emu         +
	// 4 = not found   -
	// 5 = timeout     -2
	// 6 = sleeping    #
	// 7 = fake        #
	// 8 = invalid     #
	// 9 = corrupt     #
	// 10= no card     #
	// 11= expdate     #
	// 12= disabled    #
	// 13= stopped     #
	// 100= unhandled  #
	//        + = adds statistic values
	//        # = ignored because of duplicate values, temporary failures or softblocks
	//        - = causes loadbalancer to block this reader for this caid/prov/sid
	//        -2 = causes loadbalancer to block if happens too often
	
	if (stat->ecm_count < 0)
		stat->ecm_count=0;
		
	if (rc == 0) { //found
		stat->rc = 0;
		stat->ecm_count++;
		stat->last_received = time(NULL);
		stat->request_count = 0;
		stat->fail_factor = 0;
		
		//FASTEST READER:
		stat->time_idx++;
		if (stat->time_idx >= LB_MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = ecm_time;
		calc_stat(stat);

		//OLDEST READER now set by get best reader!
		
		
		//USAGELEVEL:
		int ule = rdr->lb_usagelevel_ecmcount;
		if (ule > 0 && ((ule / cfg.lb_min_ecmcount) > 0)) //update every MIN_ECM_COUNT usagelevel:
		{
			time_t t = (time(NULL)-rdr->lb_usagelevel_time);
			rdr->lb_usagelevel = 1000/(t<1?1:t);
			ule = 0;
		}
		if (ule == 0)
			rdr->lb_usagelevel_time = time(NULL);
		rdr->lb_usagelevel_ecmcount = ule+1;
	}
	else if (rc == 1 || rc == 2) { //cache
		//no increase of statistics here, cachetime is not real time
		stat->last_received = time(NULL);
		stat->request_count = 0;
	}
	else if (rc == 4) { //not found
		//CCcam card can't decode, 0x28=NOK1, 0x29=NOK2
		//CCcam loop detection = E2_CCCAM_LOOP
		if (er->rcEx != E2_CCCAM_NOK1 && er->rcEx != E2_CCCAM_NOK2 && er->rcEx != E2_CCCAM_LOOP) {
				stat->rc = rc;
				stat->fail_factor++;
		}
		stat->last_received = time(NULL);
		
		//reduce ecm_count step by step
		if (!cfg.lb_reopen_mode)
			stat->ecm_count /= 10;
	}
	else if (rc == 5) { //timeout
		stat->request_count++;

		time_t cur_time = time(NULL);
		
		//catch suddenly occuring timeouts and block reader:
		if ((int)(cur_time-stat->last_received) < (int)(5*cfg.ctimeout) && 
						stat->rc == 0 && 
						stat->ecm_count > 0) {
				stat->rc = 5;
				stat->fail_factor++;
		}
		else if (stat->request_count >= cfg.lb_min_ecmcount) {
				stat->rc = 5;
				stat->fail_factor++;
		}
				
		stat->last_received = cur_time;

		if (!cfg.lb_reopen_mode)
			stat->ecm_count /= 10;
		
		//add timeout to stat:
		if (ecm_time<=0)
			ecm_time = cfg.ctimeout;
		stat->time_idx++;
		if (stat->time_idx >= LB_MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = ecm_time;
		calc_stat(stat);
	}
	else
	{
		if (rc >= 0)
			cs_debug_mask(D_TRACE, "loadbalancer: not handled stat for reader %s: rc %d %04hX&%06lX/%04hX/%02hX time %dms usagelevel %d",
				rdr->label, rc, er->caid, er->prid, er->srvid, er->l, ecm_time, rdr->lb_usagelevel);
	
		return;
	}
	
	housekeeping_stat(0);
		
	cs_debug_mask(D_TRACE, "loadbalancer: adding stat for reader %s: rc %d %04hX&%06lX/%04hX/%02hX time %dms usagelevel %d",
				rdr->label, rc, er->caid, er->prid, er->srvid, er->l, ecm_time, rdr->lb_usagelevel);
	
	if (cfg.lb_save) {
		stat_load_save++;
		if (stat_load_save > cfg.lb_save)
			save_stat_to_file(1);	
	}
}

void reset_stat(ushort caid, ulong prid, ushort srvid, short ecmlen)
{
	//cs_debug_mask(D_TRACE, "loadbalance: resetting ecm count");
	struct s_reader *rdr;
	for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
		if (rdr->lb_stat && rdr->client) {
			READER_STAT *stat = get_stat(rdr, caid, prid, srvid, ecmlen);
			if (stat) {
				if (stat->ecm_count > 0)
					stat->ecm_count = 1; //not zero, so we know it's decodeable
				stat->rc = 0;
				stat->request_count = 0;
				stat->fail_factor = 0;
			}
		}
	}
}

int has_ident(FTAB *ftab, ECM_REQUEST *er) {

	if (!ftab || !ftab->filts)
		return 0;
		
        int j, k;

        for (j = 0; j < ftab->nfilts; j++) {
		if (ftab->filts[j].caid) {
			if (ftab->filts[j].caid==er->caid) { //caid matches!

				int nprids = ftab->filts[j].nprids;
                                if (!nprids) // No Provider ->Ok
                                        return 1;

				for (k = 0; k < nprids; k++) {
					ulong prid = ftab->filts[j].prids[k];
					if (prid == er->prid) { //Provider matches
						return 1;
                                        }
                                }
                        }
                }
        }
        return 0; //No match!
}

struct stat_value {
	struct s_reader *rdr;
	int value;
	int time;
};

static struct stat_value *crt_cur(struct s_reader *rdr, int value, int time) {
	struct stat_value *v = malloc(sizeof(struct stat_value));
	v->rdr = rdr;
	v->value = value;
	v->time = time;
	return v;
}

static char *strend(char *c) {
	while (c && *c) c++;
	return c;
}

static int get_retrylimit(ECM_REQUEST *er) {
		int i;
		for (i = 0; i < cfg.lb_retrylimittab.n; i++) {
				if (cfg.lb_retrylimittab.caid[i] == er->caid)
						return cfg.lb_retrylimittab.value[i];
		}
		return cfg.lb_retrylimit;
}

static int get_nbest_readers(ECM_REQUEST *er) {
		int i;
		for (i = 0; i < cfg.lb_nbest_readers_tab.n; i++) {
				if (cfg.lb_nbest_readers_tab.caid[i] == er->caid)
						return cfg.lb_nbest_readers_tab.value[i];
		}
		return cfg.lb_nbest_readers;
}

static int get_reopen_seconds(READER_STAT *stat)
{
		int max = (INT_MAX / cfg.lb_reopen_seconds) - 1;
		if (stat->fail_factor > max)
				stat->fail_factor = max;
		return (stat->fail_factor+1) * cfg.lb_reopen_seconds;
}

/**	
 * Gets best reader for caid/prid/srvid/ecmlen.
 * Best reader is evaluated by lowest avg time but only if ecm_count > cfg.lb_min_ecmcount (5)
 * Also the reader is asked if he is "available"
 * returns ridx when found or -1 when not found
 */
int get_best_reader(ECM_REQUEST *er)
{
	if (!cfg.lb_mode || cfg.lb_mode==LB_LOG_ONLY)
		return 0;

	LL_ITER *it;
	struct s_reader *rdr;

	//preferred card forwarding (CCcam client):
	if (cfg.cc_forward_origin_card && er->origin_card) {
	
			struct cc_card *card = er->origin_card;
			
			it = ll_iter_create(er->matching_rdr);
			while ((rdr=ll_iter_next(it))) {
					if (card->origin_reader == rdr)
							break;				
			}
			if (rdr) {
					cs_debug_mask(D_TRACE, "loadbalancer: forward card: forced by card %d to reader %s", card->id, rdr->label);
					ll_clear(er->matching_rdr);
					ll_append(er->matching_rdr, rdr);
					return 1;
			}
	}
	
 		
	LLIST * result = ll_create();
	LLIST * selected = ll_create();
	
	struct timeb new_nulltime;
	memset(&new_nulltime, 0, sizeof(new_nulltime));
	time_t current_time = time(NULL);
	int current = -1;
	READER_STAT *stat = NULL;
	int nlocal_readers = 0;
	int retrylimit = get_retrylimit(er);

#ifdef WITH_DEBUG 
	if (cs_dblevel & 0x01) {
		//loadbalancer debug output:
		int size = 1;
		int nr = 0;
		it = ll_iter_create(er->matching_rdr);
		while ((rdr=ll_iter_next(it))) {
			if (nr > 5) {
				size+=20;
				break;
			}
			size += strlen(rdr->label)+1;
			nr++;
		}
		ll_iter_reset(it);
		char *rdrs = cs_malloc(&rdrs, size, 1);
		char *rptr = rdrs;
		*rptr = 0;
		nr = 0;
		while ((rdr=ll_iter_next(it))) {
			if (nr > 5) {
				snprintf(rptr, size, "...(%d more)", ll_count(er->matching_rdr)-nr);
				break;
			}
			snprintf(rptr, size, "%s ", rdr->label);
			rptr = strend(rptr);
			nr++;
		}
		ll_iter_release(it);
	
		cs_debug_mask(D_TRACE, "loadbalancer: client %s for %04X&%06X/%04X/%02hX: n=%d valid readers: %s", 
			username(er->client), er->caid, er->prid, er->srvid, er->l, ll_count(er->matching_rdr), rdrs);
			
		free(rdrs);
	}
#endif	
	
	it = ll_iter_create(er->matching_rdr);
	while ((rdr=ll_iter_next(it))) {
	
			int weight = rdr->lb_weight <= 0?100:rdr->lb_weight;
				
			stat = get_stat(rdr, er->caid, er->prid, er->srvid, er->l);
			if (!stat) {
				cs_debug_mask(D_TRACE, "loadbalancer: starting statistics for reader %s", rdr->label);
				add_stat(rdr, er, 1, -1);
				ll_append(result, rdr); //no statistics, this reader is active (now) but we need statistics first!
				continue;
			}
			
			if (stat->ecm_count < 0||(stat->ecm_count > cfg.lb_max_ecmcount && stat->time_avg > retrylimit)) {
				cs_debug_mask(D_TRACE, "loadbalancer: max ecms (%d) reached by reader %s, resetting statistics", cfg.lb_max_ecmcount, rdr->label);
				reset_stat(er->caid, er->prid, er->srvid, er->l);
				ll_append(result, rdr); //max ecm reached, get new statistics
				continue;
			}
				
			int hassrvid = has_srvid(rdr->client, er) || has_ident(&rdr->ftab, er);
			
			if (!hassrvid && stat->rc == 0 && stat->request_count >= cfg.lb_min_ecmcount-1) { // 4 unanswered requests or timeouts?
				cs_debug_mask(D_TRACE, "loadbalancer: reader %s does not answer, blocking", rdr->label);
				add_stat(rdr, er, 1, 4); //reader marked as unuseable
				continue;
			}

			if (stat->rc == 0 && stat->ecm_count < cfg.lb_min_ecmcount) {
				cs_debug_mask(D_TRACE, "loadbalancer: reader %s needs more statistics", rdr->label);
				ll_append(result, rdr); //need more statistics!
				continue;
			}
			
			//Reader can decode this service (rc==0) and has lb_min_ecmcount ecms:
			if (stat->rc == 0 || hassrvid) {
				if (cfg.preferlocalcards && !(rdr->typ & R_IS_NETWORK))
					nlocal_readers++; //Prefer local readers!
			
				switch (cfg.lb_mode) {
					default:
					case LB_NONE:
					case LB_LOG_ONLY:
						//cs_debug_mask(D_TRACE, "loadbalance disabled");
						ll_append(result, rdr);
						continue;
						
					case LB_FASTEST_READER_FIRST:
						current = stat->time_avg * 100 / weight;
						break;
						
					case LB_OLDEST_READER_FIRST:
						if (!rdr->lb_last.time)
							rdr->lb_last = nulltime;
						current = (1000*(rdr->lb_last.time-nulltime.time)+
							rdr->lb_last.millitm-nulltime.millitm);
						if (!new_nulltime.time || (1000*(rdr->lb_last.time-new_nulltime.time)+
							rdr->lb_last.millitm-new_nulltime.millitm) < 0)
							new_nulltime = rdr->lb_last;
						break;
						
					case LB_LOWEST_USAGELEVEL:
						current = rdr->lb_usagelevel * 100 / weight;
						break;
				}
#ifdef WEBIF
				rdr->lbvalue = current;
#endif
				if (rdr->ph.c_available
						&& !rdr->ph.c_available(rdr,
								AVAIL_CHECK_LOADBALANCE)) {
					current=current*2;
				}
				if (current < 1)
					current=1;
				ll_append(selected, crt_cur(rdr, current, stat->time_avg));
		}
	}
	ll_iter_release(it);

	int nbest_readers = get_nbest_readers(er);
	int nfb_readers = cfg.lb_nfb_readers;
	if (nlocal_readers > nbest_readers) { //if we have local readers, we prefer them!
		nlocal_readers = nbest_readers;
		nbest_readers = 0;	
	}
	else
		nbest_readers = nbest_readers-nlocal_readers;
	
	struct stat_value *stv;
	it = ll_iter_create(selected);
	
	struct s_reader *best_rdr = NULL;
	struct s_reader *best_rdri = NULL;
	int best_time = 0;
	LL_NODE *fallback = NULL;

	int n=0;
	while (1) {
		struct stat_value *best = NULL;

		ll_iter_reset(it);
		while ((stv=ll_iter_next(it))) {
			if (nlocal_readers && (stv->rdr->typ & R_IS_NETWORK))
				continue;
						
			if (stv->value && (!best || stv->value < best->value))
				best=stv;
		}
		if (!best)
			break;
	
		n++;
		best_rdri = best->rdr;
		if (!best_rdr) {
			best_rdr = best_rdri;
			best_time = best->time;
		}
		best->value = 0;
			
		if (nlocal_readers) {//primary readers, local
			nlocal_readers--;
			ll_append(result, best_rdri);
			//OLDEST_READER:
			cs_ftime(&best_rdri->lb_last);
		}
		else if (nbest_readers) {//primary readers, other
			nbest_readers--;
			ll_append(result, best_rdri);
			//OLDEST_READER:
			cs_ftime(&best_rdri->lb_last);
		}
		else if (nfb_readers) { //fallbacks:
			nfb_readers--;
			LL_NODE *node = ll_append(result, best_rdri);
			if (!fallback)
				fallback = node;
		}
		else
			break;
	}
	ll_iter_release(it);
	ll_destroy_data(selected);
	
	if (!n) //no best reader found? reopen if we have ecm_count>0
	{
		cs_debug_mask(D_TRACE, "loadbalancer: NO MATCHING READER FOUND, reopen last valid:");
		it = ll_iter_create(er->matching_rdr);
		while ((rdr=ll_iter_next(it))) {
        		stat = get_stat(rdr, er->caid, er->prid, er->srvid, er->l); 
        		if (stat && stat->ecm_count>0) {
        			if (!ll_contains(result, rdr))
        				ll_append(result, rdr);
        			n++;
        			cs_debug_mask(D_TRACE, "loadbalancer: reopened reader %s", rdr->label);
			}
		}
		ll_iter_release(it);
		cs_debug_mask(D_TRACE, "loadbalancer: reopened %d readers", n);
	}

	//algo for finding unanswered requests (newcamd reader or disconnected camd35 UDP for example:)
	it = ll_iter_create(result);
	while ((rdr=ll_iter_next(it))) {
		if (it->cur == fallback) break;
        	//primary readers 
        	stat = get_stat(rdr, er->caid, er->prid, er->srvid, er->l); 
       		
       		if (stat && current_time > stat->last_received+(time_t)(cfg.ctimeout/1000)) { 
        		stat->request_count++; 
        		stat->last_received = current_time;
        		
        		if (stat->request_count >= cfg.lb_min_ecmcount) {
        			add_stat(rdr, er, 1, 4); //reader marked as unuseable
        			cs_debug_mask(D_TRACE, "loadbalancer: reader %s does not answer, blocking", rdr->label);
        		}
        		else
        			cs_debug_mask(D_TRACE, "loadbalancer: reader %s increment request count to %d", rdr->label, stat->request_count);
		}

	}
	ll_iter_release(it);

	//algo for reopen other reader only if responsetime>retrylimit:
	int reopen = !best_rdr || (best_time && (best_time > retrylimit));
	if (reopen) {
#ifdef WITH_DEBUG 
		if (best_rdr)
			cs_debug_mask(D_TRACE, "loadbalancer: reader %s reached retrylimit (%dms), reopening other readers", best_rdr->label, best_time);
		else
			cs_debug_mask(D_TRACE, "loadbalancer: no best reader found, reopening other readers");	
#endif	
		it = ll_iter_create(er->matching_rdr);
		while ((rdr=ll_iter_next(it))) {
	        	stat = get_stat(rdr, er->caid, er->prid, er->srvid, er->l); 

			if (stat && stat->rc != 0) { //retrylimit reached:
				if (stat->last_received+get_reopen_seconds(stat) < current_time) { //Retrying reader every (900/conf) seconds
					stat->last_received = current_time;
					ll_remove(result, rdr);
					ll_prepend(result, rdr);
					cs_debug_mask(D_TRACE, "loadbalancer: retrying reader %s", rdr->label);
				}
			}
		}
		ll_iter_release(it);
	}

        //Setting return values:
	ll_destroy(er->matching_rdr);
	er->matching_rdr = result;
	er->fallback = fallback;
        
	if (new_nulltime.time)
		nulltime = new_nulltime;

#ifdef WITH_DEBUG 
	if (cs_dblevel & 0x01) {
		//loadbalancer debug output:
		int size = 3;
		int nr = 0;
		it = ll_iter_create(result);
		while ((rdr=ll_iter_next(it))) {
			if (nr > 5) { 
				size+=20;
				break;
			}
			size += strlen(rdr->label)+1;
			nr++;
		}
		ll_iter_reset(it);
		char *rdrs = cs_malloc(&rdrs, size, 1);
		char *rptr = rdrs;
		*rptr = 0;
		nr = 0;
		while ((rdr=ll_iter_next(it))) {
			if (fallback && it->cur == fallback) {
				snprintf(rptr, size, "[");
				rptr = strend(rptr);
			}
			if (nr > 5) {
				snprintf(rptr, size, "...(%d more)", ll_count(result)-nr);
				rptr = strend(rptr);
				break;
			}
			snprintf(rptr, size, "%s ", rdr->label);
			rptr = strend(rptr);

			nr++;
		}
		if (fallback) {
			rptr--;
			*rptr=']';
		}
		ll_iter_release(it);
	
		cs_debug_mask(D_TRACE, "loadbalancer: client %s for %04X&%06X/%04X:%02hX: n=%d selected readers: %s", 
			username(er->client), er->caid, er->prid, er->srvid, er->l, ll_count(result), rdrs);
		
		free(rdrs);
	}
#endif	

		
	return 1;
}

/**
 * clears statistic of reader ridx.
 **/
void clear_reader_stat(struct s_reader *rdr)
{
	if (!rdr->lb_stat) 
		return;

	ll_clear_data(rdr->lb_stat);
}

void clear_all_stat()
{
	struct s_reader *rdr;
	LL_ITER *itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(itr))) { 
		clear_reader_stat(rdr);
	}
	ll_iter_release(itr);
}

void housekeeping_stat_thread()
{	
	time_t cleanup_time = time(NULL) - (cfg.lb_stat_cleanup*60*60);
	int cleaned = 0;
	struct s_reader *rdr;
    LL_ITER *itr = ll_iter_create(configured_readers);
    while ((rdr = ll_iter_next(itr))) {
		if (rdr->lb_stat) {
			LL_ITER *it = ll_iter_create(rdr->lb_stat);
			READER_STAT *stat;
			while ((stat=ll_iter_next(it))) {
				
				if (stat->last_received < cleanup_time) {
					ll_iter_remove_data(it);
					cleaned++;
				}
			}
			
			ll_iter_release(it);
		}
	}
	ll_iter_release(itr);
	cs_debug_mask(D_TRACE, "loadbalancer cleanup: removed %d entries", cleaned);
}

void housekeeping_stat(int force)
{
	time_t now = time(NULL);
	if (!force && now/60/60 == last_housekeeping/60/60) //only clean once in an hour
		return;
	
	last_housekeeping = now;
	start_thread((void*)&housekeeping_stat_thread, "housekeeping lb stats");
}
