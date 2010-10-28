//FIXME Not checked on threadsafety yet; not necessary if only 1 stat running; after checking please remove this line
#include "module-stat.h"

#define UNDEF_AVG_TIME 80000
#define MAX_ECM_SEND_CACHE 16

#define DEFAULT_REOPEN_SECONDS 900
#define DEFAULT_MIN_ECM_COUNT 5
#define DEFAULT_MAX_ECM_COUNT 500
#define DEFAULT_NBEST 1
#define DEFAULT_NFB 1

static int stat_load_save;
static struct timeb nulltime;

int ecm_send_cache_idx = 0;
typedef struct s_ecm_send_cache {
   ushort        caid;
   uint64        grp;
   uchar         ecmd5[CS_ECMSTORESIZE];            
   int           readers[CS_MAXREADER];
   struct s_reader * best_rdr;
} ECM_SEND_CACHE;
ECM_SEND_CACHE *ecm_send_cache;

void init_stat()
{
	ecm_send_cache = malloc(sizeof(ECM_SEND_CACHE)*MAX_ECM_SEND_CACHE);
	memset(ecm_send_cache, 0, sizeof(ECM_SEND_CACHE)*MAX_ECM_SEND_CACHE);
	cs_ftime(&nulltime);
	stat_load_save = -100;

	//checking config
	if (cfg->lb_nbest_readers < 2)
		cfg->lb_nbest_readers = DEFAULT_NBEST;
	if (cfg->lb_nfb_readers < 2)
		cfg->lb_nfb_readers = DEFAULT_NFB;
	if (cfg->lb_min_ecmcount < 1)
		cfg->lb_min_ecmcount = DEFAULT_MIN_ECM_COUNT;
	if (cfg->lb_max_ecmcount < 2)
		cfg->lb_max_ecmcount = DEFAULT_MAX_ECM_COUNT;
	if (cfg->lb_reopen_seconds < 10)
		cfg->lb_reopen_seconds = DEFAULT_REOPEN_SECONDS;
		
	//init mutex lock with recusive attribute:
	pthread_mutexattr_t   mta;
	pthread_mutexattr_init(&mta);
	pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&stat_busy, &mta);
}

int chk_send_cache(int caid, uchar *ecmd5, uint64 grp)
{
	int i;
	for (i=0; i<MAX_ECM_SEND_CACHE; i++) {
		if (ecm_send_cache[i].caid == caid && (grp&ecm_send_cache[i].grp) && 
		  memcmp(ecm_send_cache[i].ecmd5, ecmd5, sizeof(uchar)*CS_ECMSTORESIZE) == 0)
			return i;
	}
	return -1;
}

void add_send_cache(int caid, uchar *ecmd5, int *readers, struct s_reader *best_rdr, uint64 grp)
{
	ecm_send_cache[ecm_send_cache_idx].caid = caid;
	memcpy(ecm_send_cache[ecm_send_cache_idx].ecmd5, ecmd5, sizeof(uchar)*CS_ECMSTORESIZE);
	memcpy(ecm_send_cache[ecm_send_cache_idx].readers, readers, sizeof(int)*CS_MAXREADER);
	ecm_send_cache[ecm_send_cache_idx].best_rdr = best_rdr;
	ecm_send_cache[ecm_send_cache_idx].grp = grp;
	ecm_send_cache_idx++;
	if (ecm_send_cache_idx >= MAX_ECM_SEND_CACHE)
		ecm_send_cache_idx = 0;
}

void clear_from_cache(int caid)
{
	int i;
	for (i=0; i<MAX_ECM_SEND_CACHE; i++) {
		if (ecm_send_cache[i].caid == caid)
			ecm_send_cache[i].caid = 0;
	}
}

void load_stat_from_file()
{
	stat_load_save = 0;
	char buf[256];
	sprintf(buf, "%s/stat", get_tmp_dir());
	FILE *file = fopen(buf, "r");
	if (!file) {
		cs_log("can't read from file %s", buf);
		return;
	}
	cs_debug_mask(D_TRACE, "loadbalancer load statistics from %s", buf);
	
	struct s_reader *rdr = NULL;
	
	//Whitespace problem: reader label can't contain spaces!
	for (rdr=first_reader; rdr ; rdr=rdr->next) {
		char *ch = rdr->label;
		while (*ch) { 
			if (*ch == '_')
				*ch = ' ';
			ch++;
		}
	}
		
	int i=1;
	int count=0;
	do
	{
		READER_STAT *stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		i = fscanf(file, "%s rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d last %ld\n",
			buf, &stat->rc, &stat->caid, &stat->prid, &stat->srvid, 
			&stat->time_avg, &stat->ecm_count, &stat->last_received);
			
		
		if (i > 5) {
			if (rdr == NULL || strcmp(buf, rdr->label) != 0) {
				for (rdr=first_reader; rdr ; rdr=rdr->next) {
					if (strcmp(rdr->label, buf) == 0) {
						break;
					}
				}
			}
			
			if (rdr != NULL && strcmp(buf, rdr->label) == 0) {
				if (!rdr->lb_stat)
					rdr->lb_stat = ll_create();
				ll_append(rdr->lb_stat, stat);
				count++;
			}
			else 
			{
				cs_log("loadbalancer statistics could not be loaded for %s", buf);
				free(stat);
			}
		}
		else 
		{
			cs_debug_mask(D_TRACE, "loadbalancer statistics ERROR  %s rc=%d i=%d", buf, stat->rc, i);
			free(stat);
		}
	} while(i != EOF && i > 0);
	fclose(file);
	cs_debug_mask(D_TRACE, "loadbalancer statistic loaded %d records", count);
}
/**
 * get statistic values for reader ridx and caid/prid/srvid
 */
READER_STAT *get_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid)
{
	pthread_mutex_lock(&stat_busy);
	if (stat_load_save < 0 && cfg->lb_save)
		load_stat_from_file();
	if (!rdr->lb_stat)
		rdr->lb_stat = ll_create();

	LL_ITER *it = ll_iter_create(rdr->lb_stat);
	READER_STAT *stat = NULL;
	while ((stat = ll_iter_next(it))) {
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid) {
			break;
		}
	}
	ll_iter_release(it);
	pthread_mutex_unlock(&stat_busy);
	return stat;
}

/**
 * removes caid/prid/srvid from stat-list of reader ridx
 */
int remove_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid)
{
	if (!rdr->lb_stat)
		return 0;

	pthread_mutex_lock(&stat_busy);
	int c = 0;
	LL_ITER *it = ll_iter_create(rdr->lb_stat);
	READER_STAT *stat;
	while ((stat = ll_iter_next(it))) {
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid) {
			ll_iter_remove_data(it);
			c++;
		}
	}
	ll_iter_release(it);
	clear_from_cache(caid);
	pthread_mutex_unlock(&stat_busy);
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
void save_stat_to_file()
{
	pthread_mutex_lock(&stat_busy);
	stat_load_save = 0;
	char buf[256];
	sprintf(buf, "%s/stat", get_tmp_dir());

	FILE *file = fopen(buf, "w");
	if (!file) {
		cs_log("can't write to file %s", buf);
		pthread_mutex_unlock(&stat_busy);
		return;
	}

	int count=0;
	struct s_reader *rdr;
	for (rdr=first_reader; rdr ; rdr=rdr->next) {
		//Replace spaces in reader names to _ because fscanf can't read spaces
		char *ch = rdr->label;
		while (*ch) {
			if (*ch == ' ')
				*ch = '_';
			ch++;
		}
		
		if (rdr->lb_stat) {
			LL_ITER *it = ll_iter_create(rdr->lb_stat);
			READER_STAT *stat;
			while ((stat = ll_iter_next(it))) {
				
				fprintf(file, "%s rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d last %ld\n",
					rdr->label, stat->rc, stat->caid, stat->prid, 
					stat->srvid, stat->time_avg, stat->ecm_count, stat->last_received);
				count++;
			}
			ll_iter_release(it);
		}
	}
	
	fclose(file);
	pthread_mutex_unlock(&stat_busy);
	cs_log("loadbalacer statistic saved %d records", count);
}

/**
 * Adds caid/prid/srvid to stat-list for reader ridx with time/rc
 */
void add_stat(struct s_reader *rdr, ushort caid, ulong prid, ushort srvid, int ecm_time, int rc)
{
	if (!rdr)
		return;
	pthread_mutex_lock(&stat_busy);
	READER_STAT *stat = get_stat(rdr, caid, prid, srvid);
	if (!stat) {
		stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		stat->caid = caid;
		stat->prid = prid;
		stat->srvid = srvid;
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
	// 5 = timeout     #
	// 6 = sleeping    #
	// 7 = fake        #
	// 8 = invalid     -
	// 9 = corrupt     -
	// 10= no card     #
	// 11= expdate     #
	// 12= disabled    #
	// 13= stopped     #
	// 100= unhandled  #
	//        + = adds statistic values
	//        # = ignored because of duplicate values, temporary failures or softblocks
	//        - = causes loadbalancer to block this reader for this caid/prov/sid
	
	if (stat->ecm_count < 0)
		stat->ecm_count=0;
		
	stat->request_count = 0;
		
	if (rc == 0 || rc == 3) {
		stat->rc = 0;
		stat->ecm_count++;
		stat->time_idx++;
		stat->last_received = time(NULL);
		
		//FASTEST READER:
		if (stat->time_idx >= LB_MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = ecm_time;
		calc_stat(stat);

		//OLDEST READER now set by get best reader!
		
		
		//USAGELEVEL:
		int ule = rdr->lb_usagelevel_ecmcount;
		if (ule > 0 && ((ule / cfg->lb_min_ecmcount) > 0)) //update every MIN_ECM_COUNT usagelevel:
		{
			time_t t = (time(NULL)-rdr->lb_usagelevel_time);
			rdr->lb_usagelevel = 1000/(t<1?1:t);
			ule = 0;
		}
		if (ule == 0)
			rdr->lb_usagelevel_time = time(NULL);
		rdr->lb_usagelevel_ecmcount = ule+1;
	}
	else if (rc == 4 || rc == 8 || rc == 9) { //not found+errors+etc
		stat->rc = rc;
		//stat->ecm_count = 0; Keep ecm_count!
		clear_from_cache(caid);
	}

	//cs_debug_mask(D_TRACE, "adding stat for reader %s (%d): rc %d caid %04hX prid %06lX srvid %04hX time %dms usagelevel %d",
	//			rdr->label, ridx, rc, caid, prid, srvid, ecm_time, rdr->lb_usagelevel);
	
	//debug only:
	if (cfg->lb_save) {
		stat_load_save++;
		if (stat_load_save > cfg->lb_save) {
			save_stat_to_file();
		}
	}
	pthread_mutex_unlock(&stat_busy);
}

void reset_stat(ushort caid, ulong prid, ushort srvid)
{
	pthread_mutex_lock(&stat_busy);
	//cs_debug_mask(D_TRACE, "loadbalance: resetting ecm count");
	struct s_reader *rdr;
	for (rdr=first_reader; rdr ; rdr=rdr->next) {
		if (rdr->lb_stat && rdr->client) {
			READER_STAT *stat = get_stat(rdr, caid, prid, srvid);
			if (stat) {
				if (stat->ecm_count > 0)
					stat->ecm_count = 1; //not zero, so we know it's decodeable
				stat->rc = 0;
			}
		}
	}
	pthread_mutex_unlock(&stat_busy);
}


/**	
 * Gets best reader for caid/prid/srvid.
 * Best reader is evaluated by lowest avg time but only if ecm_count > cfg->lb_min_ecmcount (5)
 * Also the reader is asked if he is "available"
 * returns ridx when found or -1 when not found
 */
int get_best_reader(ECM_REQUEST *er)
{
	pthread_mutex_lock(&stat_busy);
	int i;
	i = chk_send_cache(er->caid, er->ecmd5, er->client->grp);
	if (i >= 0) { //Found in cache, return same reader because he has the cached cws!
		memcpy(er->matching_rdr, ecm_send_cache[i].readers, sizeof(int)*CS_MAXREADER);
		struct s_reader * best_rdr = ecm_send_cache[i].best_rdr;
		cs_debug_mask(D_TRACE, "loadbalancer: client %s for %04X/%06X/%04X: %s readers: %d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d (cache)", 
			username(er->client), er->caid, er->prid, er->srvid,
			best_rdr?best_rdr->label:"NONE",
			er->matching_rdr[0], er->matching_rdr[1], er->matching_rdr[2], er->matching_rdr[3], 
			er->matching_rdr[4], er->matching_rdr[5], er->matching_rdr[6], er->matching_rdr[7], 
			er->matching_rdr[8], er->matching_rdr[9], er->matching_rdr[10], er->matching_rdr[11], 
			er->matching_rdr[12], er->matching_rdr[13], er->matching_rdr[14], er->matching_rdr[15]);

		pthread_mutex_unlock(&stat_busy);
		return 0;
	}

	int result[CS_MAXREADER];
	memset(result, 0, sizeof(result));
	int re[CS_MAXREADER];

	//resulting values:
	memset(re, 0, sizeof(re));

	struct timeb new_nulltime;
	memset(&new_nulltime, 0, sizeof(new_nulltime));
	time_t current_time = time(NULL);
	
	int current = -1;
	
	READER_STAT *stat = NULL;
	struct s_reader *rdr;
	for (i=0,rdr=first_reader; rdr ; rdr=rdr->next, i++) {
		if (er->matching_rdr[i]) {
 			int weight = rdr->lb_weight <= 0?100:rdr->lb_weight;
			stat = get_stat(rdr, er->caid, er->prid, er->srvid);
			if (!stat) {
				cs_debug_mask(D_TRACE, "loadbalancer: starting statistics for reader %s", rdr->label);
				add_stat(rdr, er->caid,  er->prid, er->srvid, 1, -1);
				result[i] = 1; //no statistics, this reader is active (now) but we need statistics first!
				continue; 
			}
			
			if (stat->ecm_count < 0||(stat->ecm_count > cfg->lb_max_ecmcount && stat->time_avg > (int)cfg->ftimeout)) {
				cs_debug_mask(D_TRACE, "loadbalancer: max ecms (%d) reached by reader %s, resetting statistics", cfg->lb_max_ecmcount, rdr->label);
				reset_stat(er->caid, er->prid, er->srvid);
				result[i] = 1;//max ecm reached, get new statistics
				continue;
			}
				
			if (stat->rc == 0 && stat->ecm_count < cfg->lb_min_ecmcount) {
				cs_debug_mask(D_TRACE, "loadbalancer: reader %s needs more statistics", rdr->label);
				stat->request_count++;
				//algo for finding unanswered requests (newcamd reader for example:)
				if (stat->request_count > cfg->lb_min_ecmcount) { //5 unanswered requests? 
					add_stat(rdr, er->caid, er->prid, er->srvid, 1, 4); //reader marked as unuseable 
					result[i] = 0;
				}
				else
					result[i] = 1; //need more statistics!
				continue;
			}
				

			//Reader can decode this service (rc==0) and has lb_min_ecmcount ecms:
			if (stat->rc == 0) {
					
				switch (cfg->lb_mode) {
				default:
				case LB_NONE:
					//cs_debug_mask(D_TRACE, "loadbalance disabled");
					result[i] = 1;
					current = 1;
					break;
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
				if (!rdr->ph.c_available
						|| rdr->ph.c_available(rdr,
								AVAIL_CHECK_LOADBALANCE)) {
					current=current/2;
				}
				if (current < 1)
					re[i]=1;
				else
					re[i] = current;
			}
			else 
			{
				int seconds = cfg->lb_reopen_seconds;
				if (!rdr->audisabled && (er->client->autoau || er->client->aureader == rdr))
					seconds = seconds/10;
				
				if (stat->last_received+seconds < current_time) { //Retrying reader every (900/conf) seconds
					stat->last_received = current_time;
					result[i] = 1;
					cs_log("loadbalancer: retrying reader %s", rdr->label);
				}
			}
		}
	}

	int nbest_readers = cfg->lb_nbest_readers;
	int nfb_readers = cfg->lb_nfb_readers;
	int best_ridx = -1;
	struct s_reader *best_rdr = NULL;
	struct s_reader *best_rdri = NULL;

	nfb_readers += nbest_readers;
	
	int n=0;
	while (1) {
		int best_idx=-1;
		int best=0;
		int j;
		struct s_reader *rdr2;
		for (j=0,rdr2=first_reader; rdr2 ; rdr2=rdr2->next, j++) {
			if (re[j] && (!best || re[j] < best)) {
				best_idx=j;
				best=re[j];
				best_rdri = rdr2;
			}
		}
		if (best_idx<0)
			break;
		else {
			re[best_idx]=0;
			n++;
			if (n<=nbest_readers) {
				result[best_idx] = 1;
				//OLDEST_READER:
				cs_ftime(&best_rdri->lb_last);
				if (best_ridx <0) {
					best_ridx = best_idx;
					best_rdr = best_rdri;
				}
			}
			else if (n<=nfb_readers) {
				if (!result[best_idx])
					result[best_idx] = 2;
			}
			else
				break;
		}
	}
	
	if (n)
		memcpy(er->matching_rdr, result, sizeof(result));
#ifdef WITH_DEBUG 
	else
		cs_debug_mask(D_TRACE, "loadbalancer: no best reader found, trying all readers");

	cs_debug_mask(D_TRACE, "loadbalancer: client %s for %04X/%06X/%04X: %s readers: %d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d", 
		username(er->client), er->caid, er->prid, er->srvid,
		best_rdr?best_rdr->label:"NONE",
		er->matching_rdr[0], er->matching_rdr[1], er->matching_rdr[2], er->matching_rdr[3], 
		er->matching_rdr[4], er->matching_rdr[5], er->matching_rdr[6], er->matching_rdr[7], 
		er->matching_rdr[8], er->matching_rdr[9], er->matching_rdr[10], er->matching_rdr[11], 
		er->matching_rdr[12], er->matching_rdr[13], er->matching_rdr[14], er->matching_rdr[15]);
#endif	
	add_send_cache(er->caid, er->ecmd5, er->matching_rdr, best_rdr, er->client->grp); //add to cache
	
	if (new_nulltime.time)
		nulltime = new_nulltime;
		
	pthread_mutex_unlock(&stat_busy);
	
	return 1;
}

/**
 * clears statistic of reader ridx.
 **/
void clear_reader_stat(struct s_reader *rdr)
{
	if (!rdr->lb_stat) 
		return;

	pthread_mutex_lock(&stat_busy);
	ll_destroy_data(rdr->lb_stat);
	rdr->lb_stat = ll_create();
	pthread_mutex_unlock(&stat_busy);
}
