//FIXME Not checked on threadsafety yet; not necessary if only 1 stat running; after checking please remove this line
#include "module-stat.h"

#define UNDEF_AVG_TIME 80000
#define MAX_ECM_SEND_CACHE 8

#define DEFAULT_REOPEN_SECONDS 900
#define DEFAULT_MIN_ECM_COUNT 5
#define DEFAULT_MAX_ECM_COUNT 500
#define DEFAULT_NBEST 1
#define DEFAULT_NFB 1

static int stat_load_save = 0;
static struct timeb nulltime;

int ecm_send_cache_idx = 0;
typedef struct s_ecm_send_cache {
   ushort        caid;
   uchar         ecmd5[CS_ECMSTORESIZE];            
   int           readers[CS_MAXREADER];
   int           best_reader;
} ECM_SEND_CACHE;
ECM_SEND_CACHE *ecm_send_cache;

void init_stat()
{
	memset(reader_stat, 0, sizeof(reader_stat));
	ecm_send_cache = malloc(sizeof(ECM_SEND_CACHE)*MAX_ECM_SEND_CACHE);
	memset(ecm_send_cache, 0, sizeof(ECM_SEND_CACHE)*MAX_ECM_SEND_CACHE);
	cs_ftime(&nulltime);

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

int chk_send_cache(int caid, uchar *ecmd5)
{
	int i;
	for (i=0; i<MAX_ECM_SEND_CACHE; i++) {
		if (ecm_send_cache[i].caid == caid && 
		  memcmp(ecm_send_cache[i].ecmd5, ecmd5, sizeof(uchar)*CS_ECMSTORESIZE) == 0)
			return i;
	}
	return -1;
}

void add_send_cache(int caid, uchar *ecmd5, int *readers, int best_reader)
{
	ecm_send_cache[ecm_send_cache_idx].caid = caid;
	memcpy(ecm_send_cache[ecm_send_cache_idx].ecmd5, ecmd5, sizeof(uchar)*CS_ECMSTORESIZE);
	memcpy(ecm_send_cache[ecm_send_cache_idx].readers, readers, sizeof(int)*CS_MAXREADER);
	ecm_send_cache[ecm_send_cache_idx].best_reader = best_reader;
	
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

void load_stat_from_file(int ridx)
{
	char fname[256];
	sprintf(fname, "%s/stat.%d", get_tmp_dir(), ridx);
	FILE *file = fopen(fname, "r");
	if (!file)
		return;

	int i = 0;
	do
	{
		READER_STAT *stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		i = fscanf(file, "rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d last %ld\n",
			&stat->rc, &stat->caid, &stat->prid, &stat->srvid, &stat->time_avg, &stat->ecm_count, &stat->last_received);
		if (i > 4) {
			llist_append(reader_stat[ridx], stat);
		}
		else
			free(stat);
	} while(i != EOF && i > 0);
	fclose(file);
}
/**
 * get statistic values for reader ridx and caid/prid/srvid
 */
READER_STAT *get_stat(int ridx, ushort caid, ulong prid, ushort srvid)
{
	pthread_mutex_lock(&stat_busy);
	if (!reader_stat[ridx]) {
		reader_stat[ridx] = llist_create();
		if (cfg->lb_save)
			load_stat_from_file(ridx);
	}

	LLIST_ITR itr;
	READER_STAT *stat = llist_itr_init(reader_stat[ridx], &itr);
	while (stat) {
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid) {
			pthread_mutex_unlock(&stat_busy);
			return stat;
		}
		
		stat = llist_itr_next(&itr);
	}
	pthread_mutex_unlock(&stat_busy);
	return NULL;
}

/**
 * removes caid/prid/srvid from stat-list of reader ridx
 */
int remove_stat(int ridx, ushort caid, ulong prid, ushort srvid)
{
	if (!reader_stat[ridx])
		return 0;

	pthread_mutex_lock(&stat_busy);
	int c = 0;
	LLIST_ITR itr;
	READER_STAT *stat = llist_itr_init(reader_stat[ridx], &itr);
	while (stat) {
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid) {
			free(stat);
			stat = llist_itr_remove(&itr);
			c++;
		}
		else
			stat = llist_itr_next(&itr);
	}
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
	for (i = 0; i < MAX_STAT_TIME; i++) {
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
void save_stat_to_file(int ridx)
{
	pthread_mutex_lock(&stat_busy);
	char fname[256];
	sprintf(fname, "%s/stat.%d", get_tmp_dir(), ridx);
	if (!reader_stat[ridx] || !llist_count(reader_stat[ridx])) {
		remove(fname);
		pthread_mutex_unlock(&stat_busy);
		return;
	}

	LLIST_ITR itr;
	READER_STAT *stat = llist_itr_init(reader_stat[ridx], &itr);

	if (!stat) {
		remove(fname);
		pthread_mutex_unlock(&stat_busy);
		return;
	}
	
	FILE *file = fopen(fname, "w");
	if (!file) {
		pthread_mutex_unlock(&stat_busy);
		return;
	}
		
	while (stat) {
		fprintf(file, "rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d last %ld\n",
				stat->rc, stat->caid, stat->prid, stat->srvid, stat->time_avg, stat->ecm_count, stat->last_received);
		stat = llist_itr_next(&itr);
	}
	fclose(file);
	pthread_mutex_unlock(&stat_busy);
}

void save_all_stat_to_file()
{
	pthread_mutex_lock(&stat_busy);
	int i;
	for (i = 0; i < CS_MAXREADER; i++)
		save_stat_to_file(i);
	pthread_mutex_unlock(&stat_busy);
}

/**
 * Adds caid/prid/srvid to stat-list for reader ridx with time/rc
 */
void add_stat(int ridx, ushort caid, ulong prid, ushort srvid, int ecm_time, int rc)
{
	pthread_mutex_lock(&stat_busy);
	READER_STAT *stat = get_stat(ridx, caid, prid, srvid);
	if (!stat) {
		stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		stat->caid = caid;
		stat->prid = prid;
		stat->srvid = srvid;
		stat->time_avg = UNDEF_AVG_TIME; //dummy placeholder
		llist_append(reader_stat[ridx], stat);
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
		if (stat->time_idx >= MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = ecm_time;
		calc_stat(stat);

		//OLDEST READER now set by get best reader!
		
		
		//USAGELEVEL:
		int ule = reader[ridx].lb_usagelevel_ecmcount;
		if (ule > 0 && ((ule / cfg->lb_min_ecmcount) > 0)) //update every MIN_ECM_COUNT usagelevel:
		{
			time_t t = (time(NULL)-reader[ridx].lb_usagelevel_time);
			reader[ridx].lb_usagelevel = 1000/(t<1?1:t);
			ule = 0;
		}
		if (ule == 0)
			reader[ridx].lb_usagelevel_time = time(NULL);
		reader[ridx].lb_usagelevel_ecmcount = ule+1;
	}
	else if (rc == 4 || rc == 8 || rc == 9) { //not found+errors+etc
		stat->rc = rc;
		//stat->ecm_count = 0; Keep ecm_count!
		clear_from_cache(caid);
	}

	//cs_debug_mask(D_TRACE, "adding stat for reader %s (%d): rc %d caid %04hX prid %06lX srvid %04hX time %dms usagelevel %d",
	//			reader[ridx].label, ridx, rc, caid, prid, srvid, ecm_time, reader[ridx].lb_usagelevel);
	
	//debug only:
	if (cfg->lb_save) {
		stat_load_save++;
		if (stat_load_save > cfg->lb_save) {
			stat_load_save = 0;
			save_all_stat_to_file();
		}
	}
	pthread_mutex_unlock(&stat_busy);
}

/**
 * Adds to stat-list
 */
void add_reader_stat(ADD_READER_STAT *stat)
{
	add_stat(stat->ridx, stat->caid, stat->prid, stat->srvid, stat->time, stat->rc);
}

void reset_stat(ushort caid, ulong prid, ushort srvid)
{
	pthread_mutex_lock(&stat_busy);
	//cs_debug_mask(D_TRACE, "loadbalance: resetting ecm count");
	int i;
	for (i = 0; i < CS_MAXREADER; i++) {
		if (reader_stat[i] && reader[i].pid && reader[i].cidx) {
			READER_STAT *stat = get_stat(i, caid, prid, srvid);
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
int get_best_reader(GET_READER_STAT *grs, int *result)
{
	pthread_mutex_lock(&stat_busy);
	int i;
	i = chk_send_cache(grs->caid, grs->ecmd5);
	if (i >= 0) { //Found in cache, return same reader because he has the cached cws!
		memcpy(result, ecm_send_cache[i].readers, sizeof(int)*CS_MAXREADER);
		int best_ridx = ecm_send_cache[i].best_reader;
		cs_debug_mask(D_TRACE, "loadbalancer: client %s for %04X/%06X/%04X: %s readers: %d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d (cache)", 
			username(grs->cidx), grs->caid, grs->prid, grs->srvid,
			best_ridx<0?"NONE":reader[best_ridx].label,
			result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], 
			result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15]);

		pthread_mutex_unlock(&stat_busy);
		return best_ridx;
	}

	int re[CS_MAXREADER];

	//resulting readers:
	memset(result, 0, sizeof(int)*CS_MAXREADER);
	//resulting values:
	memset(re, 0, sizeof(re));

	struct timeb new_nulltime;
	memset(&new_nulltime, 0, sizeof(new_nulltime));
	time_t current_time = time(NULL);
	
	int current = -1;
	
	READER_STAT *stat = NULL;
	for (i = 0; i < CS_MAXREADER; i++) {
		if (grs->reader_avail[i]) {
 			int weight = reader[i].lb_weight <= 0?100:reader[i].lb_weight;
			stat = get_stat(i, grs->caid, grs->prid, grs->srvid);
			if (!stat) {
				cs_debug_mask(D_TRACE, "loadbalancer: starting statistics for reader %s", reader[i].label);
				add_stat(i, grs->caid,  grs->prid, grs->srvid, 1, -1);
				result[i] = 1; //no statistics, this reader is active (now) but we need statistics first!
				continue; 
			}
			
			if (stat->ecm_count < 0||(stat->ecm_count > cfg->lb_max_ecmcount && stat->time_avg > (int)cfg->ftimeout)) {
				cs_debug_mask(D_TRACE, "loadbalancer: max ecms (%d) reached by reader %s, resetting statistics", cfg->lb_max_ecmcount, reader[i].label);
				reset_stat(grs->caid, grs->prid, grs->srvid);
				result[i] = 1;//max ecm reached, get new statistics
				continue;
			}
				
			if (stat->rc == 0 && stat->ecm_count < cfg->lb_min_ecmcount) {
				cs_debug_mask(D_TRACE, "loadbalancer: reader %s needs more statistics", reader[i].label);
				stat->request_count++;
				//algo for finding unanswered requests (newcamd reader for example:)
				if (stat->request_count > cfg->lb_min_ecmcount) { //5 unanswered requests? 
					add_stat(i, grs->caid, grs->prid, grs->srvid, 1, 4); //reader marked as unuseable 
					result[i] = 0;
				}
				else
					result[i] = 1; //need more statistics!
				continue;
			}
				

			//Reader can decode this service (rc==0) and has lb_min_ecmcount ecms:
			if (stat->rc == 0) {
				//get
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
					if (!reader[i].lb_last.time)
						reader[i].lb_last = nulltime;
					current = (1000*(reader[i].lb_last.time-nulltime.time)+
						reader[i].lb_last.millitm-nulltime.millitm);
					if (!new_nulltime.time || (1000*(reader[i].lb_last.time-new_nulltime.time)+
						reader[i].lb_last.millitm-new_nulltime.millitm) < 0)
						new_nulltime = reader[i].lb_last;
					break;
				case LB_LOWEST_USAGELEVEL:
					current = reader[i].lb_usagelevel * 100 / weight;
					break;
				}
#ifdef WEBIF
				reader[i].lbvalue = current;
#endif
				if (!reader[i].ph.c_available
						|| reader[i].ph.c_available(i,
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
				if (!reader[i].audisabled && (!client[grs->cidx].autoau || client[grs->cidx].au != i))
					seconds = seconds/10;
				
				if (stat->last_received+seconds < current_time) { //Retrying reader every (900/conf) seconds
					stat->last_received = current_time;
					result[i] = 1;
					cs_log("loadbalancer: retrying reader %s", reader[i].label);
				}
			}
		}
	}

	int nbest_readers = cfg->lb_nbest_readers;
	int nfb_readers = cfg->lb_nfb_readers;
	int best_ridx = -1;

	nfb_readers += nbest_readers;

	int n=0;
	for (i=0;i<CS_MAXREADER;i++) {
		int best=0;
		int best_idx=-1;
		int j;
		for (j=0; j<CS_MAXREADER;j++) {
			if (re[j] && (!best || re[j] < best)) {
				best_idx=j;
				best=re[j];
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
				cs_ftime(&reader[best_idx].lb_last);
				if (best_ridx <0)
					best_ridx = best_idx;
			}
			else if (n<=nfb_readers) {
				if (!result[best_idx])
					result[best_idx] = 2;
			}
			else
				break;
		}
	}

	cs_debug_mask(D_TRACE, "loadbalancer: client %s for %04X/%06X/%04X: %s readers: %d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d", 
		username(grs->cidx), grs->caid, grs->prid, grs->srvid,
		best_ridx<0?"NONE":reader[best_ridx].label,
		result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], 
		result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15]);
	
	add_send_cache(grs->caid, grs->ecmd5, result, best_ridx); //add to cache
	
	if (new_nulltime.time)
		nulltime = new_nulltime;
		
	pthread_mutex_unlock(&stat_busy);
	
	return best_ridx;
}

/**
 * clears statistic of reader ridx.
 **/
void clear_reader_stat(int ridx)
{
	if (!reader_stat[ridx]) 
		return;

	pthread_mutex_lock(&stat_busy);
			
	LLIST_ITR itr;
	READER_STAT *stat = llist_itr_init(reader_stat[ridx], &itr);
	while (stat) {
		free(stat);
		stat = llist_itr_remove(&itr);
	}
	llist_destroy(reader_stat[ridx]);
	reader_stat[ridx] = NULL;
	
	pthread_mutex_unlock(&stat_busy);
}
