#include "module-stat.h"

#define UNDEF_AVG_TIME 80000

#define MAX_ECM_SEND_CACHE 8

time_t nulltime = 0;

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
	nulltime = time(NULL);
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

void load_stat_from_file(int ridx)
{
	char fname[40];
	sprintf(fname, "%s/stat.%d", get_tmp_dir(), ridx);
	FILE *file = fopen(fname, "r");
	if (!file)
		return;

	int i = 0;
	do
	{
		READER_STAT *stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		i = fscanf(file, "rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d\n",
			&stat->rc, &stat->caid, &stat->prid, &stat->srvid, &stat->time_avg, &stat->ecm_count);
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
	if (!reader_stat[ridx]) {
		reader_stat[ridx] = llist_create();
		if (cfg->reader_auto_loadbalance_save)
			load_stat_from_file(ridx);
	}

	LLIST_ITR itr;
	READER_STAT *stat = llist_itr_init(reader_stat[ridx], &itr);
	while (stat) {
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid)
			return stat;
		
		stat = llist_itr_next(&itr);
	}
	return NULL;
}

/**
 * removes caid/prid/srvid from stat-list of reader ridx
 */
int remove_stat(int ridx, ushort caid, ulong prid, ushort srvid)
{
	if (!reader_stat[ridx])
		return 0;

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
	return c;
}

/**
 * Calculates average time
 */
void calc_stat(READER_STAT *stat)
{
	int i;
	int c=0;
	int t = 0;
	for (i = 0; i < MAX_STAT_TIME; i++) {
		if (stat->time_stat[i] > 0) {
			t += stat->time_stat[i];
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
	char fname[40];
	sprintf(fname, "%s/stat.%d", get_tmp_dir(), ridx);
	if (!reader_stat[ridx] || !llist_count(reader_stat[ridx])) {
		remove(fname);
		return;
	}

	LLIST_ITR itr;
	READER_STAT *stat = llist_itr_init(reader_stat[ridx], &itr);

	if (!stat) {
		remove(fname);
		return;
	}
	
	FILE *file = fopen(fname, "w");
	if (!file)
		return;
		
	while (stat) {
		fprintf(file, "rc %d caid %04hX prid %06lX srvid %04hX time avg %dms ecms %d\n",
				stat->rc, stat->caid, stat->prid, stat->srvid, stat->time_avg, stat->ecm_count);
		stat = llist_itr_next(&itr);
	}
	fclose(file);
}

void save_all_stat_to_file()
{
	int i;
	for (i = 0; i < CS_MAXREADER; i++)
		save_stat_to_file(i);
}

/**
 * Adds caid/prid/srvid to stat-list for reader ridx with time/rc
 */
void add_stat(int ridx, ushort caid, ulong prid, ushort srvid, int ecm_time, int rc)
{
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
	if (rc == 0) {
		stat->rc = rc;
		stat->ecm_count++;
		stat->time_idx++;
		
		//FASTEST READER:
		if (stat->time_idx >= MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = ecm_time;
		calc_stat(stat);

		//OLDEST READER:
		if (rc == 0)
			reader[ridx].lb_last = time(NULL);
		
		//USAGELEVEL:
		int ule = reader[ridx].lb_usagelevel_ecmcount;
		if (ule > 0 && ((ule / MIN_ECM_COUNT) > 0)) //update every MIN_ECM_COUNT usagelevel:
		{
			time_t t = (time(NULL)-reader[ridx].lb_usagelevel_time);
			reader[ridx].lb_usagelevel = 1000/(t<1?1:t);
			ule = 0;
		}
		if (ule == 0)
			reader[ridx].lb_usagelevel_time = time(NULL);
		reader[ridx].lb_usagelevel_ecmcount = ule+1;
	}
	else if (rc >= 4 && rc < 100) { //not found+timeout+etc
		stat->rc = rc;
		//stat->ecm_count = 0; Keep ecm_count!
	}

	//cs_debug_mask(D_TRACE, "adding stat for reader %s (%d): rc %d caid %04hX prid %06lX srvid %04hX time %dms usagelevel %d",
	//			reader[ridx].label, ridx, rc, caid, prid, srvid, ecm_time, reader[ridx].lb_usagelevel);
	
	//debug only:
	if (cfg->reader_auto_loadbalance_save) {
		stat_load_save++;
		if (stat_load_save > cfg->reader_auto_loadbalance_save) {
			stat_load_save = 0;
			save_all_stat_to_file();
		}
	}
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
	//cs_debug_mask(D_TRACE, "loadbalance: resetting ecm count");
	int i;
	for (i = 0; i < CS_MAXREADER; i++) {
		if (reader_stat[i] && reader[i].pid && reader[i].cs_idx) {
			READER_STAT *stat = get_stat(i, caid, prid, srvid);
			if (stat) {
				if (stat->ecm_count > 0)
					stat->ecm_count = 1; //not zero, so we know it's decodeable
				stat->rc = 0;
			}
		}
	}
}


/**	
 * Gets best reader for caid/prid/srvid.
 * Best reader is evaluated by lowest avg time but only if ecm_count > MIN_ECM_COUNT (5)
 * Also the reader is asked if he is "available"
 * returns ridx when found or -1 when not found
 * ONLY FROM MASTER THREAD!
 */
int get_best_reader(GET_READER_STAT *grs, int *result)
{
	int i;
	i = chk_send_cache(grs->caid, grs->ecmd5);
	if (i >= 0) { //Found in cache, return same reader because he has the cached cws!
		memcpy(result, ecm_send_cache[i].readers, sizeof(int)*CS_MAXREADER);
		return ecm_send_cache[i].best_reader;
	}

	//resulting readers:
	memset(result, 0, sizeof(int)*CS_MAXREADER);
	
	int best_ridx = -1, best_ridx2 = -1;
	int best = 0, best2 = 0;
	int current = -1;
	READER_STAT *stat = NULL;
	for (i = 0; i < CS_MAXREADER; i++) {
		if (grs->reader_avail[i]) {
 			int weight = reader[i].lb_weight <= 0?100:reader[i].lb_weight;
			stat = get_stat(i, grs->caid, grs->prid, grs->srvid);
			if (!stat) {
				//cs_debug_mask(D_TRACE, "loadbalance: starting statistics for reader %s", reader[i].label);
				add_stat(i, grs->caid,  grs->prid, grs->srvid, 1, -1);
				result[i] = 1; //no statistics, this reader is active (now) but we need statistics first!
				continue; 
			}
			
			if (stat->ecm_count > MAX_ECM_COUNT && stat->time_avg > (int)cfg->ftimeout) {
				//cs_debug_mask(D_TRACE, "loadbalance: max ecms (%d) reached by reader %s, resetting statistics", MAX_ECM_COUNT, reader[i].label);
				reset_stat(grs->caid, grs->prid, grs->srvid);
				result[i] = 1;//max ecm reached, get new statistics
				continue;
			}
				
			if (stat->rc == 0 && stat->ecm_count < MIN_ECM_COUNT) {
				//cs_debug_mask(D_TRACE, "loadbalance: reader %s needs more statistics", reader[i].label);
				result[i] = 1; //need more statistics!
				continue;
			}
				

			//Reader can decode this service (rc==0) and has MIN_ECM_COUNT ecms:
			if (stat->rc == 0) {
				//get
				switch (cfg->reader_auto_loadbalance) {
				default:
				case LB_NONE:
					//cs_debug_mask(D_TRACE, "loadbalance disabled");
					result[i] = 1;
					break;
				case LB_FASTEST_READER_FIRST:
					current = stat->time_avg * 100 / weight;
					break;
				case LB_OLDEST_READER_FIRST:
					current = (reader[i].lb_last-nulltime) * 100 / weight;
					break;
				case LB_LOWEST_USAGELEVEL:
					current = reader[i].lb_usagelevel * 100 / weight;
					break;
				}
#ifdef WEBIF
				reader[i].lbvalue = current;
#endif

				//cs_debug_mask(D_TRACE, "loadbalance reader %s value %d", reader[i].label, current);
				if (best_ridx==-1 || current < best) {
					if (!reader[i].ph.c_available
							|| reader[i].ph.c_available(i,
									AVAIL_CHECK_LOADBALANCE)) {
						best_ridx = i;
						best = current;
					}
				}
				if (best_ridx2==-1 || current < best2) {
					best_ridx2 = i;
					best2 = current;
				}
			}
			else if (stat->rc >= 4 && stat->ecm_count == 0) //Never decodeable
				grs->reader_avail[i] = 0;
		}
	}
	if (best_ridx == -1)
		best_ridx = best_ridx2;
	if (best_ridx >= 0) {
		//cs_debug_mask(D_TRACE, "-->loadbalance best reader %s (%d) best value %d", reader[best_ridx].label, best_ridx, best2);
		result[best_ridx] = 1;
	}
	//else
		//cs_debug_mask(D_TRACE, "-->loadbalance no best reader!");
		
	//setting all other readers as fallbacks:
	for (i=0;i<CS_MAXREADER; i++)
		if (grs->reader_avail[i] && !result[i])
			result[i] = 2;
			
	cs_debug_mask(D_TRACE, "loadbalance best reader: %s readers: %d%d%d%d%d%d%d%d%d%d", 
		best_ridx<0?"NONE":reader[best_ridx].label,
		result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], result[9]);
	
	add_send_cache(grs->caid, grs->ecmd5, result, best_ridx); //add to cache
	
	return best_ridx;
}
