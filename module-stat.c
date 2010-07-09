#include "module-stat.h"

#define UNDEF_AVG_TIME 80000

void init_stat()
{
	memset(reader_stat, 0, sizeof(reader_stat));
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
		i = fscanf(file, "rc %d caid %04hX prid %04lX srvid %04hX time avg %dms ecms %d\n",
			&stat->rc, &stat->caid, &stat->prid, &stat->srvid, &stat->time_avg, &stat->ecm_count);
		if (i > 4) {
			stat->ecm_count = 0; //resetting ecm-count because some readers maybe offline or new readers exists
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
	if (reader_stat[ridx])
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
	if (!reader_stat[ridx]) {
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
		fprintf(file, "rc %d caid %04hX prid %04lX srvid %04hX time avg %dms ecms %d\n",
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
		if (stat->ecm_count < INT_MAX)
			stat->ecm_count++;

		stat->time_idx++;
		if (stat->time_idx >= MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = ecm_time;
		calc_stat(stat);

		//Usagelevel updaten:
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
		stat->ecm_count = 0;
	}

	cs_debug_mask(D_TRACE, "adding stat for reader %s (%d): rc %d caid %04hX prid %04lX srvid %04hX time %dms usagelevel %d",
				reader[ridx].label, ridx, rc, caid, prid, srvid, ecm_time, reader[ridx].lb_usagelevel);
	
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
	int i;
	for (i = 0; i < CS_MAXREADER; i++) {
		if (reader_stat[i] && reader[i].pid && reader[i].cs_idx) {
			READER_STAT *stat = get_stat(i, caid, prid, srvid);
			if (stat)
				stat->ecm_count = 0;
		}
	}
}


/**	
 * Gets best reader for caid/prid/srvid.
 * Best reader is evaluated by lowest avg time but only if ecm_count > MIN_ECM_COUNT (5)
 * Also the reader is asked if he is "available"
 * returns ridx when found or -1 when not found
 */
int get_best_reader(ushort caid, ulong prid, ushort srvid)
{
	int i;
	int best_ridx = -1;
	int best = 0, current = 0;
	time_t now = time(NULL);
	READER_STAT *stat, *best_stat = NULL;
	for (i = 0; i < CS_MAXREADER; i++) {
		if (reader_stat[i] && reader[i].pid && reader[i].cs_idx) {
			if (reader[i].tcp_connected || reader[i].card_status == CARD_INSERTED) {
	 			int weight = reader[i].lb_weight <= 0?100:reader[i].lb_weight;
				stat = get_stat(i, caid, prid, srvid);
				if (!stat) {
					add_stat(i, caid, prid, srvid, 1, 0);
					return -1; //this reader is active (now) but we need statistics first!
				}
			
				if (stat->ecm_count > MAX_ECM_COUNT) {
					reset_stat(caid, prid, srvid);
					return -1;
				}

				//Reader can decode this service (rc==0) and has MIN_ECM_COUNT ecms:
				if (stat->rc == 0 && stat->ecm_count >= MIN_ECM_COUNT) {
					//get
					switch (cfg->reader_auto_loadbalance) {
					case LB_NONE:
						return -1;
					case LB_FASTEST_READER_FIRST:
						current = stat->time_avg * 100 / weight;
						break;
					case LB_OLDEST_READER_FIRST:
						current = (now - client[reader[i].cs_idx].last) * 100 / weight;
						break;
					case LB_LOWEST_USAGELEVEL:
						current = reader[i].lb_usagelevel * 100 / weight;
						break;
					default:
						return -1;
					}

					if (!best_stat || current < best) {
						if (!reader[i].ph.c_available
								|| reader[i].ph.c_available(i,
										AVAIL_CHECK_LOADBALANCE)) {
							best_stat = stat;
							best_ridx = i;
							best = current;
						}
					}
				}
			}
		}
	}
	return best_ridx;
}
