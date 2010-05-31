#include "module-stat.h"

/**
 * get statistic values for reader ridx and caid/prid/srvid
 */
READER_STAT *get_stat(int ridx, ushort caid, ulong prid, ushort srvid)
{
	if (!reader_stat[ridx])
		reader_stat[ridx] = llist_create();

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
		stat->time_avg = 9999;
	else
		stat->time_avg = t / c;
}

/**
 * Saves statistik to /tmp/.oscam/stat.n where n is reader-index
 */
void save_stat_to_file(int ridx)
{
	char fname[40];
	sprintf(fname, "/tmp/.oscam/stat.%d", ridx);
	FILE *file = fopen(fname, "w");
	if (!file)
		return;
		
	LLIST_ITR itr;
	READER_STAT *stat = llist_itr_init(reader_stat[ridx], &itr);
	while (stat) {
	
		fprintf(file, "rc %d caid %04X prid %04lX srvid %04X time avg %dms\n", stat->rc, stat->caid, stat->prid, stat->srvid, stat->time_avg);
		stat = llist_itr_next(&itr);
	}
	fclose(file);
}

/**
 * Adds caid/prid/srvid to stat-list for reader ridx with time/rc
 */
void add_stat(int ridx, ushort caid, ulong prid, ushort srvid, int time, int rc)
{
	READER_STAT *stat = get_stat(ridx, caid, prid, srvid);
	if (!stat) {
		stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		stat->rc = rc;
		stat->caid = caid;
		stat->prid = prid;
		stat->srvid = srvid;
		stat->time_avg = time;
		stat->time_stat[0] = time;
		stat->ecm_count = 1;
		llist_append(reader_stat[ridx], stat);
	}
	else
	{
		stat->rc = rc;
		stat->time_idx++;
		if (stat->rc < 4)
			stat->ecm_count++;
		else
			stat->ecm_count = 0;
		if (stat->time_idx >= MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = time;
		calc_stat(stat);
	}
	
	//debug only:
	//save_stat_to_file(ridx);
}

/**
 * Adds to stat-list
 */
void add_reader_stat(ADD_READER_STAT *stat)
{
	add_stat(stat->ridx, stat->caid, stat->prid, stat->srvid, stat->time, stat->rc);
}

/**
 * Gets best reader for caid/prid/srvid.
 * reader is reader[] from shmem !
 * Best reader is evaluated by lowest avg time but only if ecm_count > MIN_ECM_COUNT (5)
 * Also the reader is asked if he is "available"
 * returns ridx when found or -1 when not found
 */
int get_best_reader(struct s_reader *reader, ushort caid, ulong prid, ushort srvid)
{
	int i;
	int best_ridx = -1;
	READER_STAT *stat, *best_stat = NULL;
	for (i = 0; i < CS_MAXREADER; i++) {
		if (reader_stat[i] && reader[i].pid && reader[i].cs_idx) {
			stat = get_stat(i, caid, prid, srvid);
			if (stat && stat->rc == 0 && (!best_stat || stat->time_avg < best_stat->time_avg)) {
				if (stat->ecm_count >= MIN_ECM_COUNT) {
					int cs_idx = reader[i].cs_idx;
					if (!ph[client[cs_idx].ctyp].c_available || ph[client[cs_idx].ctyp].c_available(i, stat)) {
						best_stat = stat;
						best_ridx = i;
					}
				}
			}
		}
	}
	return best_ridx;
}
