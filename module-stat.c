#include "globals.h"

#ifdef WITH_LB
#include "cscrypt/md5.h"
#include "module-cacheex.h"
#include "module-cccam.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-files.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-time.h"

#define UNDEF_AVG_TIME 80000
#define MAX_ECM_SEND_CACHE 16

#define LB_REOPEN_MODE_STANDARD 0
#define LB_REOPEN_MODE_FAST 1

#define LB_NONE 0
#define LB_FASTEST_READER_FIRST 1
#define LB_OLDEST_READER_FIRST 2
#define LB_LOWEST_USAGELEVEL 3
#define LB_LOG_ONLY 10

#define DEFAULT_LOCK_TIMEOUT 1000

static int32_t stat_load_save;
static time_t last_housekeeping = 0;

void init_stat(void)
{
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

#define LINESIZE 1024

static uint32_t get_prid(uint16_t caid, uint32_t prid)
{
	int32_t i;
	for (i=0;i<CS_MAXCAIDTAB;i++) {
		uint16_t tcaid = cfg.lb_noproviderforcaid.caid[i];
		if (!tcaid) break;
		if ((tcaid == caid) || (tcaid < 0x0100 && (caid >> 8) == tcaid)) {
			prid = 0;
			break;
		}

	}
	return prid;
}

static uint32_t get_subid(ECM_REQUEST *er)
{
	if (!er->ecmlen)
		return 0;

	uint32_t id = 0;
	switch (er->caid>>8)
	{
		case 0x01: id = b2i(2, er->ecm+7); break;
		case 0x06: id = b2i(2, er->ecm+6); break;
		case 0x09: id = b2i(2, er->ecm+11); break;
		case 0x4A: // DRE-Crypt, Bulcrypt, others?
			if (er->caid != 0x4AEE) // Bulcrypt
				id = er->ecm[7];
			break;
	}
	return id;
}


static void get_stat_query(ECM_REQUEST *er, STAT_QUERY *q)
{
	memset(q, 0, sizeof(STAT_QUERY));

	q->caid = er->caid;
	q->prid = get_prid(er->caid, er->prid);
	q->srvid = er->srvid;
	q->chid = get_subid(er);
	q->ecmlen = er->ecmlen;
}

void load_stat_from_file(void)
{
	stat_load_save = 0;
	char buf[256];
	char *line;
	char *fname;
	FILE *file;

	if (!cfg.lb_savepath) {
		get_tmp_dir_filename(buf, sizeof(buf), "stat");
		fname = buf;
	}
	else
		fname = cfg.lb_savepath;

	file = fopen(fname, "r");

	if (!file) {
		cs_log("loadbalancer: can't read from file %s", fname);
		return;
	}
	
	if (!cs_malloc(&line, LINESIZE)) {
		fclose(file);
		return;
	}

	setvbuf(file, NULL, _IOFBF, 128*1024);

	cs_debug_mask(D_LB, "loadbalancer: load statistics from %s", fname);

	struct timeb ts, te;
    cs_ftime(&ts);

	struct s_reader *rdr = NULL;
	READER_STAT *s;

	int32_t i=1;
	int32_t valid=0;
	int32_t count=0;
	int32_t type=0;
	char *ptr, *saveptr1 = NULL;
	char *split[12];

	while (fgets(line, LINESIZE, file))
	{
		if (!line[0] || line[0] == '#' || line[0] == ';')
			continue;

		if (!cs_malloc(&s, sizeof(READER_STAT)))
			continue;

		//get type by evaluating first line:
		if (type==0) {
			if (strstr(line, " rc ")) type = 2;
			else type = 1;
		}

		if (type==1) { //New format - faster parsing:
			for (i = 0, ptr = strtok_r(line, ",", &saveptr1); ptr && i<12 ; ptr = strtok_r(NULL, ",", &saveptr1), i++)
				split[i] = ptr;
			valid = (i==11);
			if (valid) {
				strncpy(buf, split[0], sizeof(buf)-1);
				s->rc = atoi(split[1]);
				s->caid = a2i(split[2], 4);
				s->prid = a2i(split[3], 6);
				s->srvid = a2i(split[4], 4);
				s->chid = a2i(split[5], 4);
				s->time_avg = atoi(split[6]);
				s->ecm_count = atoi(split[7]);
				s->last_received = atol(split[8]);
				s->fail_factor = atoi(split[9]);
				s->ecmlen = a2i(split[10], 2);
			}
		} else { //Old format - keep for compatibility:
			i = sscanf(line, "%255s rc %04d caid %04hX prid %06X srvid %04hX time avg %dms ecms %d last %ld fail %d len %02hX\n",
				buf, &s->rc, &s->caid, &s->prid, &s->srvid,
				&s->time_avg, &s->ecm_count, &s->last_received, &s->fail_factor, &s->ecmlen);
			valid = i>5;
		}

		if (valid && s->ecmlen > 0) {
			if (rdr == NULL || strcmp(buf, rdr->label) != 0) {
				LL_ITER itr = ll_iter_create(configured_readers);
				while ((rdr=ll_iter_next(&itr))) {
					if (strcmp(rdr->label, buf) == 0) {
						break;
					}
				}
			}

			if (rdr != NULL && strcmp(buf, rdr->label) == 0) {
				if (!rdr->lb_stat) {
					rdr->lb_stat = ll_create("lb_stat");
					cs_lock_create(&rdr->lb_stat_lock, DEFAULT_LOCK_TIMEOUT, rdr->label);
				}

				ll_append(rdr->lb_stat, s);
				count++;
			}
			else
			{
				cs_log("loadbalancer: statistics could not be loaded for %s", buf);
				free(s);
			}
		}
		else
		{
			cs_debug_mask(D_LB, "loadbalancer: statistics ERROR: %s rc=%d i=%d", buf, s->rc, i);
			free(s);
		}
	}
	fclose(file);
	free(line);

    cs_ftime(&te);
#ifdef WITH_DEBUG
	int32_t load_time = 1000*(te.time-ts.time)+te.millitm-ts.millitm;

	cs_debug_mask(D_LB, "loadbalancer: statistics loaded %d records in %dms", count, load_time);
#endif
}

/**
 * get statistic values for reader ridx and caid/prid/srvid/ecmlen
 **/
static READER_STAT *get_stat_lock(struct s_reader *rdr, STAT_QUERY *q, int8_t lock)
{
	if (!rdr->lb_stat) {
		rdr->lb_stat = ll_create("lb_stat");
		cs_lock_create(&rdr->lb_stat_lock, DEFAULT_LOCK_TIMEOUT, rdr->label);
	}

	if (lock) cs_readlock(&rdr->lb_stat_lock);

	LL_ITER it = ll_iter_create(rdr->lb_stat);
	READER_STAT *s;
	int32_t i = 0;
	while ((s = ll_iter_next(&it))) {
		i++;
		if (s->caid==q->caid && s->prid==q->prid && s->srvid==q->srvid && s->chid==q->chid) {
			if (s->ecmlen == q->ecmlen)
				break;
			if (!s->ecmlen) {
				s->ecmlen = q->ecmlen;
				break;
			}
			if (!q->ecmlen) //Query without ecmlen from dvbapi
				break;
		}
	}
	if (lock) cs_readunlock(&rdr->lb_stat_lock);

	//Move stat to list start for faster access:
//	if (i > 10 && s) {
//		if (lock) cs_writelock(&rdr->lb_stat_lock);
//		ll_iter_move_first(&it);
//		if (lock) cs_writeunlock(&rdr->lb_stat_lock);
//	} Corsair removed, could cause crashes!

	return s;
}

/**
 * get statistic values for reader ridx and caid/prid/srvid/ecmlen
 **/
static READER_STAT *get_stat(struct s_reader *rdr, STAT_QUERY *q)
{
	return get_stat_lock(rdr, q, 1);
}

/**
 * Calculates average time
 */
static void calc_stat(READER_STAT *s)
{
	int32_t i, c=0, t = 0;
	for (i = 0; i < LB_MAX_STAT_TIME; i++) {
		if (s->time_stat[i] > 0) {
			t += (int32_t)s->time_stat[i];
			c++;
		}
	}
	if (!c)
		s->time_avg = UNDEF_AVG_TIME;
	else
		s->time_avg = t / c;
}

/**
 * Saves statistik to /tmp/.oscam/stat.n where n is reader-index
 */
static void save_stat_to_file_thread(void)
{
	stat_load_save = 0;
	char buf[256];

	set_thread_name(__func__);

	char *fname;
	if (!cfg.lb_savepath) {
		get_tmp_dir_filename(buf, sizeof(buf), "stat");
		fname = buf;
	}
	else
		fname = cfg.lb_savepath;

	FILE *file = fopen(fname, "w");

	if (!file) {
		cs_log("can't write to file %s", fname);
		return;
	}

	setvbuf(file, NULL, _IOFBF, 128*1024);

	struct timeb ts, te;
    cs_ftime(&ts);

	time_t cleanup_time = time(NULL) - (cfg.lb_stat_cleanup*60*60);

	int32_t count=0;
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while ((rdr=ll_iter_next(&itr))) {

		if (rdr->lb_stat) {
			cs_writelock(&rdr->lb_stat_lock);
			LL_ITER it = ll_iter_create(rdr->lb_stat);
			READER_STAT *s;
			while ((s = ll_iter_next(&it))) {

				if (s->last_received < cleanup_time || !s->ecmlen) { //cleanup old stats
					ll_iter_remove_data(&it);
					continue;
				}

				//Old version, too slow to parse:
				//fprintf(file, "%s rc %d caid %04hX prid %06X srvid %04hX time avg %dms ecms %d last %ld fail %d len %02hX\n",
				//	rdr->label, s->rc, s->caid, s->prid,
				//	s->srvid, s->time_avg, s->ecm_count, s->last_received, s->fail_factor, s->ecmlen);

				//New version:
				fprintf(file, "%s,%d,%04hX,%06X,%04hX,%04hX,%d,%d,%ld,%d,%02hX\n",
					rdr->label, s->rc, s->caid, s->prid,
					s->srvid, (uint16_t)s->chid, s->time_avg, s->ecm_count, s->last_received, s->fail_factor, s->ecmlen);

				count++;
//				if (count % 500 == 0) { //Saving stats is using too much cpu and causes high file load. so we need a break
//					cs_readunlock(&rdr->lb_stat_lock);
//					cs_sleepms(100);
//					cs_readlock(&rdr->lb_stat_lock);
//				}
			}
			cs_writeunlock(&rdr->lb_stat_lock);
		}
	}

	fclose(file);

    cs_ftime(&te);
	int32_t load_time = 1000*(te.time-ts.time)+te.millitm-ts.millitm;


	cs_log("loadbalancer: statistic saved %d records to %s in %dms", count, fname, load_time);
}

void save_stat_to_file(int32_t thread)
{
	stat_load_save = 0;
	if (thread)
		start_thread((void*)&save_stat_to_file_thread, "save lb stats");
	else
		save_stat_to_file_thread();
}

/**
 * fail_factor is multiplied to the reopen_time. This function increases the fail_factor
 **/
static void inc_fail(READER_STAT *s)
{
	if (s->fail_factor <= 0)
		s->fail_factor = 1;
	else
		s->fail_factor *= 2;
}

static READER_STAT *get_add_stat(struct s_reader *rdr, STAT_QUERY *q)
{
	if (!rdr->lb_stat) {
		rdr->lb_stat = ll_create("lb_stat");
		cs_lock_create(&rdr->lb_stat_lock, DEFAULT_LOCK_TIMEOUT, rdr->label);
	}

	cs_writelock(&rdr->lb_stat_lock);

	READER_STAT *s = get_stat_lock(rdr, q, 0);
	if (!s) {
		if (cs_malloc(&s,sizeof(READER_STAT))) {
			s->caid = q->caid;
			s->prid = q->prid;
			s->srvid = q->srvid;
			s->chid = q->chid;
			s->ecmlen = q->ecmlen;
			s->time_avg = UNDEF_AVG_TIME; //dummy placeholder
			s->rc = E_NOTFOUND;
			s->last_received = time(NULL);
			ll_append(rdr->lb_stat, s);
		}
	}

	if (s->ecm_count < 0)
		s->ecm_count=0;

	cs_writeunlock(&rdr->lb_stat_lock);

	return s;
}

static void housekeeping_stat(int32_t force);

/**
 * Adds caid/prid/srvid/ecmlen to stat-list for reader ridx with time/rc
 */
static void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int32_t ecm_time, int32_t rc)
{
	if (!rdr || !er || !cfg.lb_mode ||!er->ecmlen || !er->client)
		return;

	struct s_client *cl = rdr->client;
	if (!cl)
		return;

	READER_STAT *s;

	//inc ecm_count if found, drop to 0 if not found:
	// rc codes:
	// 0 = found       +
	// 1 = cache1      #
	// 2 = cache2      #
	// 3 = cacheex     #
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


	if (rc == E_NOTFOUND && (uint32_t)ecm_time >= cfg.ctimeout) //Map "not found" to "timeout" if ecm_time>client time out
		rc = E_TIMEOUT;

	if ((uint32_t)ecm_time >= 3*cfg.ctimeout) //ignore too old ecms
		return;

	STAT_QUERY q;
	get_stat_query(er, &q);

	time_t now = time(NULL);

	if (rc == E_FOUND) { //found
		s = get_add_stat(rdr, &q);
		s->rc = E_FOUND;
		s->ecm_count++;
		s->last_received = now;
		s->fail_factor = 0;

		//FASTEST READER:
		s->time_idx++;
		if (s->time_idx >= LB_MAX_STAT_TIME)
			s->time_idx = 0;
		s->time_stat[s->time_idx] = ecm_time;
		calc_stat(s);

		//OLDEST READER now set by get best reader!


		//USAGELEVEL:
		/* Assign a value to rdr->lb_usagelevel_ecmcount,
		because no determined value was assigned before. */
		if (rdr->lb_usagelevel_ecmcount < 0)
			rdr->lb_usagelevel_ecmcount = 0;

		rdr->lb_usagelevel_ecmcount++; /* ecm is found so counter should increase */
		if ((rdr->lb_usagelevel_ecmcount % cfg.lb_min_ecmcount) == 0) //update every MIN_ECM_COUNT usagelevel:
		{
			time_t t = (now - rdr->lb_usagelevel_time);
			rdr->lb_usagelevel = 1000 / (t<1?1:t);
			/* Reset of usagelevel time and counter */
			rdr->lb_usagelevel_time = now;
			rdr->lb_usagelevel_ecmcount = 0;
		}

	}
	else if (rc < E_NOTFOUND ) { //cache1+2+3
		//no increase of statistics here, cachetime is not real time
		s = get_stat(rdr, &q);
		if (s != NULL)
			s->last_received = now;
		return;
	}
	else if (rc == E_NOTFOUND||rc == E_INVALID) { //not found / invalid
		//special rcEx codes means temporary problems, so do not block!
		//CCcam card can't decode, 0x28=NOK1, 0x29=NOK2
		//CCcam loop detection = E2_CCCAM_LOOP
		if (er->rcEx >= LB_NONBLOCK_E2_FIRST) {
			s = get_stat(rdr, &q);
			if (s != NULL)
				s->last_received = now; //to avoid timeouts
			return;
		}

		s = get_add_stat(rdr, &q);
		if (s->rc == E_NOTFOUND) { //we have already "not found", so we change the time. In some cases (with services/ident set) the failing reader is selected again:
			if (ecm_time < 100)
				ecm_time = 100;
			s->time_avg += ecm_time;
		}

		if (s->ecm_count > cfg.lb_min_ecmcount) //there were many founds? Do not close, give them another chance
			s->ecm_count = 0;
		else
			s->rc = rc;

		inc_fail(s);
		s->last_received = now;

		//reduce ecm_count step by step
		if (!cfg.lb_reopen_mode)
			s->ecm_count /= 10;
	}
	else if (rc == E_TIMEOUT) { //timeout
		s = get_add_stat(rdr, &q);

		//catch suddenly occuring timeouts and block reader:
//		if ((int)(now-s->last_received) < (int)(5*cfg.ctimeout) &&
//				s->rc == E_FOUND && s->ecm_count == 0) {
//			s->rc = E_TIMEOUT;
//				//inc_fail(s); //do not inc fail factor in this case
//		}
		//reader is longer than 5s connected && not more then 5 pending ecms:
//		else if ((cl->login+(int)(2*cfg.ctimeout/1000)) < now && cl->pending < 5 &&
//				s->rc == E_FOUND && s->ecm_count == 0) {
//			s->rc = E_TIMEOUT;
//			inc_fail(s);
//		}
//		else
		if (!s->ecm_count)
			s->rc = E_TIMEOUT;
		else if (s->rc == E_FOUND && now > s->last_received+1) {
			//search for alternate readers. If we have one, block this reader:
			int8_t n = 0;
			struct s_ecm_answer *ea;
			for (ea = er->matching_rdr; ea; ea = ea->next) {
				if (ea->reader != rdr && ea->rc < E_NOTFOUND){
					n = 1;
					break;
				}
			}
			if (n > 0) //We have alternative readers, so we can block this one:
				s->rc = E_TIMEOUT;
			else { //No other reader found. Inc fail factor and retry lb_min_ecmount times:
				inc_fail(s);
				if (s->fail_factor > cfg.lb_min_ecmcount) {
					s->fail_factor = 0;
					s->rc = E_TIMEOUT;
				}
			}
		}

		s->last_received = now;

		//add timeout to s:
		if (ecm_time<=0 || ecm_time > (int)cfg.ctimeout)
			ecm_time = cfg.ctimeout;
		s->time_idx++;
		if (s->time_idx >= LB_MAX_STAT_TIME)
			s->time_idx = 0;
		s->time_stat[s->time_idx] = ecm_time;
		calc_stat(s);
	}
	else
	{
#ifdef WITH_DEBUG
		if (rc >= E_FOUND && (D_LB & cs_dblevel)) {
			char buf[ECM_FMT_LEN];
			format_ecm(er, buf, ECM_FMT_LEN);
			cs_debug_mask(D_LB, "loadbalancer: not handled stat for reader %s: rc %d %s time %dms",
				rdr->label, rc, buf, ecm_time);
		}
#endif
		return;
	}

	housekeeping_stat(0);

#ifdef WITH_DEBUG
	if (D_LB & cs_dblevel) {
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_debug_mask(D_LB, "loadbalancer: adding stat for reader %s: rc %d %s time %dms fail %d",
					rdr->label, rc, buf, ecm_time, s->fail_factor);
	}
#endif

	if (cfg.lb_save) {
		stat_load_save++;
		if (stat_load_save > cfg.lb_save)
			save_stat_to_file(1);
	}
}

static void reset_stat(STAT_QUERY *q)
{
	//cs_debug_mask(D_LB, "loadbalance: resetting ecm count");
	struct s_reader *rdr;
	cs_readlock(&readerlist_lock);
	for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
		if (rdr->lb_stat && rdr->client) {
			READER_STAT *s = get_stat(rdr, q);
			if (s) {
				if (s->ecm_count > 0)
					s->ecm_count = 1; //not zero, so we know it's decodeable
				s->rc = E_FOUND;
				s->fail_factor = 0;
			}
		}
	}
	cs_readunlock(&readerlist_lock);
}

int32_t clean_stat_by_rc(struct s_reader *rdr, int8_t rc, int8_t inverse)
{
	int32_t count = 0;
	if (rdr && rdr->lb_stat) {
		cs_writelock(&rdr->lb_stat_lock);
		READER_STAT *s;
		LL_ITER itr = ll_iter_create(rdr->lb_stat);
		while ((s = ll_iter_next(&itr))) {
			if ((!inverse && s->rc == rc) || (inverse && s->rc != rc)) {
				ll_iter_remove_data(&itr);
				count++;
			}
		}
		cs_writeunlock(&rdr->lb_stat_lock);
	}
	return count;
}

int32_t clean_all_stats_by_rc(int8_t rc, int8_t inverse)
{
	int32_t count = 0;
	LL_ITER itr = ll_iter_create(configured_readers);
	struct s_reader *rdr;
	while ((rdr = ll_iter_next(&itr))) {
		count += clean_stat_by_rc(rdr, rc, inverse);
	}
	save_stat_to_file(0);
	return count;
}

int32_t clean_stat_by_id(struct s_reader *rdr, uint16_t caid, uint32_t prid, uint16_t srvid, uint16_t chid, uint16_t ecmlen)
{
	int32_t count = 0;
	if (rdr && rdr->lb_stat) {

		cs_writelock(&rdr->lb_stat_lock);
		READER_STAT *s;
		LL_ITER itr = ll_iter_create(rdr->lb_stat);
		while ((s = ll_iter_next(&itr))) {
			if (s->caid == caid &&
					s->prid == prid &&
					s->srvid == srvid &&
					s->chid == chid &&
					s->ecmlen == ecmlen) {
				ll_iter_remove_data(&itr);
				count++;
				break; // because the entry should unique we can left here
			}
		}
		cs_writeunlock(&rdr->lb_stat_lock);
	}
	return count;
}


static int32_t has_ident(FTAB *ftab, ECM_REQUEST *er) {

	if (!ftab || !ftab->filts)
		return 0;

	int32_t j, k;

	for (j = 0; j < ftab->nfilts; j++) {
		if (ftab->filts[j].caid) {
			if (ftab->filts[j].caid==er->caid) { //caid matches!
				int32_t nprids = ftab->filts[j].nprids;
				if (!nprids) // No Provider ->Ok
					return 1;

				for (k = 0; k < nprids; k++) {
					uint32_t prid = ftab->filts[j].prids[k];
					if (prid == er->prid) { //Provider matches
						return 1;
					}
				}
			}
		}
	}
    return 0; //No match!
}

static int32_t get_retrylimit(ECM_REQUEST *er) {
		int32_t i;
		for (i = 0; i < cfg.lb_retrylimittab.n; i++) {
				if (cfg.lb_retrylimittab.caid[i] == er->caid || cfg.lb_retrylimittab.caid[i] == er->caid>>8)
						return cfg.lb_retrylimittab.value[i];
		}
		return cfg.lb_retrylimit;
}

static int32_t get_nbest_readers(ECM_REQUEST *er) {
		int32_t i;
		for (i = 0; i < cfg.lb_nbest_readers_tab.n; i++) {
				if (cfg.lb_nbest_readers_tab.caid[i] == er->caid || cfg.lb_nbest_readers_tab.caid[i] == er->caid>>8)
						return cfg.lb_nbest_readers_tab.value[i];
		}
		return cfg.lb_nbest_readers;
}

static time_t get_reopen_seconds(READER_STAT *s)
{
		int32_t max = (INT_MAX / cfg.lb_reopen_seconds);
		if (max > 9999) max = 9999;
		if (s->fail_factor > max)
				s->fail_factor = max;
		if (!s->fail_factor)
			return cfg.lb_reopen_seconds;
		return (time_t)s->fail_factor * (time_t)cfg.lb_reopen_seconds;
}

static void convert_to_beta_int(ECM_REQUEST *er, uint16_t caid_to)
{
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	convert_to_beta(er->client, er, caid_to);
	// update ecmd5 for store ECM in cache
	memcpy(er->ecmd5, MD5(er->ecm+13, er->ecmlen-13, md5tmp), CS_ECMSTORESIZE);
	cacheex_update_hash(er);
	er->btun = 2; //marked as auto-betatunnel converted. Also for fixing recursive lock in get_cw
}


static void convert_to_nagra_int(ECM_REQUEST *er, uint16_t caid_to)
{
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	convert_to_nagra(er->client, er, caid_to);
	// update ecmd5 for store ECM in cache
	memcpy(er->ecmd5, MD5(er->ecm+3, er->ecmlen-3, md5tmp), CS_ECMSTORESIZE);
	cacheex_update_hash(er);
	er->btun = 2; //marked as auto-betatunnel converted. Also for fixing recursive lock in get_cw
}

uint16_t get_betatunnel_caid_to(uint16_t caid){
	int32_t lbbm = cfg.lb_auto_betatunnel_mode;
	if (lbbm <=3) {
		if (caid == 0x1801) return 0x1722;
		if (caid == 0x1833) return 0x1702;
		if (caid == 0x1834) return 0x1722;
		if (caid == 0x1835) return 0x1722;
	}
	if (lbbm >=1) {
		if (caid == 0x1702) return 0x1833;
	}
	if (lbbm == 1 || lbbm == 4 ) {
		if (caid == 0x1722) return 0x1801;
	} else if (lbbm == 2 || lbbm == 5 ) {
		if (caid == 0x1722) return 0x1834;
	} else if (lbbm == 3 || lbbm == 6 ) {
		if (caid == 0x1722) return 0x1835;
	}
	return 0;
}

void check_lb_auto_betatunnel_mode(ECM_REQUEST *er) {
	int32_t lbbm = cfg.lb_auto_betatunnel_mode;
	if ( lbbm == 1 || lbbm == 4) {
		er->caid = 0x1801;
	} else if ( lbbm == 2 || lbbm == 5) {
		er->caid = 0x1834;
	} else if ( lbbm == 3 || lbbm == 6) {
		er->caid = 0x1835;
	}
	////no other way to autodetect is 1801,1834 or 1835
}

uint16_t get_rdr_caid(struct s_reader *rdr) {
	  if (is_network_reader(rdr)) {
		  return 0; //reader caid is not real caid
	  } else {
		  return rdr->caid;
	  }
}

uint16_t is_betatunnel_caid(uint16_t caid){
	if (caid == 0x1702 || caid == 0x1722 || caid == 0x1801 || caid == 0x1833 || caid == 0x1834 || caid == 0x1835) return 1;
	return 0;
}

/**
 * Gets best reader for caid/prid/srvid/ecmlen.
 * Best reader is evaluated by lowest avg time but only if ecm_count > cfg.lb_min_ecmcount (5)
 * Also the reader is asked if he is "available"
 * returns ridx when found or -1 when not found
 */
void stat_get_best_reader(ECM_REQUEST *er)
{
	if (!cfg.lb_mode || cfg.lb_mode==LB_LOG_ONLY)
		return;

	if (!er->reader_avail)
		return;

	struct s_reader *rdr;
	struct s_ecm_answer *ea;

	//preferred card forwarding (CCcam client):
	if (cccam_forward_origin_card(er))
		return;

	STAT_QUERY q;
	get_stat_query(er, &q);

	//auto-betatunnel: The trick is: "let the loadbalancer decide"!
	if (cfg.lb_auto_betatunnel && er->caid >> 8 == 0x18 && er->ecmlen) { //nagra
		uint16_t caid_to = get_betatunnel_caid_to(er->caid);
		if (caid_to) {
			int8_t needs_stats_nagra = 1, needs_stats_beta = 1;

			//Clone query parameters for beta:
			STAT_QUERY qbeta = q;
			qbeta.caid = caid_to;
			qbeta.prid = 0;
			qbeta.ecmlen = er->ecm[2] + 3 + 10;

			int32_t time_nagra = 0;
			int32_t time_beta = 0;
			int32_t weight;
			int32_t ntime;

			READER_STAT *stat_nagra = NULL;
			READER_STAT *stat_beta = NULL;

			//What is faster? nagra or beta?
			int8_t isn;
			int8_t isb;
			int8_t overall_valid = 0;
			int8_t overall_nvalid = 0;
			for(ea = er->matching_rdr; ea; ea = ea->next) {
				isn = 0;
				isb = 0;
				rdr = ea->reader;
				weight = rdr->lb_weight;
				if (weight <= 0) weight = 1;


				//Check if betatunnel is allowed on this reader:
				int8_t valid = chk_ctab(caid_to, &rdr->ctab) //Check caid
					&& chk_rfilter2(caid_to, 0, rdr) //Ident
					&& chk_srvid_by_caid_prov_rdr(rdr, caid_to, 0) //Services
					&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr,caid_to)); //rdr-caid
				if (valid) {
					stat_beta = get_stat(rdr, &qbeta);
					overall_valid = 1;
				}
				//else
					//stat_beta = NULL;

				//Check if nagra is allowed on this reader:
				int8_t nvalid = chk_ctab(er->caid, &rdr->ctab)//Check caid
					&& chk_rfilter2(er->caid, 0, rdr) //Ident
					&& chk_srvid_by_caid_prov_rdr(rdr, er->caid, 0) //Services
					&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr,er->caid)); //rdr-caid
				if (nvalid) {
					stat_nagra = get_stat(rdr, &q);
					overall_nvalid = 1;
				}

				//calculate nagra data:
				if (stat_nagra && stat_nagra->rc == E_FOUND) {
					ntime = stat_nagra->time_avg*100/weight;
					if (!time_nagra || ntime < time_nagra)
						time_nagra = ntime;
				}

				//calculate beta data:
				if (stat_beta && stat_beta->rc == E_FOUND) {
					ntime = stat_beta->time_avg*100/weight;
					if (!time_beta || ntime < time_beta)
						time_beta = ntime;
				}

				//Uncomplete reader evaluation, we need more stats!
				if (stat_nagra){
					needs_stats_nagra = 0;
					isn = 1;
				}
				if (stat_beta){
					needs_stats_beta = 0;
					isb = 1;
				}
				cs_debug_mask(D_LB, "loadbalancer-betatunnel valid %d, stat_nagra %d, stat_beta %d, (%04X,%04X)", valid, isn, isb ,get_rdr_caid(rdr),caid_to);
			}

			if (!overall_valid)//we have no valid betatunnel reader also we don't needs stats (converted)
				needs_stats_beta = 0;

			if (!overall_nvalid) //we have no valid reader also we don't needs stats (unconverted)
				needs_stats_nagra = 0;

			if (cfg.lb_auto_betatunnel_prefer_beta && time_beta){
				time_beta = time_beta * cfg.lb_auto_betatunnel_prefer_beta/100;
				if (time_beta <= 0)
				        time_beta = 1;
                        }

			if (needs_stats_nagra || needs_stats_beta) {
				cs_debug_mask(D_LB, "loadbalancer-betatunnel %04X:%04X (%d/%d) needs more statistics...", er->caid, caid_to,
				needs_stats_nagra, needs_stats_beta);
				if (needs_stats_beta) { //try beta first

					convert_to_beta_int(er, caid_to);
					get_stat_query(er, &q);
				}
			}
			else if (time_beta && (!time_nagra || time_beta <= time_nagra)) {
				cs_debug_mask(D_LB, "loadbalancer-betatunnel %04X:%04X selected beta: n%dms > b%dms", er->caid, caid_to, time_nagra, time_beta);
				convert_to_beta_int(er, caid_to);
				get_stat_query(er, &q);
			}
			else {
				cs_debug_mask(D_LB, "loadbalancer-betatunnel %04X:%04X selected nagra: n%dms < b%dms", er->caid, caid_to, time_nagra, time_beta);
			}
			// else nagra is faster or no beta, so continue unmodified
		}
	} else


	if (cfg.lb_auto_betatunnel && (er->caid == 0x1702 || er->caid == 0x1722) && er->ocaid == 0x0000 && er->ecmlen) { //beta
		uint16_t caid_to = get_betatunnel_caid_to(er->caid);
		if (caid_to) {
			int8_t needs_stats_nagra = 1, needs_stats_beta = 1;

			//Clone query parameters for beta:
			STAT_QUERY qnagra = q;
			qnagra.caid = caid_to;
			qnagra.prid = 0;
			qnagra.ecmlen = er->ecm[2] - 7;

			int32_t time_nagra = 0;
			int32_t time_beta = 0;
			int32_t weight;
			int32_t avg_time;

			READER_STAT *stat_nagra = NULL;
			READER_STAT *stat_beta = NULL;
			//What is faster? nagra or beta?
			int8_t isb;
			int8_t isn;
			int8_t overall_valid = 0;
			int8_t overall_bvalid = 0;
			for(ea = er->matching_rdr; ea; ea = ea->next) {
				isb = 0;
				isn = 0;
				rdr = ea->reader;
				weight = rdr->lb_weight;
				if (weight <= 0) weight = 1;



				//Check if reverse betatunnel is allowed on this reader:
				int8_t valid = chk_ctab(caid_to, &rdr->ctab)//, rdr->typ) //Check caid
					&& chk_rfilter2(caid_to, 0, rdr) //Ident
					&& chk_srvid_by_caid_prov_rdr(rdr, caid_to, 0) //Services
					&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr,caid_to)); //rdr-caid
				if (valid) {
					stat_nagra = get_stat(rdr, &qnagra);
					overall_valid = 1;
				}
				//else
					//stat_nagra = NULL;

				//Check if beta is allowed on this reader:
				int8_t bvalid = chk_ctab(er->caid, &rdr->ctab)//, rdr->typ) //Check caid
					&& chk_rfilter2(er->caid, 0, rdr) //Ident
					&& chk_srvid_by_caid_prov_rdr(rdr, er->caid, 0) //Services
					&& (!get_rdr_caid(rdr) || chk_caid_rdr(rdr,er->caid)); //rdr-caid
				if (bvalid) {
					stat_beta = get_stat(rdr, &q);
					overall_bvalid = 1;
				}

				//calculate nagra data:
				if (stat_nagra && stat_nagra->rc == E_FOUND) {
					avg_time = stat_nagra->time_avg*100/weight;
					if (!time_nagra || avg_time < time_nagra)
						time_nagra = avg_time;
				}

				//calculate beta data:
				if (stat_beta && stat_beta->rc == E_FOUND) {
					avg_time = stat_beta->time_avg*100/weight;
					if (!time_beta || avg_time < time_beta)
						time_beta = avg_time;
				}

				//Uncomplete reader evaluation, we need more stats!
				if (stat_beta){
					needs_stats_beta = 0;
					isb = 1;
				}
				if (stat_nagra){
					needs_stats_nagra = 0;
					isn = 1;
				}
				cs_debug_mask(D_LB, "loadbalancer-betatunnel valid %d, stat_beta %d, stat_nagra %d, (%04X,%04X)", valid, isb, isn ,get_rdr_caid(rdr),caid_to);
			}

			if (!overall_valid)//we have no valid reverse betatunnel reader also we don't needs stats (converted)
				needs_stats_nagra = 0;

			if (!overall_bvalid) //we have no valid reader also we don't needs stats (unconverted)
				needs_stats_beta = 0;

			if (cfg.lb_auto_betatunnel_prefer_beta && time_beta) {
				time_beta = time_beta * cfg.lb_auto_betatunnel_prefer_beta/100;
				if (time_beta < 0)
				        time_beta = 0;
                        }

			//if we needs stats, we send 2 ecm requests: 18xx and 17xx:
			if (needs_stats_nagra || needs_stats_beta) {
				cs_debug_mask(D_LB, "loadbalancer-betatunnel %04X:%04X (%d/%d) needs more statistics...", er->caid, caid_to,
				needs_stats_beta, needs_stats_nagra);
				if (needs_stats_nagra){// try nagra frist

					convert_to_nagra_int(er, caid_to);
					get_stat_query(er, &q);

				}
			}
			else if (time_nagra && (!time_beta || time_nagra <= time_beta)) {
				cs_debug_mask(D_LB, "loadbalancer-betatunnel %04X:%04X selected nagra: b%dms > n%dms", er->caid, caid_to, time_beta, time_nagra);
				convert_to_nagra_int(er, caid_to);
				get_stat_query(er, &q);
			}
			else {
				cs_debug_mask(D_LB, "loadbalancer-betatunnel %04X:%04X selected beta: b%dms < n%dms", er->caid, caid_to, time_beta, time_nagra);
			}

		}
	}

	if (cfg.lb_auto_betatunnel && is_betatunnel_caid(er->caid)) {
		//check again is caid valied to reader
		//with both caid on local readers or with proxy
		//(both caid will setup to reader for make tunnel caid in share (ccc) visible)
		//make sure dosn't send a beta ecm to nagra reader (or reverse)
		struct s_ecm_answer *prv = NULL;
		for(ea = er->matching_rdr; ea; ea = ea->next) {
			rdr = ea->reader;
			if (is_network_reader(rdr)) { //reader caid is not real caid
				prv = ea;
				continue; // proxy can convert or reject
			}
			cs_debug_mask(D_LB, "check again caid %04X on reader %s", er->caid, rdr->label);
			if ( !get_rdr_caid(ea->reader) || chk_caid_rdr(ea->reader,er->caid)) {
				prv = ea;
			} else {
				if (!rdr->fallback) er->reader_avail--;
				cs_debug_mask(D_LB, "caid %04X not found in caidlist, reader %s removed from request reader list", er->caid, rdr->label);
				if (prv){
					prv->next = ea->next;
				} else
					er->matching_rdr = ea->next;
			}
		}
		if (!er->reader_avail)
			return;
	}

	struct timeb check_time;
        cs_ftime(&check_time);
	time_t current_time = time(NULL);
	int32_t current = -1;
	READER_STAT *s = NULL;
	int32_t retrylimit = get_retrylimit(er);
	int32_t reader_count = 0;
	int32_t new_stats = 0;
	int32_t nlocal_readers = 0;
	int32_t nbest_readers = get_nbest_readers(er);
	int32_t nfb_readers = cfg.lb_nfb_readers;
	int32_t nreaders = cfg.lb_max_readers;
	if (!nreaders)
		nreaders = -1;
	else if (nreaders <= cfg.lb_nbest_readers)
		nreaders = cfg.lb_nbest_readers+1;
	int32_t nmaxreopen = nreaders-nbest_readers;
	if (nmaxreopen < 1)
	{
		if (nreaders > 0) nmaxreopen = 1;
		else nmaxreopen = er->reader_avail;
	}

#ifdef WITH_DEBUG
	if (cs_dblevel & D_LB) {
		//loadbalancer debug output:
		int32_t nr = 0;
		char buf[512];
		int n, l=512;
		char *rptr = buf;
		*rptr = 0;

		for(ea = er->matching_rdr; ea; ea = ea->next) {
			nr++;

			if (nr>5) continue;

			if (!(ea->status & READER_FALLBACK))
				n = snprintf(rptr, l, "%s%s%s ", ea->reader->label, (ea->status&READER_CACHEEX)?"*":"", (ea->status&READER_LOCAL)?"L":"");
			else
				n = snprintf(rptr, l, "[%s%s%s] ", ea->reader->label, (ea->status&READER_CACHEEX)?"*":"", (ea->status&READER_LOCAL)?"L":"");
			rptr+=n;
			l-=n;
		}

		if (nr>5)
			snprintf(rptr, l, "...(%d more)", nr - 5);

                char ecmbuf[ECM_FMT_LEN];
		format_ecm(er, ecmbuf, ECM_FMT_LEN);
                                
		cs_debug_mask(D_LB, "loadbalancer: client %s for %s: n=%d valid readers: %s",
			username(er->client), ecmbuf, nr, buf);
	}
#endif

	for(ea = er->matching_rdr; ea; ea = ea->next) {
		ea->status &= ~(READER_ACTIVE|READER_FALLBACK);
		ea->value = 0;
	}
	
	for(ea = er->matching_rdr; ea; ea = ea->next) {
			rdr = ea->reader;
#ifdef CS_CACHEEX
			int8_t cacheex = rdr->cacheex.mode;
			if (cacheex == 1) {
				ea->status |= READER_ACTIVE; //no statistics, this reader is a cacheex reader and so always active
				continue;
			}
#endif
			struct s_client *cl = rdr->client;
			reader_count++;

			int32_t weight = rdr->lb_weight <= 0?100:rdr->lb_weight;

			s = get_stat(rdr, &q);
			if (!s) {
				if (nmaxreopen>0) {
					cs_debug_mask(D_LB, "loadbalancer: starting statistics for reader %s", rdr->label);
					ea->status |= READER_ACTIVE; //no statistics, this reader is active (now) but we need statistics first!
					new_stats = 1;
					//nreaders--;
					if (!cfg.lb_reopen_mode)
						nmaxreopen--;
				}
				continue;
			}

			if (nmaxreopen>0 && (s->ecm_count < 0||(s->ecm_count > cfg.lb_max_ecmcount && s->time_avg > retrylimit))) {
				cs_debug_mask(D_LB, "loadbalancer: max ecms (%d) reached by reader %s, resetting statistics", cfg.lb_max_ecmcount, rdr->label);
				reset_stat(&q);
				ea->status |= READER_ACTIVE; //max ecm reached, get new statistics
				nreaders--;
				nmaxreopen--;
				continue;
			}

//			if (nreopen_readers && s->rc != E_FOUND && s->last_received+get_reopen_seconds(s) < current_time) {
//				cs_debug_mask(D_LB, "loadbalancer: reopen reader %s", rdr->label);
//				reset_stat(er->caid, prid, er->srvid, er->chid, er->ecmlen);
//				ea->status |= READER_ACTIVE; //max ecm reached, get new statistics
//				nreopen_readers--;
//				continue;
//			}

			int32_t hassrvid;
			if(cl)
				hassrvid = has_srvid(cl, er) || has_ident(&rdr->ftab, er);
			else
				hassrvid = 0;

			if (nmaxreopen>0 && s->rc == E_FOUND && s->ecm_count < cfg.lb_min_ecmcount) {
				cs_debug_mask(D_LB, "loadbalancer: reader %s needs more statistics", rdr->label);
				ea->status |= READER_ACTIVE; //need more statistics!
				new_stats = 1;
				nreaders--;
				nmaxreopen--;
				continue;
			}

			//Reader can decode this service (rc==0) and has lb_min_ecmcount ecms:
			if (s->rc == E_FOUND || hassrvid) {
				if (cfg.preferlocalcards && (ea->status & READER_LOCAL))
					nlocal_readers++; //Prefer local readers!

				switch (cfg.lb_mode) {
					default:
					case LB_NONE:
					case LB_LOG_ONLY:
						//cs_debug_mask(D_LB, "loadbalance disabled");
						ea->status |= READER_ACTIVE;
						if (rdr->fallback)
							ea->status |= READER_FALLBACK;
						continue;

					case LB_FASTEST_READER_FIRST:
						current = s->time_avg * 100 / weight;
						break;

					case LB_OLDEST_READER_FIRST:
						if (!rdr->lb_last.time)
							rdr->lb_last = check_time;

						//current is negative here! the older, the bigger is the difference
						current = 1000 * (rdr->lb_last.time - check_time.time) + (rdr->lb_last.millitm - check_time.millitm) - 10;
						// current /= weight; /* The others are divided by weight only OLDEST not??*/
						if (!current)
						        current = -1;
						break;

					case LB_LOWEST_USAGELEVEL:
						current = rdr->lb_usagelevel * 100 / weight;
						break;
				}
				cs_debug_mask(D_LB, "rdr %s lbvalue = %d", rdr->label, abs(current));

#if defined(WEBIF) || defined(LCDSUPPORT)
				rdr->lbvalue = abs(current);
#endif

				if (cfg.lb_mode != LB_OLDEST_READER_FIRST) { //Adjust selection to reader load:
					if (rdr->ph.c_available && !rdr->ph.c_available(rdr, AVAIL_CHECK_LOADBALANCE, er)) {
						current=current*2;
					}

					if (cl && cl->pending)
						current=current*cl->pending;

					if (s->rc >= E_NOTFOUND) { //when reader has service this is possible
						current=current*(s->fail_factor+2); //Mark als slow
					}
        				if (current < 1)
	        				current=1;
				}

				ea->value = current;
				ea->time = s->time_avg;
			}
	}

	if (nlocal_readers > nbest_readers) { //if we have local readers, we prefer them!
		nlocal_readers = nbest_readers;
		nbest_readers = 0;
	}
	else
		nbest_readers = nbest_readers - nlocal_readers;

	struct s_reader *best_rdr = NULL;
	struct s_reader *best_rdri = NULL;
	int32_t best_time = 0;
	int32_t result_count = 0;

	int32_t n=0;
	while (nreaders) {
		struct s_ecm_answer *best = NULL;

		for(ea = er->matching_rdr; ea; ea = ea->next) {
			if (nlocal_readers && !(ea->status & READER_LOCAL))
				continue;

			if (ea->value && (!best || ea->value < best->value))
				best=ea;
		}
		if (!best)
			break;

		n++;
		best_rdri = best->reader;
		if (!best_rdr) {
			best_rdr = best_rdri;
			best_time = best->time;
		}
		best->value = 0;

		if (nlocal_readers) {//primary readers, local
			nlocal_readers--;
			nreaders--;
			best->status |= READER_ACTIVE;
		}
		else if (nbest_readers) {//primary readers, other
			nbest_readers--;
			nreaders--;
			best->status |= READER_ACTIVE;
		}
		else if (nfb_readers) { //fallbacks:
			nfb_readers--;
			best->status |= (READER_ACTIVE|READER_FALLBACK);
		}
		else
			break;
		result_count++;
	}

	if (!new_stats && result_count < reader_count) {
		if (!n) //no best reader found? reopen if we have ecm_count>0
		{
			cs_debug_mask(D_LB, "loadbalancer: NO MATCHING READER FOUND, reopen last valid:");
			for(ea = er->matching_rdr; ea; ea = ea->next) {
				if (!(ea->status&READER_ACTIVE)) {
					rdr = ea->reader;
   	     			s = get_stat(rdr, &q);
   		     		if (s && s->rc != E_FOUND && s->last_received+get_reopen_seconds(s) < current_time) {
	   	     			if (nreaders) {
   	     					ea->status |= READER_ACTIVE;
   	     					nreaders--;
   	     					cs_debug_mask(D_LB, "loadbalancer: reopened reader %s", rdr->label);
	   	     			}
	   	     			n++;
   		     		}
				}
			}
			cs_debug_mask(D_LB, "loadbalancer: reopened %d readers", n);
		}

		//algo for reopen other reader only if responsetime>retrylimit:
		int32_t reopen = !best_rdr || (best_time && (best_time > retrylimit));
		if (reopen) {
#ifdef WITH_DEBUG
			if (best_rdr)
				cs_debug_mask(D_LB, "loadbalancer: reader %s reached retrylimit (%dms), reopening other readers", best_rdr->label, best_time);
			else
				cs_debug_mask(D_LB, "loadbalancer: no best reader found, reopening other readers");
#endif
			for(ea = er->matching_rdr; ea && nreaders; ea = ea->next) {
				if (!(ea->status&READER_ACTIVE)) {
					rdr = ea->reader;
					s = get_stat(rdr, &q);

					if (s && s->rc != E_FOUND) { //retrylimit reached:
						if (!cfg.lb_reopen_mode) cs_debug_mask(D_LB, "loadbalancer: reader %s need %ld seconds to reopen", ea->reader->label, (s->last_received+get_reopen_seconds(s))-current_time);
						if (cfg.lb_reopen_mode || s->last_received+get_reopen_seconds(s) < current_time) { //Retrying reader every (900/conf) seconds
							if (cfg.lb_reopen_mode) {
								cs_debug_mask(D_LB, "loadbalancer: reader %s reopen fast", rdr->label);
							} else {
								cs_debug_mask(D_LB, "loadbalancer: reader %s reopen after %ld sec.", rdr->label, get_reopen_seconds(s));
							}
							s->last_received = current_time;
							ea->status |= READER_ACTIVE;
							nreaders--;
							cs_debug_mask(D_LB, "loadbalancer: retrying reader %s (fail %d)", rdr->label, s->fail_factor);
						}
					}
				}
			}
		}
	}

#ifdef WITH_DEBUG
	if (cs_dblevel & D_LB) {
		//loadbalancer debug output:
		int32_t nr = 0;
		char buf[512];
		int32_t l=512;
		char *rptr = buf;
		*rptr = 0;

		for(ea = er->matching_rdr; ea; ea = ea->next) {
			if (!(ea->status & READER_ACTIVE))
				continue;

			nr++;

			if (nr>5) continue;

			if (!(ea->status & READER_FALLBACK))
				n = snprintf(rptr, l, "%s%s%s ", ea->reader->label, (ea->status&READER_CACHEEX)?"*":"", (ea->status&READER_LOCAL)?"L":"");
			else
				n = snprintf(rptr, l, "[%s%s%s] ", ea->reader->label, (ea->status&READER_CACHEEX)?"*":"", (ea->status&READER_LOCAL)?"L":"");
			rptr+=n;
			l-=n;
		}

		if (nr>5)
			snprintf(rptr, l, "...(%d more)", nr - 5);

                char ecmbuf[ECM_FMT_LEN];
		format_ecm(er, ecmbuf, ECM_FMT_LEN);
                                
		cs_debug_mask(D_LB, "loadbalancer: client %s for %s: n=%d selected readers: %s",
			username(er->client), ecmbuf, nr, buf);
	}
#endif
	return;
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

void clear_all_stat(void)
{
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(&itr))) {
		clear_reader_stat(rdr);
	}
}

static void housekeeping_stat_thread(void)
{
	time_t cleanup_time = time(NULL) - (cfg.lb_stat_cleanup*60*60);
	int32_t cleaned = 0;
	struct s_reader *rdr;
	set_thread_name(__func__);
	LL_ITER itr = ll_iter_create(configured_readers);
	cs_readlock(&readerlist_lock); //this avoids cleaning a reading during writing
	while ((rdr = ll_iter_next(&itr))) {
		if (rdr->lb_stat) {
			cs_writelock(&rdr->lb_stat_lock);
			LL_ITER it = ll_iter_create(rdr->lb_stat);
			READER_STAT *s;
			while ((s=ll_iter_next(&it))) {

				if (s->last_received < cleanup_time) {
					ll_iter_remove_data(&it);
					cleaned++;
				}
			}
			cs_writeunlock(&rdr->lb_stat_lock);
		}
	}
	cs_readunlock(&readerlist_lock);
	cs_debug_mask(D_LB, "loadbalancer cleanup: removed %d entries", cleaned);
}

static void housekeeping_stat(int32_t force)
{
	time_t now = time(NULL);
	if (!force && last_housekeeping + 60*60 > now) //only clean once in an hour
		return;

	last_housekeeping = now;
	start_thread((void*)&housekeeping_stat_thread, "housekeeping lb stats");
}

static int compare_stat(READER_STAT **ps1, READER_STAT **ps2) {
	READER_STAT *s1 = (*ps1), *s2 = (*ps2);
	int res = s1->rc - s2->rc;
	if (res) return res;
	res = s1->caid - s2->caid;
	if (res) return res;
	res = s1->prid - s2->prid;
	if (res) return res;
	res = s1->srvid - s2->srvid;
	if (res) return res;
	res = s1->chid - s2->chid;
	if (res) return res;
	res = s1->ecmlen - s2->ecmlen;
	if (res) return res;
	res = s1->last_received - s2->last_received;
	return res;
}

static int compare_stat_r(READER_STAT **ps1, READER_STAT **ps2) {
	return -compare_stat(ps1, ps2);
}

READER_STAT **get_sorted_stat_copy(struct s_reader *rdr, int32_t reverse, int32_t *size)
{
	if (reverse)
		return (READER_STAT **)ll_sort(rdr->lb_stat, compare_stat_r, size);
	else
		return (READER_STAT **)ll_sort(rdr->lb_stat, compare_stat, size);
}

static int8_t stat_in_ecmlen(struct s_reader *rdr, READER_STAT *s)
{
	struct s_ecmWhitelist *tmp;
	struct s_ecmWhitelistIdent *tmpIdent;
	struct s_ecmWhitelistLen *tmpLen;
	for (tmp = rdr->ecmWhitelist; tmp; tmp = tmp->next) {
		if (tmp->caid == 0 || (tmp->caid == s->caid)) {
			for (tmpIdent = tmp->idents; tmpIdent; tmpIdent = tmpIdent->next) {
				if (tmpIdent->ident == 0 || tmpIdent->ident == s->prid) {
					for (tmpLen = tmpIdent->lengths; tmpLen; tmpLen = tmpLen->next) {
						if (tmpLen->len == s->ecmlen) {
							return 1;
						}
					}
				}
			}
		}
	}
	return 0;
}

static int8_t add_to_ecmlen(struct s_reader *rdr, READER_STAT *s)
{
	struct s_ecmWhitelist *tmp = NULL;
	struct s_ecmWhitelistIdent *tmpIdent = NULL;
	struct s_ecmWhitelistLen *tmpLen = NULL;

	for (tmp = rdr->ecmWhitelist; tmp; tmp = tmp->next) {
		if (tmp->caid == s->caid) {
			for (tmpIdent = tmp->idents; tmpIdent; tmpIdent = tmpIdent->next) {
				if (tmpIdent->ident == s->prid) {
					for (tmpLen = tmpIdent->lengths; tmpLen; tmpLen = tmpLen->next) {
						if (tmpLen->len == s->ecmlen) {
							return 1;
						}
					}
					break;
				}
			}
			break;
		}
	}

	if (!tmp) {
		if (cs_malloc(&tmp, sizeof(struct s_ecmWhitelist))) {
			tmp->caid = s->caid;
			tmp->next = rdr->ecmWhitelist;
			rdr->ecmWhitelist = tmp;
		}
	}

	if (!tmpIdent && tmp) {
		if (cs_malloc(&tmpIdent, sizeof(struct s_ecmWhitelistIdent))) {
			tmpIdent->ident = s->prid;
			tmpIdent->next = tmp->idents;
			tmp->idents = tmpIdent;
		}
	}

	if (!tmpLen && tmpIdent) {
		if (cs_malloc(&tmpLen, sizeof(struct s_ecmWhitelistLen))) {
			tmpLen->len = s->ecmlen;
			tmpLen->next = tmpIdent->lengths;
			tmpIdent->lengths =  tmpLen;
		}
	}

	return 0;
}

void update_ecmlen_from_stat(struct s_reader *rdr)
{
	if (!rdr || &rdr->lb_stat)
		return;

	cs_readlock(&rdr->lb_stat_lock);
	LL_ITER it = ll_iter_create(rdr->lb_stat);
	READER_STAT *s;
	while ((s = ll_iter_next(&it))) {
		if (s->rc ==E_FOUND) {
			if (!stat_in_ecmlen(rdr, s))
				add_to_ecmlen(rdr, s);
		}
	}
	cs_readunlock(&rdr->lb_stat_lock);
}

int32_t lb_valid_btun(ECM_REQUEST *er, uint16_t caidto)
{
	STAT_QUERY q;
	READER_STAT *s;
	struct s_reader *rdr;

	get_stat_query(er, &q);
	q.caid = caidto;

	cs_readlock(&readerlist_lock);
	for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
		if (rdr->lb_stat && rdr->client) {
			s = get_stat(rdr, &q);
			if (s && s->rc == E_FOUND) {
				cs_readunlock(&readerlist_lock);
				return 1;
			}
		}
	}
	cs_readunlock(&readerlist_lock);
	return 0;
}

/**
 * mark as last reader after checked for cache requests:
 **/
void lb_mark_last_reader(ECM_REQUEST *er)
{
	 //OLDEST_READER: set lb_last 
	 struct s_ecm_answer *ea;
	 for (ea=er->matching_rdr; ea; ea=ea->next) {
	 	if ((ea->status&(READER_ACTIVE|READER_FALLBACK)) == READER_ACTIVE)
                         cs_ftime(&ea->reader->lb_last);
	}
}

/**
 * Automatic timeout feature depending on statistik values
 **/
uint32_t lb_auto_timeout(ECM_REQUEST *er, uint32_t ctimeout) {
        STAT_QUERY q;
        READER_STAT *s = NULL;
        
        struct s_reader *rdr = NULL;
        struct s_ecm_answer *ea;
        
        for (ea = er->matching_rdr; ea; ea = ea->next) {
                if ((ea->status&(READER_ACTIVE|READER_FALLBACK)) == READER_ACTIVE) {
                        rdr = ea->reader;
                        get_stat_query(er, &q);
                        s = get_stat(rdr, &q);
                        if (s) break;
                }
        }        
        if (!s) return ctimeout;
        
        uint32_t t;
        if (s->rc == E_TIMEOUT)
                t = ctimeout/2; //timeout known, early timeout!
        else {
                if (s->ecm_count < cfg.lb_min_ecmcount) return ctimeout;
                
                t = s->time_avg*(100+cfg.lb_auto_timeout_p)/100;
                if ((int32_t)(t-s->time_avg) < cfg.lb_auto_timeout_t) t = s->time_avg+cfg.lb_auto_timeout_t;
        }
        if (t > ctimeout) t = ctimeout;
#ifdef WITH_DEBUG
        if (D_TRACE & cs_dblevel) {        
	        char buf[ECM_FMT_LEN];
	        format_ecm(er, buf, ECM_FMT_LEN); 
	        cs_debug_mask(D_TRACE, "auto-timeout for %s %s set rdr %s to %d", username(er->client), buf, rdr->label, t); 
        }
#endif
        return t;
}

void send_reader_stat(struct s_reader *rdr, ECM_REQUEST *er, struct s_ecm_answer *ea, int8_t rc)
{
	if (!rdr || rc >= E_99 || cacheex_reader(rdr))
		return;
	if (er->ecmcacheptr) //ignore cache answer
		return;

	struct timeb tpe;
	cs_ftime(&tpe);
#ifndef CS_CACHEEX
	int32_t ntime = comp_timeb(&tpe,&er->tps);
#else
	int32_t ntime = comp_timeb(&tpe, &er->cacheex_wait);
#endif
	if (ntime < 1)
		ntime = 1;

	if (ea && (ea->status & READER_FALLBACK) && ntime > (int32_t)cfg.ftimeout)
		ntime = ntime - cfg.ftimeout;
	add_stat(rdr, er, ntime, rc);
}

void stat_finish(void) {
	if (cfg.lb_mode && cfg.lb_save) {
		save_stat_to_file(0);
		if (cfg.lb_savepath)
			cs_log("stats saved to file %s", cfg.lb_savepath);
		cfg.lb_save = 0; //this is for avoiding duplicate saves
	}
}

#endif
