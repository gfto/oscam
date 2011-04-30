#include "module-stat.h"
#include "module-cccam.h"

#define UNDEF_AVG_TIME 80000
#define MAX_ECM_SEND_CACHE 16

#define LB_REOPEN_MODE_STANDARD 0
#define LB_REOPEN_MODE_FAST 1

static int32_t stat_load_save;
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

#define LINESIZE 1024

void load_stat_from_file()
{
	stat_load_save = 0;
	char buf[256];
	char *line;
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

	struct timeb ts, te;
    cs_ftime(&ts);
         	
	struct s_reader *rdr = NULL;
	READER_STAT *stat, *dup=NULL;
	line = cs_malloc(&line, LINESIZE, 0);
		
	int32_t i=1;
	int32_t valid=0;
	int32_t count=0;
	int32_t type=0;
	char *ptr;
	char *split[10];
	
	while (fgets(line, LINESIZE, file))
	{
		if (!line[0] || line[0] == '#' || line[0] == ';')
			continue;
		
		stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));

		//get type by evaluating first line:
		if (type==0) {
			if (strstr(line, " rc ")) type = 2;
			else type = 1;
		}	
		
		if (type==1) { //New format - faster parsing:
			for (i = 0, ptr = strtok(line, ","); ptr && i<10 ; ptr = strtok(NULL, ","), i++)
				split[i] = ptr;
			valid = (i==10);
			if (valid) {
				strncpy(buf, split[0], sizeof(buf)-1);
				stat->rc = atoi(split[1]);
				stat->caid = a2i(split[2], 4);
				stat->prid = a2i(split[3], 6);
				stat->srvid = a2i(split[4], 4);
				stat->time_avg = atoi(split[5]);
				stat->ecm_count = atoi(split[6]);
				stat->last_received = atol(split[7]);
				stat->fail_factor = atoi(split[8]);
				stat->ecmlen = a2i(split[9], 2);
			}
		} else { //Old format - keep for compatibility:
			i = sscanf(line, "%s rc %d caid %04hX prid %06X srvid %04hX time avg %dms ecms %d last %ld fail %d len %02hX\n",
				buf, &stat->rc, &stat->caid, &stat->prid, &stat->srvid, 
				&stat->time_avg, &stat->ecm_count, &stat->last_received, &stat->fail_factor, &stat->ecmlen);
			valid = i>5;
		}
		
		if (valid) {
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
				if (cs_dblevel == 0xFF) //Only with full debug for faster reading...
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
		else 
		{
			cs_debug_mask(D_TRACE, "loadbalancer: statistics ERROR: %s rc=%d i=%d", buf, stat->rc, i);
			free(stat);
		}
	} 
	fclose(file);
	free(line);

    cs_ftime(&te);
	int32_t time = 1000*(te.time-ts.time)+te.millitm-ts.millitm;

	cs_debug_mask(D_TRACE, "loadbalancer: statistics loaded %d records in %dms", count, time);
}

static uint32_t get_prid(uint16_t caid, uint32_t prid)
{
	int32_t i;
	for (i=0;i<CS_MAXCAIDTAB;i++) {
		uint16_t tcaid = cfg.lb_noproviderforcaid.caid[i];
		if (!tcaid) break;
		if (tcaid == caid) {
			prid = 0;
			break;
		}
		if (tcaid < 0x0100 && (caid >> 8) == tcaid) {
			prid = 0;
			break;
		}
		
	}
	return prid;
}

/**
 * get statistic values for reader ridx and caid/prid/srvid/ecmlen
 */
READER_STAT *get_stat(struct s_reader *rdr, uint16_t caid, uint32_t prid, uint16_t srvid, int16_t ecmlen)
{
	if (!rdr->lb_stat)
		rdr->lb_stat = ll_create();

	prid = get_prid(caid, prid);
	
	LL_ITER *it = ll_iter_create(rdr->lb_stat);
	READER_STAT *stat = NULL;
	int32_t i = 0;
	while ((stat = ll_iter_next(it))) {
		i++;
		if (stat->caid==caid && stat->prid==prid && stat->srvid==srvid) {
			if (stat->ecmlen == ecmlen)
				break;
			if (!stat->ecmlen) {
				stat->ecmlen = ecmlen;
				break;
			}
		}
	}
	
	//Move stat to list start for faster access:
	if (i > 10 && stat)
		ll_iter_move_first(it);
	ll_iter_release(it);
	
	return stat;
}

/**
 * removes caid/prid/srvid/ecmlen from stat-list of reader ridx
 */
int32_t remove_stat(struct s_reader *rdr, uint16_t caid, uint32_t prid, uint16_t srvid, int16_t ecmlen)
{
	if (!rdr->lb_stat)
		return 0;

	int32_t c = 0;
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
	int32_t i, c=0, t = 0;
	for (i = 0; i < LB_MAX_STAT_TIME; i++) {
		if (stat->time_stat[i] > 0) {
			t += (int32_t)stat->time_stat[i];
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
	
	struct timeb ts, te;
    cs_ftime(&ts);
         
	time_t cleanup_time = time(NULL) - (cfg.lb_stat_cleanup*60*60);
         	
	int32_t count=0;
	struct s_reader *rdr;
	LL_ITER *itr = ll_iter_create(configured_readers);
	while ((rdr=ll_iter_next(itr))) {
		
		if (rdr->lb_stat) {
			LL_ITER *it = ll_iter_create(rdr->lb_stat);
			READER_STAT *stat;
			while ((stat = ll_iter_next(it))) {
			
				if (stat->last_received < cleanup_time) { //cleanup old stats
					ll_iter_remove_data(it);
					continue;
				}
				
				//Old version, too slow to parse:
				//fprintf(file, "%s rc %d caid %04hX prid %06X srvid %04hX time avg %dms ecms %d last %ld fail %d len %02hX\n",
				//	rdr->label, stat->rc, stat->caid, stat->prid, 
				//	stat->srvid, stat->time_avg, stat->ecm_count, stat->last_received, stat->fail_factor, stat->ecmlen);
				
				//New version:
				fprintf(file, "%s,%d,%04hX,%06X,%04hX,%d,%d,%ld,%d,%02hX\n",
					rdr->label, stat->rc, stat->caid, stat->prid, 
					stat->srvid, stat->time_avg, stat->ecm_count, stat->last_received, stat->fail_factor, stat->ecmlen);
				count++;
			}
			ll_iter_release(it);
		}
	}
	ll_iter_release(itr);
	
	fclose(file);

    cs_ftime(&te);
	int32_t time = 1000*(te.time-ts.time)+te.millitm-ts.millitm;


	cs_log("loadbalancer: statistic saved %d records to %s in %dms", count, fname, time);
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
void inc_fail(READER_STAT *stat)
{
	if (stat->fail_factor <= 0)
		stat->fail_factor = 1;
	else
		stat->fail_factor *= 2;
}

/**
 * Adds caid/prid/srvid/ecmlen to stat-list for reader ridx with time/rc
 */
void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int32_t ecm_time, int32_t rc)
{
	if (!rdr || !er || !cfg.lb_mode)
		return;
		
	uint32_t prid = get_prid(er->caid, er->prid);
	
	READER_STAT *stat = get_stat(rdr, er->caid, prid, er->srvid, er->l);
	if (!stat) {
		stat = malloc(sizeof(READER_STAT));
		memset(stat, 0, sizeof(READER_STAT));
		stat->caid = er->caid;
		stat->prid = prid;
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
		
	time_t ctime = time(NULL);
	
	if (rc == 0) { //found
		stat->rc = 0;
		stat->ecm_count++;
		stat->last_received = ctime;
		stat->fail_factor = 0;
		
		//If answering reader is a fallback reader, decrement answer time by fallback timeout:
		struct s_reader *r;
		LL_ITER *it = ll_iter_create(er->matching_rdr);
		int is_fallback = 0;
		while ((r=ll_iter_next(it))) {
			if (it->cur == er->fallback) is_fallback = 1;
			if (r == rdr) {
				if (is_fallback && (uint32_t)ecm_time >= cfg.ftimeout)
					ecm_time -= cfg.ftimeout;
				break;
			}
		}
		ll_iter_release(it);
		
		//FASTEST READER:
		stat->time_idx++;
		if (stat->time_idx >= LB_MAX_STAT_TIME)
			stat->time_idx = 0;
		stat->time_stat[stat->time_idx] = ecm_time;
		calc_stat(stat);

		//OLDEST READER now set by get best reader!
		
		
		//USAGELEVEL:
		int32_t ule = rdr->lb_usagelevel_ecmcount;
		if (ule > 0 && ((ule / cfg.lb_min_ecmcount) > 0)) //update every MIN_ECM_COUNT usagelevel:
		{
			time_t t = (ctime-rdr->lb_usagelevel_time);
			rdr->lb_usagelevel = 1000/(t<1?1:t);
			ule = 0;
		}
		if (ule == 0)
			rdr->lb_usagelevel_time = ctime;
		rdr->lb_usagelevel_ecmcount = ule+1;
	}
	else if (rc == 1 || rc == 2) { //cache
		//no increase of statistics here, cachetime is not real time
		stat->last_received = ctime;
	}
	else if (rc == 4) { //not found
		//CCcam card can't decode, 0x28=NOK1, 0x29=NOK2
		//CCcam loop detection = E2_CCCAM_LOOP
		if (er->rcEx == E2_CCCAM_NOK1 || er->rcEx == E2_CCCAM_NOK2 || er->rcEx == E2_CCCAM_LOOP)
			return;
			
		stat->rc = rc;
		inc_fail(stat);
		stat->last_received = ctime;
		
		//reduce ecm_count step by step
		if (!cfg.lb_reopen_mode)
			stat->ecm_count /= 10;
	}
	else if (rc == 5) { //timeout
		//catch suddenly occuring timeouts and block reader:
		if ((int)(ctime-stat->last_received) < (int)(5*cfg.ctimeout) && 
						stat->rc == 0 && 
						stat->ecm_count > 0) {
				stat->rc = 5;
				inc_fail(stat);
		}
		else if ((rdr->client->login+(int)(2*cfg.ctimeout/1000)) < ctime && rdr->client->pending < 5) { //reader is longer than 5s connected && not more then 5 pending ecms
				stat->rc = 5;
				inc_fail(stat);
		}
				
		stat->last_received = ctime;

		if (!cfg.lb_reopen_mode)
			stat->ecm_count /= 10;
		
		//add timeout to stat:
		if (ecm_time<=0 || ecm_time > (int)cfg.ctimeout)
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
			cs_debug_mask(D_TRACE, "loadbalancer: not handled stat for reader %s: rc %d %04hX&%06lX/%04hX/%02hX time %dms fail %d",
				rdr->label, rc, er->caid, prid, er->srvid, er->l, ecm_time, stat->fail_factor);
	
		return;
	}
	
	housekeeping_stat(0);
		
	cs_debug_mask(D_TRACE, "loadbalancer: adding stat for reader %s: rc %d %04hX&%06lX/%04hX/%02hX time %dms fail %d",
				rdr->label, rc, er->caid, prid, er->srvid, er->l, ecm_time, stat->fail_factor);
	
	if (cfg.lb_save) {
		stat_load_save++;
		if (stat_load_save > cfg.lb_save)
			save_stat_to_file(1);	
	}
}

void reset_stat(uint16_t caid, uint32_t prid, uint16_t srvid, int16_t ecmlen)
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
				stat->fail_factor = 0;
			}
		}
	}
}

int32_t has_ident(FTAB *ftab, ECM_REQUEST *er) {

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

struct stat_value {
	struct s_reader *rdr;
	int32_t value;
	int32_t time;
};

static struct stat_value *crt_cur(struct s_reader *rdr, int32_t value, int32_t time) {
	struct stat_value *v = malloc(sizeof(struct stat_value));
	v->rdr = rdr;
	v->value = value;
	v->time = time;
	return v;
}

#ifdef WITH_DEBUG 
static char *strend(char *c) {
	while (c && *c) c++;
	return c;
}
#endif

static int32_t get_retrylimit(ECM_REQUEST *er) {
		int32_t i;
		for (i = 0; i < cfg.lb_retrylimittab.n; i++) {
				if (cfg.lb_retrylimittab.caid[i] == er->caid)
						return cfg.lb_retrylimittab.value[i];
		}
		return cfg.lb_retrylimit;
}

static int32_t get_nbest_readers(ECM_REQUEST *er) {
		int32_t i;
		for (i = 0; i < cfg.lb_nbest_readers_tab.n; i++) {
				if (cfg.lb_nbest_readers_tab.caid[i] == er->caid)
						return cfg.lb_nbest_readers_tab.value[i];
		}
		return cfg.lb_nbest_readers;
}

static int32_t get_reopen_seconds(READER_STAT *stat)
{
		int32_t max = (INT_MAX / cfg.lb_reopen_seconds) - 1;
		if (stat->fail_factor > max)
				stat->fail_factor = max;
		return (stat->fail_factor+1) * cfg.lb_reopen_seconds;
}

ushort get_betatunnel_caid_to(ushort caid) 
{
	if (caid == 0x1801) return 0x1722;
	if (caid == 0x1833) return 0x1702;
	if (caid == 0x1834) return 0x1722;
	if (caid == 0x1835) return 0x1722;
	return 0;
}

void convert_to_beta_int(ECM_REQUEST *er, uint16_t caid_to)
{
	convert_to_beta(er->client, er, caid_to);
	// update ecmd5 for store ECM in cache
	memcpy(er->ecmd5, MD5(er->ecm+13, er->l-13, er->client->dump), CS_ECMSTORESIZE);
}

/**	
 * Gets best reader for caid/prid/srvid/ecmlen.
 * Best reader is evaluated by lowest avg time but only if ecm_count > cfg.lb_min_ecmcount (5)
 * Also the reader is asked if he is "available"
 * returns ridx when found or -1 when not found
 */
int32_t get_best_reader(ECM_REQUEST *er)
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

	uint32_t prid = get_prid(er->caid, er->prid);

	//auto-betatunnel: The trick is: "let the loadbalancer decide"!
	if (cfg.lb_auto_betatunnel && er->caid >> 8 == 0x18) { //nagra 
		ushort caid_to = get_betatunnel_caid_to(er->caid);
		if (caid_to) {
			int needs_stats_nagra, needs_stats_beta = 0;
			
			int32_t time_nagra = 0;
			int32_t time_beta = 0;
			int32_t weight;
			int32_t time;
			
			READER_STAT *stat_nagra;
			READER_STAT *stat_beta;
			
			//What is faster? nagra or beta?
			it = ll_iter_create(er->matching_rdr);
			while ((rdr=ll_iter_next(it)) && !needs_stats_nagra && !needs_stats_beta) {
				weight = rdr->lb_weight;
				if (weight <= 0) weight = 1;
				
				stat_nagra = get_stat(rdr, er->caid, prid, er->srvid, er->l);
				stat_beta = get_stat(rdr, caid_to, prid, er->srvid, er->l+10);
				
				if (stat_nagra && stat_nagra->rc == 0) {
					time = stat_nagra->time_avg/weight;
					if (!time_nagra || time < time_nagra)
						time_nagra = time;
				}
				
				if (stat_beta && stat_beta->rc == 0) {
					time = stat_beta->time_avg/weight;
					if (!time_beta || time < time_beta)
						time_beta = time;
				}
				
				//Uncomplete reader evaluation, we need more stats!
				if (!stat_nagra)
					needs_stats_nagra = 1;
				if (!stat_beta)
					needs_stats_beta = 1;
			}
			ll_iter_release(it);
			
			//if we needs stats, we send 2 ecm requests: 18xx and 17xx:
			if (needs_stats_nagra || needs_stats_beta) {
				cs_debug_mask(D_TRACE, "loadbalancer-betatunnel %04X:%04X needs more statistics...", er->caid, caid_to);
				if (needs_stats_beta)				
					convert_to_beta_int(er, caid_to);
			}
			else if (time_beta && (!time_nagra || time_beta <= time_nagra)) {
				cs_debug_mask(D_TRACE, "loadbalancer-betatunnel %04X:%04X selected beta: n%dms>b%dms", er->caid, caid_to, time_nagra, time_beta);
				convert_to_beta_int(er, caid_to);
			}
			else {
				cs_debug_mask(D_TRACE, "loadbalancer-betatunnel %04X:%04X selected nagra: n%dms<b%dms", er->caid, caid_to, time_nagra, time_beta);
			}
			// else nagra is faster or no beta, so continue unmodified
		}
	}
 		
	LLIST * result = ll_create();
	LLIST * selected = ll_create();
	LLIST * timeout_services = ll_create();
	
	struct timeb new_nulltime;
	memset(&new_nulltime, 0, sizeof(new_nulltime));
	time_t current_time = time(NULL);
	int32_t current = -1;
	READER_STAT *stat = NULL;
	int32_t retrylimit = get_retrylimit(er);
	
	int32_t nlocal_readers = 0;
	int32_t nbest_readers = get_nbest_readers(er);
	int32_t nfb_readers = cfg.lb_nfb_readers;
	int32_t nreaders = cfg.lb_max_readers;
	if (!nreaders) nreaders = -1;

#ifdef WITH_DEBUG 
	if (cs_dblevel & 0x01) {
		//loadbalancer debug output:
		int32_t size = 1;
		int32_t nr = 0;
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
			username(er->client), er->caid, prid, er->srvid, er->l, ll_count(er->matching_rdr), rdrs);
			
		free(rdrs);
	}
#endif	

	it = ll_iter_create(er->matching_rdr);
	while ((rdr=ll_iter_next(it)) && nreaders) {
	
			int32_t weight = rdr->lb_weight <= 0?100:rdr->lb_weight;
				
			stat = get_stat(rdr, er->caid, prid, er->srvid, er->l);
			if (!stat) {
				cs_debug_mask(D_TRACE, "loadbalancer: starting statistics for reader %s", rdr->label);
				add_stat(rdr, er, 1, -1);
				ll_append(result, rdr); //no statistics, this reader is active (now) but we need statistics first!
				nreaders--;
				continue;
			}
			
			if (stat->ecm_count < 0||(stat->ecm_count > cfg.lb_max_ecmcount && stat->time_avg > retrylimit)) {
				cs_debug_mask(D_TRACE, "loadbalancer: max ecms (%d) reached by reader %s, resetting statistics", cfg.lb_max_ecmcount, rdr->label);
				reset_stat(er->caid, prid, er->srvid, er->l);
				ll_append(result, rdr); //max ecm reached, get new statistics
				nreaders--;
				continue;
			}
				
			int32_t hassrvid = has_srvid(rdr->client, er) || has_ident(&rdr->ftab, er);
			
			if (stat->rc == 0 && stat->ecm_count < cfg.lb_min_ecmcount) {
				cs_debug_mask(D_TRACE, "loadbalancer: reader %s needs more statistics", rdr->label);
				ll_append(result, rdr); //need more statistics!
				nreaders--;
				continue;
			}
			
			//Reader can decode this service (rc==0) and has lb_min_ecmcount ecms:
			if (stat->rc == 0 || hassrvid) {
				if (cfg.preferlocalcards && !(rdr->typ & R_IS_NETWORK))
					nlocal_readers++; //Prefer local readers!

				if (stat->rc >= 5)
					ll_prepend(timeout_services, rdr);
					//just add another reader if best reader is nonresponding but has services
					
				switch (cfg.lb_mode) {
					default:
					case LB_NONE:
					case LB_LOG_ONLY:
						//cs_debug_mask(D_TRACE, "loadbalance disabled");
						ll_append(result, rdr);
						nreaders--;
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
				
				if (rdr->client->pending)
					current=current*rdr->client->pending;
					
				if (current < 1)
					current=1;
				ll_append(selected, crt_cur(rdr, current, stat->time_avg));
		}
	}
	ll_iter_release(it);

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
	int32_t best_time = 0;
	LL_NODE *fallback = NULL;

	int32_t n=0;
	while (nreaders) {
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
			if (!ll_contains(timeout_services, best_rdri))
				nlocal_readers--;
			ll_append(result, best_rdri);
			nreaders--;
			//OLDEST_READER:
			cs_ftime(&best_rdri->lb_last);
		}
		else if (nbest_readers) {//primary readers, other
			if (!ll_contains(timeout_services, best_rdri))
				nbest_readers--;
			ll_append(result, best_rdri);
			nreaders--;
			//OLDEST_READER:
			cs_ftime(&best_rdri->lb_last);
		}
		else if (nfb_readers) { //fallbacks:
			if (!ll_contains(timeout_services, best_rdri))
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
	ll_destroy(timeout_services);
	
	if (ll_count(result) < ll_count(er->matching_rdr)) {
		if (!n) //no best reader found? reopen if we have ecm_count>0
		{
			cs_debug_mask(D_TRACE, "loadbalancer: NO MATCHING READER FOUND, reopen last valid:");
			it = ll_iter_create(er->matching_rdr);
			while ((rdr=ll_iter_next(it))) {
   	     		stat = get_stat(rdr, er->caid, prid, er->srvid, er->l);
   	     		if (stat && stat->ecm_count>0 && stat->last_received+get_reopen_seconds(stat) < current_time) {
   	     			if (!ll_contains(result, rdr) && nreaders) {
   	     				ll_append(result, rdr);
   	     				nreaders--;
					}
        			n++;
        			cs_debug_mask(D_TRACE, "loadbalancer: reopened reader %s", rdr->label);
				}
			}
			ll_iter_release(it);
			cs_debug_mask(D_TRACE, "loadbalancer: reopened %d readers", n);
		}

		//algo for reopen other reader only if responsetime>retrylimit:
		int32_t reopen = !best_rdr || (best_time && (best_time > retrylimit));
		if (reopen) {
#ifdef WITH_DEBUG 
			if (best_rdr)
				cs_debug_mask(D_TRACE, "loadbalancer: reader %s reached retrylimit (%dms), reopening other readers", best_rdr->label, best_time);
			else
				cs_debug_mask(D_TRACE, "loadbalancer: no best reader found, reopening other readers");	
#endif	
			it = ll_iter_create(er->matching_rdr);
			while ((rdr=ll_iter_next(it)) && nreaders) {
				stat = get_stat(rdr, er->caid, prid, er->srvid, er->l); 

				if (stat && stat->rc != 0) { //retrylimit reached:
					if (cfg.lb_reopen_mode || stat->last_received+get_reopen_seconds(stat) < current_time) { //Retrying reader every (900/conf) seconds
						stat->last_received = current_time;
						nreaders += ll_remove(result, rdr);
						ll_prepend(result, rdr);
						nreaders--;
						cs_debug_mask(D_TRACE, "loadbalancer: retrying reader %s (fail %d)", rdr->label, stat->fail_factor);
					}
				}
			}
			ll_iter_release(it);
		}
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
		int32_t size = 3;
		int32_t nr = 0;
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
			username(er->client), er->caid, prid, er->srvid, er->l, ll_count(result), rdrs);
		
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
	int32_t cleaned = 0;
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

void housekeeping_stat(int32_t force)
{
	time_t now = time(NULL);
	if (!force && now/60/60 == last_housekeeping/60/60) //only clean once in an hour
		return;
	
	last_housekeeping = now;
	start_thread((void*)&housekeeping_stat_thread, "housekeeping lb stats");
}
