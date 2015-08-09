#define MODULE_LOG_PREFIX "cwccheck"

#include "globals.h"
#ifdef CW_CYCLE_CHECK

#include "module-cw-cycle-check.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-cache.h"

struct s_cwc_md5
{
	uchar           md5[CS_ECMSTORESIZE];
	int32_t         csp_hash;
	uchar           cw[16];
};

struct s_cw_cycle_check
{
	uchar           cw[16];
	time_t          time;
	time_t          locktime; // lock in learning
	uint16_t        caid;
	uint16_t        sid;
	uint16_t        chid;
	uint32_t        provid;
	int16_t         ecmlen;
	int8_t          stage;
	int32_t         cycletime;
	int32_t         dyncycletime;
	int8_t          nextcyclecw;
	struct s_cwc_md5    ecm_md5[15]; // max 15 old ecm md5 /csp-hashs
	int8_t          cwc_hist_entry;
	uint8_t         old;
	int8_t			stage4_repeat;
	struct s_cw_cycle_check *prev;
	struct s_cw_cycle_check *next;
};

extern CS_MUTEX_LOCK cwcycle_lock;

static struct s_cw_cycle_check *cw_cc_list;
static int32_t cw_cc_list_size;
static time_t last_cwcyclecleaning;

/*
 * Check for CW CYCLE
 */

static uint8_t chk_is_pos_fallback(ECM_REQUEST *er, char *reader)
{
	struct s_ecm_answer *ea;
	struct s_reader *fbrdr;
	char fb_reader[64];

	for(ea = er->matching_rdr; ea; ea = ea->next)
	{
		if(ea->reader)
		{
			fbrdr = ea->reader;
			snprintf(fb_reader, sizeof(fb_reader), "%s", ea->reader->label);
			if(!strcmp(reader, fb_reader) && chk_is_fixed_fallback(fbrdr, er))
			{
				cs_log("cyclecheck [check Fixed FB] %s is set as fixed fallback", reader);
				return 1;
			}
		}
	}
	return 0;
}

static inline uint8_t checkECMD5CW(uchar *ecmd5_cw)
{
	int8_t i;
	for(i = 0; i < CS_ECMSTORESIZE; i++)
		if(ecmd5_cw[i]) { return 1; }
	return 0;
}

/*
 * countCWpart is to prevent like this
 * D41A1A08B01DAD7A 0F1D0A36AF9777BD found -> ok
 * E9151917B01DAD7A 0F1D0A36AF9777BD found last -> worng (freeze), but for cwc is ok
 * 7730F59C6653A55E D3822A7F133D3C8C cwc bad -> but cw is right, cwc out of step
 */
static uint8_t countCWpart(ECM_REQUEST *er, struct s_cw_cycle_check *cwc)
{
	uint8_t eo = cwc->nextcyclecw ? 0 : 8;
	int8_t i, ret = 0;
	char cwc_cw[9 * 3];
	char er_cw[9 * 3];

	for(i = 0; i < 8; i++)
	{
		if(cwc->cw[i + eo] == er->cw[i + eo])
		{
			ret++;
		}
	}

	cs_hexdump(0, cwc->cw + eo, 8, cwc_cw, sizeof(cwc_cw));
	cs_hexdump(0, er->cw + eo, 8, er_cw, sizeof(er_cw));
	cs_log_dbg(D_CWC, "cyclecheck [countCWpart] er-cw %s", er_cw);
	cs_log_dbg(D_CWC, "cyclecheck [countCWpart] cw-cw %s", cwc_cw);
	if(ret > cfg.cwcycle_sensitive)
	{
		cs_log("cyclecheck [countCWpart] new cw is to like old one (unused part), sensitive %d, same bytes %d", cfg.cwcycle_sensitive, ret);
	}
	return ret;
}

static uint8_t checkvalidCW(ECM_REQUEST *er)
{
	uint8_t ret = 1;	
	if(chk_is_null_CW(er->cw)) 
	{ er->rc = E_NOTFOUND; }

	if(er->rc == E_NOTFOUND)
	{ return 0; } //wrong  leave the check

	if(checkCWpart(er->cw, 0) && checkCWpart(er->cw, 1))
	{ return 1; } //cw1 and cw2 is filled -> we can check for cwc

	if((!checkCWpart(er->cw, 0) || !checkCWpart(er->cw, 1)) && caid_is_videoguard(er->caid))
	{
		cs_log("CAID: %04X uses obviously half cycle cw's : NO need to check it with CWC! Remove CAID: %04X from CWC Config!", er->caid, er->caid);
		ret = 0;  // cw1 or cw2 is null 
	}

	return ret;
}

void cleanupcwcycle(void)
{
	time_t now = time(NULL);
	if(last_cwcyclecleaning + 120 > now)  //only clean once every 2min
		{ return; }

	last_cwcyclecleaning = now;
	int32_t count = 0, kct = cfg.keepcycletime * 60 + 30; // if keepcycletime is set, wait more before deleting
	struct s_cw_cycle_check *prv = NULL, *currentnode = NULL, *temp = NULL;

	bool bcleanup = false;

	//write lock
	cs_writelock(__func__, &cwcycle_lock);
	for(currentnode = cw_cc_list, prv = NULL; currentnode; prv = currentnode, currentnode = currentnode->next, count++)   // First Remove old Entrys
	{
		if((now - currentnode->time) <= kct)    // delete Entry which old to hold list small
		{
			continue;
		}
		cs_log_dbg(D_CWC, "cyclecheck [Cleanup] diff: %ld kct: %i", now - currentnode->time, kct);
		if(prv != NULL)
		{
			prv->next  = NULL;
		}
		else
		{
			cw_cc_list = NULL;
		}
		bcleanup = true;
		break; //we need only once, all follow to old
	}
	cs_writeunlock(__func__, &cwcycle_lock);
	while(currentnode != NULL)
	{
		temp = currentnode->next;
		if(!currentnode->old)
			{ cw_cc_list_size--; }
		NULLFREE(currentnode);
		currentnode = temp;
	}
	if(bcleanup)
		{ cs_log_dbg(D_CWC, "cyclecheck [Cleanup] list new size: %d (realsize: %d)", cw_cc_list_size, count); }
}

static int32_t checkcwcycle_int(ECM_REQUEST *er, char *er_ecmf , char *user, uchar *cw , char *reader, uint8_t cycletime_fr, uint8_t next_cw_cycle_fr)
{

	int8_t i, ret = 6; // ret = 6 no checked
	int8_t cycleok = -1;
	time_t now = er->tps.time;//time(NULL);
	uint8_t need_new_entry = 1, upd_entry = 1;
	char cwstr[17 * 3]; //cw to check

	char cwc_ecmf[ECM_FMT_LEN];
	char cwc_md5[17 * 3];
	char cwc_cw[17 * 3];
	char cwc_csp[5 * 3];
	int8_t n = 1, m = 1, k;
	int32_t mcl = cfg.maxcyclelist;
	struct s_cw_cycle_check *currentnode = NULL, *cwc = NULL;

	/*for(list = cw_cc_list; list; list = list->next) { // List all Entrys in Log for DEBUG
	    cs_log_dbg(D_CWC, "cyclecheck: [LIST] %04X@%06X:%04X OLD: %i Time: %ld DifftoNow: %ld Stage: %i cw: %s", list->caid, list->provid, list->sid, list->old, list->time, now - list->time, list->stage, cs_hexdump(0, list->cw, 16, cwstr, sizeof(cwstr)));

	}*/

	if(!checkvalidCW(er))
	{ return 3; } //cwc ign	

	//read lock
	cs_readlock(__func__, &cwcycle_lock);
	for(currentnode = cw_cc_list; currentnode; currentnode = currentnode->next)
	{
		if(currentnode->caid != er->caid || currentnode->provid != er->prid || currentnode->sid != er->srvid || currentnode->chid != er->chid)
		{
			continue;
		}
		if(er->ecmlen != 0 && currentnode->ecmlen != 0)
		{
			if(currentnode->ecmlen != er->ecmlen)
			{
				cs_log_dbg(D_CWC, "cyclecheck [other ECM LEN] -> don't check");
				continue;
			}

		}
		need_new_entry = 0; // we got a entry for caid/prov/sid so we dont need new one

		cs_hexdump(0, cw, 16, cwstr, sizeof(cwstr)); //checked cw for log

		if(cs_malloc(&cwc, sizeof(struct s_cw_cycle_check)))
		{

			memcpy(cwc, currentnode, sizeof(struct s_cw_cycle_check)); //copy current to new



			if(!currentnode->old)
			{
				currentnode->old = 1; //need later to counting
				cw_cc_list_size--;
			}
			//now we have all data and can leave read lock
			cs_readunlock(__func__, &cwcycle_lock);

			cs_hexdump(0, cwc->ecm_md5[cwc->cwc_hist_entry].md5, 16, cwc_md5, sizeof(cwc_md5));
			cs_hexdump(0, (void *)&cwc->ecm_md5[cwc->cwc_hist_entry].csp_hash, 4, cwc_csp, sizeof(cwc_csp));
			cs_hexdump(0, cwc->cw, 16, cwc_cw, sizeof(cwc_cw));
			ecmfmt(cwc_ecmf, ECM_FMT_LEN, cwc->caid, 0, cwc->provid, cwc->chid, 0, cwc->sid, cwc->ecmlen, cwc_md5, cwc_csp, cwc_cw, 0, 0, NULL);

// Cycletime over Cacheex
			if (cfg.cwcycle_usecwcfromce)
			{
				if(cycletime_fr > 0 && next_cw_cycle_fr < 2)
				{
					cs_log_dbg(D_CWC, "cyclecheck [Use Info in Request] Client: %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", user, cycletime_fr, next_cw_cycle_fr, er->caid, er->prid, er->srvid);
					cwc->stage = 3;
					cwc->cycletime = cycletime_fr;
					cwc->nextcyclecw = next_cw_cycle_fr;
					ret = 8;
					if(memcmp(cwc->cw, cw, 16) == 0) //check if the store cw the same like the current
					{
						cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
						cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
						if(now - cwc->time >= cwc->cycletime - cwc->dyncycletime)
						{
							cs_log_dbg(D_CWC, "cyclecheck [Same CW but much too late] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
							ret = cfg.cwcycle_dropold ? 2 : 4;
						}
						else
						{				
						ret = 4; // Return 4 same CW
						}
						upd_entry = 0;
					}		
					break;
				}
			}
//
			if(cwc->stage == 3 && cwc->nextcyclecw < 2 && now - cwc->time < cwc->cycletime * 2 - cwc->dyncycletime - 1)    // Check for Cycle no need to check Entrys others like stage 3
			{
				/*for (k=0; k<15; k++) { // debug md5
				            cs_log_dbg(D_CWC, "cyclecheck [checksumlist[%i]]: ecm_md5: %s csp-hash: %d Entry: %i", k, cs_hexdump(0, cwc->ecm_md5[k].md5, 16, ecm_md5, sizeof(ecm_md5)), cwc->ecm_md5[k].csp_hash, cwc->cwc_hist_entry);
				} */

					// first we check if the store cw the same like the current
					if(memcmp(cwc->cw, cw, 16) == 0)
					{
						cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
						cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
						if(now - cwc->time >= cwc->cycletime - cwc->dyncycletime)
						{
							cs_log_dbg(D_CWC, "cyclecheck [Same CW but much too late] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
							ret = cfg.cwcycle_dropold ? 2 : 4;
						}
						else
						{				
						ret = 4;  // Return 4 same CW
						}
						upd_entry = 0;
						break;
					}

					if(cwc->nextcyclecw == 0)    //CW0 must Cycle
					{
						for(i = 0; i < 8; i++)
						{
							if(cwc->cw[i] == cw[i])
							{
								cycleok = 0; //means CW0 Cycle OK
							}
							else
							{
								cycleok = -1;
								break;
							}
						}
					}
					else if(cwc->nextcyclecw == 1)     //CW1 must Cycle
					{
						for(i = 0; i < 8; i++)
						{
							if(cwc->cw[i + 8] == cw[i + 8])
							{
								cycleok = 1; //means CW1 Cycle OK
							}
							else
							{
								cycleok = -1;
								break;
							}
						}
					}

					if(cycleok >= 0 && cfg.cwcycle_sensitive && countCWpart(er, cwc) >= cfg.cwcycle_sensitive)  //2,3,4, 0 = off
					{
						cycleok = -2;
					}

				if(cycleok >= 0)
				{
					ret = 0;  // return Code 0 Cycle OK
					if(cycleok == 0)
					{
						cwc->nextcyclecw = 1;
						er->cwc_next_cw_cycle = 1;
						if(cwc->cycletime < 128 && (!(cwc->caid == 0x0100 && cwc->provid == 0x00006A))) // make sure cycletime is lower dez 128 because share over cacheex buf[18] bit 8 is used for cwc_next_cw_cycle
							{ er->cwc_cycletime = cwc->cycletime; }
						cs_log_dbg(D_CWC, "cyclecheck [Valid CW 0 Cycle] Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader);
					}
					else if(cycleok == 1)
					{
						cwc->nextcyclecw = 0;
						er->cwc_next_cw_cycle = 0;
						if(cwc->cycletime < 128 && (!(cwc->caid == 0x0100 && cwc->provid == 0x00006A))) // make sure cycletime is lower dez 128 because share over cacheex buf[18] bit 8 is used for cwc_next_cw_cycle
							{ er->cwc_cycletime = cwc->cycletime; }
						cs_log_dbg(D_CWC, "cyclecheck [Valid CW 1 Cycle] Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader);
					}
					cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
					cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
				}
				else
				{

					for(k = 0; k < 15; k++)  // check for old ECMs
					{
#ifdef CS_CACHEEX
						if((checkECMD5CW(er->ecmd5) && checkECMD5CW(cwc->ecm_md5[k].md5) && !(memcmp(er->ecmd5, cwc->ecm_md5[k].md5, sizeof(er->ecmd5)))) || (er->csp_hash && cwc->ecm_md5[k].csp_hash && er->csp_hash == cwc->ecm_md5[k].csp_hash))
#else
						if((memcmp(er->ecmd5, cwc->ecm_md5[k].md5, sizeof(er->ecmd5))) == 0)
#endif
						{
							cs_log_dbg(D_CWC, "cyclecheck [OLD] [CheckedECM] Client: %s EA: %s", user, er_ecmf);
							cs_hexdump(0, cwc->ecm_md5[k].md5, 16, cwc_md5, sizeof(cwc_md5));
							cs_hexdump(0, (void *)&cwc->ecm_md5[k].csp_hash, 4, cwc_csp, sizeof(cwc_csp));
							cs_log_dbg(D_CWC, "cyclecheck [OLD] [Stored ECM] Client: %s EA: %s.%s", user, cwc_md5, cwc_csp);
							if(!cfg.cwcycle_dropold && !memcmp(cwc->ecm_md5[k].cw, cw, 16))
								{ ret = 4; }
							else
								{ ret = 2; } // old ER
							upd_entry = 0;
							break;
						}
					}
					if(!upd_entry) { break; }
					if(cycleok == -2)
						{ cs_log_dbg(D_CWC, "cyclecheck [ATTENTION!! NON Valid CW] Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader); }
					else
						{ cs_log_dbg(D_CWC, "cyclecheck [ATTENTION!! NON Valid CW Cycle] NO CW Cycle detected! Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader); }
					cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
					cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
					ret = 1; // bad cycle
					upd_entry = 0;
					if(cfg.cwcycle_allowbadfromffb)
					{
						if(chk_is_pos_fallback(er, reader))
								{
									ret = 5;
									cwc->stage = 4;
									upd_entry = 1;
									cwc->nextcyclecw = 2;
									break;
								}
							}
					break;
				}
			}
			else
			{
				if(cwc->stage == 3)
				{
					if(cfg.keepcycletime > 0 && now - cwc->time < cfg.keepcycletime * 60)    // we are in keepcycletime window
					{
						cwc->stage++;   // go to stage 4
						cs_log_dbg(D_CWC, "cyclecheck [Set Stage 4] for Entry: %s Cycletime: %i -> Entry too old but in keepcycletime window - no cycletime learning - only check which CW must cycle", cwc_ecmf, cwc->cycletime);
					}
					else
					{
						cwc->stage--; // go one stage back, we are not in keepcycletime window
						cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 2] for Entry: %s Cycletime: %i -> new cycletime learning", cwc_ecmf, cwc->cycletime);
					}
					memset(cwc->cw, 0, sizeof(cwc->cw)); //fake cw for stage 2/4
					ret = 3;
					cwc->nextcyclecw = 2;
				}
			}
			if(upd_entry)    //  learning stages
			{
				if(now > cwc->locktime)
				{
					int16_t diff = now - cwc->time - cwc->cycletime;
					if(cwc->stage <= 0)    // stage 0 is passed; we update the cw's and time and store cycletime
					{
						// if(cwc->cycletime == now - cwc->time)    // if we got a stable cycletime we go to stage 1
						if(diff > -2 && diff < 2)    // if we got a stable cycletime we go to stage 1
						{
							cwc->cycletime = now - cwc->time;
							cs_log_dbg(D_CWC, "cyclecheck [Set Stage 1] %s Cycletime: %i Lockdiff: %ld", cwc_ecmf, cwc->cycletime, now - cwc->locktime);
							cwc->stage++; // increase stage
						}
						else
						{
							cs_log_dbg(D_CWC, "cyclecheck [Stay on Stage 0] %s Cycletime: %i -> no constant CW-Change-Time", cwc_ecmf, cwc->cycletime);
						}

					}
					else if(cwc->stage == 1)     // stage 1 is passed; we update the cw's and time and store cycletime
					{
						// if(cwc->cycletime == now - cwc->time)    // if we got a stable cycletime we go to stage 2
						if(diff > -2 && diff < 2)    // if we got a stable cycletime we go to stage 2
						{
							cwc->cycletime = now - cwc->time;
							cs_log_dbg(D_CWC, "cyclecheck [Set Stage 2] %s Cycletime: %i Lockdiff: %ld", cwc_ecmf, cwc->cycletime, now - cwc->locktime);
							cwc->stage++; // increase stage
						}
						else
						{
							cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 0] for Entry %s Cycletime: %i -> no constant CW-Change-Time", cwc_ecmf, cwc->cycletime);
							cwc->stage--;
						}
					}
					else if(cwc->stage == 2)     // stage 2 is passed; we update the cw's and compare cycletime
					{
						// if(cwc->cycletime == now - cwc->time && cwc->cycletime > 0)    // if we got a stable cycletime we go to stage 3
						if(diff > -2 && diff < 2 && cwc->cycletime > 0)    // if we got a stable cycletime we go to stage 3
						{
							cwc->cycletime = now - cwc->time;
							n = memcmp(cwc->cw, cw, 8);
							m = memcmp(cwc->cw + 8, cw + 8, 8);
							if(n == 0)
							{
								cwc->nextcyclecw = 1;
							}
							if(m == 0)
							{
								cwc->nextcyclecw = 0;
							}
							if(n == m || !checkECMD5CW(cw)) { cwc->nextcyclecw = 2; }  //be sure only one cw part cycle and is valid
							if(cwc->nextcyclecw < 2)
							{
								cs_log_dbg(D_CWC, "cyclecheck [Set Stage 3] %s Cycletime: %i Lockdiff: %ld nextCycleCW = CW%i", cwc_ecmf, cwc->cycletime, now - cwc->locktime, cwc->nextcyclecw);
								cs_log_dbg(D_CWC, "cyclecheck [Set Cycletime %i] for Entry: %s -> now we can check CW's", cwc->cycletime, cwc_ecmf);
								cwc->stage = 3; // increase stage
							}
							else
							{
								cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 1] for Entry %s Cycletime: %i -> no CW-Cycle in Learning Stage", cwc_ecmf, cwc->cycletime);  // if a server asked only every twice ECM we got a stable cycletime*2 ->but thats wrong
								cwc->stage = 1;
							}

						}
						else
						{

							cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 1] for Entry %s Cycletime: %i -> no constant CW-Change-Time", cwc_ecmf, cwc->cycletime);
							cwc->stage = 1;
						}
					}
					else if(cwc->stage == 4)	// we got a early learned cycletime.. use this cycletime and check only which cw cycle 
					{
						n = memcmp(cwc->cw, cw, 8);
						m = memcmp(cwc->cw + 8, cw + 8, 8);
						if(n == 0)
						{
							cwc->nextcyclecw = 1;
						}
						if(m == 0)
						{
							cwc->nextcyclecw = 0;
						}
						if(n == m || !checkECMD5CW(cw)) { cwc->nextcyclecw = 2; }  //be sure only one cw part cycle and is valid
						if(cwc->nextcyclecw < 2)
						{
							cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 3] %s Cycletime: %i Lockdiff: %ld nextCycleCW = CW%i", cwc_ecmf, cwc->cycletime, now - cwc->locktime, cwc->nextcyclecw);
							cs_log_dbg(D_CWC, "cyclecheck [Set old Cycletime %i] for Entry: %s -> now we can check CW's", cwc->cycletime, cwc_ecmf);
							cwc->stage = 3; // go back to stage 3
						}
						else
						{
							cs_log_dbg(D_CWC, "cyclecheck [Stay on Stage %d] for Entry %s Cycletime: %i no cycle detect!", cwc->stage, cwc_ecmf, cwc->cycletime);
							if (cwc->stage4_repeat > 12) 
							{ 
								cwc->stage = 1;
								cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 1] too much cyclefailure, maybe cycletime not correct %s Cycletime: %i Lockdiff: %ld nextCycleCW = CW%i", cwc_ecmf, cwc->cycletime, now - cwc->locktime, cwc->nextcyclecw);							
							} 
						}
						cwc->stage4_repeat++;
						ret = ret == 3 ? 3 : 7; // IGN for first stage4 otherwise LEARN
					}
					if(cwc->stage == 3)
					{
						cwc->locktime = 0;
						cwc->stage4_repeat = 0;
					}
					else
					{
						if(cwc->stage < 3) { cwc->cycletime = now - cwc->time; }
						cwc->locktime = now + (get_fallbacktimeout(cwc->caid) / 1000);
					}
				}
				else if(cwc->stage != 3)
				{
					cs_log_dbg(D_CWC, "cyclecheck [Ignore this EA] for LearningStages because of locktime EA: %s Lockdiff: %ld", cwc_ecmf, now - cwc->locktime);
					upd_entry = 0;
				}

				if(cwc->stage == 3)     // we stay in Stage 3 so we update only time and cw
				{
					if(now - cwc->time > cwc->cycletime)
					{
						cwc->dyncycletime = now - cwc->time - cwc->cycletime;
					}
					else
					{
						cwc->dyncycletime = 0;
					}
				}
			}
		}
		else
		{
			upd_entry = 0;
			cwc = NULL;
		}
		break;
	}

	if(need_new_entry)
	{
		cs_readunlock(__func__, &cwcycle_lock);
		if(cw_cc_list_size <= mcl)    //only add when we have space
		{
			struct s_cw_cycle_check *new = NULL;
			if(cs_malloc(&new, sizeof(struct s_cw_cycle_check)))    // store cw on top in cyclelist
			{
				memcpy(new->cw, cw, sizeof(new->cw));
				// csp cache got no ecm and no md5 hash
				memcpy(new->ecm_md5[0].md5, er->ecmd5, sizeof(er->ecmd5));
#ifdef CS_CACHEEX
				new->ecm_md5[0].csp_hash = er->csp_hash; // we got no ecm_md5 so CSP-Hash could be necessary
#else
				new->ecm_md5[0].csp_hash = 0; //fake CSP-Hash we got a ecm_md5 so CSP-Hash is not necessary
#endif
				memcpy(new->ecm_md5[0].cw, cw, sizeof(new->cw));
				new->ecmlen = er->ecmlen;
				new->cwc_hist_entry = 0;
				new->caid = er->caid;
				new->provid = er->prid;
				new->sid = er->srvid;
				new->chid = er->chid;
				new->time = now;
				new->locktime = now + (get_fallbacktimeout(er->caid) / 1000);
				new->dyncycletime = 0; // to react of share timings
// cycletime over Cacheex
				new->stage = (cfg.cwcycle_usecwcfromce && cycletime_fr > 0 && next_cw_cycle_fr < 2) ? 3 : 0;
				new->cycletime = (cfg.cwcycle_usecwcfromce && cycletime_fr > 0 && next_cw_cycle_fr < 2) ? cycletime_fr : 99;
				new->nextcyclecw = (cfg.cwcycle_usecwcfromce && cycletime_fr > 0 && next_cw_cycle_fr < 2) ? next_cw_cycle_fr : 2; //2=we dont know which next cw Cycle;  0= next cw Cycle CW0; 1= next cw Cycle CW1;
				ret = (cycletime_fr > 0 && next_cw_cycle_fr < 2) ? 8 : 6;
//		
				new->prev = new->next = NULL;
				new->old = 0;
				new->stage4_repeat = 0;
				//write lock
				cs_writelock(__func__, &cwcycle_lock);
				if(cw_cc_list)    // the new entry on top
				{
					cw_cc_list->prev = new;
					new->next = cw_cc_list;
				}
				cw_cc_list = new;
				cw_cc_list_size++;
				//write unlock /
				cs_writeunlock(__func__, &cwcycle_lock);

				cs_log_dbg(D_CWC, "cyclecheck [Store New Entry] %s Time: %ld Stage: %i Cycletime: %i Locktime: %ld", er_ecmf, new->time, new->stage, new->cycletime, new->locktime);
			}
		}
		else
		{
			cs_log("cyclecheck [Store New Entry] Max List arrived -> dont store new Entry list_size: %i, mcl: %i", cw_cc_list_size, mcl);
		}
	}
	else if(upd_entry && cwc)
	{
		cwc->prev = cwc->next = NULL;
		cwc->old = 0;
		memcpy(cwc->cw, cw, sizeof(cwc->cw));
		cwc->time = now;
		cwc->cwc_hist_entry++;
		if(cwc->cwc_hist_entry > 14)     //ringbuffer for md5
		{
			cwc->cwc_hist_entry = 0;
		}
		// csp cache got no ecm and no md5 hash
		memcpy(cwc->ecm_md5[cwc->cwc_hist_entry].md5, er->ecmd5, sizeof(cwc->ecm_md5[0].md5));
#ifdef CS_CACHEEX
		cwc->ecm_md5[cwc->cwc_hist_entry].csp_hash = er->csp_hash;
#else
		cwc->ecm_md5[cwc->cwc_hist_entry].csp_hash = 0; //fake CSP-Hash for logging
#endif
		memcpy(cwc->ecm_md5[cwc->cwc_hist_entry].cw, cw, sizeof(cwc->cw));
		cwc->ecmlen = er->ecmlen;
		//write lock /
		cs_writelock(__func__, &cwcycle_lock);
		if(cw_cc_list)    // the clone entry on top
		{
			cw_cc_list->prev = cwc;
			cwc->next = cw_cc_list;
		}
		cw_cc_list = cwc;
		cw_cc_list_size++;
		//write unlock /
		cs_writeunlock(__func__, &cwcycle_lock);
		cs_log_dbg(D_CWC, "cyclecheck [Update Entry and add on top] %s Time: %ld Stage: %i Cycletime: %i", er_ecmf, cwc->time, cwc->stage, cwc->cycletime);
	}
	else if(cwc)
	{
		NULLFREE(cwc);
	}
	return ret;
}

static void count_ok(struct s_client *client)
{
	if(client)
	{
		client->cwcycledchecked++;
		client->cwcycledok++;
	}
	if(client && client->account)
	{
		client->account->cwcycledchecked++;
		client->account->cwcycledok++;
	}
}

static void count_nok(struct s_client *client)
{
	if(client)
	{
		client->cwcycledchecked++;
		client->cwcyclednok++;
	}
	if(client && client->account)
	{
		client->account->cwcycledchecked++;
		client->account->cwcyclednok++;
	}
}

static void count_ign(struct s_client *client)
{
	if(client)
	{
		client->cwcycledchecked++;
		client->cwcycledign++;
	}
	if(client && client->account)
	{
		client->account->cwcycledchecked++;
		client->account->cwcycledign++;
	}
}

uint8_t checkcwcycle(struct s_client *client, ECM_REQUEST *er, struct s_reader *reader, uchar *cw, int8_t rc, uint8_t cycletime_fr, uint8_t next_cw_cycle_fr)
{

	if(!cfg.cwcycle_check_enable)
		{ return 3; }
	if(client && client->account && client->account->cwc_disable)
		{ return 3; }
	//  if (!(rc == E_FOUND) && !(rc == E_CACHEEX))
	if(rc >= E_NOTFOUND)
		{ return 2; }
	if(!cw || !er)
		{ return 2; }
	if(!(chk_ctab_ex(er->caid, &cfg.cwcycle_check_caidtab)))  // dont check caid not in list
		{ return 1; } // no match leave the check
	if(is_halfCW_er(er))
		{ return 1; } // half cw cycle, checks are done in ecm-handler

	memcpy(er->cw, cw, 16);
	char er_ecmf[ECM_FMT_LEN];
	format_ecm(er, er_ecmf, ECM_FMT_LEN);

	char c_reader[64];
	char user[64];

	if(!streq(username(client), "NULL"))
		{ snprintf(user, sizeof(user), "%s", username(client)); }
	else
		{ snprintf(user, sizeof(user), "---"); }

	if(reader)
		{ snprintf(c_reader, sizeof(c_reader), "%s", reader->label); }
	else
		{ snprintf(c_reader, sizeof(c_reader), "cache"); }


	cs_log_dbg(D_CWC | D_TRACE, "cyclecheck EA: %s rc: %i reader: %s", er_ecmf, rc, c_reader);

	switch(checkcwcycle_int(er, er_ecmf, user, cw, c_reader, cycletime_fr, next_cw_cycle_fr))
	{

	case 0: // CWCYCLE OK
		count_ok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc OK");
		break;

	case 1: // CWCYCLE NOK
		count_nok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK");
		if(cfg.onbadcycle > 0)    // ignore ECM Request
		{
			cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> drop cw (ECM Answer)", user, er_ecmf, c_reader); //D_CWC| D_TRACE
			return 0;
		}
		else      // only logging
		{
			cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> do nothing", user, er_ecmf, c_reader);//D_CWC| D_TRACE
			break;
		}

	case 2: // ER to OLD
		count_nok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK(old)");
		cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> ECM Answer is too OLD -> drop cw (ECM Answer)", user, er_ecmf, c_reader);//D_CWC| D_TRACE
		return 0;

	case 3: // CycleCheck ignored (stage 3 to stage 4)
		count_ign(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc IGN");
		break;

	case 4: // same CW
		cs_log_dbg(D_CWC, "cyclecheck [Same CW] for: %s %s -> same CW detected from: %s -> do nothing ", user, er_ecmf, c_reader);
		break;

	case 5: //answer from fixed Fallbackreader with Bad Cycle
		count_nok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK but IGN (fixed FB)");
		cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> But Ignored because of answer from Fixed Fallback Reader", user, er_ecmf, c_reader);
		break;

	case 6: // not checked ( learning Stages Cycletime and CWCycle Stage < 3)
	case 7: // not checked ( learning Stages only CWCycle Stage 4)
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc LEARN");
		break;

	case 8: // use Cyclecheck from CE Source
		count_ok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc OK(CE)");
		break;

	case 9: // CWCYCLE NOK without counting
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK");
		if(cfg.onbadcycle > 0)    // ignore ECM Request
		{
			cs_log("cyclecheck [Bad CW Cycle already Counted] for: %s %s from: %s -> drop cw (ECM Answer)", user, er_ecmf, c_reader); 
			return 0;
		}
		else      // only logging
		{
			cs_log("cyclecheck [Bad CW Cycle already Counted] for: %s %s from: %s -> do nothing", user, er_ecmf, c_reader);
			break;
		}

	}
	return 1;
}


/*
 *
 */

#endif
