//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"

#ifdef CS_ANTICASC

#include "module-anticasc.h"
#include "oscam-conf.h"
#include "oscam-garbage.h"
#include "oscam-string.h"
#include "oscam-time.h"

#define cs_ac "oscam.ac"

FILE *ac_log = NULL;

//static time_t ac_last_chk;
static uchar  ac_ecmd5[CS_ECMSTORESIZE];

static int32_t ac_init_log(void)
{
	if(ac_log)
		{ return 1; }
	if(!cfg.ac_logfile)
	{
		cs_log("ERROR: anti cascading is enabled but ac_logfile is not set.");
		return 0;
	}
	ac_log = fopen(cfg.ac_logfile, "a+");
	if(!ac_log)
	{
		cs_log("ERROR: Can't open anti cascading logfile: %s (errno=%d %s)",
			   cfg.ac_logfile, errno, strerror(errno));
		return 0;
	}
	cs_log("anti cascading log initialized");
	return 1;
}


void ac_clear(void)
{
	struct s_client *client;
	struct s_auth *account;

	for(client = first_client; client; client = client->next)
	{
		if(client->typ != 'c') { continue; }
		memset(&client->acasc, 0, sizeof(client->acasc));
	}

	for(account = cfg.account; account; account = account->next)
		{ memset(&account->ac_stat, 0, sizeof(account->ac_stat)); }
}

void ac_init_stat(void)
{
	if(!cfg.ac_enabled)
		{ return; }
	ac_clear();
	ac_init_log();
}

void ac_do_stat(void)
{
	int32_t j, idx, exceeds, maxval, prev_deny = 0;

	struct s_client *client;
	for(client = first_client; client; client = client->next)
	{
		if(client->typ != 'c') { continue; }

		struct s_acasc *ac_stat = &client->account->ac_stat;
		struct s_acasc_shm *acasc = &client->acasc;

		idx = ac_stat->idx;
		ac_stat->stat[idx] = acasc->ac_count;
		acasc->ac_count = 0;

		if(ac_stat->stat[idx])
		{
			if(client->ac_penalty == 2)    // banned
			{
				cs_debug_mask(D_CLIENT, "acasc: user '%s' banned", client->account->usr);
				acasc->ac_deny = 1;
			}
			else
			{
				for(j = exceeds = maxval = 0; j < cfg.ac_samples; j++)
				{
					if(ac_stat->stat[j] > maxval)
						{ maxval = ac_stat->stat[j]; }
					exceeds += (ac_stat->stat[j] > client->ac_limit);
				}
				prev_deny = acasc->ac_deny;
				acasc->ac_deny = (exceeds >= cfg.ac_denysamples);

				cs_debug_mask(D_CLIENT, "acasc: %s limit=%d, max=%d, samples=%d, dsamples=%d, [idx=%d]:",
							  client->account->usr, client->ac_limit, maxval,
							  cfg.ac_samples, cfg.ac_denysamples, idx);
				cs_debug_mask(D_CLIENT, "acasc: %d %d %d %d %d %d %d %d %d %d ", ac_stat->stat[0],
							  ac_stat->stat[1], ac_stat->stat[2], ac_stat->stat[3],
							  ac_stat->stat[4], ac_stat->stat[5], ac_stat->stat[6],
							  ac_stat->stat[7], ac_stat->stat[8], ac_stat->stat[9]);
				if(acasc->ac_deny)
				{
					cs_log("acasc: user '%s' exceeds limit", client->account->usr);
					ac_stat->stat[idx] = 0;
				}
				else if(prev_deny)
					{ cs_log("acasc: user '%s' restored access", client->account->usr); }
			}
		}
		else if(acasc->ac_deny)
		{
			prev_deny = 1;
			acasc->ac_deny = 0;
			cs_log("acasc: restored access for inactive user '%s'", client->account->usr);
		}

		if(!acasc->ac_deny && !prev_deny)
			{ ac_stat->idx = (ac_stat->idx + 1) % cfg.ac_samples; }
	}
}

void ac_init_client(struct s_client *client, struct s_auth *account)
{
	client->ac_limit = 0;
	client->ac_penalty = account->ac_penalty == -1 ? cfg.ac_penalty : account->ac_penalty;
	client->ac_fakedelay = account->ac_fakedelay == -1 ? cfg.ac_fakedelay : account->ac_fakedelay;
	if(cfg.ac_enabled)
	{
		int32_t numusers = account->ac_users;
		if(numusers == -1)
			{ numusers = cfg.ac_users; }

		if(numusers)
		{
			client->ac_limit = (numusers * 100 + 80) * cfg.ac_stime;
			cs_debug_mask(D_CLIENT, "acasc: user '%s', users=%d, stime=%d min, dwlimit=%d per min, penalty=%d",
						  account->usr, numusers, cfg.ac_stime,
						  numusers * 100 + 80, client->ac_penalty);
		}
		else
		{
			cs_debug_mask(D_CLIENT, "acasc: anti-cascading not used for user '%s'", account->usr);
		}
	}
}

static int32_t ac_dw_weight(ECM_REQUEST *er)
{
	struct s_cpmap *cpmap;

	for(cpmap = cfg.cpmap; (cpmap) ; cpmap = cpmap->next)
		if((cpmap->caid  == 0 || cpmap->caid  == er->caid)  &&
				(cpmap->provid == 0 || cpmap->provid == er->prid)  &&
				(cpmap->sid   == 0 || cpmap->sid   == er->srvid) &&
				(cpmap->chid  == 0 || cpmap->chid  == er->chid))
			{ return (cpmap->dwtime * 100 / 60); }

	cs_debug_mask(D_CLIENT, "acasc: WARNING: CAID %04X, PROVID %06X, SID %04X, CHID %04X not found in oscam.ac",
				  er->caid, er->prid, er->srvid, er->chid);
	cs_debug_mask(D_CLIENT, "acasc: set DW lifetime 10 sec");
	return 16; // 10*100/60
}

void ac_chk(struct s_client *cl, ECM_REQUEST *er, int32_t level)
{
	if(!cl->ac_limit || !cfg.ac_enabled) { return; }

	struct s_acasc_shm *acasc = &cl->acasc;

	if(level == 1)
	{
		if(er->rc == E_FAKE)
			{ acasc->ac_count++; }

		if(er->rc >= E_NOTFOUND)
			{ return; } // not found

		if(memcmp(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE) != 0)
		{
			acasc->ac_count += ac_dw_weight(er);
			memcpy(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE);
		}
		return;
	}

	if(acasc->ac_deny)
	{
		if(cl->ac_penalty)
		{
			if(cl->ac_penalty == 3)
			{
				if(cl->ac_fakedelay > 0)
					{ cs_debug_mask(D_CLIENT, "acasc: fake delay %dms", cl->ac_fakedelay); }
			}
			else
			{
				cs_debug_mask(D_CLIENT, "acasc: send fake dw");
				er->rc = E_FAKE; // fake
				er->rcEx = 0;
			}
			if(cl->ac_fakedelay > 0)
				{ cs_sleepms(cl->ac_fakedelay); }
		}
	}
}

static void ac_load_config(void)
{
	FILE *fp = open_config_file(cs_ac);
	if(!fp)
		{ return; }

	int32_t nr;
	char *saveptr1 = NULL, *token;
	if(!cs_malloc(&token, MAXLINESIZE))
		{ return; }
	struct s_cpmap *cur_cpmap, *first_cpmap = NULL, *last_cpmap = NULL;

	for(nr = 0; fgets(token, MAXLINESIZE, fp);)
	{
		int32_t i, skip;
		uint16_t caid, sid, chid, dwtime;
		uint32_t  provid;
		char *ptr, *ptr1;

		if(strlen(token) < 4) { continue; }

		caid = sid = chid = dwtime = 0;
		provid = 0;
		skip = 0;
		ptr1 = 0;
		for(i = 0, ptr = strtok_r(token, "=", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, "=", &saveptr1), i++)
		{
			trim(ptr);
			if(*ptr == ';' || *ptr == '#' || *ptr == '-')
			{
				skip = 1;
				break;
			}
			switch(i)
			{
			case 0:
				ptr1 = ptr;
				break;
			case 1:
				dwtime = atoi(ptr);
				break;
			}
		}

		if(!skip)
		{
			for(i = 0, ptr = strtok_r(ptr1, ":", &saveptr1); (i < 4) && (ptr); ptr = strtok_r(NULL, ":", &saveptr1), i++)
			{
				trim(ptr);
				switch(i)
				{
				case 0:
					if(*ptr == '*') { caid = 0; }
					else { caid = a2i(ptr, 4); }
					break;
				case 1:
					if(*ptr == '*') { provid = 0; }
					else { provid = a2i(ptr, 6); }
					break;
				case 2:
					if(*ptr == '*') { sid = 0; }
					else { sid = a2i(ptr, 4); }
					break;
				case 3:
					if(*ptr == '*') { chid = 0; }
					else { chid = a2i(ptr, 4); }
					break;
				}
			}
			if(!cs_malloc(&cur_cpmap, sizeof(struct s_cpmap)))
			{
				for(cur_cpmap = first_cpmap; cur_cpmap;)
				{
					last_cpmap = cur_cpmap;
					cur_cpmap = cur_cpmap->next;
					NULLFREE(last_cpmap);
				}
				NULLFREE(token);
				return;
			}
			if(last_cpmap)
				{ last_cpmap->next = cur_cpmap; }
			else
				{ first_cpmap = cur_cpmap; }
			last_cpmap = cur_cpmap;

			cur_cpmap->caid   = caid;
			cur_cpmap->provid = provid;
			cur_cpmap->sid    = sid;
			cur_cpmap->chid   = chid;
			cur_cpmap->dwtime = dwtime;
			cur_cpmap->next   = 0;

			cs_debug_mask(D_CLIENT, "nr=%d, caid=%04X, provid=%06X, sid=%04X, chid=%04X, dwtime=%d",
						  nr, caid, provid, sid, chid, dwtime);
			nr++;
		}
	}
	NULLFREE(token);
	fclose(fp);

	last_cpmap = cfg.cpmap;
	cfg.cpmap = first_cpmap;
	for(cur_cpmap = last_cpmap; cur_cpmap; cur_cpmap = cur_cpmap->next)
		{ add_garbage(cur_cpmap); }
	//cs_log("%d lengths for caid guessing loaded", nr);
	return;
}

void ac_copy_vars(struct s_auth *src, struct s_auth *dst)
{
	dst->ac_stat    = src->ac_stat;
}

void ac_init(void)
{
	if(!cfg.ac_enabled)
	{
		cs_log("anti cascading disabled");
		return;
	}

	ac_load_config();
	ac_init_stat();
}

int8_t get_caid_weight(ECM_REQUEST *er)
{
	switch(er->caid)
	{
		case 0x0100:
			switch (er->prid)
			{
				case 0x00003D:
					return 20;
				case 0x000065:
					return 7;
				default: 
					return 10;
			}
		case 0x0500:
			switch(er->prid)
			{
				case 0x020910:
					return 30;
				case 0x024400:
				case 0x032830:
					return 10;
				case 0x043800:
					return 25;
				default:
					return 15;
			}
		case 0x0604:
			return 11;	
		case 0x1702:
		case 0x1722: 
		case 0x1833:
		case 0x09C4:
			switch(er->srvid)
			{
				case 0x0022: // Disney Channel
				case 0x0016: // Heimatkanal
				case 0x0203: // MGM
				case 0x0008: // Sky Comedy
				case 0x002B: // Sky Cinema +24
				case 0x000B: // Sky Cinema +1
				case 0x0009: // Sky Action
				case 0x000A: // Sky Cinema
				case 0x0014: // Sky Emotion
				case 0x0029: // Sky Hits
				case 0x0204: // Sky Nostalgie
				case 0x0011: // Sky Sport News
				case 0x0024: // Syfy
					return 10;
				default:
					return 7;
			}
		case 0x1830:
		case 0x1843:
		case 0x1834:
		case 0x09C7:
			return 7;
		case 0x4A70: 
			return 14;
		case 0x183D:
			return 13;
		case 0x1810:
		case 0x0D05:
		case 0x0D95:
		case 0x093B:
		case 0x098C:
		case 0x0B00:
		default: 
			return 10;
		
	}
}

void insert_zaplist(ECM_REQUEST *er, struct s_client *client)
{
	bool new_zaplist_entry = false;
	int8_t zap_caid_weight;
	zap_caid_weight = get_caid_weight(er);
	int8_t k = 0;
	bool found = false;
	time_t zaptime = time(NULL);

	for(k=0; k<15 ; k++)
	{
		if(er->caid == client->client_zap_list[k].caid && er->prid == client->client_zap_list[k].provid && er->chid == client->client_zap_list[k].chid && er->srvid == client->client_zap_list[k].sid) //found
		{
			if(zaptime-zap_caid_weight*2 < client->client_zap_list[k].lasttime)
			{
				cs_debug_mask(D_TRACE, "[zaplist] update Entry [%i] for Client: %s  %04X@%06X/%04X/%04X TIME: %ld Diff: %ld zcw: %i(%i)", k, username(client), er->caid, er->prid, er->chid, er->srvid, zaptime, zaptime-client->client_zap_list[k].lasttime, zap_caid_weight, zap_caid_weight*2);
				client->client_zap_list[k].lasttime = zaptime;
				if(client->client_zap_list[k].request_stage < 10)
				{
					client->client_zap_list[k].request_stage ++;
				}
				found = true;
				break;
			}	
		}
	}
	
	if(!found)
	{
		for(k=0; k<15 ; k++)
		{
			if(zaptime-30 > client->client_zap_list[k].lasttime) //make a new Entry and use a memoryplace of a old entry
			{
				client->client_zap_list[k].caid = er->caid;
				client->client_zap_list[k].provid = er->prid;
				client->client_zap_list[k].chid = er->chid;
				client->client_zap_list[k].sid = er->srvid;
				client->client_zap_list[k].request_stage = 1; //need for ACoSC
				client->client_zap_list[k].lasttime = zaptime;
				cs_debug_mask(D_TRACE, "[zaplist] new Entry [%i] for Client: %s  %04X@%06X/%04X/%04X TIME: %ld", k, username(client), er->caid, er->prid, er->chid, er->srvid, zaptime);				
				new_zaplist_entry = true;
				break;
			}
		}
		if(!new_zaplist_entry)
			{ cs_debug_mask(D_TRACE, "[zaplist] no free slot for client: %s", username(client)); }

		if(client->account->acosc_user_zap_count_start_time+60 > zaptime)
			{ client->account->acosc_user_zap_count ++; }
		else 
		{
			client->account->acosc_user_zap_count_start_time = zaptime;
			client->account->acosc_user_zap_count = 0;
			cs_debug_mask(D_TRACE, "[zaplist] Client: %s reset acosc_user_zap_count_start_time", username(client));
			for(k=0; k<15 ; k++)
			{
				if(client->client_zap_list[k].lasttime > zaptime-60) 
				{
					client->account->acosc_user_zap_count ++;
				}
			}
			cs_debug_mask(D_TRACE, "[zaplist] Client: %s zap_count: %i", username(client), client->account->acosc_user_zap_count);
		}
	}
}

#endif
