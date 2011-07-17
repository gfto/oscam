//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"

#ifdef CS_ANTICASC

//static time_t ac_last_chk;
static uchar  ac_ecmd5[CS_ECMSTORESIZE];

void ac_clear()
{
	struct s_client *client;
	struct s_auth *account;
	
	for (client=first_client;client;client=client->next)
	{
  		if (client->typ != 'c') continue;
  		memset(&client->acasc, 0, sizeof(client->acasc));
	}
  	
	for (account=cfg.account;account;account=account->next)
		memset(&account->ac_stat, 0, sizeof(account->ac_stat));
}

void ac_init_stat()
{
  ac_clear();

  if( ac_init_log() )
    cs_exit(0);
}

void ac_do_stat()
{
  int32_t j, idx, exceeds, maxval, prev_deny=0;

  struct s_client *client;
  for (client=first_client;client;client=client->next)
  {
  	if (client->typ != 'c') continue;
  	
  	struct s_acasc *ac_stat = &client->account->ac_stat;
  	struct s_acasc_shm *acasc = &client->acasc;

    idx = ac_stat->idx;
    ac_stat->stat[idx] = acasc->ac_count;
    acasc->ac_count=0;

    if( ac_stat->stat[idx])
    {
      if( client->ac_penalty==2 ) {// banned
        cs_debug_mask(D_CLIENT, "acasc: user '%s' banned", client->account->usr);
        acasc->ac_deny=1;
      }
      else
      {
        for(j=exceeds=maxval=0; j<cfg.ac_samples; j++) 
        {
          if (ac_stat->stat[j] > maxval)
            maxval=ac_stat->stat[j];
          exceeds+=(ac_stat->stat[j] > client->ac_limit);
        }
        prev_deny=acasc->ac_deny;
        acasc->ac_deny = (exceeds >= cfg.ac_denysamples);
        
        cs_debug_mask(D_CLIENT, "acasc: %s limit=%d, max=%d, samples=%d, dsamples=%d, [idx=%d]:",
          client->account->usr, client->ac_limit, maxval, 
          cfg.ac_samples, cfg.ac_denysamples, idx);
        cs_debug_mask(D_CLIENT, "acasc: %d %d %d %d %d %d %d %d %d %d ", ac_stat->stat[0],
          ac_stat->stat[1], ac_stat->stat[2], ac_stat->stat[3],
          ac_stat->stat[4], ac_stat->stat[5], ac_stat->stat[6],
          ac_stat->stat[7], ac_stat->stat[8], ac_stat->stat[9]);
        if( acasc->ac_deny ) {
          cs_log("acasc: user '%s' exceeds limit", client->account->usr);
          ac_stat->stat[idx] = 0;
        } else if( prev_deny )
          cs_log("acasc: user '%s' restored access", client->account->usr);
      }
    }
    else if (acasc->ac_deny)
    {
      prev_deny=1;
      acasc->ac_deny=0;
      cs_log("acasc: restored access for inactive user '%s'", client->account->usr);
    }

    if (!acasc->ac_deny && !prev_deny)
      ac_stat->idx = (ac_stat->idx + 1) % cfg.ac_samples;
  }
}

/* Starts the anticascader thread. */
void start_anticascader(){
  struct s_client * cl = create_client(first_client->ip);
  if (cl == NULL) return;
  cl->thread = pthread_self();
  pthread_setspecific(getclient, cl);
  cl->typ = 'a';

  ac_init_stat();
  while(1)
  {
  	int32_t i;
  	for( i=0; i<cfg.ac_stime*60; i++ )
  		cs_sleepms(1000); //FIXME this is a cpu-killer!
    ac_do_stat();
  }
}

void ac_init_client(struct s_client *client, struct s_auth *account)
{
  client->ac_limit = 0;
  client->ac_penalty = account->ac_penalty == -1 ? cfg.ac_penalty : account->ac_penalty;
  if( cfg.ac_enabled )
  {
	int32_t numusers = account->ac_users;
	if ( numusers == -1)
		numusers = cfg.ac_users;

    if( numusers )
    {
      client->ac_limit = (numusers*100+80)*cfg.ac_stime;
      cs_debug_mask(D_CLIENT, "acasc: login '%s', users=%d, stime=%d min, dwlimit=%d per min, penalty=%d",
              account->usr, numusers, cfg.ac_stime,
              numusers*100+80, client->ac_penalty);
    }
    else
    {
      cs_debug_mask(D_CLIENT, "acasc: anti-cascading not used for login '%s'", account->usr);
    }
  }
}

static int32_t ac_dw_weight(ECM_REQUEST *er)
{
  struct s_cpmap *cpmap;

  for( cpmap=cfg.cpmap; (cpmap) ; cpmap=cpmap->next )
    if( (cpmap->caid  ==0 || cpmap->caid  ==er->caid)  &&
        (cpmap->provid==0 || cpmap->provid==er->prid)  &&
        (cpmap->sid   ==0 || cpmap->sid   ==er->srvid) &&
        (cpmap->chid  ==0 || cpmap->chid  ==er->chid) )
      return (cpmap->dwtime*100/60);

  cs_debug_mask(D_CLIENT, "acasc: WARNING: CAID %04X, PROVID %06X, SID %04X, CHID %04X not found in oscam.ac",
           er->caid, er->prid, er->srvid, er->chid);
  cs_debug_mask(D_CLIENT, "acasc: set DW lifetime 10 sec");
  return 16; // 10*100/60
}

void ac_chk(struct s_client *cl, ECM_REQUEST *er, int32_t level)
{
	if (!cl->ac_limit || !cfg.ac_enabled) return;

	struct s_acasc_shm *acasc = &cl->acasc;

	if( level == 1 ) {
		if( er->rc == E_FAKE )
			acasc->ac_count++;

		if( er->rc >= E_NOTFOUND )
			return; // not found

		if( memcmp(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE) != 0 )	{
			acasc->ac_count += ac_dw_weight(er);
			memcpy(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE);
		}
		return;
	}

	if( acasc->ac_deny ) {
		if( cl->ac_penalty ) {
			if (cl->ac_penalty == 3) {
				cs_debug_mask(D_CLIENT, "acasc: fake delay %dms", cfg.ac_fakedelay);
			} else {
				cs_debug_mask(D_CLIENT, "acasc: send fake dw");
				er->rc = E_FAKE; // fake
				er->rcEx = 0;
			}
			cs_sleepms(cfg.ac_fakedelay);
		}
	}
}
#endif
