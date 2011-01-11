//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"

#ifdef CS_ANTICASC

//static time_t ac_last_chk;
static uchar  ac_ecmd5[CS_ECMSTORESIZE];

LLIST *ac_stat_list = NULL; //struct s_acasc
LLIST *acasc_list = NULL;   //struct  s_acasc_shm

int ac_init_log(void)
{
  if( (!fpa)  && (cfg->ac_logfile[0]))
  {
    if( (fpa=fopen(cfg->ac_logfile, "a+"))<=(FILE *)0 )
    {
      fpa=(FILE *)0;
      fprintf(stderr, "can't open anti-cascading logfile: %s\n", cfg->ac_logfile);
    }
    else
      cs_log("anti-cascading log initialized");
  }

  return(fpa<=(FILE *)0);
}

void ac_clear()
{
	ll_clear_data(acasc_list);
	ll_clear_data(ac_stat_list);
}

void ac_done_stat()
{
	ll_destroy_data(acasc_list);
	ll_destroy_data(ac_stat_list);
}

void ac_init_stat()
{
  if (acasc_list)
    ac_clear();
  else {
    ac_stat_list = ll_create();
    acasc_list = ll_create();
  }

  if( fpa )
    fclose(fpa);
  fpa=(FILE *)0;
  if( ac_init_log() )
    cs_exit(0);
}

static struct s_client *idx_from_ac_idx(int ac_idx)
{
	struct s_client *cl;
	for (cl=first_client; cl ; cl=cl->next)
    if( cl->ac_idx==ac_idx )
      return cl;
  return NULL;
}

void ac_do_stat()
{
  int i, j, idx, exceeds, maxval, prev_deny=0;
  struct s_client *cl_idx;

  LL_ITER *itr1 = ll_iter_create(ac_stat_list);
  LL_ITER *itr2 = ll_iter_create(acasc_list);
  i = 1;
  struct s_acasc *ac_stat = ll_iter_next(itr1);
  struct s_acasc_shm *acasc;
  while ((acasc=ll_iter_next(itr2)))
  {
	int ac_stat_next = 1;
	if (!ac_stat) {
		ac_stat = malloc(sizeof(struct s_acasc));
		memset(ac_stat, 0, sizeof(struct s_acasc));
		ll_iter_insert(itr1, ac_stat);
		ac_stat_next = 0;
	}

    idx = ac_stat->idx;
    ac_stat->stat[idx] = acasc->ac_count;
    acasc->ac_count=0;
    cl_idx = idx_from_ac_idx(i);

    if( ac_stat->stat[idx] && cl_idx)
    {
      //if( cl_idx == NULL ) {
        //cs_log("ERROR: can't find client with ac_idx=%d", i);
        //client is no longer connected
      //}
      
      if( cl_idx->ac_penalty==2 ) {// banned
        cs_debug_mask(D_CLIENT, "user '%s' banned", cl_idx->account->usr);
        acasc->ac_deny=1;
      }
      else
      {
        for( j=exceeds=maxval=0; j<cfg->ac_samples; j++ ) 
        {
          if( ac_stat->stat[j] > maxval )
            maxval=ac_stat->stat[j];
          exceeds+=(ac_stat->stat[j]>cl_idx->ac_limit);
        }
        prev_deny=acasc->ac_deny;
        acasc->ac_deny = (exceeds >= cfg->ac_denysamples);
        
        cs_debug_mask(D_CLIENT, "%s limit=%d, max=%d, samples=%d, dsamples=%d, ac[ci=%d][si=%d]:",
          cl_idx->account->usr, cl_idx->ac_limit, maxval, 
          cfg->ac_samples, cfg->ac_denysamples, i, idx);
        cs_debug_mask(D_CLIENT, "%d %d %d %d %d %d %d %d %d %d ", ac_stat->stat[0],
          ac_stat->stat[1], ac_stat->stat[2], ac_stat->stat[3],
          ac_stat->stat[4], ac_stat->stat[5], ac_stat->stat[6],
          ac_stat->stat[7], ac_stat->stat[8], ac_stat->stat[9]);
        if( acasc->ac_deny ) {
          cs_log("user '%s' exceeds limit", cl_idx->account->usr);
          ac_stat->stat[idx] = 0;
        } else if( prev_deny )
          cs_log("user '%s' restored access", cl_idx->account->usr);
      }
    }
    else if( acasc->ac_deny )
    {
      prev_deny=1;
      acasc->ac_deny=0;
      if( cl_idx != NULL )
        cs_log("restored access for inactive user '%s'", cl_idx->account->usr);
      else
        cs_log("restored access for unknown user (ac_idx=%d)", i);
    }

    if( !acasc->ac_deny && !prev_deny )
      ac_stat->idx = (ac_stat->idx + 1) % cfg->ac_samples;

    if (ac_stat_next)
    	ac_stat = ll_iter_next(itr1);
    else
    	ac_stat = NULL;
    i++;
  }
  ll_iter_release(itr2);
  ll_iter_release(itr1);
}

void ac_init_client(struct s_auth *account)
{
  struct s_client *cl = cur_client();
  cl->ac_idx = account->ac_idx;
  cl->ac_limit = 0;
  if( cfg->ac_enabled )
  {
    if( account->ac_users )
    {
      cl->ac_limit = (account->ac_users*100+80)*cfg->ac_stime;
      cl->ac_penalty = account->ac_penalty;
      cs_debug_mask(D_CLIENT, "login '%s', ac_idx=%d, users=%d, stime=%d min, dwlimit=%d per min, penalty=%d", 
              account->usr, account->ac_idx, account->ac_users, cfg->ac_stime, 
              account->ac_users*100+80, account->ac_penalty);
    }
    else
    {
      cs_debug_mask(D_CLIENT, "anti-cascading not used for login '%s'", account->usr);
    }
  }
}

static int ac_dw_weight(ECM_REQUEST *er)
{
  struct s_cpmap *cpmap;

  for( cpmap=cfg->cpmap; (cpmap) ; cpmap=cpmap->next )
    if( (cpmap->caid  ==0 || cpmap->caid  ==er->caid)  &&
        (cpmap->provid==0 || cpmap->provid==er->prid)  &&
        (cpmap->sid   ==0 || cpmap->sid   ==er->srvid) &&
        (cpmap->chid  ==0 || cpmap->chid  ==er->chid) )
      return (cpmap->dwtime*100/60);

  cs_debug_mask(D_CLIENT, "WARNING: CAID %04X, PROVID %06X, SID %04X, CHID %04X not found in oscam.ac", 
           er->caid, er->prid, er->srvid, er->chid);
  cs_debug_mask(D_CLIENT, "set DW lifetime 10 sec");
  return 16; // 10*100/60
}

struct s_acasc_shm *get_acasc(ushort ac_idx) {
	int i=1;
	LL_ITER *itr = ll_iter_create(acasc_list);

	struct s_acasc_shm *acasc;
	while ((acasc=ll_iter_next(itr))) {
		if (i == ac_idx) {
		        ll_iter_release(itr);
			return acasc;
                }
		i++;
	}
	acasc = malloc(sizeof(struct s_acasc_shm));
	memset(acasc, 0, sizeof(struct s_acasc_shm));
	ll_iter_insert(itr, acasc);
	ll_iter_release(itr);
	return acasc;
}

void ac_chk(ECM_REQUEST *er, int level)
{
  struct s_client *cl = cur_client();
  if (!cl->ac_limit || !cfg->ac_enabled ||!acasc_list) return;

  struct s_acasc_shm *acasc = get_acasc(cl->ac_idx);

  if( level==1 ) 
  {
    if( er->rc==7 ) acasc->ac_count++;
    if( er->rc>3 ) return; // not found
    if( memcmp(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE) != 0 )
    {
      acasc->ac_count+=ac_dw_weight(er);
      memcpy(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE);
    }
    return;
  }

  if( acasc->ac_deny )
    if( cl->ac_penalty )
    {
      cs_debug_mask(D_CLIENT, "send fake dw");
      er->rc=7; // fake
      er->rcEx=0;
      cs_sleepms(cfg->ac_fakedelay);
    }
}
#endif
