//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"

#ifdef CS_ANTICASC

//static time_t ac_last_chk;
static uchar  ac_ecmd5[CS_ECMSTORESIZE];
struct s_acasc ac_stat[CS_MAXPID];

int ac_init_log(char *file)
{
  if( (!fpa)  && (file[0]))
  {
    if( (fpa=fopen(file, "a+"))<=(FILE *)0 )
    {
      fpa=(FILE *)0;
      fprintf(stderr, "can't open anti-cascading logfile: %s\n", file);
    }
    else
      cs_log("anti-cascading log initialized");
  }

  return(fpa<=(FILE *)0);
}

void ac_init_stat()
{
  memset(ac_stat, 0, sizeof(ac_stat));
  memset(acasc, 0, sizeof(acasc));

  if( fpa )
    fclose(fpa);
  fpa=(FILE *)0;
  if( ac_init_log(cfg->ac_logfile) )
    cs_exit(0);
}

int idx_from_ac_idx(int ac_idx)
{
  int i;

  for( i=0; i<CS_MAXPID; i++ )
    if( client[i].ac_idx==ac_idx ) return i;

  return -1;
}

void ac_do_stat()
{
  int i, j, idx, exceeds, maxval, prev_deny=0;
  int cl_idx;

  for( i=0; i<CS_MAXPID; i++ ) 
  {
    idx = ac_stat[i].idx;
    ac_stat[i].stat[idx] = acasc[i].ac_count;
    acasc[i].ac_count=0;
    cl_idx = idx_from_ac_idx(i);

    if( ac_stat[i].stat[idx] ) 
    {
      if( cl_idx==-1 ) {
        cs_log("ERROR: can't find client with ac_idx=%d", i);
        continue;
      }

      if( client[cl_idx].ac_penalty==2 ) {// banned
        cs_debug("user '%s' banned", client[cl_idx].usr);
        acasc[i].ac_deny=1;
      }
      else
      {
        for( j=exceeds=maxval=0; j<cfg->ac_samples; j++ ) 
        {
          if( ac_stat[i].stat[j] > maxval ) 
            maxval=ac_stat[i].stat[j];
          exceeds+=(ac_stat[i].stat[j]>client[cl_idx].ac_limit);
        }
        prev_deny=acasc[i].ac_deny;
        acasc[i].ac_deny = (exceeds >= cfg->ac_denysamples);
        
        cs_debug("%s limit=%d, max=%d, samples=%d, dsamples=%d, ac[ci=%d][si=%d]:",
          client[cl_idx].usr, client[cl_idx].ac_limit, maxval, 
          cfg->ac_samples, cfg->ac_denysamples, i, idx);
        cs_debug("%d %d %d %d %d %d %d %d %d %d ", ac_stat[i].stat[0], 
          ac_stat[i].stat[1], ac_stat[i].stat[2], ac_stat[i].stat[3], 
          ac_stat[i].stat[4], ac_stat[i].stat[5], ac_stat[i].stat[6], 
          ac_stat[i].stat[7], ac_stat[i].stat[8], ac_stat[i].stat[9]);
        if( acasc[i].ac_deny ) {
          cs_log("user '%s' exceeds limit", client[cl_idx].usr);
          ac_stat[i].stat[idx] = 0;
        } else if( prev_deny )
          cs_log("user '%s' restored access", client[cl_idx].usr);
      }
    }
    else if( acasc[i].ac_deny ) 
    {
      prev_deny=1;
      acasc[i].ac_deny=0;
      if( cl_idx!=-1 )
        cs_log("restored access for inactive user '%s'", client[cl_idx].usr);
      else
        cs_log("restored access for unknown user (ac_idx=%d)", i);
    }

    if( !acasc[i].ac_deny && !prev_deny )
      ac_stat[i].idx = (ac_stat[i].idx + 1) % cfg->ac_samples;
  }
}

void ac_init_client(struct s_auth *account)
{
  client[cs_idx].ac_idx = account->ac_idx;
  client[cs_idx].ac_limit = 0;
  if( cfg->ac_enabled )
  {
    if( account->ac_users )
    {
      client[cs_idx].ac_limit = (account->ac_users*100+80)*cfg->ac_stime;
      client[cs_idx].ac_penalty = account->ac_penalty;
      cs_debug("login '%s', ac_idx=%d, users=%d, stime=%d min, dwlimit=%d per min, penalty=%d", 
              account->usr, account->ac_idx, account->ac_users, cfg->ac_stime, 
              account->ac_users*100+80, account->ac_penalty);
    }
    else
    {
      cs_debug("anti-cascading not used for login '%s'", account->usr);
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

  cs_debug("WARNING: CAID %04X, PROVID %06X, SID %04X, CHID %04X not found in oscam.ac", 
           er->caid, er->prid, er->srvid, er->chid);
  cs_debug("set DW lifetime 10 sec");
  return 16; // 10*100/60
}

void ac_chk(ECM_REQUEST *er, int level)
{
  if( !client[cs_idx].ac_limit || !cfg->ac_enabled ) return;

  if( level==1 ) 
  {
    if( er->rc==7 ) acasc[client[cs_idx].ac_idx].ac_count++;
    if( er->rc>3 ) return; // not found
    if( memcmp(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE) != 0 )
    {
      acasc[client[cs_idx].ac_idx].ac_count+=ac_dw_weight(er);
      memcpy(ac_ecmd5, er->ecmd5, CS_ECMSTORESIZE);
    }
    return;
  }

  if( acasc[client[cs_idx].ac_idx].ac_deny )
    if( client[cs_idx].ac_penalty ) 
    {
      cs_debug("send fake dw");
      er->rc=7; // fake
      er->rcEx=0;
      cs_sleepms(cfg->ac_fakedelay);
    }
}
#endif
