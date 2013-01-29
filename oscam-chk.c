#include "globals.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-net.h"
#include "oscam-string.h"

extern struct s_module modules[CS_MAX_MOD];

#define CS_NANO_CLASS 0xE2
#define OK		1
#define ERROR 	0

#ifdef WITH_CARDREADER
static int32_t ecm_ratelimit_findspace(struct s_reader *reader, ECM_REQUEST *er, int32_t maxloop)
{
	int32_t h, foundspace;
	time_t actualtime = time(NULL);

	for (h = 0; h < maxloop; h++) {
		// Check for a useable slot
		if ((actualtime - reader->rlecmh[h].last > reader->ratelimitseconds) ||
		reader->rlecmh[h].last == -1 || reader->rlecmh[h].srvid == er->srvid) {
			if (h < maxloop - 1) { // Do housekeeping
				for (foundspace = h + 1; foundspace < maxloop; foundspace++) {
					// Check if srvid is not already in a slot
					if (reader->rlecmh[foundspace].srvid == er->srvid) {
						// Just moving and freeing slot no new assignment
						reader->rlecmh[h].srvid = reader->rlecmh[foundspace].srvid;
						reader->rlecmh[h].last = reader->rlecmh[foundspace].last;
						reader->rlecmh[foundspace].srvid = -1;
						reader->rlecmh[foundspace].last = -1;
						cs_debug_mask(D_TRACE,
						"ratelimiter moving srvid %04X from slot #%d/%d to #%d/%d of reader %s",
						er->srvid, foundspace + 1, maxloop, h + 1, maxloop, reader->label);
					}
					// Release slots with srvid that are overtime,
					// even if not called from reader module, to maximize available slots!
					if ((actualtime - reader->rlecmh[foundspace].last > reader->ratelimitseconds) &&
					(reader->rlecmh[foundspace].last != -1)) {
						cs_debug_mask(D_TRACE,
							"ratelimiter old srvid %04X released from slot #%d/%d of reader %s (%d > %d ratelimitsec!)",
							reader->rlecmh[foundspace].srvid, foundspace + 1, maxloop,
							reader->label, (int) (actualtime - reader->rlecmh[foundspace].last),
							reader->ratelimitseconds);
						reader->rlecmh[foundspace].last = -1;
						reader->rlecmh[foundspace].srvid = -1;
					}
				} // End for
			} // End if
			// Release slots with srvid that are overtime,
			// even if not called from reader module, to maximize available slots!
			if (reader->rlecmh[h].srvid != er->srvid && reader->rlecmh[h].last != -1) {
				// This h slot is found because it is overtime.
				cs_debug_mask(D_TRACE,
					"ratelimiter old srvid %04X released from slot #%d/%d of reader %s (%d > %d ratelimitsec!)",
					reader->rlecmh[h].srvid, h + 1, maxloop,
					reader->label, (int) (actualtime - reader->rlecmh[h].last),
					reader->ratelimitseconds);
				reader->rlecmh[h].last = -1;
				reader->rlecmh[h].srvid = -1;
			}
			if (reader->rlecmh[h].srvid == er->srvid)
				cs_debug_mask(D_TRACE, "ratelimiter found srvid %04X for %d sec in slot #%d/%d of reader %s",
					er->srvid, (int) (actualtime - reader->rlecmh[h].last), h+1, maxloop, reader->label);
			return h; // Free slot found, possible to assign it!
		}
	}

	#ifdef HAVE_DVBAPI
	/* Overide ratelimit priority for dvbapi request */
	foundspace = -1;
	if ((cfg.dvbapi_enabled == 1) && (strcmp(er->client->account->usr,cfg.dvbapi_usr) == 0)) {
		if (reader->lastdvbapirateoverride < actualtime - reader->ratelimitseconds) {
			time_t minecmtime = actualtime;
			for (h = 0; h < maxloop; h++) {
				if(reader->rlecmh[h].last < minecmtime) {
					minecmtime = reader->rlecmh[h].last;
					foundspace = h;
				}
			}
			reader->lastdvbapirateoverride = actualtime;
			cs_debug_mask(D_TRACE, "prioritizing DVBAPI user %s over other watching client",
				er->client->account->usr);
			cs_debug_mask(D_TRACE, "ratelimiter forcing srvid %04X into slot #%d/%d of reader %s",
				er->srvid, foundspace + 1, maxloop, reader->label);
			return foundspace; // Free slot found, possible to assign it!
		}
		else cs_debug_mask(D_TRACE, "DVBAPI User %s is switching too fast for ratelimit and can't be prioritized!",
			er->client->account->usr);
	}
	#endif

	return (-1);
}

static void sort_ecmrl(struct s_reader *reader)
{
	int32_t i, j, loc;
	struct ecmrl tmp;

	for(i = 0; i < reader->ratelimitecm; i++) {
		loc = i;
		tmp = reader->rlecmh[i];

		for(j = i + 1; j < MAXECMRATELIMIT; j++) {
			if(reader->rlecmh[j].last > tmp.last) {
				loc = j;
				tmp = reader->rlecmh[j];
			}
		} // for j

		if(loc != i) {
			reader->rlecmh[loc] = reader->rlecmh[i];
			reader->rlecmh[i] = tmp;
		}
	} // for i

	// release all slots above ratelimit ecm
	for (i = reader->ratelimitecm; i < MAXECMRATELIMIT; i++) {
		reader->rlecmh[i].last = -1;
		reader->rlecmh[i].srvid = -1;
	}

}

int32_t ecm_ratelimit_check(struct s_reader *reader, ECM_REQUEST *er, int32_t reader_mode)
// If reader_mode is 1, ECM_REQUEST need to be assigned to reader and slot.
// Else just report if a free slot is available.
{
	int32_t foundspace = -1, h, maxslots = MAXECMRATELIMIT; //init slots to oscam global maximums

	// No rate limit set
	if (!reader->ratelimitecm) return OK;

	// Below this line: rate limit functionality.
	// No cooldown set
	if (!reader->cooldown[0]) {
		cs_debug_mask(D_TRACE, "ratelimiter find a slot for srvid %04X on reader %s reader_mode = %d",
			er->srvid, reader->label, reader_mode);
		foundspace = ecm_ratelimit_findspace(reader, er, reader->ratelimitecm);
		if (foundspace < 0) {
			if (reader_mode) {
				cs_debug_mask(D_TRACE, "ratelimiter no free slot for srvid %04X on reader %s -> dropping!", er->srvid, reader->label);
				write_ecm_answer(reader, er, E_NOTFOUND, E2_RATELIMIT, NULL, "Ratelimiter: no slots free!");
			}
			return ERROR; // not even trowing an error... obvious reason ;)
		}
		else {
			if (reader_mode) {
				// Register new slot
				reader->rlecmh[foundspace].last = time(NULL);
				reader->rlecmh[foundspace].srvid = er->srvid;
			}
			return OK;
		}
	}

	// Below this line: rate limit functionality with cooldown option.

	// Cooldown state cycle:
	// state = 0: Cooldown setup phase. No rate limit set.
	//	If number of ecm request exceed reader->ratelimitecm, cooldownstate goes to 2.
	// state = 2: Cooldown delay phase. No rate limit set.
	//	If number of ecm request still exceed reader->ratelimitecm at end of cooldown delay phase,
	//		cooldownstate goes to 1 (rate limit phase).
	//	Else return back to setup phase (state 0).
	// state = 1: Cooldown ratelimit phase. Rate limit set.
	//	If cooldowntime reader->cooldown[1] is elapsed, return to cooldown setup phase (state 0).

	if (reader->cooldownstate == 1) { // Cooldown in ratelimit phase
		if (time(NULL) - reader->cooldowntime <= reader->cooldown[1]) // check if cooldowntime is elapsed
			maxslots = reader->ratelimitecm; // use user defined ratelimitecm
		else { // Cooldown time is elapsed
			reader->cooldownstate = 0; // set cooldown setup phase
			reader->cooldowntime = 0; // reset cooldowntime
			maxslots = MAXECMRATELIMIT; //use oscam defined max slots
			cs_log("Reader: %s ratelimiter returning to setup phase cooling down period of %d seconds is done!",
				reader->label, reader->cooldown[1]);
		}
	} // if cooldownstate == 1

	if (reader->cooldownstate == 2 && time(NULL) - reader->cooldowntime > reader->cooldown[0]) {
		// Need to check if the otherslots are not exceeding the ratelimit at the moment that
		// cooldown[0] time was exceeded!
		// time_t actualtime = reader->cooldowntime + reader->cooldown[0];
		maxslots = 0; // maxslots is used as counter
		for (h = 0; h < MAXECMRATELIMIT; h++) {
			// how many active slots are registered at end of cooldown delay period
			if (reader->cooldowntime + reader->cooldown[0] - reader->rlecmh[h].last
				<= reader->ratelimitseconds) {
				maxslots++;
				if (maxslots > reader->ratelimitecm) break; // Need to go cooling down phase
			}
		}

		if (maxslots <= reader->ratelimitecm) {
			reader->cooldownstate = 0; // set cooldown setup phase
			reader->cooldowntime = 0; // reset cooldowntime
			maxslots = MAXECMRATELIMIT; // maxslots is maxslots again
			cs_log("Reader: %s ratelimiter returning to setup phase after %d seconds cooldowndelay!",
				reader->label, reader->cooldown[0]);
		}
		else {
			reader->cooldownstate = 1; // Entering ratelimit for cooldown ratelimitseconds
			reader->cooldowntime = time(NULL); // set time to enforce ecmratelimit for defined cooldowntime
			maxslots = reader->ratelimitecm; // maxslots is maxslots again
			sort_ecmrl(reader); // keep youngest ecm requests in list + housekeeping
			cs_log("Reader: %s ratelimiter starting cooling down period of %d seconds!",
				reader->label, reader->cooldown[1]);
		}
	} // if cooldownstate == 2

	cs_debug_mask(D_TRACE, "ratelimiter cooldown find a slot for srvid %04X on reader %s reader_mode = %d",
		er->srvid, reader->label, reader_mode);
	foundspace = ecm_ratelimit_findspace(reader, er, maxslots);
	if (foundspace < 0) { // No space is no space, done!
		//who's calling us? reader or some stat prober?  If reader then register otherwise just report!
		if (reader_mode) {
			cs_debug_mask(D_TRACE, "ratelimiter no free slot for srvid %04X on reader %s -> dropping!",
				er->srvid, reader->label);
			write_ecm_answer(reader, er, E_NOTFOUND, E2_RATELIMIT, NULL, "Ratelimiter: no slots free!");
		}
		return ERROR; // not even trowing an error... obvious reason ;)
	}

	if (reader->cooldownstate == 0 && foundspace >= reader->ratelimitecm) {
		if (!reader_mode) return OK; // No actual ecm request, just check
		cs_log("Reader: %s ratelimiter detected overrun ecmratelimit of %d during setup phase!",
			reader->label, reader->ratelimitecm);
		reader->cooldownstate = 2; // Entering cooldowndelay phase
		reader->cooldowntime = time(NULL); // Set cooldowntime to calculate delay
		cs_debug_mask(D_TRACE, "ratelimiter cooldowndelaying %d seconds", reader->cooldown[0]);
	}

	// Cooldown state housekeeping is done. There is a slot available.
	if (reader_mode) {
		// Register new slot
		reader->rlecmh[foundspace].last = time(NULL);
		reader->rlecmh[foundspace].srvid = er->srvid;
	}
	return OK;
}
#endif

static int32_t find_nano(uchar *ecm, int32_t l, uchar nano, int32_t s)
{
  uchar *snano;

  if( s >= l ) return 0;
  if( !s ) s=(ecm[4]==0xD2) ? 12 : 9;	// tpsflag -> offset+3
  snano = ecm + s;

  while( (*snano!=nano) && (s<l) )
  {
    if( *snano == 0xEA ) return 0;
    snano++;
    s++;
  }

  return (s<l)?++s:0;
}

static int32_t chk_class(ECM_REQUEST *er, CLASSTAB *clstab, const char *type, const char *name)
{
  int32_t i, j, an, cl_n, l;
  uchar ecm_class;

  if( er->caid!=0x0500 ) return 1;
  if( !clstab->bn && !clstab->an ) return 1;

  j=an=cl_n=l=0;
  while( (j=find_nano(er->ecm, er->ecmlen, CS_NANO_CLASS, j)) > 0 )
  {
    l = er->ecm[j];
    if(l+j>er->ecmlen) continue; // skip, this is not a valid class identifier!
    ecm_class = er->ecm[j+l];
    cs_debug_mask(D_CLIENT, "ecm class=%02X", ecm_class);
    for( i=0; i<clstab->bn; i++ )  // search in blocked
      if( ecm_class==clstab->bclass[i] )
      {
        cs_debug_mask(D_CLIENT, "class %02X rejected by %s '%s' !%02X filter",
                 ecm_class, type, name, ecm_class);
        return 0;
      }

    cl_n++;
    for( i=0; i<clstab->an; i++ )  // search in allowed
      if( ecm_class==clstab->aclass[i] )
      {
        an++;
        break;
      }
    j+=l;
  }

  if( cl_n && clstab->an )
  {
    if( an )
      cs_debug_mask(D_CLIENT, "ECM classes allowed by %s '%s' filter", type, name);
    else {
      cs_debug_mask(D_CLIENT, "ECM classes don't match %s '%s' filter, rejecting", type, name);
      return 0;
    }
  }

  return 1;
}

int32_t chk_srvid_match(ECM_REQUEST *er, SIDTAB *sidtab)
{
  int32_t i, rc=0;

  if (!sidtab->num_caid)
    rc|=1;
  else
    for (i=0; (i<sidtab->num_caid) && (!(rc&1)); i++)
      if (er->caid==sidtab->caid[i]) rc|=1;

  if (!er->prid || !sidtab->num_provid)
    rc|=2;
  else
    for (i=0; (i<sidtab->num_provid) && (!(rc&2)); i++)
      if (er->prid==sidtab->provid[i]) rc|=2;

  if (!sidtab->num_srvid)
    rc|=4;
  else
    for (i=0; (i<sidtab->num_srvid) && (!(rc&4)); i++)
      if (er->srvid==sidtab->srvid[i]) rc|=4;

  return(rc==7);
}

int32_t chk_srvid(struct s_client *cl, ECM_REQUEST *er)
{
  int32_t nr, rc=0;
  SIDTAB *sidtab;

  if (!cl->sidtabs.ok)
  {
    if (!cl->sidtabs.no) return(1);
    rc=1;
  }
  for (nr=0, sidtab=cfg.sidtab; sidtab; sidtab=sidtab->next, nr++)
    if (sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid)
    {
      if ((cl->sidtabs.no&((SIDTABBITS)1<<nr)) &&
          (chk_srvid_match(er, sidtab)))
        return(0);
      if ((cl->sidtabs.ok&((SIDTABBITS)1<<nr)) &&
          (chk_srvid_match(er, sidtab)))
        rc=1;
    }
  return(rc);
}

int32_t has_srvid(struct s_client *cl, ECM_REQUEST *er) {
  if (!cl->sidtabs.ok)
    return 0;

  int32_t nr;
  SIDTAB *sidtab;

  for (nr=0, sidtab=cfg.sidtab; sidtab; sidtab=sidtab->next, nr++)
    if (sidtab->num_srvid)
    {
      if ((cl->sidtabs.ok&((SIDTABBITS)1<<nr)) &&
          (chk_srvid_match(er, sidtab)))
        return 1;
    }
  return 0;
}


int32_t chk_srvid_match_by_caid_prov(uint16_t caid, uint32_t provid, SIDTAB *sidtab)
{
  int32_t i, rc=0;

  if (!sidtab->num_caid)
    rc|=1;
  else
    for (i=0; (i<sidtab->num_caid) && (!(rc&1)); i++)
      if (caid==sidtab->caid[i]) rc|=1;

  if (!sidtab->num_provid)
    rc|=2;
  else
    for (i=0; (i<sidtab->num_provid) && (!(rc&2)); i++)
      if (provid==sidtab->provid[i]) rc|=2;

  return(rc==3);
}

int32_t chk_srvid_by_caid_prov(struct s_client *cl, uint16_t caid, uint32_t provid) {
  int32_t nr, rc=0;
  SIDTAB *sidtab;

  if (!cl->sidtabs.ok)
  {
    if (!cl->sidtabs.no) return(1);
    rc=1;
  }
  for (nr=0, sidtab=cfg.sidtab; sidtab; sidtab=sidtab->next, nr++)
    if (sidtab->num_caid | sidtab->num_provid)
    {
      if ((cl->sidtabs.no&((SIDTABBITS)1<<nr)) && !sidtab->num_srvid &&
          (chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
        return(0);
      if ((cl->sidtabs.ok&((SIDTABBITS)1<<nr)) &&
          (chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
        rc=1;
    }
  return(rc);
}

int32_t chk_srvid_by_caid_prov_rdr(struct s_reader *rdr, uint16_t caid, uint32_t provid) {
  int32_t nr, rc=0;
  SIDTAB *sidtab;

  if (!rdr->sidtabs.ok)
  {
    if (!rdr->sidtabs.no) return(1);
    rc=1;
  }
  for (nr=0, sidtab=cfg.sidtab; sidtab; sidtab=sidtab->next, nr++)
    if (sidtab->num_caid | sidtab->num_provid)
    {
      if ((rdr->sidtabs.no&((SIDTABBITS)1<<nr)) && !sidtab->num_srvid &&
          (chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
        return(0);
      if ((rdr->sidtabs.ok&((SIDTABBITS)1<<nr)) &&
          (chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
        rc=1;
    }
  return(rc);
}


// server filter for newcamd
int32_t chk_sfilter(ECM_REQUEST *er, PTAB *ptab)
{
  int32_t i, j, pi, rc=1;
  uint16_t caid, scaid;
  uint32_t  prid, sprid;

  if (!ptab) return(1);
  struct s_client *cur_cl = cur_client();

  caid = er->caid;
  prid = er->prid;
  pi = cur_cl->port_idx;

  if (cfg.ncd_mgclient && ptab == &cfg.ncd_ptab)
	  return 1;

  if (ptab->nports && ptab->ports[pi].ftab.nfilts)
  {
    for( rc=j=0; (!rc) && (j<ptab->ports[pi].ftab.nfilts); j++ )
    {
      scaid = ptab->ports[pi].ftab.filts[j].caid;
      if (caid==0||(caid!=0 && caid==scaid))
      {
        for( i=0; (!rc) && i<ptab->ports[pi].ftab.filts[j].nprids; i++ )
        {
          sprid=ptab->ports[pi].ftab.filts[j].prids[i];
          cs_debug_mask(D_CLIENT, "trying server filter %04X:%06X", scaid, sprid);
          if (prid==sprid)
          {
            rc=1;
            cs_debug_mask(D_CLIENT, "%04X:%06X allowed by server filter %04X:%06X",
                     caid, prid, scaid, sprid);
          }
        }
      }
    }
    if(!rc)
    {
      cs_debug_mask(D_CLIENT, "no match, %04X:%06X rejected by server filters", caid, prid);
      snprintf( er->msglog, MSGLOGSIZE, "no server match %04X:%06X",
        caid, (uint32_t) prid );

      if (!er->rcEx) er->rcEx=(E1_LSERVER<<4)|E2_IDENT;
      return(rc);
    }
  }
  return (rc);
}

static int32_t chk_chid(ECM_REQUEST *er, FTAB *fchid, char *type, char *name)
{
  int32_t rc=1, i, j, found_caid=0;
  if( !fchid->nfilts ) return 1;

  for( i=rc=0; (!rc) && i<fchid->nfilts; i++ )
    if( er->caid == fchid->filts[i].caid ) {
      found_caid=1;
      for( j=0; (!rc) && j<fchid->filts[i].nprids; j++ )
      {
        cs_debug_mask(D_CLIENT, "trying %s '%s' CHID filter %04X:%04X",
                 type, name, fchid->filts[i].caid, fchid->filts[i].prids[j]);
        if( er->chid == fchid->filts[i].prids[j] )
        {
          cs_debug_mask(D_CLIENT, "%04X:%04X allowed by %s '%s' CHID filter %04X:%04X",
                   er->caid, er->chid, type, name, fchid->filts[i].caid,
                   fchid->filts[i].prids[j]);
          rc=1;
        }
      }
  }

  if( !rc )
  {
    if (found_caid)
    	cs_debug_mask(D_CLIENT, "no match, %04X:%04X rejected by %s '%s' CHID filter(s)",
                      er->caid, er->chid, type, name);
    else {
    	rc=1;
        cs_debug_mask(D_CLIENT, "%04X:%04X allowed by %s '%s' CHID filter, CAID not spezified",
                   er->caid, er->chid, type, name);
    }
  }
  return (rc);
}

int32_t chk_ufilters(ECM_REQUEST *er)
{
  int32_t i, j, rc;
  uint16_t ucaid;
  uint32_t  uprid;
  struct s_client *cur_cl = cur_client();

  rc=1;
  if( cur_cl->ftab.nfilts )
  {
    FTAB *f = &cur_cl->ftab;
    for( i=rc=0; (!rc) && (i<f->nfilts); i++ )
    {
      ucaid = f->filts[i].caid;
      if( er->caid==0 || ucaid==0 || (er->caid!=0 && er->caid==ucaid) )
      {
        for( j=rc=0; (!rc) && (j<f->filts[i].nprids); j++ )
        {
          uprid = f->filts[i].prids[j];
          cs_debug_mask(D_CLIENT, "trying user '%s' filter %04X:%06X",
                   cur_cl->account->usr, ucaid, uprid);
          if( er->prid == uprid )
          {
            rc=1;
            cs_debug_mask(D_CLIENT, "%04X:%06X allowed by user '%s' filter %04X:%06X",
                      er->caid, er->prid, cur_cl->account->usr, ucaid, uprid);
          }
        }
      }
    }
    if( !rc ) {
      cs_debug_mask(D_CLIENT, "no match, %04X:%06X rejected by user '%s' filters",
                er->caid, er->prid, cur_cl->account->usr);
        snprintf( er->msglog, MSGLOGSIZE, "no card support %04X:%06X",
                er->caid, (uint32_t) er->prid );

      if( !er->rcEx ) er->rcEx=(E1_USER<<4)|E2_IDENT;
      return (rc);
    }
  }

  if( !(rc=chk_class(er, &cur_cl->cltab, "user", cur_cl->account->usr)) ) {
    if( !er->rcEx ) er->rcEx=(E1_USER<<4)|E2_CLASS;
  }
  else if( !(rc=chk_chid(er, &cur_cl->fchid, "user", cur_cl->account->usr)) )
    if( !er->rcEx ) er->rcEx=(E1_USER<<4)|E2_CHID;

  if( rc ) er->rcEx=0;

  return (rc);
}

int32_t chk_rsfilter(struct s_reader * reader, ECM_REQUEST *er)
{
  int32_t i, rc=1;
  uint16_t caid;
  uint32_t prid;

  if( reader->ncd_disable_server_filt )
  {
    cs_debug_mask(D_CLIENT, "%04X:%06X allowed - server filters disabled",
              er->caid, er->prid);
    return 1;
  }

  rc=prid=0;
  caid = reader->caid;
  if( caid==er->caid )
  {
    for( i=0; (!rc) && (i<reader->nprov); i++ )
    {
      prid = (uint32_t)((reader->prid[i][1]<<16) |
                     (reader->prid[i][2]<<8) |
                     (reader->prid[i][3]));
      cs_debug_mask(D_CLIENT, "trying server '%s' filter %04X:%06X",
                reader->device, caid, prid);
      if( prid==er->prid )
      {
        rc=1;
        cs_debug_mask(D_CLIENT, "%04X:%06X allowed by server '%s' filter %04X:%06X",
                  er->caid, er->prid, reader->device, caid, prid);
      }
    }
  }
  if(!rc) {
    cs_debug_mask(D_CLIENT, "no match, %04X:%06X rejected by server '%s' filters",
            er->caid, er->prid, reader->device);
    if( !er->rcEx ) er->rcEx=(E1_SERVER<<4)|E2_IDENT;
    return 0;
  }

  return(rc);
}

int32_t chk_rfilter2(uint16_t rcaid, uint32_t rprid, struct s_reader *rdr)
{
  int32_t i, j, rc=1;
  uint16_t caid=0;
  uint32_t prid=0;

  if( rdr->ftab.nfilts )
  {
    for( rc=i=0; (!rc) && (i<rdr->ftab.nfilts); i++ )
    {
      caid = rdr->ftab.filts[i].caid;
      if( (caid!=0 && caid==rcaid) || caid==0 )
      {
        for( j=0; (!rc) && (j<rdr->ftab.filts[i].nprids); j++)
        {
          prid = rdr->ftab.filts[i].prids[j];
          cs_debug_mask(D_CLIENT, "trying reader '%s' filter %04X:%06X",
                    rdr->label, caid, prid);
          if( prid==rprid )
          {
            rc=1;
            cs_debug_mask(D_CLIENT, "%04X:%06X allowed by reader '%s' filter %04X:%06X",
                    rcaid, rprid, rdr->label, caid, prid);
          }
        }
      }
    }
    if(!rc) {
      cs_debug_mask(D_CLIENT, "no match, %04X:%06X rejected by reader '%s' filters",
                rcaid, rprid, rdr->label);
      return 0;
    }
  }

  return(rc);
}


static int32_t chk_rfilter(ECM_REQUEST *er, struct s_reader *rdr)
{
	return chk_rfilter2(er->caid, er->prid, rdr);
}

int32_t chk_ctab(uint16_t caid, CAIDTAB *ctab) {
  if (!caid || !ctab->caid[0])
    return 1;

  int32_t i;
  for (i=0;i<CS_MAXCAIDTAB;i++)
  {
    if (!ctab->caid[i]) {
      return 0;
    }
    if ((caid & ctab->mask[i]) == ctab->caid[i])
      return 1;
  }
  return 0;
}

int32_t matching_reader(ECM_REQUEST *er, struct s_reader *rdr, int32_t slot) {
  (void)slot; // Prevent warning about unused param slot, when WITH_CARDREADER is disabled
  //simple checks first:
  if (!er || !rdr)
    return(0);

  //reader active?
  struct s_client *cl = rdr->client;
  if (!cl || !rdr->enable)
    return(0);

  // if physical reader a card needs to be inserted
  if (!is_network_reader(rdr) && rdr->card_status != CARD_INSERTED)
    return(0);

  //Checking connected & group valid:
  struct s_client *cur_cl = er->client; //cur_client();

#ifdef CS_CACHEEX
  //To avoid cascading, a incoming cache request should not invoke a outgoing cache request:
  if (rdr->cacheex.mode == 1 && cur_cl->auth && cur_cl->account->cacheex.mode == 1)
	  return (0);

  //Cacheex=3 defines a Cacheex-only reader. never match them.
  if (rdr->cacheex.mode == 3)
	  return (0);
#endif

  if (!(rdr->grp&cur_cl->grp))
    return(0);

  //Checking caids:
  if ((!er->ocaid || !chk_ctab(er->ocaid, &rdr->ctab)) && !chk_ctab(er->caid, &rdr->ctab)) {
    cs_debug_mask(D_TRACE, "caid %04X not found in caidlist reader %s", er->caid, rdr->label);
    return 0;
  }

  if (!is_network_reader(rdr) && ((rdr->caid >> 8) != ((er->caid >> 8) & 0xFF) && (rdr->caid >> 8) != ((er->ocaid >> 8) & 0xFF)))
  {
    int i, caid_found = 0;
    for (i = 0; i < 2; i++) {
      if (rdr->csystem.caids[i] == er->caid || rdr->csystem.caids[i] == er->ocaid) {
        caid_found = 1;
        break;
      }
    }
    if (!caid_found)
      return 0;
  }

  //Supports long ecms?
  if (er->ecmlen > 255 && is_network_reader(rdr) && !rdr->ph.large_ecm_support) {
	  cs_debug_mask(D_TRACE, "no large ecm support (l=%d) for reader %s", er->ecmlen, rdr->label);
	  return 0;
  }


  //Checking services:
  if (!chk_srvid(rdr->client, er)) {
    cs_debug_mask(D_TRACE, "service %04X not matching reader %s", er->srvid, rdr->label);
    return(0);
  }

  //Checking ident:
  if (er->prid && !chk_rfilter(er, rdr)) {
    cs_debug_mask(D_TRACE, "r-filter reader %s", rdr->label);
    return(0);
  }

  //Check ECM nanos:
  if (!chk_class(er, &rdr->cltab, "reader", rdr->label)) {
    cs_debug_mask(D_TRACE, "class filter reader %s", rdr->label);
    return(0);
  }


  // CDS NL: check for right seca type
  if (!is_network_reader(rdr) && er->caid == 0x100 && er->prid == 0x00006a &&
	!(er->ecm[8] == 0x00 && er->ecm[9] == 0x00)) { // no empty ecm
    if (er->ecm[8] == 0x00 && rdr->secatype == 2) {
      cs_debug_mask(D_TRACE,"Error: this is a nagra/mediaguard3 ECM and readertype is seca2!");
      return 0;  // we dont send a nagra/mediaguard3 ecm to a seca2 reader!
    }
    if ((er->ecm[8] == 0x10) && (er->ecm[9] == 0x01) && rdr->secatype == 3){
      cs_debug_mask(D_TRACE,"Error: this is a seca2 ECM and readertype is nagra/mediaguard3!");
      return 0;  // we dont send a seca2 ecm to a nagra/mediaguard3 reader!
    }
  }

  //Checking chid:
  if (!chk_chid(er, &rdr->fchid, "reader", rdr->label)) {
    cs_debug_mask(D_TRACE, "chid filter reader %s", rdr->label);
    return(0);
  }

  //Schlocke reader-defined function, reader-self-check
  if (rdr->ph.c_available && !rdr->ph.c_available(rdr, AVAIL_CHECK_CONNECTED, er)) {
    cs_debug_mask(D_TRACE, "reader unavailable %s", rdr->label);
    return 0;
  }

  //Checking entitlements:
  if (ll_count(rdr->ll_entitlements) > 0) {
		LL_ITER itr = ll_iter_create(rdr->ll_entitlements);
		S_ENTITLEMENT *item;
		int8_t found = 0;
		while ((item=ll_iter_next(&itr))) {
			//if (item->caid == er->caid && (!er->prid || !item->provid || item->provid == er->prid)) {		//provid check causing problems?
			if (item->caid == er->caid || item->caid == er->ocaid) { 										//... so check at least caid only
				found =1;
				break;
			}
		}
		if (!found){
			cs_debug_mask(D_TRACE, "entitlements check failed on reader %s", rdr->label);
			return 0;
		}
  }

  //Checking ecmlength:
  if (rdr->ecmWhitelist && er->ecmlen) {
  	struct s_ecmWhitelist *tmp;
  	struct s_ecmWhitelistIdent *tmpIdent;
  	struct s_ecmWhitelistLen *tmpLen;
  	int8_t ok = 0, foundident = 0;
  	for(tmp = rdr->ecmWhitelist; tmp; tmp = tmp->next){
  		if(tmp->caid == 0 || tmp->caid == er->caid){
  			for(tmpIdent = tmp->idents; tmpIdent; tmpIdent = tmpIdent->next){
  				if(tmpIdent->ident == 0 || tmpIdent->ident == er->prid){
  					foundident = 1;
			  		for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen = tmpLen->next){
			  			if (tmpLen->len == er->ecmlen) {
				  			ok = 1;
				  			break;
				  		}
			  		}
			  	}
			  }
	  	}
  	}
  	if(foundident == 1 && ok == 0){
  		cs_debug_mask(D_TRACE, "ECM is not in ecmwhitelist of reader %s.",rdr->label);
		rdr->ecmsfilteredlen += 1;  		
		return(0);
  	}
  }

  // ECM Header Check
  if (rdr->ecmHeaderwhitelist && er->ecmlen) {
	int8_t byteok = 0;
	int8_t entryok = 0;
	int8_t foundcaid = 0;
	int8_t foundprovid = 0;
	int16_t len = 0;
	int32_t i = 0;
	int8_t skip = 0;
	struct s_ecmHeaderwhitelist *tmp;
	for(tmp = rdr->ecmHeaderwhitelist; tmp; tmp = tmp->next){
		skip = 0;
		byteok = 0;
		entryok = 0;
		len = 0;
		if (tmp->caid == 0 || tmp->caid == er->caid){
			foundcaid = 1; //-> caid was in list
			//rdr_debug_mask(rdr, D_READER, "Headerwhitelist: found matching CAID: %04X in list", tmp->caid);
			if (tmp->provid == 0 || tmp->provid == er->prid) {
				foundprovid = 1; //-> provid was in list
				//rdr_debug_mask(rdr, D_READER, "Headerwhitelist: found matching Provid: %06X in list", tmp->provid);
				len = tmp->len;
				for (i=0; i < len/2; i++){
					if (tmp->header[i] == er->ecm[i]){ 
						byteok = 1;
						//rdr_debug_mask(rdr, D_READER, "ECM Byte: %i of ECMHeaderwhitelist is correct. (%02X = %02X Headerlen: %i)", i, er->ecm[i], tmp->header[i], len/2);
					}
					else { 
						byteok = 0;
						//rdr_debug_mask(rdr, D_READER, "ECM Byte: %i of ECMHeaderwhitelist is not valid. (%02X != %02X Headerlen: %i)", i, er->ecm[i], tmp->header[i], len/2);
						entryok = 0;						
						break;
					}
					if (i == len/2-1 && byteok == 1){
						entryok = 1;
					}
				
				}
			} else {
				//rdr_debug_mask(rdr, D_READER, "ECMHeaderwhitelist: Provid: %06X not found in List-Entry -> skipping check", er->prid);
				skip = 1; 	
				continue;
			}
		} else {
			//rdr_debug_mask(rdr, D_READER, "ECMHeaderwhitelist: CAID: %04X not found in List-Entry -> skipping check", er->caid);
			skip = 1;
			continue;
		}
		if (entryok == 1){
			break;
		}			
			
	}	
	if (foundcaid == 1 && foundprovid == 1 && byteok == 1 && entryok == 1){
		//cs_log("ECM for %04X:%06X:%04X is valid for ECMHeaderwhitelist of reader %s.", er->caid, er->prid, er->srvid, rdr->label);
	} else {
		if (skip == 0 || (foundcaid == 1 && foundprovid == 1 && entryok == 0 && skip == 1)) {
			cs_ddump_mask(D_TRACE, er->ecm, er->ecmlen,
				"following ECM %04X:%06X:%04X was filtered by ECMHeaderwhitelist of Reader %s from User %s because of not matching Header:",
				er->caid, er->prid, er->srvid, rdr->label, username(er->client));
			rdr->ecmsfilteredhead += 1;	
			return(0);
		}
	}
   } 

  //Simple ring connection check:
    
  //Check ip source+dest:
	if (cfg.block_same_ip && IP_EQUAL(cur_cl->ip, rdr->client->ip) &&
		modules[cur_cl->ctyp].listenertype != LIS_DVBAPI &&
		is_network_reader(rdr))
	{
		cs_debug_mask(D_TRACE, "ECMs origin %s has the same ip as reader %s, blocked!", username(cur_cl), rdr->label);
		return 0;
	}
  
  if (cfg.block_same_name && strcmp(username(cur_cl), rdr->label) == 0) {
  	cs_debug_mask(D_TRACE, "ECMs origin %s has the same name as reader %s, blocked!", username(cur_cl), rdr->label);
  	return 0;
  }
  #ifdef WITH_CARDREADER
  cs_debug_mask(D_TRACE, "matching_reader became slot attribute of %d", slot);
  if (!is_network_reader(rdr) && slot == 1) {
	  // just check ratelimiter & cooldown, but no srvid assignment in slot
	  if(ecm_ratelimit_check(rdr, er, 0) != OK) return 0; //just check ratelimiter & cooldown
  }
  #endif
  //All checks done, reader is matching!
  return(1);
}


int32_t emm_reader_match(struct s_reader *reader, uint16_t caid, uint32_t provid) {
	int32_t i;

	// if physical reader a card needs to be inserted
	if (!is_network_reader(reader) && reader->card_status != CARD_INSERTED) {
		return(0);
	}

	if (reader->audisabled)
		return 0;

	if (reader->caid != caid) {
		int caid_found = 0;
		for (i = 0; i < 2; i++) {
			if (reader->csystem.caids[i] == caid) {
				caid_found = 1;
				break;
			}
		}
		if (!caid_found) {
			cs_debug_mask(D_EMM, "emm reader %s reader_caid %04x != caid %04x", reader->label, reader->caid, caid);
			return 0;
		}
	}

	//if (!hexserialset(reader)) { There are cards without serial, they should get emm of type global and shared!
	//	cs_debug_mask(D_EMM, "emm reader %s has no serial set", reader->label);
	//	return 0;
	//}

	if (!provid) {
		cs_debug_mask(D_EMM, "emm for reader %s (%04X) has no provider", reader->label, caid);
		return 1;
	}

	if (reader->auprovid && reader->auprovid == provid) {
		cs_debug_mask(D_EMM, "emm provider match reader %s auprovid %06X", reader->label, reader->auprovid);
		return 1;
	}

	if (!reader->nprov) {
		cs_debug_mask(D_EMM, "emm reader %s has no provider set", reader->label);
		return 1;
	}

	for (i=0; i<reader->nprov; i++) {
		uint32_t prid = b2i(4, reader->prid[i]);
		if (prid == provid || ( (reader->typ == R_CAMD35 || reader->typ == R_CS378X) && (prid & 0xFFFF) == (provid & 0xFFFF) )) {
			cs_debug_mask(D_EMM, "emm reader %s provider match %04X:%06X", reader->label, caid, provid);
			return 1;
		}
	}
	cs_debug_mask(D_EMM, "emm reader %s skip provider %04X:%06X", reader->label, caid, provid);
	return 0;
}

int32_t chk_caid(uint16_t caid, CAIDTAB *ctab)
{
	int32_t n, rc;
	for (rc = -1, n=0; (n < CS_MAXCAIDTAB) && (rc < 0); n++)
		if ((caid & ctab->mask[n]) == ctab->caid[n])
			rc = ctab->cmap[n] ? ctab->cmap[n] : caid;
	return rc;
}

int32_t chk_caid_rdr(struct s_reader *rdr,uint16_t caid) {
  if (is_network_reader(rdr)) {
	  return 1; //reader caid is not real caid
  } else if (rdr->caid==caid) {
	  return 1;
  }
  return 0;
}
