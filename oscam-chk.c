#include "globals.h"

int chk_srvid_match(ECM_REQUEST *er, SIDTAB *sidtab)
{
  int i, rc=0;

  if (!sidtab->num_caid)
    rc|=1;
  else
    for (i=0; (i<sidtab->num_caid) && (!(rc&1)); i++)
      if (er->caid==sidtab->caid[i]) rc|=1;

  if (!sidtab->num_provid)
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

int chk_srvid(ECM_REQUEST *er, int idx)
{
  int nr, rc=0;
  SIDTAB *sidtab;

  if (!client[idx].sidtabok)
  {
    if (!client[idx].sidtabno) return(1);
    rc=1;
  }
  for (nr=0, sidtab=cfg->sidtab; sidtab; sidtab=sidtab->next, nr++)
    if (sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid)
    {
      if ((client[idx].sidtabno&(1<<nr)) &&
          (chk_srvid_match(er, sidtab)))
        return(0);
      if ((client[idx].sidtabok&(1<<nr)) &&
          (chk_srvid_match(er, sidtab)))
        rc=1;
    }
  return(rc);
}

// server filter for newcamd
int chk_sfilter(ECM_REQUEST *er, PTAB *ptab)
{
  int i, j, pi, rc=1;
  ushort caid, scaid;
  ulong  prid, sprid;

  if (!ptab) return(1);

  caid = er->caid;
  prid = er->prid;
  pi = client[cs_idx].port_idx;

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
          cs_debug("trying server filter %04X:%06X", scaid, sprid);
          if (prid==sprid)
          {
            rc=1;
            cs_debug("%04X:%06X allowed by server filter %04X:%06X",
                     caid, prid, scaid, sprid);
          }
        }
      }
    }
    if(!rc)
    {
      cs_debug("no match, %04X:%06X rejected by server filters", caid, prid);
      snprintf( er->msglog, MSGLOGSIZE, "no server match %04X:%06X",
        caid, (unsigned int) prid );

      if (!er->rcEx) er->rcEx=(E1_LSERVER<<4)|E2_IDENT;
      return(rc);
    }
  }
  return (rc);
}

static int chk_chid(ECM_REQUEST *er, FTAB *fchid, char *type, char *name)
{
  int rc=1, i, j;

  if( (er->caid & 0xFF00)!=0x600 ) return 1;
  if( !er->chid ) return 1;
  if( !fchid->nfilts ) return 1;

  for( i=rc=0; (!rc) && i<fchid->nfilts; i++ )
    if( er->caid == fchid->filts[i].caid )
      for( j=0; (!rc) && j<fchid->filts[i].nprids; j++ )
      {
        cs_debug("trying %s '%s' CHID filter %04X:%04X", 
                 type, name, fchid->filts[i].caid, fchid->filts[i].prids[j]);
        if( er->chid == fchid->filts[i].prids[j] )
        {
          cs_debug("%04X:%04X allowed by %s '%s' CHID filter %04X:%04X",
                   er->caid, er->chid, type, name, fchid->filts[i].caid, 
                   fchid->filts[i].prids[j]);
          rc=1;
        }
      }

  if( !rc ) cs_debug("no match, %04X:%04X rejected by %s '%s' CHID filter(s)", 
                      er->caid, er->chid, type, name);
  
  return (rc);
}

int chk_ufilters(ECM_REQUEST *er)
{
  int i, j, rc;
  ushort ucaid;
  ulong  uprid;

  rc=1;
  if( client[cs_idx].ftab.nfilts )
  {
    FTAB *f = &client[cs_idx].ftab;
    for( i=rc=0; (!rc) && (i<f->nfilts); i++ )
    {
      ucaid = f->filts[i].caid;
      if( er->caid==0 || ucaid==0 || (er->caid!=0 && er->caid==ucaid) )
      {
        for( j=rc=0; (!rc) && (j<f->filts[i].nprids); j++ )
        {
          uprid = f->filts[i].prids[j];
          cs_debug("trying user '%s' filter %04X:%06X",
                   client[cs_idx].usr, ucaid, uprid);
          if( er->prid == uprid )
          {
            rc=1;
            cs_debug("%04X:%06X allowed by user '%s' filter %04X:%06X",
                      er->caid, er->prid, client[cs_idx].usr, ucaid, uprid);
          }
        }
      }
    }
    if( !rc ) {
      cs_debug("no match, %04X:%06X rejected by user '%s' filters",
                er->caid, er->prid, client[cs_idx].usr);
        snprintf( er->msglog, MSGLOGSIZE, "no card support %04X:%06X",
                er->caid, (unsigned int) er->prid );

      if( !er->rcEx ) er->rcEx=(E1_USER<<4)|E2_IDENT;
      return (rc);
    }
  }

  if( !(rc=chk_class(er, &client[cs_idx].cltab, "user", client[cs_idx].usr)) ) {
    if( !er->rcEx ) er->rcEx=(E1_USER<<4)|E2_CLASS;
  }
  else if( !(rc=chk_chid(er, &client[cs_idx].fchid, "user", client[cs_idx].usr)) )
    if( !er->rcEx ) er->rcEx=(E1_USER<<4)|E2_CHID;

  if( rc ) er->rcEx=0;

  return (rc);
}

int chk_rsfilter(struct s_reader * reader, ECM_REQUEST *er, int disable_server_filt)
{
  int i, rc=1;
  ushort caid;
  ulong prid;

  if( disable_server_filt )
  { 
    cs_debug("%04X:%06X allowed - server filters disabled",
              er->caid, er->prid);
    return 1;
  }

  rc=prid=0;
  caid = reader->caid[0];
  if( caid==er->caid )
  {
    for( i=0; (!rc) && (i<reader->nprov); i++ )
    {
      prid = (ulong)((reader->prid[i][0]<<16) |
                     (reader->prid[i][1]<<8) |
                     (reader->prid[i][2]));
      cs_debug("trying server '%s' filter %04X:%06X", 
                reader->device, caid, prid);
      if( prid==er->prid )
      {
        rc=1;
        cs_debug("%04X:%06X allowed by server '%s' filter %04X:%06X",
                  er->caid, er->prid, reader->device, caid, prid);
      }
    }
  }
  if(!rc) {
    cs_debug("no match, %04X:%06X rejected by server '%s' filters",
            er->caid, er->prid, reader->device);
    if( !er->rcEx ) er->rcEx=(E1_SERVER<<4)|E2_IDENT;
    return 0;
  }

  return(rc);
}

int chk_rfilter(ECM_REQUEST *er, struct s_reader *rdr)
{
  int i, j, rc=1;
  ushort caid=0;
  ulong prid=0;

  if( rdr->ftab.nfilts )
  { 
    for( rc=i=0; (!rc) && (i<rdr->ftab.nfilts); i++ )
    {
      caid = rdr->ftab.filts[i].caid;
      if( (caid!=0 && caid==er->caid) || caid==0 )
      { 
        for( j=0; (!rc) && (j<rdr->ftab.filts[i].nprids); j++)
        {
          prid = rdr->ftab.filts[i].prids[j];
          cs_debug("trying reader '%s' filter %04X:%06X",
                    rdr->label, caid, prid);
          if( prid==er->prid )
          {
            rc=1;
            cs_debug("%04X:%06X allowed by reader '%s' filter %04X:%06X",
                    er->caid, er->prid, rdr->label, caid, prid);
          }
        }
      }
    }
    if(!rc) {
      cs_debug("no match, %04X:%06X rejected by reader '%s' filters",
                er->caid, er->prid, rdr->label);
      return 0;
    }
  }

  return(rc);
}

int chk_avail_reader(ECM_REQUEST *er, struct s_reader *rdr)
{
  if( !chk_rfilter(er, rdr) ) {
    if( !er->rcEx ) er->rcEx=(E1_READER<<4)|E2_IDENT;
    return 0;
  }
  if( !chk_class(er, &rdr->cltab, "reader", rdr->label) ) {
    if( !er->rcEx ) er->rcEx=(E1_READER<<4)|E2_CLASS;
    return 0;
  }
  if( !chk_chid(er, &rdr->fchid, "reader", rdr->label) ) {
    if( !er->rcEx ) er->rcEx=(E1_READER<<4)|E2_CHID;
    return 0;
  }
//fixme re-activated code for testing
  if( rdr->typ=='r' )
  {
    if( rdr->qlen>=rdr->maxqlen )
    {
      cs_log("reader '%s' max. queue length(%d) reached, rejected", rdr->label, rdr->qlen);
      if( !er->rcEx ) er->rcEx=(E1_READER<<4)|E2_QUEUE;
      return 0;
    }
    else {
      cs_log("reader '%s' qlen=%d", rdr->label, rdr->qlen);
      rdr->qlen++;
    }
  }

  return 1;
}

//check reader caid
int chk_caid(ushort caid, ushort *caidlist) {
  if (!caid || !caidlist || !caidlist[0])
    return 1;

  int i;
  for (i=0; i<CS_MAXREADERCAID; i++)
    if (caidlist[i] && caid==caidlist[i])
      return 1;
      
  return 0;
}

int matching_reader(ECM_REQUEST *er, struct s_reader *rdr) {
  if (!((rdr->fd) && (rdr->grp&client[cs_idx].grp)))
    return(0);

  if (!rdr->enable || rdr->deleted)
    return(0);
    
  //Schlocke reader-defined function 
  if (rdr->ph.c_available && !rdr->ph.c_available(rdr->ridx, AVAIL_CHECK_CONNECTED))
    return 0;

  if (!chk_caid(er->caid, rdr->caid))
    return 0;
    
  if (!chk_srvid(er, rdr->cs_idx))
    return(0);

  if (!chk_rfilter(er, rdr))
    return(0);

  if (!chk_class(er, &rdr->cltab, "reader", rdr->label))
    return(0);

  if (!chk_chid(er, &rdr->fchid, "reader", rdr->label))
    return(0);
 
  return(1);
}
