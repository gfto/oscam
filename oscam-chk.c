#define MODULE_LOG_PREFIX "chk"

#include "globals.h"
#include "oscam-cache.h"
#include "oscam-chk.h"
#include "oscam-ecm.h"
#include "oscam-client.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "module-stat.h"
#include "oscam-reader.h"

#define CS_NANO_CLASS 0xE2
#define OK      1
#define ERROR   0

uint32_t get_fallbacktimeout(uint16_t   caid)
{
	uint32_t ftimeout = caidvaluetab_get_value(&cfg.ftimeouttab, caid, 0);

	if(ftimeout == 0) { ftimeout = cfg.ftimeout; }

	if(ftimeout < 100) { ftimeout = CS_CLIENT_TIMEOUT / 2; }
	if(ftimeout >= cfg.ctimeout) { ftimeout = cfg.ctimeout - 100; }

	return ftimeout;
}


static int32_t find_nano(uchar *ecm, int32_t l, uchar nano, int32_t s)
{
	uchar *snano;

	if(s >= l) { return 0; }
	if(!s) { s = (ecm[4] == 0xD2) ? 12 : 9; }    // tpsflag -> offset+3
	snano = ecm + s;

	while((*snano != nano) && (s < l))
	{
		if(*snano == 0xEA) { return 0; }
		snano++;
		s++;
	}

	return (s < l) ? ++s : 0;
}

static int32_t chk_class(ECM_REQUEST *er, CLASSTAB *clstab, const char *type, const char *name)
{
	int32_t i, j, an, cl_n, l;
	uchar ecm_class;

	if(er->caid != 0x0500) { return 1; }
	if(!clstab->bn && !clstab->an) { return 1; }

	j = an = cl_n = l = 0;
	while((j = find_nano(er->ecm, er->ecmlen, CS_NANO_CLASS, j)) > 0)
	{
		l = er->ecm[j];
		if(l + j > er->ecmlen) { continue; }  // skip, this is not a valid class identifier!
		ecm_class = er->ecm[j + l];
		cs_log_dbg(D_CLIENT, "ecm class=%02X", ecm_class);
		for(i = 0; i < clstab->bn; i++)    // search in blocked
			if(ecm_class == clstab->bclass[i])
			{
				cs_log_dbg(D_CLIENT, "class %02X rejected by %s '%s' !%02X filter",
							  ecm_class, type, name, ecm_class);
				return 0;
			}

		cl_n++;
		for(i = 0; i < clstab->an; i++)    // search in allowed
			if(ecm_class == clstab->aclass[i])
			{
				an++;
				break;
			}
		j += l;
	}

	if(cl_n && clstab->an)
	{
		if(an)
			{ cs_log_dbg(D_CLIENT, "ECM classes allowed by %s '%s' filter", type, name); }
		else
		{
			cs_log_dbg(D_CLIENT, "ECM classes don't match %s '%s' filter, rejecting", type, name);
			return 0;
		}
	}

	return 1;
}

int32_t chk_srvid_match(ECM_REQUEST *er, SIDTAB *sidtab)
{
	int32_t i, rc = 0;

	if(!sidtab->num_caid)
		{ rc |= 1; }
	else
		for(i = 0; (i < sidtab->num_caid) && (!(rc & 1)); i++)
			if(er->caid == sidtab->caid[i]) { rc |= 1; }

	if(!er->prid || !sidtab->num_provid)
		{ rc |= 2; }
	else
		for(i = 0; (i < sidtab->num_provid) && (!(rc & 2)); i++)
			if(er->prid == sidtab->provid[i]) { rc |= 2; }

	if(!sidtab->num_srvid)
		{ rc |= 4; }
	else
		for(i = 0; (i < sidtab->num_srvid) && (!(rc & 4)); i++)
			if(er->srvid == sidtab->srvid[i]) { rc |= 4; }

	return (rc == 7);
}

int32_t chk_srvid(struct s_client *cl, ECM_REQUEST *er)
{
	int32_t nr, rc = 0;
	SIDTAB *sidtab;

	if(!cl->sidtabs.ok)
	{
		if(!cl->sidtabs.no) { return (1); }
		rc = 1;
	}
	for(nr = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, nr++)
		if(sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid)
		{
			if((cl->sidtabs.no & ((SIDTABBITS)1 << nr)) &&
					(chk_srvid_match(er, sidtab)))
				{ return (0); }
			if((cl->sidtabs.ok & ((SIDTABBITS)1 << nr)) &&
					(chk_srvid_match(er, sidtab)))
				{ rc = 1; }
		}
	return (rc);
}

int32_t has_srvid(struct s_client *cl, ECM_REQUEST *er)
{
	if(!cl->sidtabs.ok)
		{ return 0; }

	int32_t nr;
	SIDTAB *sidtab;

	for(nr = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, nr++)
		if(sidtab->num_srvid)
		{
			if((cl->sidtabs.ok & ((SIDTABBITS)1 << nr)) &&
					(chk_srvid_match(er, sidtab)))
				{ return 1; }
		}
	return 0;
}


int32_t has_lb_srvid(struct s_client *cl, ECM_REQUEST *er)
{
	if(!cl->lb_sidtabs.ok)
		{ return 0; }

	int32_t nr;
	SIDTAB *sidtab;

	for(nr = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, nr++)
		if((cl->lb_sidtabs.ok & ((SIDTABBITS)1 << nr)) &&
				(chk_srvid_match(er, sidtab)))
			{ return 1; }
	return 0;
}


int32_t chk_srvid_match_by_caid_prov(uint16_t caid, uint32_t provid, SIDTAB *sidtab)
{
	int32_t i, rc = 0;

	if(!sidtab->num_caid)
		{ rc |= 1; }
	else
		for(i = 0; (i < sidtab->num_caid) && (!(rc & 1)); i++)
			if(caid == sidtab->caid[i]) { rc |= 1; }

	if(!sidtab->num_provid)
		{ rc |= 2; }
	else
		for(i = 0; (i < sidtab->num_provid) && (!(rc & 2)); i++)
			if(provid == sidtab->provid[i]) { rc |= 2; }

	return (rc == 3);
}

int32_t chk_srvid_by_caid_prov(struct s_client *cl, uint16_t caid, uint32_t provid)
{
	int32_t nr, rc = 0;
	SIDTAB *sidtab;

	if(!cl->sidtabs.ok)
	{
		if(!cl->sidtabs.no) { return (1); }
		rc = 1;
	}
	for(nr = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, nr++)
		if(sidtab->num_caid | sidtab->num_provid)
		{
			if((cl->sidtabs.no & ((SIDTABBITS)1 << nr)) && !sidtab->num_srvid &&
					(chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
				{ return (0); }
			if((cl->sidtabs.ok & ((SIDTABBITS)1 << nr)) &&
					(chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
				{ rc = 1; }
		}
	return (rc);
}

int32_t chk_srvid_by_caid_prov_rdr(struct s_reader *rdr, uint16_t caid, uint32_t provid)
{
	int32_t nr, rc = 0;
	SIDTAB *sidtab;

	if(!rdr->sidtabs.ok)
	{
		if(!rdr->sidtabs.no) { return (1); }
		rc = 1;
	}
	for(nr = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, nr++)
		if(sidtab->num_caid | sidtab->num_provid)
		{
			if((rdr->sidtabs.no & ((SIDTABBITS)1 << nr)) && !sidtab->num_srvid &&
					(chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
				{ return (0); }
			if((rdr->sidtabs.ok & ((SIDTABBITS)1 << nr)) &&
					(chk_srvid_match_by_caid_prov(caid, provid, sidtab)))
				{ rc = 1; }
		}
	return (rc);
}

int32_t chk_is_betatunnel_caid(uint16_t caid)
{
	if(caid == 0x1702 || caid == 0x1722) { return 1; }
	if(caid == 0x1801 || caid == 0x1833 || caid == 0x1834 || caid == 0x1835) { return 2; }
	return 0;
}

uint16_t chk_on_btun(uint8_t chk_sx, struct s_client *cl, ECM_REQUEST *er)
{
	if(chk_is_betatunnel_caid(er->caid))
	{

		int32_t i;
		TUNTAB *ttab;
		ttab = &cl->ttab;

		if(ttab->ttdata)
		{
			for(i = 0; i < ttab->ttnum; i++)
			{
				if(er->caid == ttab->ttdata[i].bt_caidfrom)
				{
					if(er->srvid == ttab->ttdata[i].bt_srvid) { return ttab->ttdata[i].bt_caidto; }
					if(chk_sx && ttab->ttdata[i].bt_srvid == 0xFFFF) { return ttab->ttdata[i].bt_caidto; }
					if(!chk_sx && !ttab->ttdata[i].bt_srvid) { return ttab->ttdata[i].bt_caidto; }
				}
			}
		}
		if(chk_sx)
			return lb_get_betatunnel_caid_to(er);
	}
	return 0;
}

// server filter for newcamd
int32_t chk_sfilter(ECM_REQUEST *er, PTAB *ptab)
{
#ifdef MODULE_NEWCAMD
	int32_t i, j, pi, rc = 1;
	uint16_t caid, scaid;
	uint32_t  prid, sprid;

	if(!ptab) { return (1); }
	struct s_client *cur_cl = cur_client();

	caid = er->caid;
	prid = er->prid;
	pi = cur_cl->port_idx;

	if(cfg.ncd_mgclient)
		{ return 1; }

	if(ptab->nports && ptab->ports[pi].ncd && ptab->ports[pi].ncd->ncd_ftab.nfilts)
	{
		for(rc = j = 0; (!rc) && (j < ptab->ports[pi].ncd->ncd_ftab.nfilts); j++)
		{
			scaid = ptab->ports[pi].ncd->ncd_ftab.filts[j].caid;
			if(caid == 0 || (caid != 0 && caid == scaid))
			{
				for(i = 0; (!rc) && i < ptab->ports[pi].ncd->ncd_ftab.filts[j].nprids; i++)
				{
					sprid = ptab->ports[pi].ncd->ncd_ftab.filts[j].prids[i];
					cs_log_dbg(D_CLIENT, "trying server filter %04X@%06X", scaid, sprid);
					if(prid == sprid)
					{
						rc = 1;
						cs_log_dbg(D_CLIENT, "%04X@%06X allowed by server filter %04X@%06X",
									  caid, prid, scaid, sprid);
					}
				}
			}
		}
		if(!rc)
		{
			cs_log_dbg(D_CLIENT, "no match, %04X@%06X rejected by server filters", caid, prid);
			snprintf(er->msglog, MSGLOGSIZE, "no server match %04X@%06X",
					 caid, (uint32_t) prid);

			if(!er->rcEx) { er->rcEx = (E1_LSERVER << 4) | E2_IDENT; }
			return (rc);
		}
	}
	return (rc);
#else
	(void)er;
	(void)ptab;
	return 1;
#endif
}

static int32_t chk_chid(ECM_REQUEST *er, FTAB *fchid, char *type, char *name)
{
	int32_t rc = 1, i, j, found_caid = 0;
	if(!fchid->nfilts) { return 1; }

	for(i = rc = 0; (!rc) && i < fchid->nfilts; i++)
		if(er->caid == fchid->filts[i].caid)
		{
			found_caid = 1;
			for(j = 0; (!rc) && j < fchid->filts[i].nprids; j++)
			{
				cs_log_dbg(D_CLIENT, "trying %s '%s' CHID filter %04X:%04X",
							  type, name, fchid->filts[i].caid, fchid->filts[i].prids[j]);
				if(er->chid == fchid->filts[i].prids[j])
				{
					cs_log_dbg(D_CLIENT, "%04X:%04X allowed by %s '%s' CHID filter %04X:%04X",
								  er->caid, er->chid, type, name, fchid->filts[i].caid,
								  fchid->filts[i].prids[j]);
					rc = 1;
				}
			}
		}

	if(!rc)
	{
		if(found_caid)
			cs_log_dbg(D_CLIENT, "no match, %04X:%04X rejected by %s '%s' CHID filter(s)",
						  er->caid, er->chid, type, name);
		else
		{
			rc = 1;
			cs_log_dbg(D_CLIENT, "%04X:%04X allowed by %s '%s' CHID filter, CAID not spezified",
						  er->caid, er->chid, type, name);
		}
	}
	return (rc);
}


int32_t chk_ident_filter(uint16_t rcaid, uint32_t rprid, FTAB *ftab)
{
	int32_t i, j, rc=1;
	uint16_t caid=0;
	uint32_t prid=0;

	if(ftab->nfilts)
	{
		for(rc=i=0; (!rc) && (i<ftab->nfilts); i++)
		{
			caid = ftab->filts[i].caid;
			if((caid!=0 && caid==rcaid) || caid==0)
			{
				for(j=0; (!rc) && (j<ftab->filts[i].nprids); j++)
				{
					prid = ftab->filts[i].prids[j];
					if(prid==rprid)
					{
						rc=1;
					}
				}
			}
		}
		if(!rc)
			{ return 0; }
	}

	return(rc);
}


int32_t chk_ufilters(ECM_REQUEST *er)
{
	int32_t i, j, rc;
	uint16_t ucaid;
	uint32_t  uprid;
	struct s_client *cur_cl = cur_client();

	rc = 1;
	if(cur_cl->ftab.nfilts)
	{
		FTAB *f = &cur_cl->ftab;
		for(i = rc = 0; (!rc) && (i < f->nfilts); i++)
		{
			ucaid = f->filts[i].caid;
			if(er->caid == 0 || ucaid == 0 || (er->caid != 0 && er->caid == ucaid))
			{
				if (er->prid == 0)
				{
					cs_log_dbg(D_CLIENT, "%04X@%06X allowed by user '%s' filter caid %04X prid %06X",
								  er->caid, er->prid, cur_cl->account->usr, ucaid, 0);
					rc = 1;
					break;
				}
				for(j = rc = 0; (!rc) && (j < f->filts[i].nprids); j++)
				{
					uprid = f->filts[i].prids[j];
					cs_log_dbg(D_CLIENT, "trying user '%s' filter %04X@%06X",
								  cur_cl->account->usr, ucaid, uprid);
					if(er->prid == uprid)
					{
						rc = 1;
						cs_log_dbg(D_CLIENT, "%04X@%06X allowed by user '%s' filter %04X@%06X",
									  er->caid, er->prid, cur_cl->account->usr, ucaid, uprid);
					}
				}
			}
		}
		if(!rc)
		{
			cs_log_dbg(D_CLIENT, "no match, %04X@%06X rejected by user '%s' filters",
						  er->caid, er->prid, cur_cl->account->usr);
			snprintf(er->msglog, MSGLOGSIZE, "no card support %04X@%06X",
					 er->caid, (uint32_t) er->prid);

			if(!er->rcEx) { er->rcEx = (E1_USER << 4) | E2_IDENT; }
			return (rc);
		}
	}

	if(!(rc = chk_class(er, &cur_cl->cltab, "user", cur_cl->account->usr)))
	{
		if(!er->rcEx) { er->rcEx = (E1_USER << 4) | E2_CLASS; }
	}
	else if(!(rc = chk_chid(er, &cur_cl->fchid, "user", cur_cl->account->usr)))
		if(!er->rcEx) { er->rcEx = (E1_USER << 4) | E2_CHID; }

	if(rc) { er->rcEx = 0; }

	return (rc);
}

int32_t chk_rsfilter(struct s_reader *reader, ECM_REQUEST *er)
{
	int32_t i, rc = 1;
	uint16_t caid;
	uint32_t prid;

	if(reader->ncd_disable_server_filt)
	{
		cs_log_dbg(D_CLIENT, "%04X@%06X allowed - server filters disabled",
					  er->caid, er->prid);
		return 1;
	}

	rc = prid = 0;
	caid = reader->caid;
	if(caid == er->caid)
	{
		for(i = 0; (!rc) && (i < reader->nprov); i++)
		{
			prid = (uint32_t)((reader->prid[i][1] << 16) |
							  (reader->prid[i][2] << 8) |
							  (reader->prid[i][3]));
			cs_log_dbg(D_CLIENT, "trying server '%s' filter %04X@%06X",
						  reader->device, caid, prid);
			if(prid == er->prid)
			{
				rc = 1;
				cs_log_dbg(D_CLIENT, "%04X@%06X allowed by server '%s' filter %04X@%06X",
							  er->caid, er->prid, reader->device, caid, prid);
			}
		}
	}
	if(!rc)
	{
		cs_log_dbg(D_CLIENT, "no match, %04X@%06X rejected by server '%s' filters",
					  er->caid, er->prid, reader->device);
		if(!er->rcEx) { er->rcEx = (E1_SERVER << 4) | E2_IDENT; }
		return 0;
	}

	return (rc);
}

int32_t chk_rfilter2(uint16_t rcaid, uint32_t rprid, struct s_reader *rdr)
{
	int32_t i, j, rc = 1;
	uint16_t caid = 0;
	uint32_t prid = 0;

	if(rdr->ftab.nfilts)
	{
		for(rc = i = 0; (!rc) && (i < rdr->ftab.nfilts); i++)
		{
			caid = rdr->ftab.filts[i].caid;
			if((caid != 0 && caid == rcaid) || caid == 0)
			{
				for(j = 0; (!rc) && (j < rdr->ftab.filts[i].nprids); j++)
				{
					prid = rdr->ftab.filts[i].prids[j];
					cs_log_dbg(D_CLIENT, "trying reader '%s' filter %04X@%06X",
								  rdr->label, caid, prid);
					if(prid == rprid)
					{
						rc = 1;
						cs_log_dbg(D_CLIENT, "%04X@%06X allowed by reader '%s' filter %04X@%06X",
									  rcaid, rprid, rdr->label, caid, prid);
					}
				}
			}
		}
		if(!rc)
		{
			cs_log_dbg(D_CLIENT, "no match, %04X@%06X rejected by reader '%s' filters",
						  rcaid, rprid, rdr->label);
			return 0;
		}
	}

	return (rc);
}


static int32_t chk_rfilter(ECM_REQUEST *er, struct s_reader *rdr)
{
	return chk_rfilter2(er->caid, er->prid, rdr);
}

int32_t chk_ctab(uint16_t caid, CAIDTAB *ctab)
{
	if(!caid || !ctab->ctnum)
		{ return 1; }

	int32_t i;
	for(i = 0; i < ctab->ctnum; i++)
	{
		CAIDTAB_DATA *d = &ctab->ctdata[i];
		if(!d->caid)
		{
			return 0;
		}
		if((caid & d->mask) == d->caid)
			{ return 1; }
	}
	return 0;
}

int32_t chk_ctab_ex(uint16_t caid, CAIDTAB *ctab)
{
	if(!caid || !ctab->ctnum)
		{ return 0; }

	int32_t i;
	for(i = 0; i < ctab->ctnum; i++)
	{
		CAIDTAB_DATA *d = &ctab->ctdata[i];
		if(!d->caid)
		{
			return 0;
		}
		if((caid & d->mask) == d->caid)
			{ return 1; }
	}
	return 0;
}

uint8_t is_localreader(struct s_reader *rdr, ECM_REQUEST *er) //to be used for LB/reader selections checks only
{
	if(!rdr) return 0;

	if(!is_network_reader(rdr)){
		return 1;
	}

	if(!rdr->localcards.nfilts) { return 0; }

	int32_t i, k;
	for(i = 0; i < rdr->localcards.nfilts; i++)
	{
		uint16_t tcaid = rdr->localcards.filts[i].caid;
		if(tcaid && tcaid == er->caid)    //caid match
		{
			int32_t nprids = rdr->localcards.filts[i].nprids;
			if(!nprids)  // No Provider ->Ok
				{ return 1; }

			for(k = 0; k < nprids; k++)
			{
				uint32_t prid = rdr->localcards.filts[i].prids[k];
				if(prid == er->prid)    //Provider matches
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

uint8_t chk_is_fixed_fallback(struct s_reader *rdr, ECM_REQUEST *er)
{

	if(!rdr->fallback && !rdr->fallback_percaid.nfilts) { return 0; }

	if(!rdr->fallback_percaid.nfilts)
		if(rdr->fallback)
			{ return 1; }

	int32_t i, k;
	for(i = 0; i < rdr->fallback_percaid.nfilts; i++)
	{
		uint16_t tcaid = rdr->fallback_percaid.filts[i].caid;
		if(tcaid && (tcaid == er->caid || (tcaid < 0x0100 && (er->caid >> 8) == tcaid)))    //caid match
		{

			int32_t nprids = rdr->fallback_percaid.filts[i].nprids;
			if(!nprids)  // No Provider ->Ok
				{ return 1; }

			for(k = 0; k < nprids; k++)
			{
				uint32_t prid = rdr->fallback_percaid.filts[i].prids[k];
				if(prid == er->prid)    //Provider matches
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

uint8_t chk_has_fixed_fallback(ECM_REQUEST *er)
{
	struct s_ecm_answer *ea;
	struct s_reader *rdr;
	int32_t n_falb = 0;
	for(ea = er->matching_rdr; ea; ea = ea->next)
	{
		rdr = ea->reader;
		if(chk_is_fixed_fallback(rdr, er))
			{ n_falb++; }
	}
	return n_falb;
}

int32_t matching_reader(ECM_REQUEST *er, struct s_reader *rdr)
{

	//simple checks first:
	if(!er || !rdr)
		{ return (0); }

	//reader active?
	struct s_client *cl = rdr->client;
	if(!cl || !rdr->enable)
		{ return (0); }

	// if physical reader a card needs to be inserted
	if(!is_network_reader(rdr) && rdr->card_status != CARD_INSERTED)
		{ return (0); }

	//Checking connected & group valid:
	struct s_client *cur_cl = er->client; //cur_client();

#ifdef CS_CACHEEX
	//Cacheex=3 defines a Cacheex-only reader. never match them.
	if(rdr->cacheex.mode == 3)
		{ return (0); }
	if(rdr->cacheex.mode == 2 && !rdr->cacheex.allow_request)
		{ return (0); }
#endif

	if(!(rdr->grp & cur_cl->grp))
		{ return (0); }

	//Checking caids:
	if((!er->ocaid || !chk_ctab(er->ocaid, &rdr->ctab)) && !chk_ctab(er->caid, &rdr->ctab))
	{
		cs_log_dbg(D_TRACE, "caid %04X not found in caidlist reader %s", er->caid, rdr->label);
		return 0;
	}

	if(!is_network_reader(rdr) && ((rdr->caid >> 8) != ((er->caid >> 8) & 0xFF) && (rdr->caid >> 8) != ((er->ocaid >> 8) & 0xFF)))
	{
		if (!rdr->csystem)
			return 0;
		int i, caid_found = 0;
		for(i = 0; rdr->csystem->caids[i]; i++)
		{
			uint16_t cs_caid = rdr->csystem->caids[i];
			if(!cs_caid)
				{ continue; }
			if(cs_caid == er->caid || cs_caid == er->ocaid)
			{
				caid_found = 1;
				break;
			}
		}
		if(!caid_found)
			{ return 0; }
	}

	//Supports long ecms?
	if(er->ecmlen > 255 && is_network_reader(rdr) && !rdr->ph.large_ecm_support)
	{
		cs_log_dbg(D_TRACE, "no large ecm support (l=%d) for reader %s", er->ecmlen, rdr->label);
		return 0;
	}


	//Checking services:
	if(!chk_srvid(rdr->client, er))
	{
		cs_log_dbg(D_TRACE, "service %04X not matching reader %s", er->srvid, rdr->label);
		return (0);
	}

	//Checking ident:
	if(!chk_rfilter(er, rdr))
	{
		cs_log_dbg(D_TRACE, "r-filter reader %s", rdr->label);
		return (0);
	}

	//Check ECM nanos:
	if(!chk_class(er, &rdr->cltab, "reader", rdr->label))
	{
		cs_log_dbg(D_TRACE, "class filter reader %s", rdr->label);
		return (0);
	}


	// CDS NL: check for right seca type
	if(!is_network_reader(rdr) && er->caid == 0x100 && er->prid == 0x00006a &&
			!(er->ecm[8] == 0x00 && er->ecm[9] == 0x00))   // no empty ecm
	{
		if(er->ecm[8] == 0x00 && rdr->secatype == 2)
		{
			cs_log_dbg(D_TRACE, "Error: this is a nagra/mediaguard3 ECM and readertype is seca2!");
			return 0;  // we dont send a nagra/mediaguard3 ecm to a seca2 reader!
		}
		if((er->ecm[8] == 0x10) && (er->ecm[9] == 0x01) && rdr->secatype == 3)
		{
			cs_log_dbg(D_TRACE, "Error: this is a seca2 ECM and readertype is nagra/mediaguard3!");
			return 0;  // we dont send a seca2 ecm to a nagra/mediaguard3 reader!
		}
	}
	// CDS NL: check for right seca type by ECMPID
	if(!is_network_reader(rdr) && er->caid == 0x100 && er->prid == 0x00006a)
	{
		if(rdr->secatype == 2 && er->pid >> 8 == 7)
		{
			cs_log_dbg(D_TRACE, "Error: this is a nagra/mediaguard3 ECM and readertype is seca2!");
			return 0;  // we dont send a nagra/mediaguard3 ecm to a seca2 reader!
		}
		if(rdr->secatype == 3 && er->pid >> 8 == 6)
		{
			cs_log_dbg(D_TRACE, "Error: this is a seca2 ECM and readertype is nagra/mediaguard3!");
			return 0;  // we dont send a seca2 ecm to a nagra/mediaguard3 reader!
		}
	}

	//Checking chid:
	if(!chk_chid(er, &rdr->fchid, "reader", rdr->label))
	{
		cs_log_dbg(D_TRACE, "chid filter reader %s", rdr->label);
		return (0);
	}

	//Schlocke reader-defined function, reader-self-check
	if(rdr->ph.c_available && !rdr->ph.c_available(rdr, AVAIL_CHECK_CONNECTED, er))
	{
		cs_log_dbg(D_TRACE, "reader unavailable %s", rdr->label);
		return 0;
	}

	//Checking entitlements:
	if(ll_count(rdr->ll_entitlements) > 0)
	{
		LL_ITER itr = ll_iter_create(rdr->ll_entitlements);
		S_ENTITLEMENT *item;
		int8_t found = 0;
		while((item = ll_iter_next(&itr)))
		{
			//if (item->caid == er->caid && (!er->prid || !item->provid || item->provid == er->prid)) {     //provid check causing problems?
			if(item->caid == er->caid || item->caid == er->ocaid)                                           //... so check at least caid only
			{
				found = 1;
				break;
			}
		}
		if(!found)
		{
			cs_log_dbg(D_TRACE, "entitlements check failed on reader %s", rdr->label);
			return 0;
		}
	}

	//Checking ecmlength:
	if(rdr->ecm_whitelist.ewnum && er->ecmlen)
	{
		int32_t i;
		int8_t ok = 0, foundident = 0;
		for (i = 0; i < rdr->ecm_whitelist.ewnum; i++)
		{
			ECM_WHITELIST_DATA *d = &rdr->ecm_whitelist.ewdata[i];
			if ((d->caid == 0 || d->caid == er->caid) && (d->ident == 0 || d->ident == er->prid))
			{
				foundident = 1;
				if (d->len == er->ecmlen)
				{
					ok = 1;
					break;
				}
			}
		}
		if(foundident == 1 && ok == 0)
		{
			cs_log_dbg(D_TRACE, "ECM is not in ecmwhitelist of reader %s.", rdr->label);
			rdr->ecmsfilteredlen += 1;
			return (0);
		}
	}

	// ECM Header Check
	if(rdr->ecm_hdr_whitelist.ehdata && er->ecmlen)
	{
		int8_t byteok = 0;
		int8_t entryok = 0;
		int8_t foundcaid = 0;
		int8_t foundprovid = 0;
		int16_t len = 0;
		int32_t i = 0;
		int8_t skip = 0;
		int32_t r;
		for(r = 0; r < rdr->ecm_hdr_whitelist.ehnum; r++)
		{
			ECM_HDR_WHITELIST_DATA *tmp = &rdr->ecm_hdr_whitelist.ehdata[r];
			skip = 0;
			byteok = 0;
			entryok = 0;
			len = 0;
			if(tmp->caid == 0 || tmp->caid == er->caid)
			{
				foundcaid = 1; //-> caid was in list
				//rdr_log_dbg(rdr, D_READER, "Headerwhitelist: found matching CAID: %04X in list", tmp->caid);
				if(tmp->provid == 0 || tmp->provid == er->prid)
				{
					foundprovid = 1; //-> provid was in list
					//rdr_log_dbg(rdr, D_READER, "Headerwhitelist: found matching Provid: %06X in list", tmp->provid);
					len = tmp->len;
					for(i = 0; i < len / 2; i++)
					{
						if(tmp->header[i] == er->ecm[i])
						{
							byteok = 1;
							//rdr_log_dbg(rdr, D_READER, "ECM Byte: %i of ECMHeaderwhitelist is correct. (%02X = %02X Headerlen: %i)", i, er->ecm[i], tmp->header[i], len/2);
						}
						else
						{
							byteok = 0;
							//rdr_log_dbg(rdr, D_READER, "ECM Byte: %i of ECMHeaderwhitelist is not valid. (%02X != %02X Headerlen: %i)", i, er->ecm[i], tmp->header[i], len/2);
							entryok = 0;
							break;
						}
						if(i == len / 2 - 1 && byteok == 1)
						{
							entryok = 1;
						}

					}
				}
				else
				{
					//rdr_log_dbg(rdr, D_READER, "ECMHeaderwhitelist: Provid: %06X not found in List-Entry -> skipping check", er->prid);
					skip = 1;
					continue;
				}
			}
			else
			{
				//rdr_log_dbg(rdr, D_READER, "ECMHeaderwhitelist: CAID: %04X not found in List-Entry -> skipping check", er->caid);
				skip = 1;
				continue;
			}
			if(entryok == 1)
			{
				break;
			}

		}
		if(foundcaid == 1 && foundprovid == 1 && byteok == 1 && entryok == 1)
		{
			//cs_log("ECM for %04X@%06X:%04X is valid for ECMHeaderwhitelist of reader %s.", er->caid, er->prid, er->srvid, rdr->label);
		}
		else
		{
			if(skip == 0 || (foundcaid == 1 && foundprovid == 1 && entryok == 0 && skip == 1))
			{
				cs_log_dump_dbg(D_TRACE, er->ecm, er->ecmlen,
							  "following ECM %04X@%06X:%04X was filtered by ECMHeaderwhitelist of Reader %s from User %s because of not matching Header:",
							  er->caid, er->prid, er->srvid, rdr->label, username(er->client));
				rdr->ecmsfilteredhead += 1;
				return (0);
			}
		}
	}

	//Simple ring connection check:

	//Check ip source+dest:
	if(cfg.block_same_ip && IP_EQUAL(cur_cl->ip, rdr->client->ip) &&
			get_module(cur_cl)->listenertype != LIS_DVBAPI &&
			is_network_reader(rdr))
	{
		rdr_log_dbg(rdr, D_TRACE, "User (%s) has the same ip (%s) as the reader, blocked because block_same_ip=1!",
					   username(cur_cl), cs_inet_ntoa(rdr->client->ip));
		return 0;
	}

	if(cfg.block_same_name && strcmp(username(cur_cl), rdr->label) == 0)
	{
		rdr_log_dbg(rdr, D_TRACE, "User (%s) has the same name as the reader, blocked because block_same_name=1!",
					   username(cur_cl));
		return 0;
	}

	if(!reader_slots_available(rdr, er)&& er->ecmlen > 0)  // check free slots, er->ecmlen>0 trick to skip this test for matching readers in dvbapi module
	{
		return 0;
	}

	//All checks done, reader is matching!
	return (1);
}

int32_t chk_caid(uint16_t caid, CAIDTAB *ctab)
{
	int32_t i;
	if (!ctab->ctnum) return caid;
	for(i = 0; i < ctab->ctnum; i++)
	{
		CAIDTAB_DATA *d = &ctab->ctdata[i];
		if((caid & d->mask) == d->caid)
			return d->cmap ? d->cmap : caid;
	}
	return -1;
}

int32_t chk_caid_rdr(struct s_reader *rdr, uint16_t caid)
{
	if(is_network_reader(rdr))
	{
		return 1; //reader caid is not real caid
	}
	else if(rdr->caid == caid)
	{
		return 1;
	}
	return 0;
}

int32_t chk_bcaid(ECM_REQUEST *er, CAIDTAB *ctab)
{
	int32_t caid;
	caid = chk_caid(er->caid, ctab);
	if(caid < 0)
		{ return 0; }
	er->caid = caid;
	return 1;
}

/**
 * Check for NULL CWs
 **/
int32_t chk_is_null_CW(uchar cw[])
{
	int8_t i;
	for(i = 0; i < 16; i++)
	{
		if(cw[i])
			{ return 0; }
	}
	return 1;
}



/**
 * Check for ecm request that expects half cw format
 **/
int8_t is_halfCW_er(ECM_REQUEST *er)
{
	if(caid_is_videoguard(er->caid) &&
	 (er->caid == 0x09C4 || er->caid ==  0x098C || er->caid == 0x0963 || er->caid == 0x09CD || er->caid == 0x0919 || er->caid == 0x093B || er->caid == 0x098E)
	)
		return 1;

  return 0;
}


/**
 * Check for wrong half CWs
 **/
int8_t chk_halfCW(ECM_REQUEST *er, uchar *cw)
{
  if(is_halfCW_er(er) && cw){

	 int8_t part1 = checkCWpart(cw, 0);
	 int8_t part2 = checkCWpart(cw, 1);

	 //check for correct half cw format
	 if(part1 && part2){
		 return 0;
	 }

	 //check for correct cw position
	 if(
	    (get_odd_even(er) == 0x80 && part1 && !part2)   //xxxxxxxx00000000
		||
		(get_odd_even(er) == 0x81 && !part1 && part2)   //00000000xxxxxxxx
	 )
	 {
		return 1;
	 }

	 return 0;  //not correct swapped cw

  }else
	return 1;
}


/**
 * Check for NULL nodeid
 **/
int32_t chk_is_null_nodeid(uint8_t node_id[], uint8_t len)
{
	int8_t i;
	for(i = 0; i < len; i++)
	{
		if(node_id[i])
			{ return 0; }
	}
	return 1;
}

//check if client structure is accessible
bool check_client(struct s_client *cl)
{
	if(cl && !cl->kill)
		{ return true; }
	return false;
}

uint16_t caidvaluetab_get_value(CAIDVALUETAB *cv, uint16_t caid, uint16_t default_value)
{
	int32_t i;
	for(i = 0; i < cv->cvnum; i++)
	{
		CAIDVALUETAB_DATA *cvdata = &cv->cvdata[i];
		if(cvdata->caid == caid || cvdata->caid == caid >> 8)
			return cvdata->value;
	}
	return default_value;
}

int32_t chk_is_fakecw(uint8_t *cw)
{
	uint32_t i, is_fakecw = 0;
	uint32_t idx = ((cw[0]&0xF)<<4) | (cw[8]&0xF); 
	
	cs_readlock(__func__, &config_lock);
	for(i=0; i<cfg.fakecws[idx].count; i++)
	{
		if(memcmp(cw, cfg.fakecws[idx].data[i].cw, 16) == 0)
		{
			is_fakecw = 1;
			break;
		}	
	}
	cs_readunlock(__func__, &config_lock);
	
	return is_fakecw;
	 if((er->client) && (strncmp(rdr->ph.desc,"cccam",5)==0)) {

    int canUse0Maxdown=((strncmp(ph[er->client->ctyp].desc,"dvbapi",6)!=0)
    (er->client->account->cccignorereshare));

    struct s_client *cl=rdr->client;
    struct cc_data *cc = cl->cc;
    LL_ITER *it;
    it = ll_iter_create(cc->cards);
    struct cc_card *ncard;
    int found=0;
    while ((ncard = ll_iter_next(it))) {

        if(ncard->caid == er->caid) {

            if(canUse0Maxdown) {

                found=1;
                break;

            }
            else if(ncard->maxdown>0) {

                found=1;
                break;

            }

        }

    }
    ll_iter_release(it);
    if(!found)

        return 0;
	
}
