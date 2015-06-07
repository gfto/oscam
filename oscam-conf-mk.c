#define MODULE_LOG_PREFIX "config"

#include "globals.h"
#include "oscam-conf-mk.h"
#include "oscam-net.h"
#include "oscam-string.h"

/*
 * Creates a string ready to write as a token into config or WebIf for CAIDs. You must free the returned value through free_mk_t().
 */
char *mk_t_caidtab(CAIDTAB *caidtab)
{
	if (!caidtab || !caidtab->ctnum) return "";
	// Max entry length is strlen("1234&ffff:1234,") == 15
	int32_t i, maxlen = 16 * caidtab->ctnum, pos = 0;
	char *ret;
	if (!cs_malloc(&ret, maxlen))
		return "";
	const char *comma = "";
	for(i = 0; i < caidtab->ctnum; i++)
	{
		CAIDTAB_DATA *d = &caidtab->ctdata[i];
		if (d->caid < 0x0100)
			pos += snprintf(ret + pos, maxlen - pos, "%s%02X", comma, d->caid);
		else
			pos += snprintf(ret + pos, maxlen - pos, "%s%04X", comma, d->caid);
		if (d->mask && d->mask != 0xffff)
			pos += snprintf(ret + pos, maxlen - pos, "&%04X", d->mask);
		if (d->cmap)
			pos += snprintf(ret + pos, maxlen - pos, ":%04X", d->cmap);
		comma = ",";
	}
	return ret;
}

/*
 * Creates a string ready to write as a token into config or WebIf for TunTabs. You must free the returned value through free_mk_t().
 */
char *mk_t_tuntab(TUNTAB *ttab)
{
	if (!ttab || !ttab->ttnum) return "";
	// Each entry max length is strlen("aaaa.bbbb:cccc,") == 15
	int32_t i, maxlen = 16 * ttab->ttnum, pos = 0;
	char *ret;
	if (!cs_malloc(&ret, maxlen))
		return "";
	const char *comma = "";
	for(i = 0; i < ttab->ttnum; i++)
	{
		TUNTAB_DATA *d = &ttab->ttdata[i];
		pos += snprintf(ret + pos, maxlen - pos, "%s%04X", comma, d->bt_caidfrom);
		pos += snprintf(ret + pos, maxlen - pos, ".%04X", d->bt_srvid);
		if (d->bt_caidto)
			pos += snprintf(ret + pos, maxlen - pos, ":%04X", d->bt_caidto);
		comma = ",";
	}
	return ret;
}

/*
 * Creates a string ready to write as a token into config or WebIf for groups. You must free the returned value through free_mk_t().
 */
char *mk_t_group(uint64_t grp)
{
	int32_t i = 0, needed = 1, pos = 0, dot = 0;

	for(i = 0; i < 64; i++)
	{
		if(grp & ((uint64_t)1 << i))
		{
			needed += 2;
			if(i > 9) { needed += 1; }
		}
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed)) { return ""; }
	char *saveptr = value;
	for(i = 0; i < 64; i++)
	{
		if(grp & ((uint64_t)1 << i))
		{
			if(dot == 0)
			{
				snprintf(value + pos, needed - (value - saveptr), "%d", i + 1);
				if(i > 8) { pos += 2; }
				else { pos += 1; }
				dot = 1;
			}
			else
			{
				snprintf(value + pos, needed - (value - saveptr), ",%d", i + 1);
				if(i > 8) { pos += 3; }
				else { pos += 2; }
			}
		}
	}
	value[pos] = '\0';
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for FTabs (CHID, Ident). You must free the returned value through free_mk_t().
 */
char *mk_t_ftab(FTAB *ftab)
{
	if (!ftab || !ftab->nfilts) return "";
	// Worst case scenario where each entry have different
	// caid, ident and only one length in it is strlen("1234:123456,") == 12
	int32_t i, j, maxlen = 13 * ftab->nfilts, pos = 0;
	for(i = 0; i < ftab->nfilts; i++)
		maxlen += ftab->filts[i].nprids * 7; /* strlen("123456,") == 7 */
	char *ret;
	if (!cs_malloc(&ret, maxlen))
		return "";
	const char *semicolon = "", *comma = "";
	for(i = 0; i < ftab->nfilts; i++)
	{
		FILTER *cur = &ftab->filts[i];
		pos += snprintf(ret + pos, maxlen - pos, "%s%04X:", semicolon, cur->caid);
		semicolon = ";";
		comma = "";
		for (j = 0; j < cur->nprids; j++)
		{
			pos += snprintf(ret + pos, maxlen - pos, "%s%06X", comma, cur->prids[j]);
			comma = ",";
		}
	}
	return ret;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the camd35 tcp ports. You must free the returned value through free_mk_t().
 */
char *mk_t_camd35tcp_port(void)
{
#if defined(MODULE_CAMD35) || defined(MODULE_CAMD35_TCP)
	int32_t i, j, pos = 0, needed = 1;

	/* Precheck to determine how long the resulting string will maximally be (might be a little bit smaller but that shouldn't hurt) */
	for(i = 0; i < cfg.c35_tcp_ptab.nports; ++i)
	{
		/* Port is maximally 5 chars long, plus the @caid, plus the ";" between ports */
		needed += 11;
		if(cfg.c35_tcp_ptab.ports[i].ncd && cfg.c35_tcp_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids > 1)
		{
			needed += cfg.c35_tcp_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids * 7;
		}
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed)) { return ""; }
	char *saveptr = value;
	char *dot1 = "", *dot2;
	for(i = 0; i < cfg.c35_tcp_ptab.nports; ++i)
	{

		if(cfg.c35_tcp_ptab.ports[i].ncd && cfg.c35_tcp_ptab.ports[i].ncd->ncd_ftab.filts[0].caid)
		{
			pos += snprintf(value + pos, needed - (value - saveptr), "%s%d@%04X", dot1,
							cfg.c35_tcp_ptab.ports[i].s_port,
							cfg.c35_tcp_ptab.ports[i].ncd->ncd_ftab.filts[0].caid);

			if(cfg.c35_tcp_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids > 1)
			{
				dot2 = ":";
				for(j = 0; j < cfg.c35_tcp_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids; ++j)
				{
					pos += snprintf(value + pos, needed - (value - saveptr), "%s%X", dot2, cfg.c35_tcp_ptab.ports[i].ncd->ncd_ftab.filts[0].prids[j]);
					dot2 = ",";
				}
			}
			dot1 = ";";
		}
		else
		{
			pos += snprintf(value + pos, needed - (value - saveptr), "%d", cfg.c35_tcp_ptab.ports[i].s_port);
		}
	}
	return value;
#else
	return NULL;
#endif
}

#ifdef MODULE_CCCAM
/*
 * Creates a string ready to write as a token into config or WebIf for the cccam tcp ports. You must free the returned value through free_mk_t().
 */
char *mk_t_cccam_port(void)
{
	int32_t i, pos = 0, needed = CS_MAXPORTS * 6 + 8;

	char *value;
	if(!cs_malloc(&value, needed)) { return ""; }
	char *dot = "";
	for(i = 0; i < CS_MAXPORTS; i++)
	{
		if(!cfg.cc_port[i]) { break; }

		pos += snprintf(value + pos, needed - pos, "%s%d", dot, cfg.cc_port[i]);
		dot = ",";
	}
	return value;
}
#endif

#ifdef MODULE_GBOX
/*
 * Creates a string ready to write as a token into config or WebIf for the gbox udp ports. You must free the returned value through free_mk_t().
 */
char *mk_t_gbox_port(void)
{
	int32_t i, pos = 0, needed = CS_MAXPORTS * 6 + 8;

	char *value;
	if(!cs_malloc(&value, needed)) { return ""; }
	char *dot = "";
	for(i = 0; i < CS_MAXPORTS; i++)
	{
		if(!cfg.gbx_port[i]) { break; }

		pos += snprintf(value + pos, needed - pos, "%s%d", dot, cfg.gbx_port[i]);
		dot = ",";
	}
	return value;
}
#endif

/*
 * Creates a string ready to write as a token into config or WebIf for AESKeys. You must free the returned value through free_mk_t().
 */
char *mk_t_aeskeys(struct s_reader *rdr)
{
	AES_ENTRY *current = rdr->aes_list;
	int32_t i, pos = 0, needed = 1, prevKeyid = 0, prevCaid = 0;
	uint32_t prevIdent = 0;

	/* Precheck for the approximate size that we will need; it's a bit overestimated but we correct that at the end of the function */
	while(current)
	{
		/* The caid, ident, "@" and the trailing ";" need to be output when they are changing */
		if(prevCaid != current->caid || prevIdent != current->ident) { needed += 12 + (current->keyid * 2); }
		/* "0" keys are not saved so we need to check for gaps */
		else if(prevKeyid != current->keyid + 1) { needed += (current->keyid - prevKeyid - 1) * 2; }
		/* The 32 byte key plus either the (heading) ":" or "," */
		needed += 33;
		prevCaid = current->caid;
		prevIdent = current->ident;
		prevKeyid = current->keyid;
		current = current->next;
	}

	/* Set everything back and now create the string */
	current = rdr->aes_list;
	prevCaid = 0;
	prevIdent = 0;
	prevKeyid = 0;
	char tmp[needed];
	char dot;
	if(needed == 1) { tmp[0] = '\0'; }
	char tmpkey[33];
	while(current)
	{
		/* A change in the ident or caid means that we need to output caid and ident */
		if(prevCaid != current->caid || prevIdent != current->ident)
		{
			if(pos > 0)
			{
				tmp[pos] = ';';
				++pos;
			}
			pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%04X@%06X", current->caid, current->ident);
			prevKeyid = -1;
			dot = ':';
		}
		else { dot = ','; }
		/* "0" keys are not saved so we need to check for gaps and output them! */
		for(i = prevKeyid + 1; i < current->keyid; ++i)
		{
			pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%c0", dot);
			dot = ',';
		}
		tmp[pos] = dot;
		++pos;
		for(i = 0; i < 16; ++i) { snprintf(tmpkey + (i * 2), sizeof(tmpkey) - (i * 2), "%02X", current->plainkey[i]); }
		/* A key consisting of only FFs has a special meaning (just return what the card outputted) and can be specified more compact */
		if(strcmp(tmpkey, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0) { pos += snprintf(tmp + pos, sizeof(tmp) - pos, "FF"); }
		else { pos += snprintf(tmp + pos, sizeof(tmp) - pos, "%s", tmpkey); }
		prevCaid = current->caid;
		prevIdent = current->ident;
		prevKeyid = current->keyid;
		current = current->next;
	}

	/* copy to result array of correct size */
	char *value;
	if(pos == 0 || !cs_malloc(&value, pos + 1)) { return ""; }
	memcpy(value, tmp, pos + 1);
	return (value);
}

/*
 * Creates a string ready to write as a token into config or WebIf for the Newcamd Port. You must free the returned value through free_mk_t().
 */
char *mk_t_newcamd_port(void)
{
#ifdef MODULE_NEWCAMD
	int32_t i, j, k, pos = 0, needed = 1;

	/* Precheck to determine how long the resulting string will maximally be (might be a little bit smaller but that shouldn't hurt) */
	for(i = 0; i < cfg.ncd_ptab.nports; ++i)
	{
		/* Port is maximally 5 chars long, plus the @caid, plus the ";" between ports */
		needed += 11;
		if(cfg.ncd_ptab.ports[i].ncd)
		{
			if(cfg.ncd_ptab.ports[i].ncd->ncd_key_is_set) { needed += 30; }
			if(cfg.ncd_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids > 0)
			{
				needed += cfg.ncd_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids * 7;
			}
		}
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed)) { return ""; }
	char *dot1 = "", *dot2;

	for(i = 0; i < cfg.ncd_ptab.nports; ++i)
	{
		pos += snprintf(value + pos, needed - pos,  "%s%d", dot1, cfg.ncd_ptab.ports[i].s_port);

		// separate DES Key for this port
		if(cfg.ncd_ptab.ports[i].ncd)
		{
			if(cfg.ncd_ptab.ports[i].ncd->ncd_key_is_set)
			{
				pos += snprintf(value + pos, needed - pos, "{");
				for(k = 0; k < (int32_t)sizeof(cfg.ncd_ptab.ports[i].ncd->ncd_key); k++)
					{ pos += snprintf(value + pos, needed - pos, "%02X", cfg.ncd_ptab.ports[i].ncd->ncd_key[k]); }
				pos += snprintf(value + pos, needed - pos, "}");
			}

			pos += snprintf(value + pos, needed - pos, "@%04X", cfg.ncd_ptab.ports[i].ncd->ncd_ftab.filts[0].caid);

			if(cfg.ncd_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids > 0)
			{
				dot2 = ":";
				for(j = 0; j < cfg.ncd_ptab.ports[i].ncd->ncd_ftab.filts[0].nprids; ++j)
				{
					pos += snprintf(value + pos, needed - pos, "%s%06X", dot2, (int)cfg.ncd_ptab.ports[i].ncd->ncd_ftab.filts[0].prids[j]);
					dot2 = ",";
				}
			}
		}
		dot1 = ";";
	}
	return value;
#else
	return NULL;
#endif
}

/*
 * Creates a string ready to write as a token into config or WebIf for au readers. You must free the returned value through free_mk_t().
 */
char *mk_t_aureader(struct s_auth *account)
{
	int32_t pos = 0;
	char *dot = "";

	char *value;
	if(ll_count(account->aureader_list) == 0 || !cs_malloc(&value, 256)) { return ""; }
	value[0] = '\0';

	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(account->aureader_list);
	while((rdr = ll_iter_next(&itr)))
	{
		pos += snprintf(value + pos, 256 - pos, "%s%s", dot, rdr->label);
		dot = ",";
	}

	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for blocknano and savenano. You must free the returned value through free_mk_t().
 */
char *mk_t_nano(uint16_t nano)
{
	int32_t i, pos = 0, needed = 0;

	for(i = 0; i < 16; i++)
		if((1 << i) & nano)
			{ needed++; }

	char *value;
	if(nano == 0xFFFF)
	{
		if(!cs_malloc(&value, 4)) { return ""; }
		snprintf(value, 4, "all");
	}
	else
	{
		if(needed == 0 || !cs_malloc(&value, needed * 3 + 1)) { return ""; }
		value[0] = '\0';
		for(i = 0; i < 16; i++)
		{
			if((1 << i) & nano)
				{ pos += snprintf(value + pos, (needed * 3) + 1 - pos, "%s%02x", pos ? "," : "", (i + 0x80)); }
		}
	}
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the sidtab. You must free the returned value through free_mk_t().
 */
char *mk_t_service(SIDTABS *sidtabs)
{
	int32_t i, pos;
	char *dot;
	char *value;
	struct s_sidtab *sidtab = cfg.sidtab;
	if(!sidtab || (!sidtabs->ok && !sidtabs->no) || !cs_malloc(&value, 1024)) { return ""; }
	value[0] = '\0';

	for(i = pos = 0, dot = ""; sidtab; sidtab = sidtab->next, i++)
	{
		if(sidtabs->ok & ((SIDTABBITS)1 << i))
		{
			pos += snprintf(value + pos, 1024 - pos, "%s%s", dot, sidtab->label);
			dot = ",";
		}
		if(sidtabs->no & ((SIDTABBITS)1 << i))
		{
			pos += snprintf(value + pos, 1024 - pos, "%s!%s", dot, sidtab->label);
			dot = ",";
		}
	}
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the logfile parameter. You must free the returned value through free_mk_t().
 */
char *mk_t_logfile(void)
{
	int32_t pos = 0, needed = 1;
	char *value, *dot = "";

	if(cfg.logtostdout == 1) { needed += 7; }
	if(cfg.logtosyslog == 1) { needed += 7; }
	if(cfg.logfile) { needed += strlen(cfg.logfile); }
	if(needed == 1 || !cs_malloc(&value, needed)) { return ""; }

	if(cfg.logtostdout == 1)
	{
		pos += snprintf(value + pos, needed - pos, "stdout");
		dot = ";";
	}
	if(cfg.logtosyslog == 1)
	{
		pos += snprintf(value + pos, needed - pos, "%ssyslog", dot);
		dot = ";";
	}
	if(cfg.logfile)
	{
		pos += snprintf(value + pos, needed - pos, "%s%s", dot, cfg.logfile);
	}
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the ecm whitelist. You must free the returned value through free_mk_t().
 */
char *mk_t_ecm_whitelist(struct s_ecm_whitelist *ecm_whitelist)
{
	if (!ecm_whitelist || !ecm_whitelist->ewnum) return "";
	// Worst case scenario where each entry have different
	// caid, ident and only one length in it is strlen("1234@123456:01;") == 15
	int32_t i, maxlen = 16 * ecm_whitelist->ewnum, pos = 0;
	char *ret;
	if (!cs_malloc(&ret, maxlen))
		return "";
	const char *semicolon = "", *comma = "";
	ECM_WHITELIST_DATA *last = NULL;
	for(i = 0; i < ecm_whitelist->ewnum; i++)
	{
		ECM_WHITELIST_DATA *cur = &ecm_whitelist->ewdata[i];
		bool change = !last || last->caid != cur->caid || last->ident != cur->ident;
		if (change)
		{
			if (cur->caid && cur->ident)
				pos += snprintf(ret + pos, maxlen - pos, "%s%04X@%06X:", semicolon, cur->caid, cur->ident);
			else if (cur->caid)
				pos += snprintf(ret + pos, maxlen - pos, "%s%04X:", semicolon, cur->caid);
			else if (cur->ident)
				pos += snprintf(ret + pos, maxlen - pos, "%s@%06X:", semicolon, cur->ident);
			else
				pos += snprintf(ret + pos, maxlen - pos, "%s", semicolon);
			semicolon = ";";
			comma = "";
		}
		pos += snprintf(ret + pos, maxlen - pos, "%s%02X", comma, cur->len);
		comma = ",";
		last = &ecm_whitelist->ewdata[i];
	}
	return ret;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the ECM Headerwhitelist. You must free the returned value through free_mk_t().
 */
char *mk_t_ecm_hdr_whitelist(struct s_ecm_hdr_whitelist *ecm_hdr_whitelist)
{
	if (!ecm_hdr_whitelist || !ecm_hdr_whitelist->ehnum) return "";
	// Worst case scenario where each entry have different
	// caid, provid and only one header in it is strlen("1234@123456:0102030405060708091011121314151617181920;") == 52 ((sizeof(header) / 2) + 12)
	int32_t i, r, maxlen = 53 * ecm_hdr_whitelist->ehnum, pos = 0;
	char *ret;
	if (!cs_malloc(&ret, maxlen))
		return "";
	const char *semicolon = "", *comma = "";
	ECM_HDR_WHITELIST_DATA *last = NULL;
	for(i = 0; i < ecm_hdr_whitelist->ehnum; i++)
	{
		ECM_HDR_WHITELIST_DATA *cur = &ecm_hdr_whitelist->ehdata[i];
		bool change = !last || last->caid != cur->caid || last->provid != cur->provid;
		if (change)
		{
			if (cur->caid && cur->provid)
				pos += snprintf(ret + pos, maxlen - pos, "%s%04X@%06X:", semicolon, cur->caid, cur->provid);
			else if (cur->caid)
				pos += snprintf(ret + pos, maxlen - pos, "%s%04X:", semicolon, cur->caid);
			else if (cur->provid)
				pos += snprintf(ret + pos, maxlen - pos, "%s@%06X:", semicolon, cur->provid);
			else
				pos += snprintf(ret + pos, maxlen - pos, "%s", semicolon);
			semicolon = ";";
			comma = "";
		}
		pos += snprintf(ret + pos, maxlen - pos, "%s", comma);
		for(r = 0; r < cur->len / 2; r++)
			pos += snprintf(ret + pos, maxlen - pos, "%02X", cur->header[r]);
		comma = ",";
		last = &ecm_hdr_whitelist->ehdata[i];
	}
	return ret;
}

/*
 * Creates a string ready to write as a token into config or WebIf for an iprange. You must free the returned value through free_mk_t().
 */
char *mk_t_iprange(struct s_ip *range)
{
	struct s_ip *cip;
	char *value, *dot = "";
	int32_t needed = 1, pos = 0;
	for(cip = range; cip; cip = cip->next) { needed += 32; }

	char tmp[needed];

	for(cip = range; cip; cip = cip->next)
	{
		pos += snprintf(tmp + pos, needed - pos, "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if(!IP_EQUAL(cip->ip[0], cip->ip[1]))  { pos += snprintf(tmp + pos, needed - pos, "-%s", cs_inet_ntoa(cip->ip[1])); }
		dot = ",";
	}
	if(pos == 0 || !cs_malloc(&value, pos + 1)) { return ""; }
	memcpy(value, tmp, pos + 1);
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the class attribute. You must free the returned value through free_mk_t().
 */
char *mk_t_cltab(CLASSTAB *clstab)
{
	char *value, *dot = "";
	int32_t i, needed = 1, pos = 0;
	for(i = 0; i < clstab->an; ++i) { needed += 3; }
	for(i = 0; i < clstab->bn; ++i) { needed += 4; }

	char tmp[needed];

	for(i = 0; i < clstab->an; ++i)
	{
		pos += snprintf(tmp + pos, needed - pos, "%s%02x", dot, (int32_t)clstab->aclass[i]);
		dot = ",";
	}
	for(i = 0; i < clstab->bn; ++i)
	{
		pos += snprintf(tmp + pos, needed - pos, "%s!%02x", dot, (int32_t)clstab->bclass[i]);
		dot = ",";
	}

	if(pos == 0 || !cs_malloc(&value, pos + 1)) { return ""; }
	memcpy(value, tmp, pos + 1);
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf. You must free the returned value through free_mk_t().
 */
char *mk_t_caidvaluetab(CAIDVALUETAB *caidvaluetab)
{
	if (!caidvaluetab || !caidvaluetab->cvnum) return "";
	// Max entry length is strlen("1234@65535,") == 11
	int32_t i, maxlen = 12 * caidvaluetab->cvnum, pos = 0;
	char *ret;
	if (!cs_malloc(&ret, maxlen))
		return "";
	const char *comma = "";
	for(i = 0; i < caidvaluetab->cvnum; i++)
	{
		CAIDVALUETAB_DATA *d = &caidvaluetab->cvdata[i];
		if (d->caid < 0x0100)
			pos += snprintf(ret + pos, maxlen - pos, "%s%02X:%d", comma, d->caid, d->value);
		else
			pos += snprintf(ret + pos, maxlen - pos, "%s%04X:%d", comma, d->caid, d->value);
		comma = ",";
	}
	return ret;
}

char *mk_t_cacheex_valuetab(CECSPVALUETAB *tab)
{
	if(!tab->n) { return ""; }
	int32_t i, size = 2 + tab->n * (4 + 1 + 4 + 1 + 6 + 1 + 4 + 1 + 5 + 1 + 5 + 1); //caid&mask@provid$servid:awtime:dwtime","
	char *buf;
	if(!cs_malloc(&buf, size))
		{ return ""; }
	char *ptr = buf;

	for(i = 0; i < tab->n && tab->n <= CS_MAXCAIDTAB ; i++)
	{
		if(i) { ptr += snprintf(ptr, size - (ptr - buf), ","); }
		if(tab->caid[i] >= 0)
		{
			if(tab->caid[i] == 0)
			{
				if(tab->awtime[i] > 0)
					{ ptr += snprintf(ptr, size - (ptr - buf), "%d", tab->caid[i]); }
			}
			else if(tab->caid[i] < 256)   //Do not format 0D as 000D, its a shortcut for 0Dxx:
				{ ptr += snprintf(ptr, size - (ptr - buf), "%02X", tab->caid[i]); }
			else
				{ ptr += snprintf(ptr, size - (ptr - buf), "%04X", tab->caid[i]); }
		}
		if(tab->cmask[i] >= 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), "&%04X", tab->cmask[i]); }
		if(tab->prid[i] >= 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), "@%06X", tab->prid[i]); }
		if(tab->srvid[i] >= 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), "$%04X", tab->srvid[i]); }
		if(tab->awtime[i] > 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), ":%d", tab->awtime[i]); }
		if(!tab->dwtime[i] > 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), ":0"); }
		if(tab->dwtime[i] > 0)
		{
			if((tab->caid[i] <= 0) && (tab->prid[i] == -1) && (tab->srvid[i] == -1) && (tab->srvid[i] == -1) && (tab->awtime[i] <= 0))
				{ ptr += snprintf(ptr, size - (ptr - buf), "%d", tab->dwtime[i]); }
			else
				{ ptr += snprintf(ptr, size - (ptr - buf), ":%d", tab->dwtime[i]); }
		}
	}
	*ptr = 0;
	return buf;
}


char *mk_t_cacheex_cwcheck_valuetab(CWCHECKTAB *tab)
{
	if(!tab->n) { return ""; }
	int32_t i, size = 2 + tab->n * (4 + 1 + 4 + 1 + 6 + 1 + 4 + 1 + 5 + 1 + 5 + 1); //caid[&mask][@provid][$servid]:mode:counter","
	char *buf;
	if(!cs_malloc(&buf, size))
		{ return ""; }
	char *ptr = buf;

	for(i = 0; i < tab->n && i <= CS_MAXCAIDTAB; i++)
	{
		if(i) { ptr += snprintf(ptr, size - (ptr - buf), ","); }
		if(tab->caid[i] >= 0)
		{
			if(tab->caid[i] == 0)
				{ ptr += snprintf(ptr, size - (ptr - buf), "%d", tab->caid[i]); }
			else if(tab->caid[i] < 256)   //Do not format 0D as 000D, its a shortcut for 0Dxx:
				{ ptr += snprintf(ptr, size - (ptr - buf), "%02X", tab->caid[i]); }
			else
				{ ptr += snprintf(ptr, size - (ptr - buf), "%04X", tab->caid[i]); }
		}
		if(tab->cmask[i] >= 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), "&%04X", tab->cmask[i]); }
		if(tab->prid[i] >= 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), "@%06X", tab->prid[i]); }
		if(tab->srvid[i] >= 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), "$%04X", tab->srvid[i]); }
		if(tab->mode[i] >= 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), ":%d", tab->mode[i]); }
		if(tab->counter[i] > 0)
			{ ptr += snprintf(ptr, size - (ptr - buf), ":%d", tab->counter[i]); }
	}
	*ptr = 0;
	return buf;
}

char *mk_t_cacheex_hitvaluetab(CECSPVALUETAB *tab)
{
	if(!tab->n) { return ""; }
	int32_t i, size = 2 + tab->n * (4 + 1 + 4 + 1 + 6 + 1 + 4 + 1); //caid&mask@provid$servid","
	char *buf;
	if(!cs_malloc(&buf, size))
		{ return ""; }
	char *ptr = buf;

	for(i = 0; i < tab->n; i++)
	{
		if(i) { ptr += snprintf(ptr, size - (ptr - buf), ","); }
		if(tab->caid[i] > 0)
		{
			if(tab->caid[i] < 256)  //Do not format 0D as 000D, its a shortcut for 0Dxx:
				{ ptr += snprintf(ptr, size - (ptr - buf), "%02X", tab->caid[i]); }
			else
				{ ptr += snprintf(ptr, size - (ptr - buf), "%04X", tab->caid[i]); }
			if(tab->cmask[i] >= 0)
				{ ptr += snprintf(ptr, size - (ptr - buf), "&%04X", tab->cmask[i]); }
			if(tab->prid[i] >= 0)
				{ ptr += snprintf(ptr, size - (ptr - buf), "@%06X", tab->prid[i]); }
			if(tab->srvid[i] >= 0)
				{ ptr += snprintf(ptr, size - (ptr - buf), "$%04X", tab->srvid[i]); }
		}
	}
	*ptr = 0;
	return buf;
}

/*
 * returns string of comma separated values
 */
char *mk_t_emmbylen(struct s_reader *rdr)
{
	char *value, *pos, *dot = "";
	int32_t num, needed = 0;
	struct s_emmlen_range *blocklen;

	if(!rdr->blockemmbylen)
		{ return ""; }

	LL_ITER it = ll_iter_create(rdr->blockemmbylen);
	while((blocklen = ll_iter_next(&it)))
	{
		needed += 5 + 1; // max digits of int16 + ","
		if(blocklen->max == 0)
			{ needed += 1 + 1; } // "-" + ","
		else if(blocklen->min != blocklen->max)
			{ needed += 1 + 5 + 1; } // "-" + max digits of int16 + ","
	}
	// the trailing zero is already included: it's the first ","
	if(!cs_malloc(&value, needed))
		{ return ""; }

	pos = value;
	ll_iter_reset(&it);
	while((blocklen = ll_iter_next(&it)))
	{
		if(blocklen->min == blocklen->max)
			{ num = snprintf(pos, needed, "%s%d", dot, blocklen->min); }
		else if(blocklen->max == 0)
			{ num = snprintf(pos, needed, "%s%d-", dot, blocklen->min); }
		else
			{ num = snprintf(pos, needed, "%s%d-%d", dot, blocklen->min, blocklen->max); }
		pos += num;
		needed -= num;
		dot = ",";
	}
	return value;
}

/*
 * makes string from binary structure
 */
char *mk_t_allowedprotocols(struct s_auth *account)
{

	if(!account->allowedprotocols)
		{ return ""; }

	int16_t i, tmp = 1, pos = 0, needed = 255, tagcnt;
	char *tag[] = {"camd33", "cs357x", "cs378x", "newcamd", "cccam", "gbox", "radegast", "dvbapi", "constcw", "serial"};
	char *value, *dot = "";

	if(!cs_malloc(&value, needed))
		{ return ""; }

	tagcnt = sizeof(tag) / sizeof(char *);
	for(i = 0; i < tagcnt; i++)
	{
		if((account->allowedprotocols & tmp) == tmp)
		{
			pos += snprintf(value + pos, needed, "%s%s", dot, tag[i]);
			dot = ",";
		}
		tmp = tmp << 1;
	}
	return value;
}

/*
 * mk_t-functions give back a constant empty string when allocation fails or when the result is an empty string.
 * This function thus checks the stringlength and only frees if necessary.
 */
void free_mk_t(char *value)
{
	if(strlen(value) > 0) { NULLFREE(value); }
}
