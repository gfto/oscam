#define MODULE_LOG_PREFIX "config"

#include "globals.h"
#include "oscam-array.h"
#include "oscam-conf-chk.h"
#include "oscam-garbage.h"
#include "oscam-net.h"
#include "oscam-string.h"

void chk_iprange(char *value, struct s_ip **base)
{
	int32_t i = 0;
	char *ptr1, *ptr2, *saveptr1 = NULL;
	struct s_ip *fip, *lip, *cip;

	if(!cs_malloc(&cip, sizeof(struct s_ip)))
		{ return; }
	fip = cip;

	for(ptr1 = strtok_r(value, ",", &saveptr1); ptr1; ptr1 = strtok_r(NULL, ",", &saveptr1))
	{
		if(i == 0)
			{ ++i; }
		else
		{
			if(!cs_malloc(&cip, sizeof(struct s_ip)))
				{ break; }
			lip->next = cip;
		}

		if((ptr2 = strchr(trim(ptr1), '-')))
		{
			*ptr2++ = '\0';
			cs_inet_addr(trim(ptr1), &cip->ip[0]);
			cs_inet_addr(trim(ptr2), &cip->ip[1]);
		}
		else
		{
			cs_inet_addr(ptr1, &cip->ip[0]);
			IP_ASSIGN(cip->ip[1], cip->ip[0]);
		}
		lip = cip;
	}
	lip = *base;
	*base = fip;
	clear_sip(&lip);
}

void chk_caidtab(char *value, CAIDTAB *caidtab)
{
	caidtab_clear(caidtab);
	char *ptr, *saveptr1 = NULL;
	for(ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1))
	{
		CAIDTAB_DATA d;
		memset(&d, 0, sizeof(d));
		d.mask = 0xffff;
		char *caid_end_ptr = strchr(ptr, ':'); // caid_end_ptr + 1 -> cmap
		if(caid_end_ptr) {
			*caid_end_ptr++ = '\0';
			d.cmap = a2i(caid_end_ptr, 2);
			if (errno == EINVAL) continue;
		}
		char *mask_start_ptr = strchr(ptr, '&'); // mask_start_ptr + 1 -> mask
		errno = 0;
		if(mask_start_ptr) { // Mask is optional
			*mask_start_ptr++ = '\0';
			d.mask = a2i(mask_start_ptr, 2);
			if (errno == EINVAL) continue;
		}
		d.caid = a2i(ptr, 2);
		if (errno == EINVAL) continue;
		if (d.caid || d.cmap)
			caidtab_add(caidtab, &d);
	}
}

void chk_caidvaluetab(char *value, CAIDVALUETAB *caidvaluetab)
{
	caidvaluetab_clear(caidvaluetab);
	char *ptr, *saveptr1 = NULL;
	for(ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1))
	{
		CAIDVALUETAB_DATA d;
		memset(&d, 0, sizeof(d));
		char *caid_end_ptr = strchr(ptr, ':'); // caid_end_ptr + 1 -> value
		if(!caid_end_ptr)
			continue;
		*caid_end_ptr++ = '\0';
		errno = 0;
		d.caid = a2i(ptr, 2);
		if (errno == EINVAL)
			continue;
		d.value = atoi(caid_end_ptr);
		if (d.caid && d.value < 10000)
			caidvaluetab_add(caidvaluetab, &d);
	}
}

void chk_cacheex_valuetab(char *lbrlt, CECSPVALUETAB *tab)
{
	//[caid][&mask][@provid][$servid][:awtime][:]dwtime
	char *ptr = NULL, *saveptr1 = NULL;
	cecspvaluetab_clear(tab);

	int32_t i;
	for(i = 0, ptr = strtok_r(lbrlt, ",", &saveptr1); (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
	{
		CECSPVALUETAB_DATA d;
		memset(&d, 0, sizeof(d));

		int32_t caid = -1, cmask = -1, srvid = -1;
		int32_t j, provid = -1;
		int16_t awtime = -1, dwtime = -1;
		char *ptr1 = NULL, *ptr2 = NULL, *ptr3 = NULL, *ptr4 = NULL, *ptr5 = NULL, *saveptr2 = NULL;

		if((ptr4 = strchr(trim(ptr), ':')))
		{
			//awtime & dwtime
			*ptr4++ = '\0';
			for(j = 0, ptr5 = strtok_r(ptr4, ":", &saveptr2); (j < 2) && ptr5; ptr5 = strtok_r(NULL, ":", &saveptr2), j++)
			{
				if(!j)
				{
					dwtime = atoi(ptr5);
				}
				if(j)
				{
					awtime = dwtime;
					dwtime = atoi(ptr5);
				}
			}
		}
		if((ptr3 = strchr(trim(ptr), '$')))
		{
			*ptr3++ = '\0';
			srvid = a2i(ptr3, 4);
		}
		if((ptr2 = strchr(trim(ptr), '@')))
		{
			*ptr2++ = '\0';
			provid = a2i(ptr2, 6);
		}
		if((ptr1 = strchr(ptr, '&')))
		{
			*ptr1++ = '\0';
			cmask = a2i(ptr1, -2);
		}
		if(!ptr1 && !ptr2 && !ptr3 && !ptr4)  //only dwtime
			{ dwtime = atoi(ptr); }
		else
			{ caid = a2i(ptr, 2); }
		if((i == 0 && (caid <= 0)) || (caid > 0))
		{
			d.caid = caid;
			d.cmask = cmask;
			d.prid = provid;
			d.srvid = srvid;
			d.awtime = awtime;
			d.dwtime = dwtime;
			cecspvaluetab_add(tab, &d);
		}
	}
}


void chk_cacheex_cwcheck_valuetab(char *lbrlt, CWCHECKTAB *tab)
{
	//caid[&mask][@provid][$servid]:mode:counter
	int32_t i;
	char *ptr = NULL, *saveptr1 = NULL;
	cwcheckvaluetab_clear(tab);

	for(i = 0, ptr = strtok_r(lbrlt, ",", &saveptr1); (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
	{
		CWCHECKTAB_DATA d;
		memset(&d, 0, sizeof(d));

		int32_t caid = -1, cmask = -1, provid = -1, srvid = -1;
		int16_t mode = -1, counter = -1;

		char *ptr1 = NULL, *ptr2 = NULL, *ptr3 = NULL, *ptr4 = NULL, *ptr5 = NULL, *saveptr2 = NULL;

		if((ptr4 = strchr(trim(ptr), ':')))
		{
			*ptr4++ = '\0';
			ptr5 = strtok_r(ptr4, ":", &saveptr2);
			if(ptr5) mode = atoi(ptr5);
			ptr5 = strtok_r(NULL, ":", &saveptr2);
			if(ptr5) counter = atoi(ptr5);
		}
		if((ptr3 = strchr(trim(ptr), '$')))
		{
			*ptr3++ = '\0';
			srvid = a2i(ptr3, 4);
		}
		if((ptr2 = strchr(trim(ptr), '@')))
		{
			*ptr2++ = '\0';
			provid = a2i(ptr2, 6);
		}
		if((ptr1 = strchr(ptr, '&')))
		{
			*ptr1++ = '\0';
			cmask = a2i(ptr1, -2);
		}

		caid = a2i(ptr, 2);

		if((i == 0 && (caid <= 0)) || (caid > 0))
		{
			d.caid = caid;
			d.cmask = cmask;
			d.prid = provid;
			d.srvid = srvid;
			d.mode = mode;
			d.counter = counter;
			cwcheckvaluetab_add(tab, &d);
		}

	}
}


void chk_cacheex_hitvaluetab(char *lbrlt, CECSPVALUETAB *tab)
{
	//[caid][&mask][@provid][$servid]
	int32_t i;
	char *ptr = NULL, *saveptr1 = NULL;
	cecspvaluetab_clear(tab);

	for(i = 0, ptr = strtok_r(lbrlt, ",", &saveptr1); (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
	{
		CECSPVALUETAB_DATA d;
		memset(&d, 0, sizeof(d));

		int32_t caid = -1, cmask = -1, srvid = -1;
		int32_t provid = -1;
		char *ptr1 = NULL, *ptr2 = NULL, *ptr3 = NULL;

		if((ptr3 = strchr(trim(ptr), '$')))
		{
			*ptr3++ = '\0';
			srvid = a2i(ptr3, 4);
		}
		if((ptr2 = strchr(trim(ptr), '@')))
		{
			*ptr2++ = '\0';
			provid = a2i(ptr2, 6);
		}
		if((ptr1 = strchr(ptr, '&')))
		{
			*ptr1++ = '\0';
			cmask = a2i(ptr1, -2);
		}
		caid = a2i(ptr, 2);
		if(caid > 0)
		{
			d.caid = caid;
			d.cmask = cmask;
			d.prid = provid;
			d.srvid = srvid;
			cecspvaluetab_add(tab, &d);
		}
	}

}

void chk_tuntab(char *tunasc, TUNTAB *ttab)
{
	int32_t i;
	tuntab_clear(ttab);
	errno = 0;
	char *caid_ptr, *savecaid_ptr = NULL;
	for(i = 0, caid_ptr = strtok_r(tunasc, ",", &savecaid_ptr); (caid_ptr); caid_ptr = strtok_r(NULL, ",", &savecaid_ptr), i++)
	{
		TUNTAB_DATA d;
		char *srvid_ptr  = strchr(trim(caid_ptr), '.');
		char *caidto_ptr = strchr(trim(caid_ptr), ':');
		if (!srvid_ptr)
			continue;
		*srvid_ptr++ = '\0';
		if (caidto_ptr)
			*caidto_ptr++ = '\0';
		d.bt_caidfrom = a2i(caid_ptr, 2);
		d.bt_srvid    = a2i(srvid_ptr, 2);
		d.bt_caidto   = 0;
		if (caidto_ptr)
			d.bt_caidto = a2i(caidto_ptr, 2);
		if (errno == EINVAL)
			continue;
		if (d.bt_caidfrom | d.bt_srvid | d.bt_caidto)
			tuntab_add(ttab, &d);
	}
}

void chk_services(char *labels, SIDTABS *sidtabs)
{
	int32_t i;
	char *ptr, *saveptr1 = NULL;
	SIDTAB *sidtab;
	SIDTABBITS newsidok, newsidno;
	newsidok = newsidno = 0;
	for(ptr = strtok_r(labels, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1))
	{
		for(trim(ptr), i = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, i++)
		{
			if(!strcmp(sidtab->label, ptr)) { newsidok |= ((SIDTABBITS)1 << i); }
			if((ptr[0] == '!') && (!strcmp(sidtab->label, ptr + 1))) { newsidno |= ((SIDTABBITS)1 << i); }
		}
	}
	sidtabs->ok = newsidok;
	sidtabs->no = newsidno;
}

void chk_ftab(char *value, FTAB *ftab)
{
	ftab_clear(ftab);
	char *ptr1, *saveptr1 = NULL;
	errno = 0;
	for(ptr1 = strtok_r(value, ";", &saveptr1); (ptr1); ptr1 = strtok_r(NULL, ";", &saveptr1))
	{
		FILTER d;
		memset(&d, 0, sizeof(d));
		char *caid_end_ptr = strchr(ptr1, ':'); // caid_end_ptr + 1 -> headers
		if(!caid_end_ptr)
			continue;
		caid_end_ptr[0] = '\0';
		d.caid = a2i(ptr1, 4);
		if (!d.caid || errno == EINVAL)
		{
			errno = 0;
			continue;
		}
		ptr1 = caid_end_ptr + 1; // -> headers
		char *ident_ptr, *saveident_ptr = NULL;
		for(ident_ptr = strtok_r(ptr1, ",", &saveident_ptr); ident_ptr && d.nprids < ARRAY_SIZE(d.prids); ident_ptr = strtok_r(NULL, ",", &saveident_ptr))
		{
			uint32_t ident = a2i(ident_ptr, 4);
			if (errno == EINVAL)
			{
				errno = 0;
				continue;
			}
			d.prids[d.nprids++] = ident;
		}
		if (d.nprids)
			ftab_add(ftab, &d);
	}
}

void chk_cltab(char *classasc, CLASSTAB *clstab)
{
	int32_t max_an = 0, max_bn = 0;
	char *ptr1, *saveptr1 = NULL, *classasc_org;
	CLASSTAB newclstab, oldclstab;
	memset(&newclstab, 0, sizeof(newclstab));
	newclstab.an = newclstab.bn = 0;
	
	if(!cs_malloc(&classasc_org, sizeof(char)*strlen(classasc)+1))
		{ return; }
	
	cs_strncpy(classasc_org, classasc, sizeof(char)*strlen(classasc)+1);
	
	for(ptr1 = strtok_r(classasc, ",", &saveptr1); ptr1; ptr1 = strtok_r(NULL, ",", &saveptr1))
	{
		ptr1 = trim(ptr1);
		if(ptr1[0] == '!')
			{ max_bn++; }
		else
			{ max_an++; }
	}

	if(max_an && !cs_malloc(&newclstab.aclass, sizeof(uchar)*max_an))
		{ NULLFREE(classasc_org); return; }	

	if(max_bn && !cs_malloc(&newclstab.aclass, sizeof(uchar)*max_bn))
		{ NULLFREE(newclstab.aclass); NULLFREE(classasc_org); return; }	
	
	classasc = classasc_org;

	for(ptr1 = strtok_r(classasc, ",", &saveptr1); ptr1; ptr1 = strtok_r(NULL, ",", &saveptr1))
	{
		ptr1 = trim(ptr1);
		if(ptr1[0] == '!')
			{ newclstab.bclass[newclstab.bn++] = (uchar)a2i(ptr1 + 1, 2); }
		else
			{ newclstab.aclass[newclstab.an++] = (uchar)a2i(ptr1, 2); }
	}
	
	NULLFREE(classasc_org);
	
	memcpy(&oldclstab, clstab, sizeof(CLASSTAB));
	memcpy(clstab, &newclstab, sizeof(CLASSTAB));
	
	NULLFREE(oldclstab.aclass);
	NULLFREE(oldclstab.bclass);
}

void chk_port_tab(char *portasc, PTAB *ptab)
{
	int32_t i, j, nfilts, ifilt, iport;
	PTAB *newptab;
	char *ptr1, *ptr2, *ptr3, *saveptr1 = NULL;
	char *ptr[CS_MAXPORTS] = {0};
	int32_t port[CS_MAXPORTS] = {0};
	if(!cs_malloc(&newptab, sizeof(PTAB)))
		{ return; }

	for(nfilts = i = 0, ptr1 = strtok_r(portasc, ";", &saveptr1); (i < CS_MAXPORTS) && (ptr1); ptr1 = strtok_r(NULL, ";", &saveptr1), i++)
	{
		ptr[i] = ptr1;

		if(!newptab->ports[i].ncd && !cs_malloc(&newptab->ports[i].ncd, sizeof(struct ncd_port)))
			{ break; }

		if((ptr2 = strchr(trim(ptr1), '@')))
		{
			*ptr2++ = '\0';
			newptab->ports[i].s_port = atoi(ptr1);

			//checking for des key for port
			newptab->ports[i].ncd->ncd_key_is_set = false;
			if((ptr3 = strchr(trim(ptr1), '{')))
			{
				*ptr3++ = '\0';
				if(key_atob_l(ptr3, newptab->ports[i].ncd->ncd_key, sizeof(newptab->ports[i].ncd->ncd_key) * 2))
					{ fprintf(stderr, "newcamd: error in DES Key for port %s -> ignored\n", ptr1); }
				else
					{ newptab->ports[i].ncd->ncd_key_is_set = true; }
			}

			ptr[i] = ptr2;
			port[i] = newptab->ports[i].s_port;
			newptab->nports++;
		}
		nfilts++;
	}

	if(nfilts == 1 && strlen(portasc) < 6 && newptab->ports[0].s_port == 0)
	{
		newptab->ports[0].s_port = atoi(portasc);
		newptab->nports = 1;
	}

	iport = ifilt = 0;
	for(i = 0; i < nfilts; i++)
	{
		if(port[i] != 0)
			{ iport = i; }
		for(j = 0, ptr3 = strtok_r(ptr[i], ",", &saveptr1); (j < CS_MAXPROV) && (ptr3); ptr3 = strtok_r(NULL, ",", &saveptr1), j++)
		{
			if((ptr2 = strchr(trim(ptr3), ':')))
			{
				*ptr2++ = '\0';
				ifilt = newptab->ports[iport].ncd->ncd_ftab.nfilts++;
				j = 0;
				newptab->ports[iport].ncd->ncd_ftab.filts[ifilt].caid = (uint16_t)a2i(ptr3, 4);
				newptab->ports[iport].ncd->ncd_ftab.filts[ifilt].prids[j] = a2i(ptr2, 6);
			}
			else
			{
				newptab->ports[iport].ncd->ncd_ftab.filts[ifilt].prids[j] = a2i(ptr3, 6);
			}
			newptab->ports[iport].ncd->ncd_ftab.filts[ifilt].nprids++;
		}
	}
	memcpy(ptab, newptab, sizeof(PTAB));
	NULLFREE(newptab);
}

void chk_ecm_whitelist(char *value, ECM_WHITELIST *ecm_whitelist)
{
	ecm_whitelist_clear(ecm_whitelist);
	char *ptr, *saveptr1 = NULL;
	for(ptr = strtok_r(value, ";", &saveptr1); ptr; ptr = strtok_r(NULL, ";", &saveptr1))
	{
		ECM_WHITELIST_DATA d;
		memset(&d, 0, sizeof(d));
		char *caid_end_ptr = strchr(ptr, ':'); // caid_end_ptr + 1 -> headers
		char *provid_ptr = strchr(ptr, '@'); // provid_ptr + 1 -> provid
		char *headers = ptr;
		if(caid_end_ptr)
		{
			caid_end_ptr[0] = '\0';
			if (provid_ptr)
			{
				provid_ptr[0] = '\0';
				provid_ptr++;
				d.ident = a2i(provid_ptr, 6);
			}
			d.caid = dyn_word_atob(ptr);
			headers = caid_end_ptr + 1; // -> headers
		} else if(provid_ptr) {
			provid_ptr[0] = '\0';
			d.ident = a2i(provid_ptr, 6);
		}
		if (d.caid == 0xffff) d.caid = 0;
		if (d.ident == 0xffff) d.ident = 0;
		char *len_ptr, *savelen_ptr = NULL;
		for(len_ptr = strtok_r(headers, ",", &savelen_ptr); len_ptr; len_ptr = strtok_r(NULL, ",", &savelen_ptr))
		{
			d.len = dyn_word_atob(len_ptr);
			if (d.len == 0xffff)
				continue;
			ecm_whitelist_add(ecm_whitelist, &d);
		}
	}
}

void chk_ecm_hdr_whitelist(char *value, ECM_HDR_WHITELIST *ecm_hdr_whitelist)
{
	ecm_hdr_whitelist_clear(ecm_hdr_whitelist);
	char *ptr, *saveptr = NULL;
	for(ptr = strtok_r(value, ";", &saveptr); ptr; ptr = strtok_r(NULL, ";", &saveptr))
	{
		ECM_HDR_WHITELIST_DATA d;
		memset(&d, 0, sizeof(d));
		char *caid_end_ptr = strchr(ptr, ':'); // caid_end_ptr + 1 -> headers
		char *provid_ptr = strchr(ptr, '@'); // provid_ptr + 1 -> provid
		char *headers = ptr;
		if(caid_end_ptr)
		{
			caid_end_ptr[0] = '\0';
			if (provid_ptr)
			{
				provid_ptr[0] = '\0';
				provid_ptr++;
				d.provid = a2i(provid_ptr, 6);
			}
			d.caid = dyn_word_atob(ptr);
			headers = caid_end_ptr + 1; // -> headers
		} else if(provid_ptr) {
			provid_ptr[0] = '\0';
			d.provid = a2i(provid_ptr, 6);
		}
		if (d.caid == 0xffff) d.caid = 0;
		if (d.provid == 0xffff) d.provid = 0;
		char *hdr_ptr, *savehdr_ptr = NULL;
		for(hdr_ptr = strtok_r(headers, ",", &savehdr_ptr); hdr_ptr; hdr_ptr = strtok_r(NULL, ",", &savehdr_ptr))
		{
			hdr_ptr = trim(hdr_ptr);
			d.len = strlen(hdr_ptr);
			if (d.len / 2 > sizeof(d.header))
				d.len = sizeof(d.header) * 2;
			if (d.len > 1)
			{
				key_atob_l(hdr_ptr, d.header, d.len);
				ecm_hdr_whitelist_add(ecm_hdr_whitelist, &d);
			}
		}
	}
}

/* Clears the s_ip structure provided. The pointer will be set to NULL so everything is cleared.*/
void clear_sip(struct s_ip **sip)
{
	struct s_ip *cip = *sip;
	for(*sip = NULL; cip != NULL; cip = cip->next)
	{
		add_garbage(cip);
	}
}

/* Clears the s_ptab struct provided by setting nfilts and nprids to zero. */
void clear_ptab(struct s_ptab *ptab)
{
	int32_t i;
	ptab->nports = 0;
	for(i = 0; i < CS_MAXPORTS; i++)
	{
		if(ptab->ports[i].ncd)
		{
			ptab->ports[i].ncd->ncd_ftab.nfilts = 0;
			ptab->ports[i].ncd->ncd_ftab.filts[0].nprids = 0;
			NULLFREE(ptab->ports[i].ncd);
			ptab->ports[i].ncd = NULL;
		}
	}
}

/* Clears given csptab */
void clear_cacheextab(CECSPVALUETAB *ctab)
{
	ctab->cevnum = 0;
	NULLFREE(ctab->cevdata);
}
