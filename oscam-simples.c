#include "globals.h"
#include "oscam-string.h"

static void cl_set_last_providptr(struct s_client *cl, uint32_t provid, uint16_t caid)
{
	int32_t i;
	struct s_provid *this = cfg.provid;

	cl->last_providptr = NULL;
	
	if(!caid) {
		return;
	}

	for(; this; this = this->next)
	{
		if(this->caid == caid)
		{
			for(i=0; i < this->nprovid; i++)
			{
				if(this->provid[i] == provid)
				{
					cl->last_providptr = this;
					return;
				}
			}
		}
	}
	
}

/* Gets the servicename. */
static char *__get_servicename(struct s_client *cl, uint16_t srvid, uint32_t provid, uint16_t caid, char *buf, uint32_t buflen, bool return_unknown)
{
	int32_t i, j;
	struct s_srvid *this, *provid_zero_match = NULL, *provid_any_match = NULL;
	buf[0] = '\0';

	if(!srvid || (srvid >> 12) >= 16)  //cfg.srvid[16]
		{ return (buf); }

	if(cl && cl->last_srvidptr && cl->last_srvidptr->srvid == srvid)
		for(i = 0; i < cl->last_srvidptr->ncaid; i++)
			if(cl->last_srvidptr->caid[i].caid == caid 
				&& cl->last_srvidptr_search_provid == provid
				&& cl->last_srvidptr->name)
			{
				if(cl->last_providptr == NULL)
					{ cl_set_last_providptr(cl, provid, caid); }
				cs_strncpy(buf, cl->last_srvidptr->name, buflen);
				return (buf);
			}

	for(this = cfg.srvid[srvid >> 12]; this; this = this->next)
		if(this->srvid == srvid)
			for(i = 0; i < this->ncaid; i++)
			{			
				if(this->caid[i].caid == caid && this->name)
				{
					provid_any_match = this;

					if(this->caid[i].nprovid == 0)
					{
						provid_zero_match = this;
						
						if(0 == provid)
						{
							if(cl)
							{
								cl_set_last_providptr(cl, provid, caid);
								cl->last_srvidptr = this;
								cl->last_srvidptr_search_provid = provid;
							}
							cs_strncpy(buf, this->name, buflen);
							return (buf);
						}					
					}
											
					for(j = 0; j < this->caid[i].nprovid; j++)
					{
						if(this->caid[i].provid[j] == 0)
							{ provid_zero_match = this; }
						
						if(this->caid[i].provid[j] == provid)
						{
							if(cl)
							{
								cl_set_last_providptr(cl, provid, caid);
								cl->last_srvidptr = this;
								cl->last_srvidptr_search_provid = provid;
							}
							cs_strncpy(buf, this->name, buflen);
							return (buf);
						}
					}
				}
			}

	if(!buf[0])
	{
		if(provid != 0 && provid_zero_match != NULL)
		{
			if(cl)
			{ 
				cl_set_last_providptr(cl, provid, caid);
				cl->last_srvidptr = provid_zero_match;
				cl->last_srvidptr_search_provid = provid;
			}
			cs_strncpy(buf, provid_zero_match->name, buflen);
			return (buf);			
		}		
		else if(provid == 0 && provid_any_match != NULL)
		{
			if(cl)
			{ 
				cl_set_last_providptr(cl, provid, caid);
				cl->last_srvidptr = provid_any_match;
				cl->last_srvidptr_search_provid = provid;
			}
			cs_strncpy(buf, provid_any_match->name, buflen);
			return (buf);
		}

		if(return_unknown)
			{ snprintf(buf, buflen, "%04X@%06X:%04X unknown", caid, provid, srvid); }
		if(cl)
		{ 
			cl->last_srvidptr = NULL;
			cl->last_srvidptr_search_provid = provid;
		}
	}
	return (buf);
}

char *get_servicename(struct s_client *cl, uint16_t srvid, uint32_t provid, uint16_t caid, char *buf, uint32_t buflen)
{
	return __get_servicename(cl, srvid, provid, caid, buf, buflen, true);
}

char *get_servicename_or_null(struct s_client *cl, uint16_t srvid, uint32_t provid, uint16_t caid, char *buf, uint32_t buflen)
{
	return __get_servicename(cl, srvid, provid, caid, buf, buflen, false);
}

char *get_picon_servicename_or_null(struct s_client *cl, uint16_t srvid, uint32_t provid, uint16_t caid, char *buf, uint32_t buflen)
{
	uint32_t i, j;
	
	__get_servicename(cl, srvid, provid, caid, buf, buflen, false);
	
	char *tmp_buf;
	
	if(buf[0])
	{
		if(!cs_malloc(&tmp_buf, buflen))
		{
			buf[0] = '\0';
			return (buf);	
		}
		
		j = 0;
		
		for(i=0; i<buflen && buf[i] && j+4<buflen; i++)
		{
			if(isalnum((int)buf[i]))
			{
				tmp_buf[j] = (char)tolower((int)buf[i]);
				j++;
			}
			else if(buf[i] == '*')
			{
				tmp_buf[j] = 's';
				tmp_buf[j+1] = 't';
				tmp_buf[j+2] = 'a';
				tmp_buf[j+3] = 'r';						
				j += 4;
			}
			else if(buf[i] == '+')
			{
				tmp_buf[j] = 'p';
				tmp_buf[j+1] = 'l';
				tmp_buf[j+2] = 'u';
				tmp_buf[j+3] = 's';				
				j += 4;
			}
			else if(buf[i] == '&')
			{
				tmp_buf[j] = 'a';
				tmp_buf[j+1] = 'n';
				tmp_buf[j+2] = 'd';				
				j += 3;
			}						
		}
		
		tmp_buf[buflen-1] = '\0';
		cs_strncpy(buf, tmp_buf, buflen);
		
		NULLFREE(tmp_buf);
	}
	
	return (buf);
}

int32_t picon_servicename_remve_hd(char *buf, uint32_t UNUSED(buflen))
{
	int32_t l = strlen(buf);
	
	if(l < 3)
	{
		return 0;
	}
	
	if(buf[l-2] == 'h' && buf[l-1] == 'd')
	{
		buf[l-2] = '\0';
		buf[l-1] = '\0';
		return 1;
	}
	
	return 0;
}

/* Gets the tier name. Make sure that buf is at least 83 bytes long. */
char *get_tiername(uint16_t tierid, uint16_t caid, char *buf)
{
	uint8_t found = 0;
	int32_t i;
	struct s_tierid *this = cfg.tierid;

	for(buf[0] = 0; this && !found; this = this->next)
		if(this->tierid == tierid)
			for(i = 0; i < this->ncaid && !found; i++)
				if(this->caid[i] == caid)
					{ cs_strncpy(buf, this->name, 32); found = 1; }

	if(!tierid) { buf[0] = '\0'; }
	return (buf);
}

/* Gets the provider name. */
char *get_provider(uint32_t provid, uint16_t caid, char *buf, uint32_t buflen)
{
	uint8_t found = 0;
	int32_t i;
	struct s_provid *this = cfg.provid;

	if(!caid) {
		buf[0] = '\0';
		return (buf);
	}

	for(buf[0] = 0; this && !found; this = this->next)
	{
		if(this->caid == caid)
		{
			for(i=0; i<this->nprovid && !found; i++)
			{
				if(this->provid[i] == provid)
				{
					snprintf(buf, buflen, "%s%s%s%s%s", this->prov,
							 this->sat && this->sat[0] ? " / " : "", this->sat,
							 this->lang[0] ? " / " : "", this->lang);
					found = 1;
				}
			}
		}
	}

	if(!buf[0]) { snprintf(buf, buflen, "%04X:%06X unknown", caid, provid); }
		
	return (buf);
}

char *__get_providername(uint32_t provid, uint16_t caid, char *buf, uint32_t buflen, bool return_unknown)
{
	uint8_t found = 0;
	int32_t i;
	struct s_provid *this = cfg.provid;

	if(!caid) {
		buf[0] = '\0';
		return (buf);
	}

	for(buf[0] = 0; this && !found; this = this->next)
	{
		if(this->caid == caid)
		{
			for(i=0; i<this->nprovid && !found; i++)
			{
				if(this->provid[i] == provid)
				{
					cs_strncpy(buf, this->prov, buflen);
					found = 1;
				}
			}
		}
	}

	if(!buf[0] && return_unknown) { snprintf(buf, buflen, "%04X:%06X unknown", caid, provid); }

	return (buf);
}

char *get_providername(uint32_t provid, uint16_t caid, char *buf, uint32_t buflen)
{
	return __get_providername(provid, caid, buf, buflen, true);
}

char *get_providername_or_null(uint32_t provid, uint16_t caid, char *buf, uint32_t buflen)
{
	return __get_providername(provid, caid, buf, buflen, false);
}

const char *get_cl_lastprovidername(struct s_client *cl)
{
	if(!cl->last_srvidptr || !cl->last_srvidptr->prov
		 || cl->last_srvidptr->prov[0] == '\0' || !strcmp(cl->last_srvidptr->prov, " "))
	{
		if(!cl->last_providptr)
		{
			return "";	
		}
		else
		{
			return cl->last_providptr->prov;
		}
	} 
	
	return cl->last_srvidptr->prov;
}

// Add provider description. If provider was already present, do nothing.
void add_provider(uint16_t caid, uint32_t provid, const char *name, const char *sat, const char *lang)
{
	int32_t i;
	struct s_provid **ptr;
	
	for(ptr = &cfg.provid; *ptr; ptr = &(*ptr)->next)
	{
		if((*ptr)->caid == caid)
		{
			for(i=0; i<(*ptr)->nprovid; i++)
			{
			 	if((*ptr)->provid[i] == provid)
				{ 
					return;
				}
			}
		}
	}

	struct s_provid *prov;
	if(!cs_malloc(&prov, sizeof(struct s_provid)))
		{ return; }

	if(!cs_malloc(&prov->provid, sizeof(uint32_t)))
		{ NULLFREE(prov); return; }
		
	prov->nprovid = 1;
	prov->provid[0] = provid;
	prov->caid = caid;
	cs_strncpy(prov->prov, name, sizeof(prov->prov));
	cs_strncpy(prov->sat, sat, sizeof(prov->sat));
	cs_strncpy(prov->lang, lang, sizeof(prov->lang));
	*ptr = prov;
}

// Get a cardsystem name based on caid
// used in webif/CCcam share and in dvbapi/ecminfo
const char *get_cardsystem_desc_by_caid(uint16_t caid)
{
        if(caid_is_seca(caid)) { return "seca"; }
        if(caid_is_viaccess(caid)) { return "viaccess"; }
        if(caid_is_irdeto(caid)) { return "irdeto"; }
        if(caid_is_videoguard(caid)) { return "videoguard"; }
        if(caid >= 0x0B00 && caid <= 0x0BFF) { return "conax"; }
        if(caid_is_cryptoworks(caid)) { return "cryptoworks"; }
        if(caid_is_betacrypt(caid)) { return "betacrypt"; }
        if(caid_is_nagra(caid)) { return "nagra"; }
        if(caid >= 0x4B00 && caid <= 0x4BFF) { return "tongfang"; }
        if(caid >= 0x5501 && caid <= 0x551A) { return "griffin"; }
        if(caid == 0x4AE0 || caid == 0x4AE1) { return "drecrypt"; }
        if(caid_is_bulcrypt(caid)) { return "bulcrypt"; }
        if(caid_is_biss(caid)) { return "biss"; }
        if(caid == 0x4ABF) { return "dgcrypt"; }
        return "???";
}
