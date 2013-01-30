//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#include "oscam-garbage.h"
#include "oscam-string.h"

extern struct s_cardsystem cardsystems[CS_MAX_MOD];

/* Gets the servicename. Make sure that buf is at least 32 bytes large. */
char *get_servicename(struct s_client *cl, uint16_t srvid, uint16_t caid, char *buf){
	int32_t i;
	struct s_srvid *this;
	buf[0] = '\0';

	if (!srvid || (srvid>>12) >= 16) //cfg.srvid[16]
		return(buf);

	if (cl && cl->last_srvidptr && cl->last_srvidptr->srvid==srvid)
		for (i=0; i < cl->last_srvidptr->ncaid; i++)
			if (cl->last_srvidptr->caid[i] == caid && cl->last_srvidptr->name){
				cs_strncpy(buf, cl->last_srvidptr->name, 32);
				return(buf);
			}

	for (this = cfg.srvid[srvid>>12]; this; this = this->next)
		if (this->srvid == srvid)
			for (i=0; i < this->ncaid; i++)
				if (this->caid[i] == caid && this->name && cl) {
					cs_strncpy(buf, this->name, 32);
					cl->last_srvidptr = this;
					return(buf);
				}

	if (!buf[0]) {
		snprintf(buf, 32, "%04X:%04X unknown", caid, srvid);
		if (cl) cl->last_srvidptr = NULL;
	}
	return(buf);
}

/* Gets the tier name. Make sure that buf is at least 83 bytes long. */
char *get_tiername(uint16_t tierid, uint16_t caid, char *buf){
	int32_t i;
	struct s_tierid *this = cfg.tierid;

	for (buf[0] = 0; this && (!buf[0]); this = this->next)
		if (this->tierid == tierid)
			for (i=0; i<this->ncaid; i++)
				if (this->caid[i] == caid)
					cs_strncpy(buf, this->name, 32);

	//if (!name[0]) sprintf(name, "%04X:%04X unknown", caid, tierid);
	if (!tierid) buf[0] = '\0';
	return(buf);
}

/* Gets the provider name. */
char *get_provider(uint16_t caid, uint32_t provid, char *buf, uint32_t buflen){
	struct s_provid *this = cfg.provid;

	for (buf[0] = 0; this && (!buf[0]); this = this->next) {
		if (this->caid == caid && this->provid == provid) {
			snprintf(buf, buflen, "%s%s%s%s%s", this->prov,
					this->sat[0] ? " / " : "", this->sat,
					this->lang[0] ? " / " : "", this->lang);
		}
	}

	if (!buf[0]) snprintf(buf, buflen, "%04X:%06X unknown", caid, provid);
	if (!caid) buf[0] = '\0';
	return(buf);
}

// Add provider description. If provider was already present, do nothing.
void add_provider(uint16_t caid, uint32_t provid, const char *name, const char *sat, const char *lang)
{
	struct s_provid **ptr;
	for (ptr = &cfg.provid; *ptr; ptr = &(*ptr)->next) {
		if ((*ptr)->caid == caid && (*ptr)->provid == provid)
			return;
	}

	struct s_provid *prov;
	if (!cs_malloc(&prov, sizeof(struct s_provid)))
		return;

	prov->provid = provid;
	prov->caid = caid;
	cs_strncpy(prov->prov, name, sizeof(prov->prov));
	cs_strncpy(prov->sat, sat, sizeof(prov->sat));
	cs_strncpy(prov->lang, lang, sizeof(prov->lang));
	*ptr = prov;
}

int32_t check_sct_len(const uchar *data, int32_t off)
{
	int32_t len = SCT_LEN(data);
	if (len + off > MAX_LEN) {
		cs_debug_mask(D_TRACE | D_READER, "check_sct_len(): smartcard section too long %d > %d", len, MAX_LEN - off);
		len = -1;
	}
	return len;
}

struct s_cardsystem *get_cardsystem_by_caid(uint16_t caid) {
	int32_t i, j;
	for (i = 0; i < CS_MAX_MOD; i++) {
		if (cardsystems[i].caids) {
			for (j = 0; j < 2; j++) {
				uint16_t cs_caid = cardsystems[i].caids[j];
				if (cs_caid == caid || cs_caid == caid >> 8)
					return &cardsystems[i];
			}
		}
	}
	return NULL;
}
