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

int32_t ecmfmt(uint16_t caid, uint32_t prid, uint16_t chid, uint16_t pid, uint16_t srvid, uint16_t l, uint16_t checksum, char *result, size_t size)
{
	if (!cfg.ecmfmt)
		return snprintf(result, size, "%04X&%06X/%04X/%04X/%02X:%04X", caid, prid, chid, srvid, l, htons(checksum));

	uint32_t s=0, zero=0, flen=0, value=0;
	char *c = cfg.ecmfmt, fmt[5] = "%04X";
	while (*c) {
		switch(*c)
		{
			case '0': zero=1; value=0; break;
			case 'c': flen=4; value=caid; break;
			case 'p': flen=6; value=prid; break;
			case 'i': flen=4; value=chid; break;
			case 'd': flen=4; value=pid; break;
			case 's': flen=4; value=srvid; break;
			case 'l': flen=2; value=l; break;
			case 'h': flen=4; value=htons(checksum); break;
			case '\\':
				c++;
				flen=0;
				value=*c;
				break;
			default:  flen=0; value=*c; break;
		}
		if (value) zero=0;

		if (!zero) {
			//fmt[0] = '%';
			if (flen) { //Build %04X / %06X / %02X
				fmt[1] = '0';
				fmt[2] = flen+'0';
				fmt[3] = 'X';
				fmt[4] = 0;
			}
			else {
				fmt[1] = 'c';
				fmt[2] = 0;
			}

			s += snprintf(result+s, size-s, fmt, value);
		}
		c++;
	}
	return s;
}

int32_t format_ecm(ECM_REQUEST *ecm, char *result, size_t size)
{
	return ecmfmt(ecm->caid, ecm->prid, ecm->chid, ecm->pid, ecm->srvid, ecm->l, ecm->checksum, result, size);
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

int8_t cs_emmlen_is_blocked(struct s_reader *rdr, int16_t len)
{
	int i;
	for (i = 0; i < CS_MAXEMMBLOCKBYLEN; i++)
		if (rdr->blockemmbylen[i] == len)
			return 1;
	return 0;
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
