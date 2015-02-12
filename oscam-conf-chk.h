#ifndef OSCAM_CONF_CHK_H
#define OSCAM_CONF_CHK_H

void chk_iprange(char *value, struct s_ip **base);
void chk_caidtab(char *caidasc, CAIDTAB *ctab);
void chk_caidvaluetab(char *lbrlt, CAIDVALUETAB *tab, int32_t minvalue);
void chk_cacheex_valuetab(char *lbrlt, CECSPVALUETAB *tab);
void chk_cacheex_cwcheck_valuetab(char *lbrlt, CWCHECKTAB *tab);
void chk_cacheex_hitvaluetab(char *lbrlt, CECSPVALUETAB *tab);
void chk_tuntab(char *tunasc, TUNTAB *ttab);
void chk_services(char *labels, SIDTABS *sidtabs);
void chk_ftab(char *zFilterAsc, FTAB *ftab, const char *zType, const char *zName, const char *zFiltName);
void chk_cltab(char *classasc, CLASSTAB *clstab);
void chk_port_tab(char *portasc, PTAB *ptab);
void chk_ecm_whitelist(char *value, ECM_WHITELIST *ecm_whitelist);
void chk_ecm_hdr_whitelist(char *value, ECM_HDR_WHITELIST *ecm_hdr_whitelist);

void clear_sip(struct s_ip **sip);
void clear_ptab(struct s_ptab *ptab);
void clear_caidtab(struct s_caidtab *ctab);
void clear_cacheextab(CECSPVALUETAB *ctab);

void ftab_clear(struct s_ftab *ftab);
void tuntab_clear(struct s_tuntab *ttab);
void ecm_whitelist_clear(ECM_WHITELIST *ecm_whitelist);
void ecm_hdr_whitelist_clear(ECM_HDR_WHITELIST *ecm_hdr_whitelist);

void tuntab_clone(TUNTAB *src_ttab, TUNTAB *dst_ttab);
void ftab_clone(FTAB *src_ftab, FTAB *dst_ftab);

void ftab_add(FTAB *ftab, FILTER *filter);
void tuntab_add(TUNTAB *ttab, TUNTAB_DATA *td);
void ecm_whitelist_add(ECM_WHITELIST *ecm_whitelist, ECM_WHITELIST_DATA *ew);
void ecm_hdr_whitelist_add(ECM_HDR_WHITELIST *ecm_hdr_whitelist, ECM_HDR_WHITELIST_DATA *eh);

#endif
