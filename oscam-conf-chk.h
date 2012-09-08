#ifndef OSCAM_CONF_CHK_H
#define OSCAM_CONF_CHK_H

void chk_iprange(char *value, struct s_ip **base);
void chk_caidtab(char *caidasc, CAIDTAB *ctab);
void chk_caidvaluetab(char *lbrlt, CAIDVALUETAB *tab, int32_t minvalue);
void chk_tuntab(char *tunasc, TUNTAB *ttab);
void chk_services(char *labels, SIDTABBITS *sidok, SIDTABBITS *sidno);
void chk_ftab(char *zFilterAsc, FTAB *ftab, const char *zType, const char *zName, const char *zFiltName);
void chk_cltab(char *classasc, CLASSTAB *clstab);
void chk_port_tab(char *portasc, PTAB *ptab);

#endif
