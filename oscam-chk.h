#ifndef OSCAM_CHK_H_
#define OSCAM_CHK_H_

int32_t ecm_ratelimit_check(struct s_reader * reader, ECM_REQUEST *er, int32_t reader_mode);
int32_t matching_reader(ECM_REQUEST *er, struct s_reader *rdr, int32_t slot);
int32_t emm_reader_match(struct s_reader *reader, uint16_t caid, uint32_t provid);

int32_t chk_srvid_match(ECM_REQUEST *er, SIDTAB *sidtab);
int32_t chk_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t has_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t chk_srvid_match_by_caid_prov(uint16_t caid, uint32_t provid, SIDTAB *sidtab);
int32_t chk_srvid_by_caid_prov(struct s_client *cl, uint16_t caid, uint32_t provid);
int32_t chk_srvid_by_caid_prov_rdr(struct s_reader *rdr, uint16_t caid, uint32_t provid);
int32_t chk_sfilter(ECM_REQUEST *er, PTAB *ptab);
int32_t chk_ufilters(ECM_REQUEST *er);
int32_t chk_rsfilter(struct s_reader * reader, ECM_REQUEST *er);
int32_t chk_rfilter2(uint16_t rcaid, uint32_t rprid, struct s_reader *rdr);
int32_t chk_ctab(uint16_t caid, CAIDTAB *ctab);
int32_t chk_caid(uint16_t caid, CAIDTAB *ctab);
int32_t chk_caid_rdr(struct s_reader *rdr,uint16_t caid);

#endif
