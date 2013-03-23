#ifndef OSCAM_ECM_H_
#define OSCAM_ECM_H_

void cw_process_thread_start(void);

void convert_to_beta(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto);
void convert_to_nagra(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto);

struct ecm_request_t *check_cwcache(ECM_REQUEST *, struct s_client *);

int32_t write_ecm_answer(struct s_reader * reader, ECM_REQUEST *er, int8_t rc, uint8_t rcEx, uint8_t *cw, char *msglog);

void get_cw(struct s_client *, ECM_REQUEST *);

void update_chid(ECM_REQUEST *ecm);
uint32_t chk_provid(uint8_t *ecm, uint16_t caid);

void free_ecm(ECM_REQUEST *ecm);
void reader_get_ecm(struct s_reader * reader, ECM_REQUEST *er);

ECM_REQUEST *get_ecmtask(void);
void cleanup_ecmtasks(struct s_client *cl);
void remove_reader_from_ecm(struct s_reader *rdr);

void chk_dcw(struct s_client *cl, struct s_ecm_answer *ea);
void request_cw_from_readers(ECM_REQUEST *er);

void checkCW(ECM_REQUEST *er);

#define debug_ecm(mask, args...) \
	do { \
		if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) { \
			char buf[ECM_FMT_LEN]; \
			format_ecm(er, buf, ECM_FMT_LEN); \
			cs_debug_mask(mask, ##args); \
		} \
	} while(0)

int32_t ecmfmt(uint16_t caid, uint32_t prid, uint16_t chid, uint16_t pid, uint16_t srvid, uint16_t l, char *ecmd5hex, char *csphash, char *cw, char *result, size_t size);
int32_t format_ecm(ECM_REQUEST *ecm, char *result, size_t size);

#endif
