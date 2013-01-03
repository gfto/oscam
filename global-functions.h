#ifndef GLOBAL_FUNCTIONS_H_
#define GLOBAL_FUNCTIONS_H_

/* ===========================
 *           oscam
 * =========================== */
extern void cs_exit_oscam(void);
extern void cs_restart_oscam(void);
extern int32_t cs_get_restartmode(void);

int32_t restart_cardreader(struct s_reader *rdr, int32_t restart);

extern int32_t chk_global_whitelist(ECM_REQUEST *er, uint32_t *line);
extern void global_whitelist_read(void);

extern int32_t accept_connection(int32_t i, int32_t j);
extern void start_thread(void * startroutine, char * nameroutine);
extern int32_t add_job(struct s_client *cl, int8_t action, void *ptr, int32_t len);
extern void add_check(struct s_client *client, int8_t action, void *ptr, int32_t size, int32_t ms_delay);
extern int32_t reader_init(struct s_reader *);
extern void cs_reload_config(void);
extern int32_t recv_from_udpipe(uchar *);
extern int32_t chk_bcaid(ECM_REQUEST *, CAIDTAB *);
extern void cs_exit(int32_t sig);
extern struct ecm_request_t *check_cwcache(ECM_REQUEST *, struct s_client *);
extern int32_t write_to_pipe(struct s_client *, int32_t, uchar *, int32_t);
extern int32_t read_from_pipe(struct s_client *, uchar **);
extern int32_t write_ecm_answer(struct s_reader *, ECM_REQUEST *, int8_t, uint8_t, uchar *, char *);
extern uint32_t chk_provid(uchar *, uint16_t);
extern void convert_to_beta(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto);
extern void convert_to_nagra(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto);
extern void get_cw(struct s_client *, ECM_REQUEST *);
extern void do_emm(struct s_client *, EMM_PACKET *);
extern ECM_REQUEST *get_ecmtask(void);
extern int32_t send_dcw(struct s_client *, ECM_REQUEST *);
extern int32_t process_input(uchar *, int32_t, int32_t);
extern void set_signal_handler(int32_t , int32_t , void (*));
extern void cs_waitforcardinit(void);
extern int32_t process_client_pipe(struct s_client *cl, uchar *buf, int32_t l);
extern void *clientthread_init(void * init);
extern void cleanup_thread(void *var);
extern void kill_thread(struct s_client *cl);
extern void remove_reader_from_active(struct s_reader *rdr);
extern void add_reader_to_active(struct s_reader *rdr);
extern void cs_card_info(void);
extern void cs_debug_level(void);
extern void update_chid(ECM_REQUEST *ecm);
extern void free_ecm(ECM_REQUEST *ecm);

#define debug_ecm(mask, args...) \
	do { \
		if (config_WITH_DEBUG() && (mask & cs_dblevel)) { \
			char buf[ECM_FMT_LEN]; \
			format_ecm(er, buf, ECM_FMT_LEN); \
			cs_debug_mask(mask, ##args); \
		} \
	} while(0)

/* ===========================
 *        oscam-config
 * =========================== */
extern int32_t  init_config(void);
extern int32_t  init_free_userdb(struct s_auth *auth);
extern void     account_set_defaults(struct s_auth *auth);
extern void     reader_set_defaults(struct s_reader *rdr);
extern struct s_auth *init_userdb(void);
extern int32_t  init_readerdb(void);
extern void free_reader(struct s_reader *rdr);
extern int32_t  init_sidtab(void);
extern void free_sidtab(struct s_sidtab *sidtab);
extern void init_free_sidtab(void);
extern int32_t init_provid(void);

extern void config_set(char *section, const char *token, char *value);
extern void config_free(void);

extern int32_t  init_srvid(void);
extern int32_t  init_tierid(void);
extern void init_len4caid(void);
extern int32_t csp_ecm_hash(ECM_REQUEST *er);
extern void chk_reader(char *token, char *value, struct s_reader *rdr);

extern void dvbapi_chk_caidtab(char *caidasc, char type);
extern void dvbapi_read_priority(void);

void check_caidtab_fn(const char *token, char *value, void *setting, FILE *f);

extern void cs_accounts_chk(void);
extern void chk_account(const char *token, char *value, struct s_auth *account);
extern void chk_sidtab(char *token, char *value, struct s_sidtab *sidtab);
extern int32_t write_services(void);
extern int32_t write_userdb(void);
extern int32_t write_config(void);
extern int32_t write_server(void);

#include "oscam-log.h"
#include "oscam-log-reader.h"

/* ===========================
 *        oscam-reader
 * =========================== */
extern int32_t check_sct_len(const unsigned char *data, int32_t off);
extern void * start_cardreader(void *);
extern int32_t hostResolve(struct s_reader * reader);
extern int32_t network_tcp_connection_open(struct s_reader *);
extern void network_tcp_connection_close(struct s_reader *, char *);
extern void block_connect(struct s_reader *rdr);
extern int32_t is_connect_blocked(struct s_reader *rdr);
void cs_add_entitlement(struct s_reader *rdr, uint16_t caid, uint32_t provid, uint64_t id, uint32_t class, time_t start, time_t end, uint8_t type);
extern void cs_clear_entitlement(struct s_reader *rdr);

extern void reader_do_idle(struct s_reader * reader);
extern int32_t reader_do_emm(struct s_reader * reader, EMM_PACKET *ep);
extern void reader_log_emm(struct s_reader * reader, EMM_PACKET *ep, int32_t i, int32_t rc, struct timeb *tps);
extern void reader_get_ecm(struct s_reader * reader, ECM_REQUEST *er);
extern void casc_check_dcw(struct s_reader * reader, int32_t idx, int32_t rc, uchar *cw);
extern void casc_do_sock_log(struct s_reader * reader);
extern void reader_do_card_info(struct s_reader * reader);

/* ===========================
 *        oscam-simples
 * =========================== */
extern char *get_servicename(struct s_client *cl, uint16_t srvid, uint16_t caid, char *buf);
extern char *get_tiername(uint16_t tierid, uint16_t caid, char *buf);
extern char *get_provider(uint16_t caid, uint32_t provid, char *buf, uint32_t buflen);
void add_provider(uint16_t caid, uint32_t provid, const char *name, const char *sat, const char *lang);
extern int32_t ecmfmt(uint16_t caid, uint32_t prid, uint16_t chid, uint16_t pid, uint16_t srvid, uint16_t l, char *ecmd5hex, char *result, size_t size);
extern int32_t format_ecm(ECM_REQUEST *ecm, char *result, size_t size);

/* ===========================
 *       module-newcamd
 * =========================== */
extern const char *newcamd_get_client_name(uint16_t client_id);

/* ===========================
 *       reader-common
 * =========================== */
extern struct s_cardsystem *get_cardsystem_by_caid(uint16_t caid);
extern int8_t cs_emmlen_is_blocked(struct s_reader *rdr, int16_t len);

#endif
