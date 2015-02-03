#ifndef MODULE_CACHEEX_H_
#define MODULE_CACHEEX_H_

static inline uint64_t cacheex_node_id(void *var)
{
	uint64_t *x = var;
	return *x;
}

uint32_t get_cacheex_wait_time(ECM_REQUEST *er, struct s_client *cl);
CWCHECK get_cwcheck(ECM_REQUEST *er);
uint16_t get_cacheex_mode1_delay(ECM_REQUEST *er);
int32_t chk_csp_ctab(ECM_REQUEST *er, CECSPVALUETAB *tab);
uint8_t check_cacheex_filter(struct s_client *cl, ECM_REQUEST *er);
void cacheex_add_to_cache(struct s_client *cl, ECM_REQUEST *er);
void cacheex_add_to_cache_from_csp(struct s_client *cl, ECM_REQUEST *er);
void cacheex_cache_push(ECM_REQUEST *er);
int32_t cacheex_add_stats(struct s_client *cl, uint16_t caid, uint16_t srvid, uint32_t prid, uint8_t direction);
int8_t cacheex_maxhop(struct s_client *cl);

#ifdef CS_CACHEEX
extern void cacheex_init(void);
extern void cacheex_clear_account_stats(struct s_auth *account);
extern void cacheex_clear_client_stats(struct s_client *client);
extern void cacheex_load_config_file(void);
static inline bool cacheex_reader(struct s_reader *rdr) { return rdr->cacheex.mode == 1; }
extern bool cacheex_is_match_alias(struct s_client *cl, ECM_REQUEST *er);
void cacheex_set_csp_lastnode(ECM_REQUEST *er);
void cacheex_set_cacheex_src(ECM_REQUEST *ecm, struct s_client *cl);
void cacheex_init_cacheex_src(ECM_REQUEST *ecm, ECM_REQUEST *er);
void cacheex_free_csp_lastnodes(ECM_REQUEST *er);
void checkcache_process_thread_start(void);
void cacheex_push_out(struct s_client *cl, ECM_REQUEST *er);
bool cacheex_check_queue_length(struct s_client *cl);
static inline int8_t cacheex_get_rdr_mode(struct s_reader *reader) { return reader->cacheex.mode; }
void cacheex_init_hitcache(void);
void cacheex_cleanup_hitcache(void);
void cacheex_update_hash(ECM_REQUEST *er);
void cacheex_mode1_delay(ECM_REQUEST *er);
void cacheex_timeout(ECM_REQUEST *er);
#else
static inline void cacheex_init(void) { }
static inline void cacheex_clear_account_stats(struct s_auth *UNUSED(account)) { }
static inline void cacheex_clear_client_stats(struct s_client *UNUSED(client)) { }
static inline void cacheex_load_config_file(void) { }
static inline bool cacheex_reader(struct s_reader *UNUSED(rdr)) { return false; }
static inline bool cacheex_is_match_alias(struct s_client *UNUSED(cl), ECM_REQUEST *UNUSED(er)) { return false; }
static inline void cacheex_set_csp_lastnode(ECM_REQUEST *UNUSED(er)) { }
static inline void cacheex_free_csp_lastnodes(ECM_REQUEST *UNUSED(er)) { }
static inline void cacheex_set_cacheex_src(ECM_REQUEST *UNUSED(ecm), struct s_client *UNUSED(cl)) { }
static inline void cacheex_init_cacheex_src(ECM_REQUEST *UNUSED(ecm), ECM_REQUEST *UNUSED(er)) { }
static inline void checkcache_process_thread_start(void) { }
static inline void cacheex_push_out(struct s_client *UNUSED(cl), ECM_REQUEST *UNUSED(er)) { }
static inline bool cacheex_check_queue_length(struct s_client *UNUSED(cl)) { return 0; }
static inline int8_t cacheex_get_rdr_mode(struct s_reader *UNUSED(reader)) { return 0; }
static inline void cacheex_init_hitcache(void) { }
static inline void cacheex_cleanup_hitcache(void) { }
static inline void cacheex_update_hash(ECM_REQUEST *UNUSED(er)) { }
static inline void cacheex_mode1_delay(ECM_REQUEST *UNUSED(er)) { }
static inline void cacheex_timeout(ECM_REQUEST *UNUSED(er)) { }
#endif

#endif
