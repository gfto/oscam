#ifndef MODULE_CACHEEX_H_
#define MODULE_CACHEEX_H_

static inline uint64_t cacheex_node_id(void *var) { uint64_t *x = var; return *x; }

extern uint8_t cacheex_peer_id[8];

extern int32_t cacheex_add_stats(struct s_client *cl, uint16_t caid, uint16_t srvid, uint32_t prid, uint8_t direction);
extern int8_t cacheex_maxhop(struct s_client *cl);
void cacheex_cache_push(ECM_REQUEST *er);
extern int8_t cacheex_is_match_alias(struct s_client *cl, ECM_REQUEST *er);
extern int8_t cacheex_match_alias(struct s_client *cl, ECM_REQUEST *er, ECM_REQUEST *ecm);
extern void cacheex_add_to_cache(struct s_client *cl, ECM_REQUEST *er);
extern void cacheex_add_to_cache_from_csp(struct s_client *cl, ECM_REQUEST *er);
#ifdef CS_CACHEEX
extern void cacheex_init(void);
extern void cacheex_clear_account_stats(struct s_auth *account);
extern void cacheex_clear_client_stats(struct s_client *client);
extern void cacheex_load_config_file(void);
#else
static inline void cacheex_init(void) { };
static inline void cacheex_clear_account_stats(struct s_auth *UNUSED(account)) { };
static inline void cacheex_clear_client_stats(struct s_client *UNUSED(client)) { };
static inline void cacheex_load_config_file(void) { };
#endif

#endif
