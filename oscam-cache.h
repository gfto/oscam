#ifndef OSCAM_CACHE_H_
#define OSCAM_CACHE_H_

void init_cache(void);
void add_cache(ECM_REQUEST *er);
struct ecm_request_t *check_cache(ECM_REQUEST *er, struct s_client *cl);
void cleanup_cache(void);
void remove_client_from_cache(struct s_client *cl);
uint32_t cache_size(void);
void cacheex_update_hash(ECM_REQUEST *er);
uint8_t get_odd_even(ECM_REQUEST *er);

#ifdef CS_CACHEEX
uint8_t check_is_pushed(void *cw, struct s_client *cl);
void init_hitcache(void);
void add_hitcache(struct s_client *cl, ECM_REQUEST *er);
void del_hitcache(ECM_REQUEST *er);
struct csp_ce_hit_t *check_hitcache(ECM_REQUEST *er, struct s_client *cl);
void cleanup_hitcache(void);
uint32_t hitcache_size(void);
#else
static inline void init_hitcache(void) { }
#endif


#endif
