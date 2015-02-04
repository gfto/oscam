#ifndef OSCAM_CACHE_H_
#define OSCAM_CACHE_H_

void init_cache(void);
void free_cache(void);
void add_cache(ECM_REQUEST *er);
struct ecm_request_t *check_cache(ECM_REQUEST *er, struct s_client *cl);
void cleanup_cache(void);
void remove_client_from_cache(struct s_client *cl);
uint32_t cache_size(void);
uint8_t get_odd_even(ECM_REQUEST *er);
uint8_t check_is_pushed(void *cw, struct s_client *cl);

#endif
