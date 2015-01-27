#ifndef MODULE_CAMD35_CACHEEX_H_
#define MODULE_CAMD35_CACHEEX_H_

#ifdef CS_CACHEEX
void camd35_cacheex_init_dcw(struct s_client *client, ECM_REQUEST *er);
void camd35_cacheex_recv_ce1_cwc_info(struct s_client *cl, uchar *buf, int32_t idx);
void camd35_cacheex_push_request_remote_id(struct s_client *cl);
void camd35_cacheex_send_push_filter(struct s_client *cl, uint8_t mode);
bool camd35_cacheex_server(struct s_client *client, uint8_t *mbuf);
bool camd35_cacheex_recv_chk(struct s_client *client, uint8_t *buf);
void camd35_cacheex_module_init(struct s_module *ph);
#else
static inline void camd35_cacheex_init_dcw(struct s_client *UNUSED(client), ECM_REQUEST *UNUSED(er)) { }
static inline void camd35_cacheex_recv_ce1_cwc_info(struct s_client *UNUSED(cl), uchar *UNUSED(buf), int32_t UNUSED(idx)) { }
static inline void camd35_cacheex_push_request_remote_id(struct s_client *UNUSED(cl)) { }
static inline void camd35_cacheex_send_push_filter(struct s_client *UNUSED(cl), uint8_t UNUSED(mode)) { }
static inline bool camd35_cacheex_server(struct s_client *UNUSED(client), uint8_t *UNUSED(mbuf)) { return 0; }
static inline bool camd35_cacheex_recv_chk(struct s_client *UNUSED(client), uint8_t *UNUSED(buf)) { return 0; }
static inline void camd35_cacheex_module_init(struct s_module *UNUSED(ph)) { }
#endif

#endif
