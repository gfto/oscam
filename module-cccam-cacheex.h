#ifndef MODULE_CCCAM_CACHEEX_H_
#define MODULE_CCCAM_CACHEEX_H_

#ifdef CS_CACHEEX
void cc_cacheex_filter_out(struct s_client *cl);
void cc_cacheex_filter_in(struct s_client *cl, uchar *buf);
void cc_cacheex_push_in(struct s_client *cl, uchar *buf);
void cc_cacheex_module_init(struct s_module *ph);
#else
static inline void cc_cacheex_filter_out(struct s_client *UNUSED(cl)) { }
static inline void cc_cacheex_filter_in(struct s_client *UNUSED(cl), uchar *UNUSED(buf)) { }
static inline void cc_cacheex_push_in(struct s_client *UNUSED(cl), uchar *UNUSED(buf)) { }
static inline void cc_cacheex_module_init(struct s_module *UNUSED(ph)) { }
#endif

#endif
