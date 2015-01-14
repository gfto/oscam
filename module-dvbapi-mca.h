#ifndef _MODULE_MCA_H_
#define _MODULE_MCA_H_

void mca_send_dcw(struct s_client *client, ECM_REQUEST *er);
void *mca_handler(struct s_client *cl, uchar *mbuf, int32_t module_idx);

#if defined(HAVE_DVBAPI) && defined(WITH_MCA)
void mca_init(void);
void mca_close(void);
#else
static inline void mca_init(void) { }
static inline void mca_close(void) { }
#endif

#endif
