#ifndef _MODULE_AZBOX_H_
#define _MODULE_AZBOX_H_

void azbox_send_dcw(struct s_client *client, ECM_REQUEST *er);
void *azbox_handler(struct s_client *cl, uchar *mbuf, int32_t module_idx);

#if defined(HAVE_DVBAPI) && defined(WITH_AZBOX)
void azbox_init(void);
void azbox_close(void);
#else
static inline void azbox_init(void) { }
static inline void azbox_close(void) { }
#endif

#endif
