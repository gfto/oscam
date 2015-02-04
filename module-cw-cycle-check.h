#ifndef MODULE_CW_CYCLE_CHECK_H_
#define MODULE_CW_CYCLE_CHECK_H_

uint8_t checkcwcycle(struct s_client *client, ECM_REQUEST *er, struct s_reader *reader, uchar *cw, int8_t rc, uint8_t cycletime_fr, uint8_t next_cw_cycle_fr);

#ifdef CW_CYCLE_CHECK
void cleanupcwcycle(void);
#else
static inline void cleanupcwcycle(void) { }
#endif

#endif
