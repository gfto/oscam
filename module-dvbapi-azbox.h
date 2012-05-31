#ifndef _MODULE_AZBOX_H_
#define _MODULE_AZBOX_H_

#include "openxcas/openxcas_api.h"
#include "openxcas/openxcas_message.h"

void azbox_openxcas_ecm_callback(int32_t stream_id, uint32_t sequence, int32_t cipher_index, uint32_t caid, unsigned char *ecm_data, int32_t l, uint16_t pid);
void azbox_openxcas_ex_callback(int32_t stream_id, uint32_t seq, int32_t idx, uint32_t pid, unsigned char *ecm_data, int32_t l);
void azbox_send_dcw(struct s_client *client, ECM_REQUEST *er);

void * azbox_main_thread(void * cli);

#endif
