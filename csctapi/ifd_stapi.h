#ifndef CSCTAPI_IFD_STAPI_H_
#define CSCTAPI_IFD_STAPI_H_

#include "atr.h"

/* These functions are implemented in liboscam_stapi.a */
extern int32_t STReader_Open(char *device, uint32_t *stsmart_handle);
extern int32_t STReader_GetStatus(uint32_t stsmart_handle, int32_t *in);
extern int32_t STReader_Reset(uint32_t stsmart_handle, ATR *atr);
extern int32_t STReader_Transmit(uint32_t stsmart_handle, unsigned char *sent, uint32_t size);
extern int32_t STReader_Receive(uint32_t stsmart_handle, unsigned char *data, uint32_t size);
extern int32_t STReader_Close(uint32_t stsmart_handle);
extern int32_t STReader_SetProtocol(uint32_t stsmart_handle, unsigned char *params, unsigned *length, uint32_t len_request);
extern int32_t STReader_SetClockrate(uint32_t stsmart_handle);

#endif
