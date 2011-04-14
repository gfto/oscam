
#ifndef IFD_AZBOX_H_
#define IFD_AZBOX_H_

#include "../globals.h"

#include "../openxcas/openxcas_api.h"
#include "../openxcas/openxcas_smartcard.h"

#include "atr.h"

#define AZBOX_MODES 16

int32_t Azbox_Init(struct s_reader *reader);
void Azbox_SetMode(int32_t mode);
int32_t Azbox_GetStatus(struct s_reader *reader, int32_t *in);
int32_t Azbox_Reset(struct s_reader *reader, ATR *atr);
int32_t Azbox_Transmit(struct s_reader *reader, BYTE *buffer, uint32_t size);
int32_t Azbox_Receive(struct s_reader *reader, BYTE *buffer, uint32_t size);
int32_t Azbox_Close(struct s_reader *reader);

#endif
