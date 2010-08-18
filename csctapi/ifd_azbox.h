
#ifndef IFD_AZBOX_H_
#define IFD_AZBOX_H_

#include "../globals.h"

#include "../openxcas/openxcas_api.h"
#include "../openxcas/openxcas_smartcard.h"

#include "atr.h"

#define AZBOX_MODES 10

int Azbox_Init(struct s_reader *reader);
void Azbox_SetMode(int mode);
int Azbox_GetStatus(struct s_reader *reader, int *in);
int Azbox_Reset(struct s_reader *reader, ATR *atr);
int Azbox_Transmit(struct s_reader *reader, BYTE *buffer, unsigned size);
int Azbox_Receive(struct s_reader *reader, BYTE *buffer, unsigned size);
int Azbox_Close(struct s_reader *reader);

#endif
