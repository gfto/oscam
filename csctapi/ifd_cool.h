/*
    ifd_cool.h
    Header file for Coolstream internal reader.
*/
#ifdef COOL

#include "atr.h"
int Cool_Init (void);
int Cool_Reset (ATR * atr);
int Cool_Transmit (BYTE * buffer, unsigned size);
int Cool_Receive (BYTE * buffer, unsigned size);
int Cool_SetClockrate (int mhz);

void * handle;
#endif
