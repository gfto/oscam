/*
    ifd_cool.h
    Header file for Coolstream internal reader.
*/
#ifdef COOL

#include "atr.h"
int32_t Cool_Init (char *device);
int32_t Cool_Reset (ATR * atr);
int32_t Cool_Transmit (BYTE * buffer, uint32_t size);
int32_t Cool_Receive (BYTE * buffer, uint32_t size);
int32_t Cool_SetClockrate (int32_t mhz);
int32_t Cool_FastReset (void);
void * handle;
#endif
