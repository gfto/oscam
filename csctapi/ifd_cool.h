/*
    ifd_cool.h
    Header file for Coolstream internal reader.
*/
#ifdef COOL

#include "atr.h"
int32_t Cool_Init (struct s_reader *reader);
int32_t Cool_Reset (struct s_reader *reader, ATR * atr);
int32_t Cool_Transmit (struct s_reader *reader, BYTE * buffer, uint32_t size);
int32_t Cool_Receive (struct s_reader *reader, BYTE * buffer, uint32_t size);
int32_t Cool_SetClockrate (struct s_reader *reader, int32_t mhz);
int32_t Cool_FastReset (struct s_reader *reader);
int32_t Cool_GetStatus (struct s_reader *reader, int32_t * in);
int32_t Cool_WriteSettings (struct s_reader *reader, uint32_t BWT, uint32_t CWT, uint32_t EGT, uint32_t BGT);
int32_t Cool_Close (struct s_reader *reader);
void * handle;
#endif
