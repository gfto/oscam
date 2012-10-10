/*
    ifd_smartreader.h
    Header file for Argolis smartreader+.
*/
#ifndef __SMARTREADER__
#define __SMARTREADER__

#include <memory.h>

#ifdef WITH_LIBUSB
#if defined(__FreeBSD__)
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif
#endif

#include "smartreader_types.h"

int32_t SR_Init (struct s_reader *reader);
int32_t SR_GetStatus (struct s_reader *reader,int32_t * in);
int32_t SR_Reset (struct s_reader *reader, ATR * atr);
int32_t SR_Transmit (struct s_reader *reader, unsigned char * buffer, uint32_t size);
int32_t SR_Receive (struct s_reader *reader, unsigned char * buffer, uint32_t size);
int32_t SR_SetBaudrate (struct s_reader *reader);
int32_t SR_SetParity (struct s_reader *reader, uint16_t parity);
int32_t SR_Close (struct s_reader *reader);
int32_t SR_FastReset(struct s_reader *reader, int32_t delay);
int32_t SR_FastReset_With_ATR(struct s_reader *reader, ATR *atr);
int32_t SR_WriteSettings (struct s_reader *reader, uint16_t F, unsigned char D, unsigned char N, unsigned char T, uint16_t convention);

#endif // __SMARTREADER__
