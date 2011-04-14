/*
    ifd_smartreader.h
    Header file for Argolis smartreader+.
*/
#if defined(LIBUSB)
#ifndef __SMARTREADER__
#define __SMARTREADER__

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>

#include <pthread.h>
#include <memory.h>
#ifdef __FreeBSD__
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif
#include "../globals.h"
#include "atr.h"

#include "smartreader_types.h"

int32_t SR_Init (struct s_reader *reader);
int32_t SR_GetStatus (struct s_reader *reader,int32_t * in);
int32_t SR_Reset (struct s_reader *reader, ATR * atr);
int32_t SR_Transmit (struct s_reader *reader, BYTE * buffer, uint32_t size);
int32_t SR_Receive (struct s_reader *reader, BYTE * buffer, uint32_t size);
int32_t SR_SetBaudrate (struct s_reader *reader);
int32_t SR_SetParity (struct s_reader *reader, uint16_t parity);
int32_t SR_Close (struct s_reader *reader);
int32_t SR_FastReset(struct s_reader *reader, int32_t delay);

#endif // __SMARTREADER__
#endif // HAVE_LIBUSB
