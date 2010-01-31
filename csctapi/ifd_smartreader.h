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

#include "../globals.h"
#include "ftdi.h"
#include "atr.h"


int SR_Init (struct s_reader *reader);
int SR_GetStatus (struct s_reader *reader,int * in);
int SR_Reset (struct s_reader *reader, ATR * atr);
int SR_Transmit (struct s_reader *reader, BYTE * buffer, unsigned size);
int SR_Receive (struct s_reader *reader, BYTE * buffer, unsigned size);
int SR_SetBaudrate (struct s_reader *reader);
int SR_SetParity (struct s_reader *reader);
int SR_Close (struct s_reader *reader);

#endif // __SMARTREADER__
#endif // HAVE_LIBUSB && USE_PTHREAD
