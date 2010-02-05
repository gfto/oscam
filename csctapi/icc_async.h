/*
    icc_async.h
    Asynchronous integrated circuit cards handling functions

    This file is part of the Unix driver for Towitoko smartcard readers
    Copyright (C) 2000 2001 Carlos Prados <cprados@yahoo.com>

    This version is modified by doz21 to work in a special manner ;)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _ICC_ASYNC_
#define _ICC_ASYNC_

#include "defines.h"
#include "atr.h"

/*
 * Exported constants definition
 */

/* Return codes */
#define OK		0
#define ERROR	1

#define ATR_TIMEOUT				800
#define DEFAULT_BAUDRATE	9600
/*
 * Exported types definition
 */

typedef struct
{
  unsigned block_delay;          /* Delay (ms) after starting to transmit */
  unsigned char_delay;           /* Delay (ms) after transmiting each sucesive char*/
}
ICC_Async_Timings;

int convention;               /* Convention of this ICC */
BYTE protocol_type;		/* Type of protocol */
ICC_Async_Timings icc_timings;    /* Current timings for transmiting to this ICC */
unsigned short BWT,CWT; //(for overclocking uncorrected) block waiting time, character waiting time, in ETU
unsigned long current_baudrate; //(for overclocking uncorrected) baudrate to prevent unnecessary conversions from/to termios structure
unsigned int read_timeout;		// Max timeout (ms) to receive characters

/*
 * Exported functions declaration
 */

/* Initialization and Deactivation */
extern int ICC_Async_Activate (ATR * newatr, unsigned short deprecated);
extern int ICC_Async_Close (void);
int ICC_Async_Device_Init (void);

/* Attributes */
int ICC_Async_SetTimings (unsigned wait_etu);
extern int ICC_Async_SetBaudrate (unsigned long baudrate);
extern unsigned long ICC_Async_GetClockRate (void);
int ICC_Async_GetStatus (int * has_card);


/* Operations */
int ICC_Async_CardWrite (unsigned char *cmd, unsigned short lc, unsigned char *rsp, unsigned short *lr);
extern int ICC_Async_Transmit (unsigned size, BYTE * buffer);
extern int ICC_Async_Receive (unsigned size, BYTE * buffer);

#endif /* _ICC_ASYNC_ */

