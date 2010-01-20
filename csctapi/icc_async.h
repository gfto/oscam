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
#define ICC_ASYNC_OK            0
#define ICC_ASYNC_IFD_ERROR     1
#define ICC_ASYNC_ATR_ERROR     2

/* Card status */
#define IFD_TOWITOKO_NOCARD_NOCHANGE    0x00
#define IFD_TOWITOKO_CARD_NOCHANGE      0x40
#define IFD_TOWITOKO_NOCARD_CHANGE      0x80
#define IFD_TOWITOKO_CARD_CHANGE        0xC0
#define IFD_TOWITOKO_CARD(status)       (((status) & 0x40) == 0x40)
#define IFD_TOWITOKO_CHANGE(status)     (((status) & 0x80) == 0x80)

/*
 * Exported types definition
 */

typedef struct
{
  unsigned block_delay;          /* Delay (ms) after starting to transmit */
  unsigned char_delay;           /* Delay (ms) after transmiting each sucesive char*/
  unsigned block_timeout;        /* Max timeout (ms) to receive first char */
  unsigned char_timeout;         /* Max timeout (ms) to receive sucesive characters */
}
ICC_Async_Timings;

ATR *atr;                     /* Answer to reset of this ICC */
int convention;               /* Convention of this ICC */
BYTE protocol_type;		/* Type of protocol */
ICC_Async_Timings icc_timings;    /* Current timings for transmiting to this ICC */

/*
 * Exported functions declaration
 */

/* Initialization and Deactivation */
extern int ICC_Async_Init ();
extern int ICC_Async_Close ();

/* Attributes */
extern int ICC_Async_SetTimings (unsigned short bwt);
extern int ICC_Async_SetBaudrate (unsigned long baudrate);
extern unsigned long ICC_Async_GetClockRate ();

/* Operations */
extern int ICC_Async_Transmit (unsigned size, BYTE * buffer);
extern int ICC_Async_Receive (unsigned size, BYTE * buffer);

#endif /* _ICC_ASYNC_ */

