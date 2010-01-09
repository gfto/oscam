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
#include "ifd_towitoko.h"
#include "atr.h"

/*
 * Exported constants definition
 */

/* Return codes */
#define ICC_ASYNC_OK            0
#define ICC_ASYNC_IFD_ERROR     1
#define ICC_ASYNC_ATR_ERROR     2

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

typedef struct
{
  IFD *ifd;                     /* Interface device */
  ATR *atr;                     /* Answer to reset of this ICC */
  int convention;               /* Convention of this ICC */
  unsigned long baudrate;	/* Current baudrate (bps) for transmiting to this ICC */
  ICC_Async_Timings timings;    /* Current timings for transmiting to this ICC */
  BYTE protocol_type;		/* Type of protocol */
}
ICC_Async;

/*
 * Exported functions declaration
 */

/* Creation and Deletion */
extern ICC_Async * ICC_Async_New (void);
extern void ICC_Async_Delete (ICC_Async * icc);

/* Initialization and Deactivation */
extern int ICC_Async_Init (ICC_Async * icc, IFD * ifd);
extern int ICC_Async_Close (ICC_Async * icc);

/* Attributes */
extern int ICC_Async_SetTimings (ICC_Async * icc, ICC_Async_Timings * timings);
extern int ICC_Async_GetTimings (ICC_Async * icc, ICC_Async_Timings * timings);
extern int ICC_Async_SetBaudrate (ICC_Async * icc, unsigned long baudrate);
extern int ICC_Async_GetBaudrate (ICC_Async * icc, unsigned long * baudrate);
extern ATR *ICC_Async_GetAtr (ICC_Async * icc);
extern IFD *ICC_Async_GetIFD (ICC_Async * icc);
extern unsigned long ICC_Async_GetClockRate (ICC_Async * icc);

/* Operations */
#ifndef NO_PAR_SWITCH
extern int ICC_Async_BeginTransmission (ICC_Async * icc);
extern int ICC_Async_EndTransmission (ICC_Async * icc);
#endif
extern int ICC_Async_Transmit (ICC_Async * icc, unsigned size, BYTE * buffer);
extern int ICC_Async_Receive (ICC_Async * icc, unsigned size, BYTE * buffer);

#endif /* _ICC_ASYNC_ */

