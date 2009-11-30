/*
    cardterminal.h
    Card Terminal handling definitions

    This file is part of the Unix driver for Towitoko smartcard readers
    Copyright (C) 2000 Carlos Prados <cprados@yahoo.com>

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

#ifndef _CARDTERMINAL_
#define _CARDTERMINAL_

#include "defines.h"
#include "ct_slot.h"
#include "io_serial.h"
#include "apdu.h"
#include "ctapi.h"
#include "ctbcs.h"
#ifdef HAVE_PTHREAD_H
#include "pthread.h"
#endif

/* 
 * Exported constats definition
 */

/* Maximum number of slots in a cardterminal */
#define CARDTERMINAL_MAX_SLOTS		2

/*
 * Exported datatypes definition 
 */

typedef struct
{
  IO_Serial * io;				/* Serial device */
  CT_Slot * slots[CARDTERMINAL_MAX_SLOTS];	/* Array of CT_Slot's */
  int num_slots;				/* Number of CT_Slot's */
#ifdef HAVE_PTHREAD_H
  pthread_mutex_t mutex;
#endif
}
CardTerminal;

/*
 * Exported functions declaration
 */

/* Cretate a new CardTerminal */
extern CardTerminal *
CardTerminal_New ();

/* Intialice a CardTerminal in a given port */
extern char 
CardTerminal_Init (CardTerminal * ct, unsigned short pn, int reader_type, int mhz);

/* Send a CT-BCS command to a CardTerminal */
extern char
CardTerminal_Command (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp);

/* Return the reference to a slot */
extern CT_Slot *
CardTerminal_GetSlot (CardTerminal * ct, int number);

/* Close a CardTerminal */
extern char
CardTerminal_Close (CardTerminal * cn);

/* Delete a CardTerminal */
extern void 
CardTerminal_Delete (CardTerminal * ct);

#ifdef HAVE_PTHREAD_H
extern pthread_mutex_t *
CardTerminal_GetMutex (CardTerminal * ct);
#endif

#endif
