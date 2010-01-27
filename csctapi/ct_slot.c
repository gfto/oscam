/*
    ct_slot.c
    Card Terminal Slot handling functions

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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
// globals.h is needed on some platform for uint and other defs.. they need to move to oscam-types.h
#include "../globals.h"
#include "defines.h"
#include "ct_slot.h"
#include "icc_async.h"
#include "protocol_t0.h"
#include "protocol_t1.h"
#include "pps.h"
#include "ifd.h"

/* Card status *///FIXME simplify this + duplicate in icc_async.h
#define IFD_TOWITOKO_CARD(status)       (((status) & 0x40) == 0x40)
#define IFD_TOWITOKO_CHANGE(status)     (((status) & 0x80) == 0x80)

/* Try first asynchronous init and if it fails try synchronous */
//#undef ICC_PROBE_ASYNC_FIRST
//#define ICC_PROBE_ASYNC_FIRST

/*
 * Not exported functions declaration
 */

static void  CT_Slot_Clear (CT_Slot * slot);

/*
 * Exported functions definition
 */

CT_Slot * CT_Slot_New ()
{
	CT_Slot *slot;
	
	slot = (CT_Slot *) malloc (sizeof (CT_Slot));
	
	if (slot != NULL)
		CT_Slot_Clear (slot);
	
	return slot;
}

char CT_Slot_Init ()
{
	if (!Phoenix_Init())
		return ERR_TRANS;
	
	return OK;
}

char CT_Slot_Check (bool * card, bool * change)
{
	BYTE status;
	
	if (ICC_Async_GetStatus (&status) != ICC_ASYNC_OK)
		return ERR_TRANS;
	(*change) = IFD_TOWITOKO_CHANGE (status);
	(*card) = IFD_TOWITOKO_CARD (status);
	return OK;
}

char CT_Slot_Probe (CT_Slot * slot, BYTE * userdata, unsigned length)
{
	//PPS * pps;
	BYTE buffer[PPS_MAX_LENGTH];
	unsigned buffer_len  = 0;
	
	if (ICC_Async_Init () != ICC_ASYNC_OK)
	{
		return ERR_TRANS;
		
		/* Synchronous card present */
//		slot->icc_type = CT_SLOT_ICC_SYNC;
	}
	else
	{
		/* Asyncronous card present */
		slot->icc_type = CT_SLOT_ICC_ASYNC;
	}
	
	
	/* Initialise protocol */
	{
		/* Prepare PPS request */
		if ((userdata != NULL) && (length > 0))
			memcpy (buffer, userdata, buffer_len = MIN(length, PPS_MAX_LENGTH));
		
		/* Do PPS */
		if (PPS_Perform (buffer, &buffer_len) != PPS_OK)
		{
			ICC_Async_Close ();
			
			slot->icc_type = CT_SLOT_NULL;
			
			return ERR_TRANS;
		}
	}
	
	return OK;	
}

char CT_Slot_Release (CT_Slot * slot)
{
	char ret;
	
	ret = OK;
	
	if (slot->icc_type == CT_SLOT_ICC_ASYNC)
	{
		if (ICC_Async_Close () != ICC_ASYNC_OK)
			ret = ERR_TRANS;
	}
	
	slot->icc_type = CT_SLOT_NULL;
	
	return ret;
}

int CT_Slot_GetICCType (CT_Slot * slot)
{
	return slot->icc_type;
}

void * CT_Slot_GetAtr (CT_Slot * slot)
{
	if (slot->icc_type == CT_SLOT_ICC_ASYNC)
		return ((void *) atr );
		//return ((void *) ICC_Async_GetAtr((ICC_Async *) slot->icc));
	
	return NULL;
}

char CT_Slot_Close (CT_Slot * slot)
{
	char ret; 
	
	ret = OK;
	
	if (slot->icc_type == CT_SLOT_ICC_ASYNC)
	{
		if (ICC_Async_Close () != ICC_ASYNC_OK)
			ret = ERR_TRANS;
	}
	
		if (!Phoenix_Close ())
			ret = ERR_TRANS;
	
	CT_Slot_Clear (slot);
	
	return ret;
}

void CT_Slot_Delete (CT_Slot * slot)
{
	free (slot);
}

/*
 * Not exported functions definition
 */

static void CT_Slot_Clear (CT_Slot * slot)
{
	slot->icc_type = CT_SLOT_NULL;
}
