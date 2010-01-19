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

#include "defines.h"
#include "ct_slot.h"
#include "icc_async.h"
#include "protocol_t0.h"
#include "protocol_t1.h"
#include "pps.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

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

char CT_Slot_Init (CT_Slot * slot, int sn)
{
	if (!Phoenix_Init())
		return ERR_TRANS;
	
	return OK;
}

char CT_Slot_Check (CT_Slot * slot, uint timeout, bool * card, bool * change)
{
	BYTE status;
#ifdef HAVE_NANOSLEEP
	struct timespec req_ts;
	
	req_ts.tv_sec = 1;
	req_ts.tv_nsec = 0;
#endif
	
	/* Do first time check */
	if (ICC_Async_GetStatus (&status) != ICC_ASYNC_OK)
	{
		return ERR_TRANS;
	}

	(*change) = IFD_TOWITOKO_CHANGE (status);
	
	while ((timeout > 0) && (!IFD_TOWITOKO_CARD (status)))
	{
		timeout --;
		
#ifdef HAVE_NANOSLEEP
		/* Sleep one second */
		nanosleep (&req_ts,NULL);
#else
		usleep (1000);
#endif
		
		if (ICC_Async_GetStatus (&status) != ICC_ASYNC_OK)
			return ERR_TRANS;
		
		(*change) |= IFD_TOWITOKO_CHANGE (status);
	}
	
	(*card) = IFD_TOWITOKO_CARD (status);
	
	return OK;
}

char CT_Slot_Probe (CT_Slot * slot, BYTE * userdata, unsigned length)
{
	PPS * pps;
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
	if (slot->icc_type == CT_SLOT_ICC_ASYNC)
	{
		pps = PPS_New();
		
		if (pps == NULL)
		{
			ICC_Async_Close ();
			
			slot->icc = NULL;
			slot->icc_type = CT_SLOT_NULL;
			return ERR_MEMORY;
		}
		
		/* Prepare PPS request */
		if ((userdata != NULL) && (length > 0))
			memcpy (buffer, userdata, buffer_len = MIN(length, PPS_MAX_LENGTH));
		
		/* Do PPS */
		if (PPS_Perform (pps, buffer, &buffer_len) != PPS_OK)
		{
			PPS_Delete (pps);
			
			ICC_Async_Close ();
			
			slot->icc = NULL;
			slot->icc_type = CT_SLOT_NULL;
			slot->protocol_type = CT_SLOT_NULL;
			
			return ERR_TRANS;
		}
		
		slot->protocol_type = (PPS_GetProtocolParameters (pps))->t;
		slot->protocol = PPS_GetProtocol (pps);
		
		
		PPS_Delete (pps);
	}
	
	return OK;	
}

char CT_Slot_Release (CT_Slot * slot)
{
	char ret;
	
	ret = OK;
	
	slot->protocol = NULL;
	slot->protocol_type = CT_SLOT_NULL;
	
	if (slot->icc_type == CT_SLOT_ICC_ASYNC)
	{
		if (ICC_Async_Close () != ICC_ASYNC_OK)
			ret = ERR_TRANS;
	}
	
	slot->icc = NULL;
	slot->icc_type = CT_SLOT_NULL;
	
	return ret;
}

char CT_Slot_Command (CT_Slot * slot, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[2];
	char ret;
	
	if (slot->protocol_type == CT_SLOT_PROTOCOL_T0) /* T=0 protocol ICC */
	{
		if (Protocol_T0_Command (cmd, rsp) != PROTOCOL_T0_OK)
			ret = ERR_TRANS;
		else
			ret = OK;
	}
	else if (slot->protocol_type == CT_SLOT_PROTOCOL_T1) /* T=1 protocol ICC */
	{
		if (Protocol_T1_Command (cmd, rsp) != PROTOCOL_T1_OK)
			ret = ERR_TRANS;
		else
			ret = OK;
	}
	else if (slot->protocol_type == CT_SLOT_PROTOCOL_T14) /* T=14 protocol ICC */
	{
		if (Protocol_T14_Command (cmd, rsp) != PROTOCOL_T14_OK)
			ret = ERR_TRANS;
		else
			ret = OK;
	}
	else if (slot->protocol_type == CT_SLOT_NULL) /* Card removed */
	{
		buffer[0] = CTBCS_SW1_ICC_ERROR;
		buffer[1] = CTBCS_SW2_ICC_ERROR;
		
		(*rsp) = APDU_Rsp_New (buffer, 2);
		ret = OK;
	}
	else /* Other protocol */
	{
		(*rsp) = NULL;
		ret = ERR_HTSI;
	}
	
	return ret;
}

int CT_Slot_GetICCType (CT_Slot * slot)
{
	return slot->icc_type;
}

void * CT_Slot_GetICC (CT_Slot * slot)
{
	return slot->icc;
}

void * CT_Slot_GetAtr (CT_Slot * slot)
{
	if (slot->icc_type == CT_SLOT_ICC_ASYNC)
		return ((void *) atr );
		//return ((void *) ICC_Async_GetAtr((ICC_Async *) slot->icc));
	
	return NULL;
}

bool CT_Slot_IsLast (CT_Slot * slot)
{
	//return (IFD_Towitoko_GetSlot(slot->ifd) >= IFD_Towitoko_GetNumSlots()-1);
	return 1; //GetSlot always returns 0, and GetNumSlots returns always 1
}

void CT_Slot_GetType (CT_Slot * slot, BYTE * buffer, int len)
{
	//IFD_Towitoko_GetDescription (slot->ifd, buffer, len)
	buffer="dummy";
	len=5;
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
	slot->icc = NULL;
	slot->protocol = NULL;
	slot->icc_type = CT_SLOT_NULL;
	slot->protocol_type = CT_SLOT_NULL;
}
