/*
    pps.c
    Protocol Parameters Selection
  
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

#include "pps.h"
#include "atr.h"
#include "protocol_t0.h"
#include "protocol_t1.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Not exported constants definition
 */

#define PPS_DEFAULT_PROTOCOL	0x00

/*
 * Not exported macros definition
 */

#define PPS_HAS_PPS1(block)	((block[1] & 0x10) == 0x10)
#define PPS_HAS_PPS2(block)	((block[1] & 0x20) == 0x20)
#define PPS_HAS_PPS3(block)	((block[1] & 0x40) == 0x40)

/*
 * Not exported funtions declaration
 */

static int PPS_Exchange (PPS * pps, BYTE * params, unsigned *length);

static bool PPS_Match (BYTE * request, unsigned len_request, BYTE * reply, unsigned len_reply);

static unsigned PPS_GetLength (BYTE * block);

static int PPS_InitICC (PPS * pps);

static int PPS_InitProtocol (PPS * pps);

static void PPS_SelectFirstProtocol (PPS * pps);

static BYTE PPS_GetPCK (BYTE * block, unsigned length);

/*
 * Exported functions definition
 */

PPS * PPS_New (ICC_Async * icc)
{
	PPS *pps;
	
	pps = (PPS *) malloc (sizeof (PPS));
	
	if (pps != NULL)
	{
		pps->icc = icc;
		pps->protocol = NULL;
		pps->parameters.t = PPS_DEFAULT_PROTOCOL;
		pps->parameters.f = ATR_DEFAULT_F;
		pps->parameters.d = ATR_DEFAULT_D;
		pps->parameters.n = ATR_DEFAULT_N;
	}
	
	return pps;
}

int PPS_Perform (PPS * pps, BYTE * params, unsigned *length)
{
	ATR *atr;
	int ret = PPS_HANDSAKE_ERROR;
	
	/* Perform PPS Exchange if requested */
	if ((*length) > 0)
	{
		ret = PPS_Exchange (pps, params, length);
		
		/* Get parameters from PPS handsake */
		if (ret == PPS_OK)
		{
			pps->parameters.t = params[1] & 0x0F;
			
			if (PPS_HAS_PPS1 (params))
			{
				pps->parameters.f = atr_f_table[(params[2] >> 4)];
				pps->parameters.d = atr_d_table[(params[2] & 0x0F)];
			}
			
/*			
			ret  = PPS_InitICC(pps);
			
			if (ret != PPS_OK)
				return ret;
*/
		}
/*		
		else
		{
			return ret;
		}
*/
	}
	if ((*length) <= 0 || ret != PPS_OK) /* Get parameters from ATR */
	{
		PPS_SelectFirstProtocol (pps);
		
#ifndef PTS_USE_DEFAULT_TIMINGS
		atr = ICC_Async_GetAtr (pps->icc);
		
		ATR_GetParameter (atr, ATR_PARAMETER_N, &(pps->parameters.n));
		ATR_GetParameter (atr, ATR_PARAMETER_D, &(pps->parameters.d));
		ATR_GetParameter (atr, ATR_PARAMETER_F, &(pps->parameters.f));
#endif
	}
	
	ret  = PPS_InitICC(pps);
			
	if (ret != PPS_OK)
		return ret;
	
#ifdef DEBUG_PROTOCOL
	printf("PPS: T=%X, F=%.0f, D=%.6f, N=%.0f\n", 
	pps->parameters.t, 
	pps->parameters.f, 
	pps->parameters.d, 
	pps->parameters.n);
#endif
	
	/* Initialize selected protocol with selected parameters */
	ret = PPS_InitProtocol (pps);
	
	return ret;
}

void * PPS_GetProtocol (PPS * pps)
{
	return pps->protocol;
}

PPS_ProtocolParameters *PPS_GetProtocolParameters (PPS * pps)
{
	/* User must Remember not to reference this struct after removing PPS */
	return &(pps->parameters);
}

void PPS_Delete (PPS * pps)
{
	free (pps);
}

/*
 * Not exported funtions definition
 */

static int PPS_Exchange (PPS * pps, BYTE * params, unsigned *length)
{
	BYTE confirm[PPS_MAX_LENGTH];
	unsigned len_request, len_confirm;
	int ret;
#ifdef DEBUG_PROTOCOL
	int i;
#endif
	
	len_request = PPS_GetLength (params);
	params[len_request - 1] = PPS_GetPCK(params, len_request - 1);
	
#ifdef DEBUG_PROTOCOL
	printf ("PPS: Sending request: ");
	for (i = 0; i < len_request; i++)
		printf ("%X ", params[i]);
	printf ("\n");
#endif
	
	/* Send PPS request */
	if (ICC_Async_Transmit (pps->icc, len_request, params) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;
	
	/* Get PPS confirm */
	if (ICC_Async_Receive (pps->icc, 2, confirm) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;
	
	len_confirm = PPS_GetLength (confirm);
	
	if (ICC_Async_Receive (pps->icc, len_confirm - 2, confirm + 2) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;
	
#ifdef DEBUG_PROTOCOL
	printf ("PPS: Receivig confirm: ");
	for (i = 0; i < len_confirm; i++)
		printf ("%X ", confirm[i]);
	printf ("\n");
#endif
	
	if (!PPS_Match (params, len_request, confirm, len_confirm))
		ret = PPS_HANDSAKE_ERROR;
	else
		ret = PPS_OK;
	
	/* Copy PPS handsake */
	memcpy (params, confirm, len_confirm);
	(*length) = len_confirm;
	
	return ret;
}

static bool PPS_Match (BYTE * request, unsigned len_request, BYTE * confirm, unsigned len_confirm)
{
	/* See if the reply differs from request */
	if ((len_request != len_confirm) || (!memcmp (request, confirm, len_request)))
	{
		/* See if the card specifies other than default FI and D */
		if ((PPS_HAS_PPS1 (confirm)) && (confirm[2] != request[2]))
			return FALSE;
	}
	
	return TRUE;
}

static unsigned PPS_GetLength (BYTE * block)
{
	unsigned length = 3;
	
	if (PPS_HAS_PPS1 (block))
	length++;
	
	if (PPS_HAS_PPS2 (block))
	length++;
	
	if (PPS_HAS_PPS3 (block))
	length++;
	
	return length;
}

static int PPS_InitICC (PPS * pps)
{
#ifdef SCI_DEV
        //case readertype = internal
	//code for setting parameters to SCI_DEV (currently in ifd_towitoko.c in ResetAsync_ICC should be placed here
	//if ok return PPS_OK;
	//else return PPS_ICC_ERROR;
	//
#endif
	unsigned long baudrate;

	baudrate = pps->parameters.d * ICC_Async_GetClockRate (pps->icc) / pps->parameters.f; 
	//FIXME notice that cardmhz is taken into account here
	//not sure whether that goes ok when cardmhz = 600
	//if not then IFD_GetClockRate should be devaluated to returning the DEFINED 372L * 9600L (like it usd to be..)

#ifdef DEBUG_PROTOCOL
	printf ("PPS: Baudrate = %d\n", (int)baudrate);
#endif
	

	//FIXME currently for SCI_DEV Setbaudrate is dummied
	//but it should be something like
	//case readertype = smart:
	//case readertype = mouse:
	if (ICC_Async_SetBaudrate (pps->icc, baudrate) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;
	
	return PPS_OK;
}

static int PPS_InitProtocol (PPS * pps)
{
	int ret;
	
	if (pps->parameters.t == ATR_PROTOCOL_TYPE_T0)
	{
		pps->protocol = Protocol_T0_New ();
		
		if ((pps->protocol) != NULL)
		{
			ret = Protocol_T0_Init ((Protocol_T0 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters));
			
			if (ret != PROTOCOL_T0_OK)
			{
				Protocol_T0_Delete ((Protocol_T0 *) pps->protocol);
				pps->protocol = NULL;
				return PPS_PROTOCOL_ERROR;
			}
			
			return PPS_OK;
		}		
	}
	else if (pps->parameters.t == ATR_PROTOCOL_TYPE_T1)
	{
		pps->protocol = Protocol_T1_New ();
		
		if (pps->protocol != NULL)
		{
			ret = Protocol_T1_Init ((Protocol_T1 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters));
			
			if (ret != PROTOCOL_T1_OK)
			{
				Protocol_T1_Delete ((Protocol_T1 *) pps->protocol);
				pps->protocol = NULL;
				return PPS_PROTOCOL_ERROR;
			}
			
			return PPS_OK;
		}
	}
	else if (pps->parameters.t == ATR_PROTOCOL_TYPE_T14)
	{
		pps->protocol = Protocol_T14_New ();
		
		if ((pps->protocol) != NULL)
		{
			ret = Protocol_T14_Init ((Protocol_T14 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters));
			
			if (ret != PROTOCOL_T14_OK)
			{
				Protocol_T14_Delete ((Protocol_T14 *) pps->protocol);
				pps->protocol = NULL;
				return PPS_PROTOCOL_ERROR;
			}
			
			return PPS_OK;
		}		
	}
	else
	{
		pps->protocol = NULL;
	}
	
	return PPS_PROTOCOL_ERROR;
}

static void PPS_SelectFirstProtocol (PPS * pps)
{
	ATR *atr = ICC_Async_GetAtr (pps->icc);
	unsigned np;
	
	pps->parameters.t = ATR_PROTOCOL_TYPE_T0;
	
	ATR_GetNumberOfProtocols (atr, &np);
	
	/* 
	* Get protocol offered by interface bytes T*2 if available, 
	* (that is, if TD1 is available), * otherwise use default T=0
	*/
	if (np>1)
		ATR_GetProtocolType (atr, 2, &(pps->parameters.t));
	
#ifdef DEBUG_PROTOCOL
	printf ("PPS: Protocol T=%d selected\n", pps->parameters.t);
#endif
}

static BYTE PPS_GetPCK (BYTE * block, unsigned length)
{
	BYTE pck;
	unsigned i;
	
	pck = block[0];
	for (i = 1; i < length; i++)
		pck ^= block[i];
	
	return pck;
}
