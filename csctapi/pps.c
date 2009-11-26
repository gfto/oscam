
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

static int PPS_Exchange(PPS * pps, BYTE * params, unsigned *length);

static bool PPS_Match(BYTE * request, unsigned len_request, BYTE * reply, unsigned len_reply);

static unsigned PPS_GetLength(BYTE * block);

static int PPS_InitICC(PPS * pps);

static int PPS_InitProtocol(PPS * pps);

static void PPS_SelectFirstProtocol(PPS * pps);

static BYTE PPS_GetPCK(BYTE * block, unsigned length);

/*
 * Exported functions definition
 */

PPS *PPS_New(ICC_Async * icc)
{
	PPS *pps;

	pps = (PPS *) malloc(sizeof (PPS));

	if (pps != NULL) {
		pps->icc = icc;
		pps->protocol = NULL;
		pps->parameters.t = PPS_DEFAULT_PROTOCOL;
		pps->parameters.f = ATR_DEFAULT_F;
		pps->parameters.d = ATR_DEFAULT_D;
		pps->parameters.n = ATR_DEFAULT_N;
	}

	return pps;
}

int PPS_PreformPTS(PPS *pps)
{
	int ret;
	unsigned long baudrate;
	BYTE req[4];
	BYTE confirm[PPS_MAX_LENGTH];
	ATR *atr;
	unsigned len_confirm;
	unsigned len_request=4;
	
	
	atr = ICC_Async_GetAtr(pps->icc);
	ATR_GetProtocolType(atr,0,&(pps->parameters.t));

	req[0]=0xFF;
    req[1]=0x10 | pps->parameters.t;
    req[2]=atr->ib[0][ATR_INTERFACE_BYTE_TA].value;
    req[3]=PPS_GetPCK(req,len_request-1);
	
#ifdef DEBUG_PROTOCOL
	printf("PTS: Sending request: ");
	for (i = 0; i < len_request; i++)
		printf("%X ", req[i]);
	printf("\n");
#endif
	
	/* Send PTS request */
	if (ICC_Async_Transmit(pps->icc, len_request, req) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;
	
	if (ICC_Async_Receive(pps->icc, len_request, confirm) != ICC_ASYNC_OK)
	{
#ifdef DEBUG_PROTOCOL
		printf("PTS: error receiving PTS answer !!\n");
#endif
		return PPS_ICC_ERROR;
	}
	
	len_confirm=len_request;
	
#ifdef DEBUG_PROTOCOL
	printf("PTS: Receiving confirm: ");
	for (i = 0; i < len_confirm; i++)
		printf("%X ", confirm[i]);
	printf("\n");
#endif
	
	if (!PPS_Match(req, len_request, confirm, len_confirm))
		ret = PPS_HANDSAKE_ERROR;
	else
		ret = PPS_OK;
	
	/* Copy PPS handsake */
	memcpy(req, confirm, len_confirm);
	
	// compute baudrate to be use if PTS handshake was successfull.
	baudrate=(long unsigned int)((float)ICC_Async_GetClockRate(pps->icc)*pps->parameters.d /pps->parameters.f);

	if (ICC_Async_SetBaudrate(pps->icc, baudrate) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;

	return ret;
}

int PPS_Perform(PPS * pps, BYTE * params, unsigned *length)
{
	ATR *atr;
	int ret;

	/* Perform PPS Exchange if requested */
	if ((*length) > 0) {
		ret = PPS_Exchange(pps, params, length);

		/* Get parameters from PPS handsake */
		if (ret == PPS_OK) {
			pps->parameters.t = params[1] & 0x0F;

			if (PPS_HAS_PPS1(params)) {
				pps->parameters.f = atr_f_table[(params[2] >> 4)];
				pps->parameters.d = atr_d_table[(params[2] & 0x0F)];
				if(pps->parameters.d==0)
				    {
				    // set pps->parameters.d to 1 as 0 is not a valid value
				    pps->parameters.d=ATR_DEFAULT_D;
				    }
#ifdef DEBUG_PROTOCOL
				printf("PPS: pps->parameters.n %f\n",pps->parameters.n);
				printf("PPS: pps->parameters.d %f\n",pps->parameters.d);
				printf("PPS: pps->parameters.f %f\n",pps->parameters.f);
				printf("PPS: Calling PPP_InitICC to set PPS params\n");
#endif        
			}

			ret = PPS_InitICC(pps);

			if (ret != PPS_OK)
				return ret;
		} else {
			return ret;
		}
	} else {	/* Get parameters from ATR */

		PPS_SelectFirstProtocol(pps);

#ifndef PPS_USE_DEFAULT_TIMINGS
		atr = ICC_Async_GetAtr(pps->icc);
#ifdef DEBUG_PROTOCOL
		printf("PPS: atr.lenght = %u\n",atr->length);
		printf("PPS: atr.TS = %u\n",atr->TS);
		printf("PPS: atr.T0 = %u\n",atr->T0);
		printf("PPS: atr.TA = %u\n",atr->ib[0][ATR_INTERFACE_BYTE_TA].value);
		printf("PPS: atr.FI = %u\n",(atr->ib[0][ATR_INTERFACE_BYTE_TA].value & 0xF0) >> 4);
		printf("PPS: atr.DI = %u\n",(atr->ib[0][ATR_INTERFACE_BYTE_TA].value & 0x0F));
#endif		
		ATR_GetParameter(atr, ATR_PARAMETER_N, &(pps->parameters.n));
		ATR_GetParameter(atr, ATR_PARAMETER_D, &(pps->parameters.d));
		ATR_GetParameter(atr, ATR_PARAMETER_F, &(pps->parameters.f));
        if(pps->parameters.d==0)
            {
            // set pps->parameters.d to 1 as 0 is not a valid value
            pps->parameters.d=ATR_DEFAULT_D;
            }

#ifdef DEBUG_PROTOCOL
		printf("PPS: pps->parameters.n %f\n",pps->parameters.n);
		printf("PPS: pps->parameters.d %f\n",pps->parameters.d);
		printf("PPS: pps->parameters.f %f\n",pps->parameters.f);
		printf("PPS: Calling PPP_InitICC to set PPS params\n");
#endif        
		ret = PPS_InitICC(pps);

		if (ret != PPS_OK)
			return ret;
#endif
	}

#ifdef DEBUG_PROTOCOL
	printf("PPS: T=%X, F=%.0f, D=%.6f, N=%.0f\n", pps->parameters.t, pps->parameters.f, pps->parameters.d, pps->parameters.n);
#endif

	/* Initialize selected protocol with selected parameters */
	ret = PPS_InitProtocol(pps);
/*
#ifdef DEBUG_PROTOCOL
	printf("PPS: Attempting PTS\n");
#endif
	if(PPS_PreformPTS(pps)==PPS_OK)
	{
		printf("PTS handcheck succeded.\n");
	}
	else
	{
		printf("PTS handcheck failed.\n");
	}
	
#ifdef DEBUG_PROTOCOL
	printf("PPS: pps->parameters.n %f\n",pps->parameters.n);
	printf("PPS: pps->parameters.d %f\n",pps->parameters.d);
	printf("PPS: pps->parameters.f %f\n",pps->parameters.f);
#endif
 */
	return ret;
}

void *PPS_GetProtocol(PPS * pps)
{
	return pps->protocol;
}

PPS_ProtocolParameters *PPS_GetProtocolParameters(PPS * pps)
{
	/* User must Remember not to reference this struct after removing PPS */
	return &(pps->parameters);
}

void PPS_Delete(PPS * pps)
{
	free(pps);
}

/*
 * Not exported funtions definition
 */

static int PPS_Exchange(PPS * pps, BYTE * params, unsigned *length)
{
	BYTE confirm[PPS_MAX_LENGTH];
	unsigned len_request, len_confirm;
	int ret;

#ifdef DEBUG_PROTOCOL
	int i;
#endif

	len_request = PPS_GetLength(params);
	params[len_request - 1] = PPS_GetPCK(params, len_request - 1);

#ifdef DEBUG_PROTOCOL
	printf("PPS: Sending request: ");
	for (i = 0; i < len_request; i++)
		printf("%X ", params[i]);
	printf("\n");
#endif

	/* Send PPS request */
	if (ICC_Async_Transmit(pps->icc, len_request, params) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;

	/* Get PPS confirm */
	if (ICC_Async_Receive(pps->icc, 2, confirm) != ICC_ASYNC_OK)
	{
#ifdef DEBUG_PROTOCOL
		printf("PPS: error receiving confirm !!\n");
#endif
		return PPS_ICC_ERROR;
	}
	len_confirm = PPS_GetLength(confirm);

	if (ICC_Async_Receive(pps->icc, len_confirm - 2, confirm + 2) != ICC_ASYNC_OK)
	{
#ifdef DEBUG_PROTOCOL
		printf("PPS: error receiving answer !!\n");
#endif
		return PPS_ICC_ERROR;
	}
	
#ifdef DEBUG_PROTOCOL
	printf("PPS: Receiving confirm: ");
	for (i = 0; i < len_confirm; i++)
		printf("%X ", confirm[i]);
	printf("\n");
#endif

	if (!PPS_Match(params, len_request, confirm, len_confirm))
		ret = PPS_HANDSAKE_ERROR;
	else
		ret = PPS_OK;

	/* Copy PPS handsake */
	memcpy(params, confirm, len_confirm);
	(*length) = len_confirm;

	return ret;
}

static bool PPS_Match(BYTE * request, unsigned len_request, BYTE * confirm, unsigned len_confirm)
{
	/* See if the reply differs from request */
	if ((len_request != len_confirm) || (!memcmp(request, confirm, len_request))) {
		/* See if the card specifies other than default FI and D */
		if ((PPS_HAS_PPS1(confirm)) && (confirm[2] != request[2]))
			return FALSE;
	}

	return TRUE;
}

static unsigned PPS_GetLength(BYTE * block)
{
	unsigned length = 3;

	if (PPS_HAS_PPS1(block))
		length++;

	if (PPS_HAS_PPS2(block))
		length++;

	if (PPS_HAS_PPS3(block))
		length++;

	return length;
}

static int PPS_InitICC(PPS * pps)
{
	unsigned long baudrate;
	long double work_etu;

	/* Work etu = (1/D) * (F/fs) * 1000 milliseconds */
	work_etu = (1000 * pps->parameters.f) / (pps->parameters.d * ICC_Async_GetClockRate(pps->icc));

	// FIXME : 
	// initializing the baudrate here is plain wrong.
	// the card inits MUST be done at 9600 bps 
	// and if , and only if, there is a PPS (or PTS) handshake
	// then we use this value for the new baudrate
	// The F and D parameter returned by the ATR are to be used ONLY
	// if a PPS or PTS exchange is done, otherwize everything MUST
	// be done at 9600 bps
	// this mean we need to fix the logic around the card reset
	// as for now it uses this new rate in the midle of the reset just after getting the ATR
	// which doesn't work for example with a card returning 3F 77 18 .. as in this case
	// F=372 and D=12 (see the commented atr_d_table in atr.c which has the right value
	// as the curent one as 0 for the index 8 which is of course wrong as D=0 is an invalid value).
	// I'm leaving it like this until we discuss what to do as a rework of the code is needed.
	// 
	
	/* Baudrate = 1000 / etu bps */
	baudrate = (long unsigned int) (1000 / work_etu);

#ifdef DEBUG_PROTOCOL
	printf("PPS: Baudrate = %d\n", (int) baudrate);
#endif

	if (ICC_Async_SetBaudrate(pps->icc, baudrate) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;

	return PPS_OK;
}

static int PPS_InitProtocol(PPS * pps)
{
	int ret;

	if (pps->parameters.t == ATR_PROTOCOL_TYPE_T0) {
		pps->protocol = Protocol_T0_New();

		if ((pps->protocol) != NULL) {
			ret = Protocol_T0_Init((Protocol_T0 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters));

			if (ret != PROTOCOL_T0_OK) {
				Protocol_T0_Delete((Protocol_T0 *) pps->protocol);
				pps->protocol = NULL;
				return PPS_PROTOCOL_ERROR;
			}

			return PPS_OK;
		}
	} else if (pps->parameters.t == ATR_PROTOCOL_TYPE_T1) {
		pps->protocol = Protocol_T1_New();

		if (pps->protocol != NULL) {
			ret = Protocol_T1_Init((Protocol_T1 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters));

			if (ret != PROTOCOL_T1_OK) {
				Protocol_T1_Delete((Protocol_T1 *) pps->protocol);
				pps->protocol = NULL;
				return PPS_PROTOCOL_ERROR;
			}

			return PPS_OK;
		}
	} else if (pps->parameters.t == ATR_PROTOCOL_TYPE_T14) {
		pps->protocol = Protocol_T14_New();

		if ((pps->protocol) != NULL) {
			ret = Protocol_T14_Init((Protocol_T14 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters));

			if (ret != PROTOCOL_T14_OK) {
				Protocol_T14_Delete((Protocol_T14 *) pps->protocol);
				pps->protocol = NULL;
				return PPS_PROTOCOL_ERROR;
			}

			return PPS_OK;
		}
	} else {
		pps->protocol = NULL;
	}

	return PPS_PROTOCOL_ERROR;
}

static void PPS_SelectFirstProtocol(PPS * pps)
{
	ATR *atr = ICC_Async_GetAtr(pps->icc);
	unsigned np;

	pps->parameters.t = ATR_PROTOCOL_TYPE_T0;

	ATR_GetNumberOfProtocols(atr, &np);

	/* 
	 * Get protocol offered by interface bytes T*2 if available, 
	 * (that is, if TD1 is available), * otherwise use default T=0
	 */
	if (np > 1)
		ATR_GetProtocolType(atr, 2, &(pps->parameters.t));

#ifdef DEBUG_PROTOCOL
	printf("PPS: Protocol T=%d selected\n", pps->parameters.t);
#endif
}

static BYTE PPS_GetPCK(BYTE * block, unsigned length)
{
	BYTE pck;
	unsigned i;

	pck = block[0];
	for (i = 1; i < length; i++)
		pck ^= block[i];

	return pck;
}
