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

static int PPS_InitICC (PPS * pps, int protocol_selected);

static int PPS_InitProtocol (PPS * pps, int protocol_selected);

//static void PPS_SelectFirstProtocol (PPS * pps);

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
		pps->parameters.FI = ATR_DEFAULT_FI;
		pps->parameters.d = ATR_DEFAULT_D;
		pps->parameters.n = ATR_DEFAULT_N;
	}
	
	return pps;
}

int PPS_Perform (PPS * pps, BYTE * params, unsigned *length)
{
	//Performs PPS Exchange on command when *length >0
	//If unsuccesfull, or when length <= 0
	//Gets parametes from ATR
	//If necessary perform PPS session
	//
	//Output is pps->params.FI,n,d,t set with correct values
	//and switched SC-device conform these values to correct baudrate
	//
	//We need to store FI instread of F, because SCI_DEV works with FI
	//and it is easier to overclock then
	//also from FI -> F is easy, other way around not
	
	ATR *atr;
	int ret;
	bool PPS_success; 
	
	/* Perform PPS Exchange if requested by command */
	if ((*length) > 0)
	{
		ret = PPS_Exchange (pps, params, length);
		
		/* Get parameters from PPS handsake */
		if (ret == PPS_OK)
		{
			pps->parameters.t = params[1] & 0x0F;
			
			if (PPS_HAS_PPS1 (params))
			{
				pps->parameters.FI = (params[2] >> 4);
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
	PPS_success = PPS_OK;
	int protocol_selected = 0; //stores which TAi,TBi etc. bytes must be used 0 means not set
	atr = ICC_Async_GetAtr (pps->icc);
	if ((*length) <= 0 || !PPS_success) // If not by command, or PPS Exchange by command failed: Try PPS Exchange by ATR or Get parameters from ATR
	{
		int numprot = atr->pn;
		BYTE tx;
	  cs_debug("ATR reports smartcard supports %i protocols:",numprot);
		int i,point;
		char txt[50];
		for (i=1; i<= numprot; i++) {
			sprintf(txt,"Protocol %01i:  ",i);
			point = 12;
			if (ATR_GetInterfaceByte (atr, i, ATR_INTERFACE_BYTE_TA, &tx) == ATR_OK) {
			  sprintf((char *)txt+point,"TA%i=%02X ",i,tx);
				point +=7;
			}
			if (ATR_GetInterfaceByte (atr, i, ATR_INTERFACE_BYTE_TB, &tx) == ATR_OK) {
			  sprintf((char *)txt+point,"TB%i=%02X ",i,tx);
				point +=7;
			}
			if (ATR_GetInterfaceByte (atr, i, ATR_INTERFACE_BYTE_TC, &tx) == ATR_OK) {
			  sprintf((char *)txt+point,"TC%i=%02X ",i,tx);
				point +=7;
			}
			if (ATR_GetInterfaceByte (atr, i, ATR_INTERFACE_BYTE_TD, &tx) == ATR_OK) {
			  sprintf((char *)txt+point,"TD%i=%02X ",i,tx);
				point +=7;
			  sprintf((char *)txt+point,"(T%i)",tx&0x0F);
			}
			else
				sprintf((char *)txt+point,"no TD%i means T0",i);
			cs_debug("%s",txt);
		}

//If more than one protocol type and/or TA1 parameter values other than the default values and/or N equeal to 255 is/are indicated in the answer to reset, the card shall know unambiguously, after having sent the answer to reset, which protocol type or/and transmission parameter values (FI, D, N) will be used. Consequently a selection of the protocol type and/or the transmission parameters values shall be specified.
		ATR_GetParameter (atr, ATR_PARAMETER_N, &(pps->parameters.n));
		ATR_GetProtocolType(atr,2,&(pps->parameters.t)); //get protocol from TD1
		if ((numprot > 1) && (pps->icc->ifd->io->com != RTYP_SCI) && (pps->parameters.t != 14) && ((atr->ib[0][ATR_INTERFACE_BYTE_TA].present == TRUE && atr->ib[0][ATR_INTERFACE_BYTE_TA].value != 0x11) || pps->parameters.n == 255)) {
			//             PTSS  PTS0  PTS1  PTS2  PTS3  PCK
			//             PTSS  PTS0  PTS1  PCK
			BYTE req[] = { 0xFF, 0x10, 0x00, 0x00 }; //we currently do not support PTS2, standard guardtimes

			int p; 
			for (p=1; p<=numprot; p++) {
				if (p == 1)
					pps->parameters.t = 0; //default T0 protocol
				else
				  ATR_GetProtocolType(atr,p+1,&(pps->parameters.t)); //get protocol from TDi //FIXME p+1 is needed for flaw in atr.c
				//if (pps->parameters.t == 14) 
				//	continue; //skip T14!!!
				req[1]=0x10 | pps->parameters.t; //PTS0 always flags PTS1 to be sent always
				if (ATR_GetInterfaceByte (atr, p, ATR_INTERFACE_BYTE_TA, &req[2]) != ATR_OK)  //PTS1 
					req[2] = 0x11; //defaults FI and DI to 1
	  		//req[3]=PPS_GetPCK(req,sizeof(req)-1); will be set by PPS_Exchange
				unsigned int len = sizeof(req);
				ret = PPS_Exchange (pps, req, &len);
		  	if (ret == PPS_OK) {
					pps->parameters.FI = req[2] >> 4;
					BYTE DI = req[2] & 0x0F;
					pps->parameters.d = (double) (atr_d_table[DI]);
					PPS_success = TRUE;
					protocol_selected = p;
					cs_debug("PTS Succesfull, selected protocol %i: T%i, F=%.0f, D=%.6f, N=%.0f\n", protocol_selected, pps->parameters.t, (double) atr_f_table[pps->parameters.FI], pps->parameters.d, pps->parameters.n);
					break;
				}
				else
					cs_ddump(req,4,"PTS Failure for protocol %i, response:",p);
			}
		}
		//FIXME Currently InitICC sets baudrate to 9600 for all T14 cards, which is the old behaviour...
		if (!PPS_success) {//last PPS not succesfull
			BYTE TA1;
			if ((numprot > 1) && ATR_GetInterfaceByte (atr, 1 , ATR_INTERFACE_BYTE_TA, &TA1) == ATR_OK && pps->parameters.t != 14) { //do not obey TA1 if T14 and no PTS 
				pps->parameters.FI = TA1 >> 4;
				ATR_GetParameter (atr, ATR_PARAMETER_D, &(pps->parameters.d));
			}
			else {
				pps->parameters.FI = ATR_DEFAULT_FI;
				pps->parameters.d = ATR_DEFAULT_D;
			}
			// Get protocol offered by interface bytes T*2 if TD1 available,
			// FIXME or would it be wiser to not switch anything and stick to 9600? 
			ATR_GetProtocolType (atr, 2, &(pps->parameters.t));
			protocol_selected = 1;
			cs_debug("No PTS, selected protocol 1: T%i, F=%.0f, D=%.6f, N=%.0f\n", pps->parameters.t, (double) atr_f_table[pps->parameters.FI], pps->parameters.d, pps->parameters.n);
		}
	}//end length<0
		
	//make sure no zero values
	double F =  (double) atr_f_table[pps->parameters.FI];
	if (!F) {
		pps->parameters.FI = ATR_DEFAULT_FI;
		cs_log("Warning: F=0 is invalid, forcing F=%.0f",F);
	}
	if (!pps->parameters.d) {
		pps->parameters.d = ATR_DEFAULT_D;
		cs_log("Warning: D=0 is invalid, forcing D=%.0f",pps->parameters.d);
	}

	pps->icc->protocol_type = pps->parameters.t;
	
#ifdef DEBUG_PROTOCOL
	printf("PPS: T=%i, F=%.0f, D=%.6f, N=%.0f\n", 
	pps->parameters.t, 
	F, 
	pps->parameters.d, 
	pps->parameters.n);
#endif

	ret  = PPS_InitICC(pps, protocol_selected);
			
	if (ret != PPS_OK)
		return ret;
	
	/* Initialize selected protocol with selected parameters */
	ret = PPS_InitProtocol (pps, protocol_selected);
	
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

	cs_debug("PTS: Sending request: %s", cs_hexdump(1, params, len_request));
	
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
	
	cs_debug("PTS: Receiving confirm: %s", cs_hexdump(1, confirm, len_confirm));
	
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
	if ((len_request != len_confirm) || (memcmp (request, confirm, len_request)))
	{
		/* See if the card specifies other than default FI and D */
		//if ((PPS_HAS_PPS1 (confirm)) && (confirm[2] != request[2]))
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

static int PPS_InitICC (PPS * pps, int selected_protocol)
{
#ifdef SCI_DEV
#include <sys/ioctl.h>
#include "sci_global.h"
#include "sci_ioctl.h"
	if(pps->icc->ifd->io->com==RTYP_SCI)
	{
		int n;
		SCI_PARAMETERS params;
		int m;
		//memset(&params,0,sizeof(SCI_PARAMETERS));
		if (ioctl(pps->icc->ifd->io->fd, IOCTL_GET_PARAMETERS, &params) < 0 )
			return PPS_ICC_ERROR;

    		ATR *atr = ICC_Async_GetAtr (pps->icc);

		params.T = pps->parameters.t;

    		BYTE oldFI = params.FI;
//		params.FI = pps->parameters.FI; //somehow setting this gets "card unsupported" 
/*		if (pps->icc->ifd->io->mhz > 368) {
			int number_of_overclock_steps = ((pps->icc->ifd->io->mhz)/200) - 2; //600 is 1 overclock, 800 2 overclocks etc.
			do 
			{
				if (params.FI != 1 && params.FI != 9)
					params.FI --;
				number_of_overclock_steps --;
			} while (number_of_overclock_steps > 0);
		}*/
		if (pps->icc->ifd->io->mhz == 600)
			params.FI = 5; //routine above should be tested so hardcoding can get removed

		if (oldFI != params.FI)
		  cs_log("Forcing params.FI from %i to %i", oldFI, params.FI);

	  	double F =  (double) atr_f_table[pps->parameters.FI];
		params.ETU = F / pps->parameters.d;
		if (pps->parameters.n == 255)
			params.EGT = 0;
		else
			params.EGT = pps->parameters.n;

		double a;
		ATR_GetParameter(atr, ATR_PARAMETER_P, &a);
		params.P=(unsigned char)a;
		ATR_GetParameter(atr, ATR_PARAMETER_I, &a);
		params.I=(unsigned char)a;

		if (ioctl(pps->icc->ifd->io->fd, IOCTL_SET_PARAMETERS, &params)!=0)
			return PPS_ICC_ERROR;
			
		ioctl(pps->icc->ifd->io->fd, IOCTL_GET_PARAMETERS, &params);
			
		cs_debug("T=%d f=%d ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d", (int)params.T,(int)atr_f_table[pps->parameters.FI], (int)params.ETU, (int)params.WWT, (int)params.CWT, (int)params.BWT, (int)params.EGT, (int)params.clock_stop_polarity, (int)params.check, (int)params.P, (int)params.I, (int)params.U);
	}
#endif
	{
	unsigned long baudrate;
	double F =  (double) atr_f_table[pps->parameters.FI];
	if (pps->parameters.t == 14)
		baudrate = 9600;
	else
		baudrate = pps->parameters.d * ICC_Async_GetClockRate (pps->icc) / F; 

#ifdef DEBUG_PROTOCOL
	printf ("PPS: Baudrate = %d\n", (int)baudrate);
#endif
	

	if (ICC_Async_SetBaudrate (pps->icc, baudrate) != ICC_ASYNC_OK)
		return PPS_ICC_ERROR;
	
	return PPS_OK;
	}
}

static int PPS_InitProtocol (PPS * pps, int selected_protocol)
{
	int ret;
	
	if (pps->parameters.t == ATR_PROTOCOL_TYPE_T0)
	{
		pps->protocol = Protocol_T0_New ();
		
		if ((pps->protocol) != NULL)
		{
			ret = Protocol_T0_Init ((Protocol_T0 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters), selected_protocol);
			
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
			ret = Protocol_T1_Init ((Protocol_T1 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters), selected_protocol);
			
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
			ret = Protocol_T14_Init ((Protocol_T14 *) pps->protocol, (ICC_Async *) pps->icc, &(pps->parameters), selected_protocol);
			
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
/*
static void PPS_SelectFirstProtocol (PPS * pps)
{
	ATR *atr = ICC_Async_GetAtr (pps->icc);
	unsigned np;
	
	pps->parameters.t = ATR_PROTOCOL_TYPE_T0;
	
	ATR_GetNumberOfProtocols (atr, &np);
	
	 
	// Get protocol offered by interface bytes T*2 if available, 
	// (that is, if TD1 is available), * otherwise use default T=0
	
	if (np>1)
		ATR_GetProtocolType (atr, 2, &(pps->parameters.t));
	
#ifdef DEBUG_PROTOCOL
	printf ("PPS: Protocol T=%d selected\n", pps->parameters.t);
#endif
}
*/
static BYTE PPS_GetPCK (BYTE * block, unsigned length)
{
	BYTE pck;
	unsigned i;
	
	pck = block[0];
	for (i = 1; i < length; i++)
		pck ^= block[i];
	
	return pck;
}
