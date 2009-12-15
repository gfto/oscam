/*
    icc_async.c
    Asynchronous ICC's handling functions

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

#include "defines.h"
#include "icc_async.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Not exported constants definition
 */
#define ICC_ASYNC_MAX_TRANSMIT	255
#define ICC_ASYNC_BAUDRATE	9600

/*
 * Not exported functions declaration
 */

static void ICC_Async_InvertBuffer (unsigned size, BYTE * buffer);
static void ICC_Async_Clear (ICC_Async * icc);

/*
 * Exported functions definition
 */

ICC_Async *ICC_Async_New (void)
{
	ICC_Async *icc;
	
	/* Allocate memory */
	icc = (ICC_Async *) malloc (sizeof (ICC_Async));
	
	if (icc != NULL)
		ICC_Async_Clear (icc);
	
	return icc;
}

int ICC_Async_Init (ICC_Async * icc, IFD * ifd)
{
#ifndef ICC_TYPE_SYNC 
	unsigned np=0;

	/* LED Red */
	if (IFD_Towitoko_SetLED (ifd, IFD_TOWITOKO_LED_RED) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	
	/* Initialize Baudrate */
	if (IFD_Towitoko_SetBaudrate (ifd, ICC_ASYNC_BAUDRATE)!= IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	
	/* Activate ICC */
	if (IFD_Towitoko_ActivateICC (ifd) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	/* Reset ICC */
	if (IFD_Towitoko_ResetAsyncICC (ifd, &(icc->atr)) != IFD_TOWITOKO_OK)
	{
		icc->atr = NULL;
		return ICC_ASYNC_IFD_ERROR;
	}
	
	/* Get ICC convention */
	if (ATR_GetConvention (icc->atr, &(icc->convention)) != ATR_OK)
	{
		ATR_Delete (icc->atr);
		icc->atr = NULL;
		icc->convention = 0;
		
		return ICC_ASYNC_ATR_ERROR;
	}
	
	icc->protocol_type = ATR_PROTOCOL_TYPE_T0;
	
	ATR_GetNumberOfProtocols (icc->atr, &np);
	
	/* 
	* Get protocol offered by interface bytes T*2 if available, 
	* (that is, if TD1 is available), * otherwise use default T=0
	*/
/*	if (np>1)
		ATR_GetProtocolType (icc->atr, 2, &(icc->protocol_type));
	
#ifdef DEBUG_ICC
	printf("ICC: Detected %s convention processor card T=%d\n",(icc->convention == ATR_CONVENTION_DIRECT ? "direct" : "inverse"), icc->protocol_type);
#endif
	*///really should let PPS handle this
	/* LED Green */
	if (IFD_Towitoko_SetLED (ifd, IFD_TOWITOKO_LED_GREEN) != IFD_TOWITOKO_OK)
	{
		ATR_Delete (icc->atr);
		icc->atr = NULL;
		icc->convention = 0;
		
		return ICC_ASYNC_IFD_ERROR;
	}
	
	/* Initialize member variables */
	icc->baudrate = ICC_ASYNC_BAUDRATE;
	icc->ifd = ifd;
	
#ifdef NO_PAR_SWITCH
	if (icc->convention == ATR_CONVENTION_INVERSE)
	{
		if (IFD_Towitoko_SetParity (icc->ifd, IFD_TOWITOKO_PARITY_ODD) != IFD_TOWITOKO_OK)
			return ICC_ASYNC_IFD_ERROR;
	}
	else if(icc->protocol_type == ATR_PROTOCOL_TYPE_T14)
	{
		if (IFD_Towitoko_SetParity (icc->ifd, IFD_TOWITOKO_PARITY_NONE) != IFD_TOWITOKO_OK)
			return ICC_ASYNC_IFD_ERROR;		
	}
	else
	{
		if (IFD_Towitoko_SetParity (icc->ifd, IFD_TOWITOKO_PARITY_EVEN) != IFD_TOWITOKO_OK)
			return ICC_ASYNC_IFD_ERROR;		
	}
	IO_Serial_Flush(ifd->io);
#endif
	return ICC_ASYNC_OK;
#else
	return ICC_ASYNC_ATR_ERROR;
#endif
}

int ICC_Async_SetTimings (ICC_Async * icc, ICC_Async_Timings * timings)
{
	icc->timings.block_delay = timings->block_delay;
	icc->timings.char_delay = timings->char_delay;
	icc->timings.block_timeout = timings->block_timeout;
	icc->timings.char_timeout = timings->char_timeout;
	if (icc->protocol_type == ATR_PROTOCOL_TYPE_T1)
		cs_debug("SetTimings: T1: chardelay %d, chartimeout CWT %d, blockdelay BGT??? %d, blocktimeout BWT %d",timings->char_delay,timings->char_timeout, timings->block_delay, timings->block_timeout);
	else
		cs_debug("SetTimings: T0/T14: chardelay %d, chartimeout WWT %d, blockdelay %d, blocktimeout %d",timings->char_delay,timings->char_timeout, timings->block_delay, timings->block_timeout);

#ifdef SCI_DEV
#include <sys/ioctl.h>
#include "sci_global.h"
#include "sci_ioctl.h"
	if (icc->ifd->io->com == RTYP_SCI) {
		SCI_PARAMETERS params;
		if (ioctl(icc->ifd->io->fd, IOCTL_GET_PARAMETERS, &params) < 0 )
			return ICC_ASYNC_IFD_ERROR;
		switch (icc->protocol_type) {
			case ATR_PROTOCOL_TYPE_T1:
				params.BWT = icc->timings.block_timeout;
				params.CWT = icc->timings.char_timeout;
				//params.BGT = icc->timings.block_delay; load into params.EGT??
				break;
			case ATR_PROTOCOL_TYPE_T0:
			case ATR_PROTOCOL_TYPE_T14:
			default:
  			params.WWT = icc->timings.char_timeout;
				break;
		}
		if (ioctl(icc->ifd->io->fd, IOCTL_SET_PARAMETERS, &params)!=0)
			return ICC_ASYNC_IFD_ERROR;
			
		cs_debug("Set Timings: T=%d FI=%d ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d", (int)params.T,(int)params.FI, (int)params.ETU, (int)params.WWT, (int)params.CWT, (int)params.BWT, (int)params.EGT, (int)params.clock_stop_polarity, (int)params.check, (int)params.P, (int)params.I, (int)params.U);
	}
#endif
	return ICC_ASYNC_OK;
}

int ICC_Async_GetTimings (ICC_Async * icc, ICC_Async_Timings * timings)
{
	timings->block_delay = icc->timings.block_delay;
	timings->char_delay = icc->timings.char_delay;
	timings->block_timeout = icc->timings.block_timeout;
	timings->char_timeout = icc->timings.char_timeout;
	
	return ICC_ASYNC_OK;
}

int ICC_Async_SetBaudrate (ICC_Async * icc, unsigned long baudrate)
{
	icc->baudrate = baudrate;
	if (IFD_Towitoko_SetBaudrate (icc->ifd, baudrate) !=  IFD_TOWITOKO_OK)
	  return ICC_ASYNC_IFD_ERROR;
	
	return ICC_ASYNC_OK;
}

int ICC_Async_GetBaudrate (ICC_Async * icc, unsigned long * baudrate)
{
	(*baudrate) = icc->baudrate;
	return ICC_ASYNC_OK;  
}

int ICC_Async_BeginTransmission (ICC_Async * icc)
{
	/* Setup parity for this ICC */
#ifndef NO_PAR_SWITCH
	if (icc->convention == ATR_CONVENTION_INVERSE)
	{
		if (IFD_Towitoko_SetParity (icc->ifd, IFD_TOWITOKO_PARITY_ODD) != IFD_TOWITOKO_OK)
			return ICC_ASYNC_IFD_ERROR;
	}
	else if(icc->protocol_type == ATR_PROTOCOL_TYPE_T14)
	{
		if (IFD_Towitoko_SetParity (icc->ifd, IFD_TOWITOKO_PARITY_NONE) != IFD_TOWITOKO_OK)
			return ICC_ASYNC_IFD_ERROR;		
	}
	else
	{
		if (IFD_Towitoko_SetParity (icc->ifd, IFD_TOWITOKO_PARITY_EVEN) != IFD_TOWITOKO_OK)
			return ICC_ASYNC_IFD_ERROR;		
	}
	
	/* Setup baudrate for  this ICC */
/*	if (IFD_Towitoko_SetBaudrate (icc->ifd, icc->baudrate)!= IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
*/	
#endif
	return ICC_ASYNC_OK;
}

int ICC_Async_Transmit (ICC_Async * icc, unsigned size, BYTE * data)
{
	BYTE *buffer = NULL, *sent; 
	IFD_Timings timings;
	
	if (icc->convention == ATR_CONVENTION_INVERSE && icc->ifd->io->com!=RTYP_SCI)
	{
		buffer = (BYTE *) calloc(sizeof (BYTE), size);
		memcpy (buffer, data, size);
		ICC_Async_InvertBuffer (size, buffer);
		sent = buffer;
	}
	else
	{
		sent = data;
	}
	
	timings.block_delay = icc->timings.block_delay;
	timings.char_delay = icc->timings.char_delay;
	
	if (IFD_Towitoko_Transmit (icc->ifd, &timings, size, sent) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	
	if (icc->convention == ATR_CONVENTION_INVERSE)
		free (buffer);
	
	return ICC_ASYNC_OK;
}

int ICC_Async_Receive (ICC_Async * icc, unsigned size, BYTE * data)
{
	IFD_Timings timings;
	
	timings.block_timeout = icc->timings.block_timeout;
	timings.char_timeout = icc->timings.char_timeout;
	
	if (IFD_Towitoko_Receive (icc->ifd, &timings, size, data) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	
	if (icc->convention == ATR_CONVENTION_INVERSE && icc->ifd->io->com!=RTYP_SCI)
		ICC_Async_InvertBuffer (size, data);
	
	return ICC_ASYNC_OK;
}

int ICC_Async_EndTransmission (ICC_Async * icc)
{
#ifndef NO_PAR_SWITCH
	/* Restore parity */
	if (IFD_Towitoko_SetParity (icc->ifd, IFD_TOWITOKO_PARITY_NONE) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;		
#endif
	
	return ICC_ASYNC_OK;
}

ATR * ICC_Async_GetAtr (ICC_Async * icc)
{
	return icc->atr;
}

IFD * ICC_Async_GetIFD (ICC_Async * icc)
{
	return icc->ifd;
}

int ICC_Async_Close (ICC_Async * icc)
{
	/* Dectivate ICC */
	if (IFD_Towitoko_DeactivateICC (icc->ifd) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	
	/* LED Off */
	if (IFD_Towitoko_SetLED (icc->ifd, IFD_TOWITOKO_LED_OFF) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	
	/* Delete atr */
	ATR_Delete (icc->atr);
	
	ICC_Async_Clear (icc);
	
	return ICC_ASYNC_OK;
}

unsigned long ICC_Async_GetClockRate (ICC_Async * icc)
{
	switch (icc->ifd->io->cardmhz) {
		case 357:
		case 358:
	  	return (372L * 9600L);
		case 368:
	  	return (384L * 9600L);
		default:
 	  	return icc->ifd->io->cardmhz * 10000L;
	}
}

void ICC_Async_Delete (ICC_Async * icc)
{
	free (icc);
}

/*
 * Not exported functions definition
 */

static void ICC_Async_InvertBuffer (unsigned size, BYTE * buffer)
{
	int i;
	
	for (i = 0; i < size; i++)
		buffer[i] = ~(INVERT_BYTE (buffer[i]));
}

static void ICC_Async_Clear (ICC_Async * icc)
{
	icc->ifd = NULL;
	icc->atr = NULL;
	icc->baudrate = 0L;
	icc->convention = 0;
	icc->protocol_type = -1;
	icc->timings.block_delay = 0;
	icc->timings.char_delay = 0;
	icc->timings.block_timeout = 0;
	icc->timings.char_timeout = 0;
}
