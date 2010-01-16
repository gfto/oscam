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
#include "../globals.h"
#include "icc_async.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ifd.h"

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

int fdmc=(-1);

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

int ICC_Async_Device_Init ()
{

	wr = 0;	
#ifdef DEBUG_IO
	printf ("IO: Opening serial port %s\n", reader[ridx].device);
#endif
	
#if defined(SCI_DEV) || defined(COOL)
	if (reader[ridx].typ == R_INTERNAL)
#ifdef SH4
		reader[ridx].handle = open (reader[ridx].device, O_RDWR|O_NONBLOCK|O_NOCTTY);
#elif COOL
		return Cool_Init();
#else
		reader[ridx].handle = open (reader[ridx].device, O_RDWR);
#endif
	else
#endif

	reader[ridx].handle = open (reader[ridx].device,  O_RDWR | O_NOCTTY| O_NONBLOCK);

	if (reader[ridx].handle < 0)
		return ICC_ASYNC_IFD_ERROR;

#if defined(TUXBOX) && defined(PPC)
	if ((reader[ridx].typ == R_DB2COM1) || (reader[ridx].typ == R_DB2COM2))
		if ((fdmc = open(DEV_MULTICAM, O_RDWR)) < 0)
		{
			close(reader[ridx].handle);
			return ICC_ASYNC_IFD_ERROR;
		}
#endif

	if (reader[ridx].typ != R_INTERNAL) { //FIXME move to ifd_phoenix.c
		if(!IO_Serial_InitPnP ())
			return ICC_ASYNC_IFD_ERROR;
		IO_Serial_Flush();
	}

	return ICC_ASYNC_OK;
}

int ICC_Async_GetStatus (BYTE * result)
{
	BYTE status[2];
//	unsigned int modembits=0;
	int in;
	
//	printf("\n%08X\n", (int)ifd->io);
	
// status : 0 -start, 1 - card, 2- no card

#ifdef SCI_DEV
	if(reader[ridx].typ == R_INTERNAL)
	{
		if(!Sci_GetStatus(reader[ridx].handle, &in))
			return IFD_TOWITOKO_IO_ERROR;			
	}
	else
#elif COOL
	if(reader[ridx].typ == R_INTERNAL)
	{	
		if (!Cool_GetStatus(&in))
			return IFD_TOWITOKO_IO_ERROR;
	}
	else
#endif

#if defined(TUXBOX) && defined(PPC)
	if ((reader[ridx].typ == R_DB2COM1) || (reader[ridx].typ == R_DB2COM2))
	{
		ushort msr=1;
		extern int fdmc;
		IO_Serial_Ioctl_Lock(1);
		ioctl(fdmc, GET_PCDAT, &msr);
		if (reader[ridx].typ == R_DB2COM2)
			in=(!(msr & 1));
		else
			in=((msr & 0x0f00) == 0x0f00);
		IO_Serial_Ioctl_Lock(0);
	}
	else
#endif
#ifdef USE_GPIO
	if (gpio_detect)
		in=get_gpio();
	else
#endif
  if (!Phoenix_GetStatus(&in))
			return IFD_TOWITOKO_IO_ERROR;

	if (in)
	{       
		if(reader[ridx].status == 0)
		{
			status[0] = IFD_TOWITOKO_CARD_CHANGE;
			reader[ridx].status = 1;
#ifdef USE_GPIO
			if (gpio_detect) set_gpio1(0);
#endif
		}
		else if(reader[ridx].status == 1)
		{
			status[0] = IFD_TOWITOKO_CARD_NOCHANGE;
		}
		else
		{
			status[0] = IFD_TOWITOKO_CARD_CHANGE;
			reader[ridx].status = 1;
#ifdef USE_GPIO
			if (gpio_detect) set_gpio1(0);
#endif
		}
	}
	else
	{
		if(reader[ridx].status == 0)
		{
			status[0] = IFD_TOWITOKO_NOCARD_CHANGE;
			reader[ridx].status = 2;
#ifdef USE_GPIO
			if (gpio_detect) set_gpio1(1);
#endif
		}
		else if(reader[ridx].status == 1)
		{
			status[0] = IFD_TOWITOKO_NOCARD_CHANGE;
			reader[ridx].status = 2;
#ifdef USE_GPIO
			if (gpio_detect) set_gpio1(1);
#endif
		}
		else
		{
			status[0] = IFD_TOWITOKO_NOCARD_NOCHANGE;
		}
	}
	
		
	(*result) = status[0];
	
#ifdef DEBUG_IFD
	printf ("IFD: com%d Status = %s / %s\n", reader[ridx].typ, IFD_TOWITOKO_CARD(status[0])? "card": "no card", IFD_TOWITOKO_CHANGE(status[0])? "change": "no change");
#endif
	
	return IFD_TOWITOKO_OK;
}

int ICC_Async_Init (ICC_Async * icc, IFD * ifd)
{
#ifndef ICC_TYPE_SYNC 
	unsigned np=0;

	/* Initialize Baudrate */
	if (!Phoenix_SetBaudrate (ICC_ASYNC_BAUDRATE))
		return ICC_ASYNC_IFD_ERROR;
	
	/* Activate ICC */
	if (IFD_Towitoko_ActivateICC (ifd) != IFD_TOWITOKO_OK)
		return ICC_ASYNC_IFD_ERROR;
	/* Reset ICC */
#ifdef SCI_DEV
	if (reader[ridx].typ == R_INTERNAL) {
		if (!Sci_Reset(&(icc->atr)))
		{
			icc->atr = NULL;
			return ICC_ASYNC_IFD_ERROR;
		}
	}
	else
#endif
#ifdef COOL
	if (reader[ridx].typ == R_INTERNAL) {
		if (!Cool_Reset(&(icc->atr)))
		{
			icc->atr = NULL;
			return ICC_ASYNC_IFD_ERROR;
		}
	}
	else
#endif
	if (!Phoenix_Reset(&(icc->atr)))
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
		ATR_GetProtocolType (icc->atr, 1, &(icc->protocol_type));
	
#ifdef DEBUG_ICC
	printf("ICC: Detected %s convention processor card T=%d\n",(icc->convention == ATR_CONVENTION_DIRECT ? "direct" : "inverse"), icc->protocol_type);
#endif
	*///really should let PPS handle this
	
	/* Initialize member variables */
	icc->baudrate = ICC_ASYNC_BAUDRATE;
	icc->ifd = ifd;
	
	if (icc->convention == ATR_CONVENTION_INVERSE)
	{
		if (!IO_Serial_SetParity (PARITY_ODD))
			return ICC_ASYNC_IFD_ERROR;
	}
	else if(icc->protocol_type == ATR_PROTOCOL_TYPE_T14)
	{
		if (!IO_Serial_SetParity (PARITY_NONE))
			return ICC_ASYNC_IFD_ERROR;		
	}
	else
	{
		if (!IO_Serial_SetParity (PARITY_EVEN))
			return ICC_ASYNC_IFD_ERROR;		
	}
#ifdef COOL
	if (reader[ridx].typ != R_INTERNAL)
#endif
	IO_Serial_Flush();
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
/*	if (icc->protocol_type == ATR_PROTOCOL_TYPE_T1)
		cs_debug("SetTimings: T1: chardelay %d, chartimeout CWT %d, blockdelay BGT??? %d, blocktimeout BWT %d",timings->char_delay,timings->char_timeout, timings->block_delay, timings->block_timeout);
	else
		cs_debug("SetTimings: T0/T14: chardelay %d, chartimeout WWT %d, blockdelay %d, blocktimeout %d",timings->char_delay,timings->char_timeout, timings->block_delay, timings->block_timeout);*/

#ifdef SCI_DEV
#include <sys/ioctl.h>
#include "sci_global.h"
#include "sci_ioctl.h"
	if (reader[ridx].typ == R_INTERNAL) {
		SCI_PARAMETERS params;
		if (ioctl(reader[ridx].handle, IOCTL_GET_PARAMETERS, &params) < 0 )
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
		if (ioctl(reader[ridx].handle, IOCTL_SET_PARAMETERS, &params)!=0)
			return ICC_ASYNC_IFD_ERROR;
			
		cs_debug("Set Timings: T=%d fs=%lu ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d", (int)params.T, params.fs, (int)params.ETU, (int)params.WWT, (int)params.CWT, (int)params.BWT, (int)params.EGT, (int)params.clock_stop_polarity, (int)params.check, (int)params.P, (int)params.I, (int)params.U);
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
	if (!Phoenix_SetBaudrate (baudrate))
	  return ICC_ASYNC_IFD_ERROR;
	
	return ICC_ASYNC_OK;
}

int ICC_Async_GetBaudrate (ICC_Async * icc, unsigned long * baudrate)
{
	(*baudrate) = icc->baudrate;
	return ICC_ASYNC_OK;  
}

int ICC_Async_Transmit (ICC_Async * icc, unsigned size, BYTE * data)
{
	BYTE *buffer = NULL, *sent; 
	IFD_Timings timings;
	
	if (icc->convention == ATR_CONVENTION_INVERSE && reader[ridx].typ != R_INTERNAL)
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
	
#ifdef COOL
	if (reader[ridx].typ == R_INTERNAL) {
		if (!Cool_Transmit(sent, size))
			return ICC_ASYNC_IFD_ERROR;
	}
	else
#endif
	if (!Phoenix_Transmit (sent, size, &timings, size))
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
	
#ifdef COOL
	if (reader[ridx].typ == R_INTERNAL) {
		if (!Cool_Receive(data, size))
			return ICC_ASYNC_IFD_ERROR;
	}
	else
#else
	if (!Phoenix_Receive (data, size, &timings))
		return ICC_ASYNC_IFD_ERROR;
#endif
	
	if (icc->convention == ATR_CONVENTION_INVERSE && reader[ridx].typ != R_INTERNAL)
		ICC_Async_InvertBuffer (size, data);
	
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
	
	/* Delete atr */
	ATR_Delete (icc->atr);
	
	ICC_Async_Clear (icc);
	
	return ICC_ASYNC_OK;
}

unsigned long ICC_Async_GetClockRate ()
{
	switch (reader[ridx].cardmhz) {
		case 357:
		case 358:
	  	return (372L * 9600L);
		case 368:
	  	return (384L * 9600L);
		default:
 	  	return reader[ridx].cardmhz * 10000L;
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
	uint i;
	
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
