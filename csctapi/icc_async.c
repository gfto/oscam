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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../globals.h"
#include "defines.h"
#include "icc_async.h"
#include "mc_global.h"
#include "protocol_t0.h"
#include "io_serial.h"
#include "ifd_cool.h"
#include "ifd_mp35.h"
#include "ifd_phoenix.h"
#include "ifd_sc8in1.h"
#include "ifd_sci.h"
#include "ifd_smartreader.h"
#include "ifd_azbox.h"
#ifdef HAVE_PCSC
#include "ifd_pcsc.h"
#endif

// Default T0/T14 settings
#define DEFAULT_WI		10
// Default T1 settings
#define DEFAULT_IFSC	32
#define MAX_IFSC			251  /* Cannot send > 255 buffer */
#define DEFAULT_CWI		13
#define DEFAULT_BWI		4
#define EDC_LRC				0

#define PPS_MAX_LENGTH	6
#define PPS_HAS_PPS1(block)       ((block[1] & 0x10) == 0x10)
#define PPS_HAS_PPS2(block)       ((block[1] & 0x20) == 0x20)
#define PPS_HAS_PPS3(block)       ((block[1] & 0x40) == 0x40)

//declare locking stuff for sc8in1 reader
static pthread_mutex_t sc8in1; //semaphore for SC8in1, FIXME should not be global, but one per SC8in1

#define LOCK_SC8IN1 \
{ \
	if (reader->typ == R_SC8in1) { \
		pthread_mutex_lock(&sc8in1); \
		cs_debug_mask(D_ATR, "SC8in1: locked for access of slot %i", reader->slot); \
		Sc8in1_Selectslot(reader, reader->slot); \
	} \
}

#define UNLOCK_SC8IN1 \
{	\
	if (reader->typ == R_SC8in1) { \
		cs_debug_mask(D_ATR, "SC8in1: unlocked for access of slot %i", reader->slot); \
		pthread_mutex_unlock(&sc8in1); \
	} \
}

/*
 * Not exported functions declaration
 */

static void ICC_Async_InvertBuffer (unsigned size, BYTE * buffer);
static int Parse_ATR (struct s_reader * reader, ATR * atr, unsigned short deprecated);
static int PPS_Exchange (struct s_reader * reader, BYTE * params, unsigned *length);
static unsigned PPS_GetLength (BYTE * block);
static int InitCard (struct s_reader * reader, ATR * atr, BYTE FI, double d, double n, unsigned short deprecated);
static unsigned int ETU_to_ms(struct s_reader * reader, unsigned long WWT);
static BYTE PPS_GetPCK (BYTE * block, unsigned length);
static int SetRightParity (struct s_reader * reader);

/*
 * Exported functions definition
 */

int ICC_Async_Device_Init (struct s_reader *reader)
{
	reader->fdmc=-1;
	cs_debug_mask (D_IFD, "IFD: Opening device %s\n", reader->device);

	reader->written = 0;

	if (reader->crdr.active==1 && reader->crdr.reader_init) {
		return reader->crdr.reader_init(reader);
	}

	switch(reader->typ) {
		case R_SC8in1:
			//pthread_mutex_init(&sc8in1, NULL);
			pthread_mutex_lock(&sc8in1);
			if (reader->handle != 0) {//this reader is already initialized
				pthread_mutex_unlock(&sc8in1);
				return OK;
			}

			//this reader is uninitialized, thus the first one, since the first one initializes all others

			//get physical device name
			int pos = strlen(reader->device)-2; //this is where : should be located; is also valid length of physical device name
			if (reader->device[pos] != 0x3a) //0x3a = ":"
				cs_log("ERROR: '%c' detected instead of slot separator `:` at second to last position of device %s", reader->device[pos], reader->device);
			reader->slot=(int)reader->device[pos+1] - 0x30;
			reader->device[pos]= 0; //slot 1 reader now gets correct physicalname

			//open physical device
			reader->handle = open (reader->device,  O_RDWR | O_NOCTTY| O_NONBLOCK);
			if (reader->handle < 0) {
				cs_log("ERROR opening device %s",reader->device);
				pthread_mutex_unlock(&sc8in1);
				return ERROR;
			}

			//copy physical device name and file handle to other slots
			struct s_reader *rdr;
			for (rdr=first_reader; rdr ; rdr=rdr->next) //copy handle to other slots
				if (rdr->typ == R_SC8in1 && rdr != reader) { //we have another sc8in1 reader
					unsigned char save = rdr->device[pos];
					rdr->device[pos]=0; //set to 0 so we can compare device names
					if (!strcmp(reader->device, rdr->device)) {//we have a match to another slot with same device name
						rdr->handle = reader->handle;
						rdr->slot=(int)rdr->device[pos+1] - 0x30;
					}
					else
						rdr->device[pos] = save; //restore character
				}
			break;
		case R_MP35:
		case R_MOUSE:
			reader->handle = open (reader->device,  O_RDWR | O_NOCTTY| O_NONBLOCK);
			if (reader->handle < 0) {
				cs_log("ERROR opening device %s",reader->device);
				return ERROR;
			}
			break;
#if defined(TUXBOX) && defined(PPC)
		case R_DB2COM1:
		case R_DB2COM2:
			reader->handle = open (reader->device,  O_RDWR | O_NOCTTY| O_SYNC);
			if (reader->handle < 0) {
				cs_log("ERROR opening device %s",reader->device);
				return ERROR;
			}
			if ((reader->fdmc = open(DEV_MULTICAM, O_RDWR)) < 0) {
				close(reader->handle);
				cs_log("ERROR opening device %s",DEV_MULTICAM);
				return ERROR;
			}
			break;
#endif
		case R_SMART:
#if defined(LIBUSB)
			call (SR_Init(reader));
			break;
#else
			cs_log("ERROR, you have specified 'protocol = smartreader' in oscam.server,");
			cs_log("recompile with SmartReader support.");
			return ERROR;
#endif
		case R_INTERNAL:
#if defined(COOL)
			return Cool_Init(reader->device);
#elif defined(AZBOX)
			return Azbox_Init(reader);
#elif defined(SCI_DEV)
	#if defined(SH4) || defined(STB04SCI)
			reader->handle = open (reader->device, O_RDWR|O_NONBLOCK|O_NOCTTY);
	#else
			reader->handle = open (reader->device, O_RDWR);
	#endif
			if (reader->handle < 0) {
				cs_log("ERROR opening device %s",reader->device);
				return ERROR;
			}
#elif defined(WITH_STAPI)
			return STReader_Open(reader->device, &reader->stsmart_handle);
#else//SCI_DEV
			cs_log("ERROR, you have specified 'protocol = internal' in oscam.server,");
			cs_log("recompile with internal reader support.");
			return ERROR;
#endif//SCI_DEV
			break;
#ifdef HAVE_PCSC
		case R_PCSC:
			return (pcsc_reader_init(reader, reader->device));
			break;
#endif
		default:
			cs_log("ERROR ICC_Device_Init: unknow reader type %i",reader->typ);
			return ERROR;
	}

	if (reader->typ == R_MP35)
	{
		if (MP35_Init(reader)) {
				cs_log("ERROR: MP35_Init returns error");
				MP35_Close (reader);
				return ERROR;
		}
	}
	else if (reader->typ <= R_MOUSE)
		if (Phoenix_Init(reader)) {
				cs_log("ERROR: Phoenix_Init returns error");
				Phoenix_Close (reader);
				return ERROR;
		}

	if (reader->typ == R_SC8in1) {
		call(Sc8in1_Init(reader));
		pthread_mutex_unlock(&sc8in1);
	}

 cs_debug_mask (D_IFD, "IFD: Device %s succesfully opened\n", reader->device);
 return OK;
}

int ICC_Async_GetStatus (struct s_reader *reader, int * card)
{
	int in=0;

	if (reader->crdr.active==1 && reader->crdr.get_status) {
		reader->crdr.get_status(reader, &in);

		if (in)
			*card = TRUE;
		else
			*card = FALSE;

		return OK;
	}

	switch(reader->typ) {
		case R_DB2COM1:
		case R_DB2COM2:
#if defined(TUXBOX) && defined(PPC)
			{
			ushort msr=1;
			IO_Serial_Ioctl_Lock(reader, 1);
			ioctl(reader->fdmc, GET_PCDAT, &msr);
			if (reader->typ == R_DB2COM2)
				in=(!(msr & 1));
			else
				in=((msr & 0x0f00) == 0x0f00);
			IO_Serial_Ioctl_Lock(reader, 0);
			}
			break;
#endif
		case R_SC8in1:
			pthread_mutex_lock(&sc8in1);
			call (Sc8in1_GetStatus(reader, &in));
			pthread_mutex_unlock(&sc8in1);
			break;
		case R_MP35:
		case R_MOUSE:
			call (Phoenix_GetStatus(reader, &in));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_GetStatus(reader, &in));
			break;
#endif
		case R_INTERNAL:
#if defined(SCI_DEV)
			call (Sci_GetStatus(reader, &in));
#elif defined(COOL)
			call (Cool_GetStatus(&in));
#elif defined(WITH_STAPI)
			call (STReader_GetStatus(reader->stsmart_handle, &in));
#elif defined(AZBOX)
			call(Azbox_GetStatus(reader, &in));
#endif
			break;
#ifdef HAVE_PCSC
		case R_PCSC:
			in =  pcsc_check_card_inserted(reader);
			break;
#endif
		default:
			cs_log("ERROR ICC_Get_Status: unknow reader type %i",reader->typ);
			return ERROR;
	}

  if (in)
		*card = TRUE;
	else
		*card = FALSE;

	return OK;
}

int ICC_Async_Activate (struct s_reader *reader, ATR * atr, unsigned short deprecated)
{
	cs_debug_mask (D_IFD, "IFD: Activating card in reader %s\n", reader->label);

	reader->current_baudrate = DEFAULT_BAUDRATE; //this is needed for all readers to calculate work_etu for timings

	if (reader->atr[0] != 0) {
		cs_log("using ATR from reader config");
		ATR_InitFromArray(atr, reader->atr, ATR_MAX_SIZE);
	}
	else {
		if (reader->crdr.active && reader->crdr.activate) {
			call(reader->crdr.activate(reader, atr));
		} else {

		switch(reader->typ) {
			case R_MP35:
			case R_DB2COM1:
			case R_DB2COM2:
			case R_SC8in1:
			case R_MOUSE:
				LOCK_SC8IN1;
				int ret = Phoenix_Reset(reader, atr);
				UNLOCK_SC8IN1;
				if (ret) {
					cs_debug_mask(D_TRACE, "ERROR, function call Phoenix_Reset returns error.");
					return ERROR;
				}
				break;
#if defined(LIBUSB)
			case R_SMART:
				call (SR_Reset(reader, atr));
				break;
#endif
			case R_INTERNAL:
#if defined(SCI_DEV)
				call (Sci_Activate(reader));
				call (Sci_Reset(reader, atr));
#elif defined(COOL)
				call (Cool_Reset(atr));
#elif defined(WITH_STAPI)
				call (STReader_Reset(reader->stsmart_handle, atr));
#elif defined(AZBOX)
				call (Azbox_Reset(reader, atr));
#endif
				break;
#ifdef HAVE_PCSC
			case R_PCSC:
				 {
					unsigned char atrarr[ATR_MAX_SIZE];
					ushort atr_size = 0;
					if (pcsc_activate_card(reader, atrarr, &atr_size))
					{
						if (ATR_InitFromArray (atr, atrarr, atr_size) == ATR_OK)
							return OK;
						else
							return ERROR;
					}
					else
						return ERROR;
				 }
				break;
#endif
			default:
				cs_log("ERROR ICC_Async_Activate: unknow reader type %i",reader->typ);
				return ERROR;
		}
		}
	}

	unsigned char atrarr[ATR_MAX_SIZE];
	unsigned int atr_size;
	ATR_GetRaw(atr, atrarr, &atr_size);
	cs_ri_log(reader, "ATR: %s", cs_hexdump(1, atrarr, atr_size));


	/* Get ICC reader->convention */
	if (ATR_GetConvention (atr, &(reader->convention)) != ATR_OK) {
		cs_log("ERROR: Could not read reader->convention");
		reader->convention = 0;
		reader->protocol_type = 0;
		return ERROR;
	}

	reader->protocol_type = ATR_PROTOCOL_TYPE_T0;

	LOCK_SC8IN1;
	int ret = Parse_ATR(reader, atr, deprecated);
	UNLOCK_SC8IN1; //Parse_ATR and InitCard need to be included in lock because they change parity of serial port
	if (ret)
		cs_log("ERROR: Parse_ATR returned error");
	if (ret)
		return ERROR;
	cs_debug_mask (D_IFD, "IFD: Card in reader %s succesfully activated\n", reader->label);

	return OK;
}

int ICC_Async_CardWrite (struct s_reader *reader, unsigned char *command, unsigned short command_len, unsigned char *rsp, unsigned short *lr)
{
#ifdef HAVE_PCSC
	if (reader->typ == R_PCSC)
 	  return (pcsc_reader_do_api(reader, command, rsp, lr, command_len));
#endif
	*lr = 0; //will be returned in case of error

	int ret;

	LOCK_SC8IN1;

	switch (reader->protocol_type) {
		case ATR_PROTOCOL_TYPE_T0:
			ret = Protocol_T0_Command (reader, command, command_len, rsp, lr);
			break;
		case ATR_PROTOCOL_TYPE_T1:
		 {
			int try = 1;
			do {
				ret = Protocol_T1_Command (reader, command, command_len, rsp, lr);
				if (ret == OK)
					break;
				try++;
				//try to resync
				unsigned char resync[] = { 0x21, 0xC0, 0x00, 0xE1 };
				Protocol_T1_Command (reader, resync, sizeof(resync), rsp, lr);
				reader->ifsc = DEFAULT_IFSC;
			} while (try <= 3);
			break;
		 }
		case ATR_PROTOCOL_TYPE_T14:
			ret = Protocol_T14_ExchangeTPDU (reader, command, command_len, rsp, lr);
			break;
		default:
			cs_log("Error, unknown protocol type %i",reader->protocol_type);
			ret = ERROR;
	}

	UNLOCK_SC8IN1;

	if (ret) {
		cs_debug_mask(D_TRACE, "ERROR, function call Protocol_T0_Command returns error.");
		return ERROR;
	}

	cs_ddump_mask(D_READER, rsp, *lr, "answer from cardreader %s:", reader->label);
	return OK;
}

int ICC_Async_SetTimings (struct s_reader * reader, unsigned wait_etu)
{
	reader->read_timeout = ETU_to_ms(reader, wait_etu);
	cs_debug_mask(D_IFD, "Setting timeout to %i", wait_etu);
	return OK;
}

int ICC_Async_Transmit (struct s_reader *reader, unsigned size, BYTE * data)
{
	cs_ddump_mask(D_IFD, data, size, "IFD Transmit: ");
	BYTE *buffer = NULL, *sent;

	if (reader->convention == ATR_CONVENTION_INVERSE && reader->typ <= R_MOUSE) {
		buffer = (BYTE *) calloc(sizeof (BYTE), size);
		memcpy (buffer, data, size);
		ICC_Async_InvertBuffer (size, buffer);
		sent = buffer;
	}
	else
		sent = data;

	if (reader->crdr.active==1 && reader->crdr.transmit) {
		call(reader->crdr.transmit(reader, sent, size));
		if (buffer)
			free (buffer);
		cs_debug_mask(D_IFD, "IFD Transmit succesful");
		return OK;
	}

	switch(reader->typ) {
		case R_MP35:
		case R_DB2COM1:
		case R_DB2COM2:
		case R_SC8in1:
		case R_MOUSE:
			call (Phoenix_Transmit (reader, sent, size, reader->block_delay, reader->char_delay));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_Transmit(reader, sent, size));
			break;
#endif
		case R_INTERNAL:
#if defined(COOL)
			call (Cool_Transmit(sent, size));
#elif defined(AZBOX)
			call (Azbox_Transmit(reader, sent, size));
#elif defined(SCI_DEV)
			call (Phoenix_Transmit (reader, sent, size, 0, 0)); //the internal reader will provide the delay
#elif defined(WITH_STAPI)
			call (STReader_Transmit(reader->stsmart_handle, sent, size));
#endif
			break;
		default:
			cs_log("ERROR ICC_Async_Transmit: unknow reader type %i",reader->typ);
			return ERROR;
	}

	if (buffer)
		free (buffer);
	cs_debug_mask(D_IFD, "IFD Transmit succesful");
	return OK;
}

int ICC_Async_Receive (struct s_reader *reader, unsigned size, BYTE * data)
{

	if (reader->crdr.active && reader->crdr.receive) {
		call(reader->crdr.receive(reader, data, size));

		if (reader->convention == ATR_CONVENTION_INVERSE && reader->crdr.set_baudrate)
			ICC_Async_InvertBuffer (size, data);

		cs_ddump_mask(D_IFD, data, size, "IFD Received: ");
		return OK;
	}

	switch(reader->typ) {
		case R_MP35:
		case R_DB2COM1:
		case R_DB2COM2:
		case R_SC8in1:
		case R_MOUSE:
			call (Phoenix_Receive (reader, data, size, reader->read_timeout));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_Receive(reader, data, size));
			break;
#endif
		case R_INTERNAL:
#if defined(COOL)
			call (Cool_Receive(data, size));
#elif defined(AZBOX)
			call (Azbox_Receive(reader, data, size));
#elif defined(SCI_DEV)
			call (Phoenix_Receive (reader, data, size, reader->read_timeout));
#elif defined(WITH_STAPI)
			call (STReader_Receive(reader->stsmart_handle, data, size));
#endif
			break;
		default:
			cs_log("ERROR ICC_Async_Receive: unknow reader type %i",reader->typ);
			return ERROR;
	}

	if (reader->convention == ATR_CONVENTION_INVERSE && reader->typ <= R_MOUSE)
		ICC_Async_InvertBuffer (size, data);

	cs_ddump_mask(D_IFD, data, size, "IFD Received: ");
	return OK;
}

int ICC_Async_Close (struct s_reader *reader)
{
	cs_debug_mask (D_IFD, "IFD: Closing device %s", reader->device);

	if (reader->crdr.active && reader->crdr.close) {
		call(reader->crdr.close(reader));
		cs_debug_mask (D_IFD, "IFD: Device %s succesfully closed", reader->device);
		return OK;
	}

	switch(reader->typ) {
		case R_MP35:
			call (MP35_Close(reader));
			break;
		case R_DB2COM1:
		case R_DB2COM2:
		case R_SC8in1:
		case R_MOUSE:
			call (Phoenix_Close(reader));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_Close(reader));
			break;
#endif
		case R_INTERNAL:
#if defined(SCI_DEV)
			/* Dectivate ICC */
			call (Sci_Deactivate(reader));
			call (Phoenix_Close(reader));
#elif defined(WITH_STAPI)
			call(STReader_Close(reader->stsmart_handle));
#endif
			break;
#ifdef HAVE_PCSC
		case R_PCSC:
			pcsc_close(reader);
			break;
#endif
		default:
			cs_log("ERROR ICC_Async_Close: unknow reader type %i",reader->typ);
			return ERROR;
	}

	cs_debug_mask (D_IFD, "IFD: Device %s succesfully closed", reader->device);
	return OK;
}

static unsigned long ICC_Async_GetClockRate (int cardmhz)
{
	switch (cardmhz) {
		case 357:
		case 358:
	  	return (372L * 9600L);
		case 368:
	  	return (384L * 9600L);
		default:
 	  	return cardmhz * 10000L;
	}
}

static void ICC_Async_InvertBuffer (unsigned size, BYTE * buffer)
{
	uint i;

	for (i = 0; i < size; i++)
		buffer[i] = ~(INVERT_BYTE (buffer[i]));
}

static int Parse_ATR (struct s_reader * reader, ATR * atr, unsigned short deprecated)
{
	BYTE FI = ATR_DEFAULT_FI;
	//BYTE t = ATR_PROTOCOL_TYPE_T0;
	double d = ATR_DEFAULT_D;
	double n = ATR_DEFAULT_N;
	int ret;

		int numprot = atr->pn;
		//if there is a trailing TD, this number is one too high
		BYTE tx;
		if (ATR_GetInterfaceByte (atr, numprot-1, ATR_INTERFACE_BYTE_TD, &tx) == ATR_OK)
			if ((tx & 0xF0) == 0)
				numprot--;
		int i,point;
		char txt[50];
		bool OffersT[3]; //T14 stored as T2
		for (i = 0; i <= 2; i++)
			OffersT[i] = FALSE;
		for (i=1; i<= numprot; i++) {
			point = 0;
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
				tx &= 0X0F;
				sprintf((char *)txt+point,"(T%i)",tx);
				if (tx == 14)
					OffersT[2] = TRUE;
				else
					OffersT[tx] = TRUE;
			}
			else {
				sprintf((char *)txt+point,"no TD%i means T0",i);
				OffersT[0] = TRUE;
			}
			cs_debug_mask(D_ATR, "%s",txt);
		}

		int numprottype = 0;
		for (i = 0; i <= 2; i++)
			if (OffersT[i])
				numprottype ++;
		cs_debug_mask(D_ATR, "%i protocol types detected. Historical bytes: %s",numprottype, cs_hexdump(1,atr->hb,atr->hbn));

		ATR_GetParameter (atr, ATR_PARAMETER_N, &(n));
		ATR_GetProtocolType(atr,1,&(reader->protocol_type)); //get protocol from TD1
		BYTE TA2;
		bool SpecificMode = (ATR_GetInterfaceByte (atr, 2, ATR_INTERFACE_BYTE_TA, &TA2) == ATR_OK); //if TA2 present, specific mode, else negotiable mode
		if (SpecificMode) {
			reader->protocol_type = TA2 & 0x0F;
			if ((TA2 & 0x10) != 0x10) { //bit 5 set to 0 means F and D explicitly defined in interface characters
				BYTE TA1;
				if (ATR_GetInterfaceByte (atr, 1 , ATR_INTERFACE_BYTE_TA, &TA1) == ATR_OK) {
					FI = TA1 >> 4;
					ATR_GetParameter (atr, ATR_PARAMETER_D, &(d));
				}
				else {
					FI = ATR_DEFAULT_FI;
					d = ATR_DEFAULT_D;
				}
			}
			else {
				cs_log("Specific mode: speed 'implicitly defined', not sure how to proceed, assuming default values");
				FI = ATR_DEFAULT_FI;
				d = ATR_DEFAULT_D;
			}
			cs_debug_mask(D_ATR, "Specific mode: T%i, F=%.0f, D=%.6f, N=%.0f\n", reader->protocol_type, (double) atr_f_table[FI], d, n);
		}
		else { //negotiable mode

			bool PPS_success = FALSE;
			bool NeedsPTS = ((reader->protocol_type != ATR_PROTOCOL_TYPE_T14) && (numprottype > 1 || (atr->ib[0][ATR_INTERFACE_BYTE_TA].present == TRUE && atr->ib[0][ATR_INTERFACE_BYTE_TA].value != 0x11) || n == 255)); //needs PTS according to old ISO 7816
			if (NeedsPTS && deprecated == 0) {
				//						 PTSS	PTS0	PTS1	PCK
				BYTE req[6] = { 0xFF, 0x10, 0x00, 0x00 }; //we currently do not support PTS2, standard guardtimes or PTS3,
																									//but spare 2 bytes in arrayif card responds with it
				req[1]=0x10 | reader->protocol_type; //PTS0 always flags PTS1 to be sent always
				if (ATR_GetInterfaceByte (atr, 1, ATR_INTERFACE_BYTE_TA, &req[2]) != ATR_OK)	//PTS1
					req[2] = 0x11; //defaults FI and DI to 1
				unsigned int len = 0;
				call (SetRightParity (reader));
				ret = PPS_Exchange (reader, req, &len);
				if (ret == OK) {
					FI = req[2] >> 4;
					BYTE DI = req[2] & 0x0F;
					d = (double) (atr_d_table[DI]);
					PPS_success = TRUE;
					cs_debug_mask(D_ATR, "PTS Succesfull, selected protocol: T%i, F=%.0f, D=%.6f, N=%.0f\n", reader->protocol_type, (double) atr_f_table[FI], d, n);
				}
				else
					cs_ddump_mask(D_ATR, req, len,"PTS Failure, response:");
			}

			//When for SCI, T14 protocol, TA1 is obeyed, this goes OK for mosts devices, but somehow on DM7025 Sky S02 card goes wrong when setting ETU (ok on DM800/DM8000)
			if (!PPS_success) {//last PPS not succesfull
				BYTE TA1;
				if (ATR_GetInterfaceByte (atr, 1 , ATR_INTERFACE_BYTE_TA, &TA1) == ATR_OK) {
					FI = TA1 >> 4;
					ATR_GetParameter (atr, ATR_PARAMETER_D, &(d));
				}
				else { //do not obey TA1
					FI = ATR_DEFAULT_FI;
					d = ATR_DEFAULT_D;
				}
				if (NeedsPTS) {
					if ((d == 32) || (d == 12) || (d == 20)) //those values were RFU in old table
						d = 0; // viaccess cards that fail PTS need this
				}

				cs_debug_mask(D_ATR, "No PTS %s, selected protocol T%i, F=%.0f, D=%.6f, N=%.0f\n", NeedsPTS?"happened":"needed", reader->protocol_type, (double) atr_f_table[FI], d, n);
			}
		}//end negotiable mode

	//make sure no zero values
	double F =	(double) atr_f_table[FI];
	if (!F) {
		FI = ATR_DEFAULT_FI;
		cs_log("Warning: F=0 is invalid, forcing FI=%d", FI);
	}
	if (!d) {
		d = ATR_DEFAULT_D;
		cs_log("Warning: D=0 is invalid, forcing D=%.0f",d);
	}

	if (deprecated == 0)
		return InitCard (reader, atr, FI, d, n, deprecated);
	else
		return InitCard (reader, atr, ATR_DEFAULT_FI, ATR_DEFAULT_D, n, deprecated);
}

static int PPS_Exchange (struct s_reader * reader, BYTE * params, unsigned *length)
{
	BYTE confirm[PPS_MAX_LENGTH];
	unsigned len_request, len_confirm;
	int ret;

	len_request = PPS_GetLength (params);
	params[len_request - 1] = PPS_GetPCK(params, len_request - 1);
	cs_debug_mask (D_IFD, "PTS: Sending request: %s", cs_hexdump(1, params, len_request));

	if (reader->crdr.active && reader->crdr.set_protocol) {
		ret = reader->crdr.set_protocol(reader, params, length, len_request);
		return ret;
	}
	
#if defined(WITH_STAPI) && !defined(SCI_DEV)
	ret = STReader_SetProtocol(reader->stsmart_handle, params, length, len_request);
	return ret;
#endif

	/* Send PPS request */
	call (ICC_Async_Transmit (reader, len_request, params));

	/* Get PPS confirm */
	call (ICC_Async_Receive (reader, 2, confirm));
	len_confirm = PPS_GetLength (confirm);
	call (ICC_Async_Receive (reader, len_confirm - 2, confirm + 2));

	cs_debug_mask(D_IFD, "PTS: Receiving confirm: %s", cs_hexdump(1, confirm, len_confirm));
	if ((len_request != len_confirm) || (memcmp (params, confirm, len_request)))
		ret = ERROR;
	else
		ret = OK;

	/* Copy PPS handshake */
	memcpy (params, confirm, len_confirm);
	(*length) = len_confirm;
	return ret;
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

static unsigned int ETU_to_ms(struct s_reader * reader, unsigned long WWT)
{
#define CHAR_LEN 10L //character length in ETU, perhaps should be 9 when parity = none?
	if (WWT > CHAR_LEN)
		WWT -= CHAR_LEN;
	else
		WWT = 0;
	double work_etu = 1000 / (double)reader->current_baudrate;//FIXME sometimes work_etu should be used, sometimes initial etu
	return (unsigned int) WWT * work_etu * reader->cardmhz / reader->mhz;
}

static int ICC_Async_SetParity (struct s_reader * reader, unsigned short parity)
{
	if (reader->crdr.active && reader->crdr.set_parity) {
		call(reader->crdr.set_parity(reader, parity));
		return OK;
	} else if(reader->crdr.active)
		return OK;

	switch(reader->typ) {
		case R_MP35:
		case R_DB2COM1:
		case R_DB2COM2:
		case R_SC8in1:
		case R_MOUSE:
			call (IO_Serial_SetParity (reader, parity));
		break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_SetParity(reader, parity));
			break;
#endif
		case R_INTERNAL:
			return OK;
		default:
			cs_log("ERROR ICC_Async_SetParity: unknow reader type %i",reader->typ);
			return ERROR;
	}
	return OK;
}

static int SetRightParity (struct s_reader * reader)
{
	//set right parity
	unsigned short parity = PARITY_EVEN;
	if (reader->convention == ATR_CONVENTION_INVERSE)
		parity = PARITY_ODD;
	else if(reader->protocol_type == ATR_PROTOCOL_TYPE_T14)
		parity = PARITY_NONE;

	call (ICC_Async_SetParity(reader, parity));

	if (reader->crdr.active) {
		if (reader->crdr.flush==1)
			IO_Serial_Flush(reader);
		return OK;
	}

#if defined(COOL) || defined(WITH_STAPI) || defined(AZBOX)
	if (reader->typ != R_INTERNAL)
#endif
#if defined(LIBUSB)
  if (reader->typ != R_SMART)
#endif
            IO_Serial_Flush(reader);
	return OK;
}

static int InitCard (struct s_reader * reader, ATR * atr, BYTE FI, double d, double n, unsigned short deprecated)
{
	double I;
	double F;
    	unsigned long BGT, edc, EGT, CGT, WWT = 0;
    	unsigned int GT;
    	unsigned long gt_ms;

	//set the amps and the volts according to ATR
	if (ATR_GetParameter(atr, ATR_PARAMETER_I, &I) != ATR_OK)
		I = 0;

	//set clock speed to max if internal reader
	if(reader->typ > R_MOUSE || (reader->crdr.active == 1 && reader->crdr.set_baudrate))
		if (reader->mhz == 357 || reader->mhz == 358) //no overclocking
			reader->mhz = atr_fs_table[FI] / 10000; //we are going to clock the card to this nominal frequency

	//set clock speed/baudrate must be done before timings
	//because reader->current_baudrate is used in calculation of timings
	F =	(double) atr_f_table[FI];

	reader->current_baudrate = DEFAULT_BAUDRATE;

	if (deprecated == 0) {
		if (reader->protocol_type != ATR_PROTOCOL_TYPE_T14) { //dont switch for T14
			unsigned long baud_temp = d * ICC_Async_GetClockRate (reader->cardmhz) / F;
			if (reader->crdr.active == 1) {
				if (reader->crdr.set_baudrate)
					call (reader->crdr.set_baudrate(reader, baud_temp));
			} else {
				if (reader->typ <= R_MOUSE) 
					call (Phoenix_SetBaudrate(reader, baud_temp));
			}
			cs_debug_mask(D_IFD, "Setting baudrate to %lu", baud_temp);
			reader->current_baudrate = baud_temp; //this is needed for all readers to calculate work_etu for timings
		}
	}

	//set timings according to ATR
	reader->read_timeout = 0;
	reader->block_delay = 0;
	reader->char_delay = 0;

	if (n == 255) //Extra Guard Time
		EGT = 0;
	else
		EGT = n;
	GT = EGT + 12; //Guard Time in ETU
	gt_ms = ETU_to_ms(reader, GT);

	switch (reader->protocol_type) {
		case ATR_PROTOCOL_TYPE_T0:
		case ATR_PROTOCOL_TYPE_T14:
			{
			BYTE wi;
			/* Integer value WI	= TC2, by default 10 */
#ifndef PROTOCOL_T0_USE_DEFAULT_TIMINGS
			if (ATR_GetInterfaceByte (atr, 2, ATR_INTERFACE_BYTE_TC, &(wi)) != ATR_OK)
#endif
			wi = DEFAULT_WI;

			// WWT = 960 * WI * (Fi / f) * 1000 milliseconds
			WWT = (unsigned long) 960 * wi; //in ETU
			if (reader->protocol_type == ATR_PROTOCOL_TYPE_T14)
				WWT >>= 1; //is this correct?

			reader->read_timeout = ETU_to_ms(reader, WWT);
			reader->block_delay = gt_ms;
			reader->char_delay = gt_ms;
			cs_debug_mask(D_ATR, "Setting timings: timeout=%u ms, block_delay=%u ms, char_delay=%u ms", reader->read_timeout, reader->block_delay, reader->char_delay);
			cs_debug_mask (D_IFD, "Protocol: T=%i: WWT=%d, Clockrate=%lu\n", reader->protocol_type, (int)(WWT), ICC_Async_GetClockRate(reader->cardmhz));
			}
			break;
	 case ATR_PROTOCOL_TYPE_T1:
			{
				BYTE ta, tb, tc, cwi, bwi;

				// Set IFSC
				if (ATR_GetInterfaceByte (atr, 3, ATR_INTERFACE_BYTE_TA, &ta) == ATR_NOT_FOUND)
					reader->ifsc = DEFAULT_IFSC;
				else if ((ta != 0x00) && (ta != 0xFF))
					reader->ifsc = ta;
				else
					reader->ifsc = DEFAULT_IFSC;

				//FIXME workaround for Smargo until native mode works
				if (reader->smargopatch == 1)
					reader->ifsc = MIN (reader->ifsc, 28);
				else
					// Towitoko does not allow IFSC > 251
					//FIXME not sure whether this limitation still exists
					reader->ifsc = MIN (reader->ifsc, MAX_IFSC);

			#ifndef PROTOCOL_T1_USE_DEFAULT_TIMINGS
				// Calculate CWI and BWI
				if (ATR_GetInterfaceByte (atr, 3, ATR_INTERFACE_BYTE_TB, &tb) == ATR_NOT_FOUND)
					{
			#endif
						cwi	= DEFAULT_CWI;
						bwi = DEFAULT_BWI;
			#ifndef PROTOCOL_T1_USE_DEFAULT_TIMINGS
					}
				else
					{
						cwi	= tb & 0x0F;
						bwi = tb >> 4;
					}
			#endif

				// Set CWT = (2^CWI + 11) work etu
				reader->CWT = (unsigned short) (((1<<cwi) + 11)); // in ETU

				// Set BWT = (2^BWI * 960 + 11) work etu
				reader->BWT = (unsigned short)((1<<bwi) * 960 * 372 * 9600 / ICC_Async_GetClockRate(reader->cardmhz))	+ 11 ;

				// Set BGT = 22 * work etu
				BGT = 22L; //in ETU

				if (n == 255)
					CGT = 11L; //in ETU
				else
					CGT = GT;

				// Set the error detection code type
				if (ATR_GetInterfaceByte (atr, 3, ATR_INTERFACE_BYTE_TC, &tc) == ATR_NOT_FOUND)
					edc = EDC_LRC;
				else
					edc = tc & 0x01;

				// Set initial send sequence (NS)
				reader->ns = 1;

				cs_debug_mask(D_ATR, "Protocol: T=1: IFSC=%d, CWT=%d etu, BWT=%d etu, BGT=%d etu, EDC=%s\n", reader->ifsc, reader->CWT, reader->BWT, BGT, (edc == EDC_LRC) ? "LRC" : "CRC");

				reader->read_timeout = ETU_to_ms(reader, reader->BWT);
				reader->block_delay = ETU_to_ms(reader, BGT);
				reader->char_delay = ETU_to_ms(reader, CGT);
				cs_debug_mask(D_ATR, "Setting timings: timeout=%u ms, block_delay=%u ms, char_delay=%u ms", reader->read_timeout, reader->block_delay, reader->char_delay);
			}
			break;
	 default:
			return ERROR;
			break;
	}//switch

	call (SetRightParity (reader));

	if (reader->crdr.active && reader->crdr.write_settings) {
		unsigned long ETU = 0;
		//for Irdeto T14 cards, do not set ETU
		if (!(atr->hbn >= 6 && !memcmp(atr->hb, "IRDETO", 6) && reader->protocol_type == ATR_PROTOCOL_TYPE_T14))
			ETU = F / d;
		call(reader->crdr.write_settings(reader, ETU, EGT, 5, I));
	}

  //write settings to internal device
	if(reader->typ == R_INTERNAL) {
#if defined(SCI_DEV)
		double F =	(double) atr_f_table[FI];
		unsigned long ETU = 0;
		//for Irdeto T14 cards, do not set ETU
		if (!(atr->hbn >= 6 && !memcmp(atr->hb, "IRDETO", 6) && reader->protocol_type == ATR_PROTOCOL_TYPE_T14))
			ETU = F / d;
		call (Sci_WriteSettings (reader, reader->protocol_type, reader->mhz / 100, ETU, WWT, reader->BWT, reader->CWT, EGT, 5, (unsigned char)I)); //P fixed at 5V since this is default class A card, and TB is deprecated
#elif defined(COOL)
		call (Cool_SetClockrate(reader->mhz));
		call (Cool_WriteSettings (reader->BWT, reader->CWT, EGT, BGT));
#elif defined(WITH_STAPI)
		call (STReader_SetClockrate(reader->stsmart_handle));
#endif //COOL
	}
#if defined(LIBUSB)
	if (reader->typ == R_SMART)
		SR_WriteSettings(reader, (unsigned short) atr_f_table[FI], (BYTE)d, (BYTE)EGT, (BYTE)reader->protocol_type, reader->convention);
#endif
	cs_log("Maximum frequency for this card is formally %i Mhz, clocking it to %.2f Mhz", atr_fs_table[FI] / 1000000, (float) reader->mhz / 100);

	//IFS setting in case of T1
	if ((reader->protocol_type == ATR_PROTOCOL_TYPE_T1) && (reader->ifsc != DEFAULT_IFSC)) {
		unsigned char rsp[CTA_RES_LEN];
		unsigned short lr=0;
		unsigned char tmp[] = { 0x21, 0xC1, 0x01, 0x00, 0x00 };
		tmp[3] = reader->ifsc; // Information Field size
		tmp[4] = reader->ifsc ^ 0xE1;
		Protocol_T1_Command (reader, tmp, sizeof(tmp), rsp, &lr);
	}
 return OK;
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
