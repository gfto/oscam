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
#include "ifd.h"
#include "mc_global.h"
#include "apdu.h"
#include "protocol_t0.h"
#include "protocol_t1.h"

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


/*
 * Not exported functions declaration
 */

static void ICC_Async_InvertBuffer (unsigned size, BYTE * buffer);
static int Parse_ATR (ATR * atr, unsigned short deprecated);
static int PPS_Exchange (BYTE * params, unsigned *length);
static unsigned PPS_GetLength (BYTE * block);
static int InitCard (ATR * atr, BYTE FI, double d, double n, unsigned short deprecated);
static unsigned int ETU_to_ms(unsigned long WWT);
static BYTE PPS_GetPCK (BYTE * block, unsigned length);
static int Protocol_Command (APDU_Cmd * cmd, APDU_Rsp ** rsp);
static int SetRightParity (void);

int fdmc=(-1);

/*
 * Exported functions definition
 */

int ICC_Async_Device_Init ()
{
	cs_debug_mask (D_IFD, "IFD: Opening device %s\n", reader[ridx].device);

	wr = 0;
	if (reader[ridx].typ <= R_MOUSE)	
		reader[ridx].handle = open (reader[ridx].device,  O_RDWR | O_NOCTTY| O_NONBLOCK);
		if (reader[ridx].handle < 0) {
			cs_log("ERROR opening device %s",reader[ridx].device);
			return ERROR;
		}

	switch(reader[ridx].typ) {
		case R_MOUSE:
			break;
#if defined(TUXBOX) && defined(PPC)
		case R_DB2COM1:
		case R_DB2COM2:
			if ((fdmc = open(DEV_MULTICAM, O_RDWR)) < 0) {
				close(reader[ridx].handle);
				cs_log("ERROR opening device %s",DEV_MULTICAM);
				return ERROR;
			}
			break;
#endif
		case R_SMART:
#if defined(LIBUSB)
			call (SR_Init(&reader[ridx]));
			break;
#else
			cs_log("ERROR, you have specified 'protocol = smartreader' in oscam.server,");
			cs_log("recompile with SmartReader support.");
			return ERROR;
#endif
		case R_INTERNAL:
#ifdef COOL
			return Cool_Init();
#elif SCI_DEV
	#if defined(SH4) || defined(STB04SCI)
			reader[ridx].handle = open (reader[ridx].device, O_RDWR|O_NONBLOCK|O_NOCTTY);
	#else
			reader[ridx].handle = open (reader[ridx].device, O_RDWR);
	#endif
			if (reader[ridx].handle < 0) {
				cs_log("ERROR opening device %s",reader[ridx].device);
				return ERROR;
			}
#else//SCI_DEV
			cs_log("ERROR, you have specified 'protocol = internal' in oscam.server,");
			cs_log("recompile with internal reader support.");
			return ERROR;
#endif//SCI_DEV
			break;
		default:
			cs_log("ERROR ICC_Device_Init: unknow reader type %i",reader[ridx].typ);
			return ERROR;
	}

	if (reader[ridx].typ <= R_MOUSE)
	  if (Phoenix_Init()) {
			cs_log("ERROR: Phoenix_Init returns error");
			Phoenix_Close ();
			return ERROR;
		}
 cs_debug_mask (D_IFD, "IFD: Device %s succesfully opened\n", reader[ridx].device);
 return OK;
}

int ICC_Async_GetStatus (int * card)
{
	int in;
	
//	printf("\n%08X\n", (int)ifd->io);
	
	switch(reader[ridx].typ) {
		case R_DB2COM1:
		case R_DB2COM2:
#if defined(TUXBOX) && defined(PPC)
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
			break;
#endif
		case R_MOUSE:
			call (Phoenix_GetStatus(&in));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_GetStatus(&reader[ridx],&in));
			break;
#endif
		case R_INTERNAL:
#ifdef SCI_DEV
			call (Sci_GetStatus(reader[ridx].handle, &in));
#elif COOL
			call (Cool_GetStatus(&in));
#endif
			break;
		default:
			cs_log("ERROR ICC_Device_Init: unknow reader type %i",reader[ridx].typ);
			return ERROR;
	}

  if (in)
		*card = TRUE;
	else
		*card = FALSE;
	
	cs_debug ("IFD: Status = %s", in ? "card": "no card");
	
	return OK;
}

int ICC_Async_Activate (ATR * atr, unsigned short deprecated)
{
	cs_debug_mask (D_IFD, "IFD: Activating card in reader %s\n", reader[ridx].label);
	int card;

	call (ICC_Async_GetStatus (&card));
	if (card == 0) {
		cs_log("ERROR: Trying to activate card but no card inside");
		return ERROR;
	}

	current_baudrate = DEFAULT_BAUDRATE; //this is needed for all readers to calculate work_etu for timings
	switch(reader[ridx].typ) {
		case R_DB2COM1:
		case R_DB2COM2:
		case R_MOUSE:
			call (Phoenix_Reset(atr));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_Reset(&reader[ridx],atr));
			break;
#endif
		case R_INTERNAL:
#ifdef SCI_DEV
			call (Sci_Activate());
			call (Sci_Reset(atr));
#elif COOL
			call (Cool_Reset(atr));
#endif
			break;
		default:
			cs_log("ERROR ICC_Async_Activate: unknow reader type %i",reader[ridx].typ);
			return ERROR;
	}

	unsigned char atrarr[64];
	unsigned int atr_size;
	ATR_GetRaw(atr, atrarr, &atr_size);
	cs_ri_log("ATR: %s", cs_hexdump(1, atrarr, atr_size));

	/* Get ICC convention */
	if (ATR_GetConvention (atr, &(convention)) != ATR_OK) {
		cs_log("ERROR: Could not read convention");
		convention = 0;
	  protocol_type = 0; 
		return ERROR;
	}
	
	protocol_type = ATR_PROTOCOL_TYPE_T0;
	
	unsigned short cs_ptyp_orig=cs_ptyp;
	cs_ptyp=D_ATR;
	int ret = Parse_ATR(atr, deprecated);
	if (ret)
		cs_log("ERROR: Parse_ATR returned error");
	cs_ptyp=cs_ptyp_orig;
	if (ret)
		return ERROR;		
	cs_debug_mask (D_IFD, "IFD: Card in reader %s succesfully activated\n", reader[ridx].label);
	return OK;
}

int ICC_Async_CardWrite (unsigned char *cmd, unsigned short lc, unsigned char *rsp, unsigned short *lr)
{
	APDU_Cmd *apdu_cmd;
	APDU_Rsp *apdu_rsp = NULL;
	int remain;
	bool err = FALSE;

	/* Create a command APDU */
	apdu_cmd = APDU_Cmd_New (cmd, lc);
	if (apdu_cmd == NULL) {
		cs_log("ERROR creating APDU command");
		return ERROR;
	}
	
	call (Protocol_Command (apdu_cmd, &apdu_rsp));
	{
		if (apdu_rsp != NULL) {
			/* Copy APDU data to rsp */
			remain = MAX ((short)APDU_Rsp_RawLen(apdu_rsp) - (*lr),0);
			if (remain > 0) {
				cs_log("MEMORY ERROR");
				err = TRUE; //FIXME do I need this?
			}
			(*lr) = MIN ((*lr), (short)APDU_Rsp_RawLen (apdu_rsp));
			memcpy (rsp, APDU_Rsp_Raw (apdu_rsp) + remain, (*lr));
			APDU_Rsp_Delete (apdu_rsp);
		}
		else 
			(*lr) = 0;
	}
		
	APDU_Cmd_Delete (apdu_cmd);
	if (err) {
		cs_log("ERROR creating APDU response");
		return ERROR;
	}

	return OK;
}

int Protocol_Command (APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	switch (protocol_type) {
		case ATR_PROTOCOL_TYPE_T0:
			call (Protocol_T0_Command (cmd, rsp));
			break;
		case ATR_PROTOCOL_TYPE_T1:
			call (Protocol_T1_Command (cmd, rsp));
			break;
		case ATR_PROTOCOL_TYPE_T14:
			call (Protocol_T14_ExchangeTPDU (cmd, rsp));
			break;
		default:
			cs_log("Error, unknown protocol type %i",protocol_type);
			return ERROR;
	}
	return OK;
}

int ICC_Async_SetTimings (unsigned wait_etu)
{
//		if (reader[ridx].typ == R_INTERNAL) {
//not sure whether this tampering with Block/Character timeouts is needed with SCI devices, 
//since we have set CWT and BWT it seems logical the reader is taking care of this
//#ifdef SCI_DEV
//#include <sys/ioctl.h>
//#include "sci_global.h"
//#include "sci_ioctl.h"
//			SCI_PARAMETERS params;
//			if (ioctl(reader[ridx].handle, IOCTL_GET_PARAMETERS, &params) < 0 )
//				return ERROR;
//			params.BWT = bwt;
//			if (ioctl(reader[ridx].handle, IOCTL_SET_PARAMETERS, &params)!=0)
//				return ERROR;
//#endif
//		}
//		else {
			read_timeout = ETU_to_ms(wait_etu);
			cs_debug_mask(D_IFD, "Setting timeout to %i", wait_etu);
//		}
	return OK;
}

int ICC_Async_Transmit (unsigned size, BYTE * data)
{
	cs_ddump_mask(D_IFD, data, size, "IFD Transmit: ");
	BYTE *buffer = NULL, *sent; 
	
	if (convention == ATR_CONVENTION_INVERSE && reader[ridx].typ <= R_MOUSE) {
		buffer = (BYTE *) calloc(sizeof (BYTE), size);
		memcpy (buffer, data, size);
		ICC_Async_InvertBuffer (size, buffer);
		sent = buffer;
	}
	else
		sent = data;

	switch(reader[ridx].typ) {
		case R_DB2COM1:
		case R_DB2COM2:
		case R_MOUSE:
			call (Phoenix_Transmit (sent, size, icc_timings.block_delay, icc_timings.char_delay));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_Transmit(&reader[ridx], sent, size));
			break;
#endif
		case R_INTERNAL:
#ifdef COOL
			call (Cool_Transmit(sent, size));
#elif SCI_DEV
			call (Phoenix_Transmit (sent, size, 0, 0)); //the internal reader will provide the delay
#endif
			break;
		default:
			cs_log("ERROR ICC_Async_Transmit: unknow reader type %i",reader[ridx].typ);
			return ERROR;
	}

	if (convention == ATR_CONVENTION_INVERSE && reader[ridx].typ <= R_MOUSE)
		free (buffer);
	cs_debug_mask(D_IFD, "IFD Transmit succesful");
	return OK;
}

int ICC_Async_Receive (unsigned size, BYTE * data)
{
	switch(reader[ridx].typ) {
		case R_DB2COM1:
		case R_DB2COM2:
		case R_MOUSE:
			call (Phoenix_Receive (data, size, read_timeout));
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_Receive(&reader[ridx], data, size));
			break;
#endif
		case R_INTERNAL:
#ifdef COOL
	    call (Cool_Receive(data, size));
#elif SCI_DEV
			call (Phoenix_Receive (data, size, read_timeout));
#endif
			break;
		default:
			cs_log("ERROR ICC_Async_Receive: unknow reader type %i",reader[ridx].typ);
			return ERROR;
	}

	if (convention == ATR_CONVENTION_INVERSE && reader[ridx].typ <= R_MOUSE)
		ICC_Async_InvertBuffer (size, data);

	cs_ddump_mask(D_IFD, data, size, "IFD Received: ");
	return OK;
}

int ICC_Async_Close ()
{ //FIXME this routine is never called!
	cs_debug_mask (D_IFD, "IFD: Closing device %s", reader[ridx].device);

	switch(reader[ridx].typ) {
		case R_DB2COM1:
		case R_DB2COM2:
		case R_MOUSE:
			call (Phoenix_Close());
			break;
#if defined(LIBUSB)
		case R_SMART:
			call (SR_Close(&reader[ridx]));
			break;
#endif
		case R_INTERNAL:
#ifdef SCI_DEV
			/* Dectivate ICC */
			call (Sci_Deactivate());
			call (Phoenix_Close());
#endif
			break;
		default:
			cs_log("ERROR ICC_Async_Close: unknow reader type %i",reader[ridx].typ);
			return ERROR;
	}
	
	cs_debug_mask (D_IFD, "IFD: Device %s succesfully closed", reader[ridx].device);
	return OK;
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

/*
 * Not exported functions definition
 */

static void ICC_Async_InvertBuffer (unsigned size, BYTE * buffer)
{
	uint i;
	
	for (i = 0; i < size; i++)
		buffer[i] = ~(INVERT_BYTE (buffer[i]));
}

static int Parse_ATR (ATR * atr, unsigned short deprecated)
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
			cs_debug("%s",txt);
		}
		
		int numprottype = 0;
		for (i = 0; i <= 2; i++)
			if (OffersT[i])
				numprottype ++;
		cs_debug("%i protocol types detected. Historical bytes: %s",numprottype, cs_hexdump(1,atr->hb,atr->hbn));

//If more than one protocol type and/or TA1 parameter values other than the default values and/or N equeal to 255 is/are indicated in the answer to reset, the card shall know unambiguously, after having sent the answer to reset, which protocol type or/and transmission parameter values (FI, D, N) will be used. Consequently a selection of the protocol type and/or the transmission parameters values shall be specified.
		ATR_GetParameter (atr, ATR_PARAMETER_N, &(n));
		ATR_GetProtocolType(atr,1,&(protocol_type)); //get protocol from TD1
		BYTE TA2;
		bool SpecificMode = (ATR_GetInterfaceByte (atr, 2, ATR_INTERFACE_BYTE_TA, &TA2) == ATR_OK); //if TA2 present, specific mode, else negotiable mode
		if (SpecificMode) {
			protocol_type = TA2 & 0x0F;
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
			cs_debug("Specific mode: T%i, F=%.0f, D=%.6f, N=%.0f\n", protocol_type, (double) atr_f_table[FI], d, n);
		}
		else { //negotiable mode

			bool PPS_success = FALSE; 
			bool NeedsPTS = ((protocol_type != ATR_PROTOCOL_TYPE_T14) && (numprottype > 1 || (atr->ib[0][ATR_INTERFACE_BYTE_TA].present == TRUE && atr->ib[0][ATR_INTERFACE_BYTE_TA].value != 0x11) || n == 255)); //needs PTS according to ISO 7816 , SCI gets stuck on our PTS
			if (NeedsPTS && deprecated == 0) {
				//						 PTSS	PTS0	PTS1	PTS2	PTS3	PCK
				//						 PTSS	PTS0	PTS1	PCK
				BYTE req[] = { 0xFF, 0x10, 0x00, 0x00 }; //we currently do not support PTS2, standard guardtimes
				req[1]=0x10 | protocol_type; //PTS0 always flags PTS1 to be sent always
				if (ATR_GetInterfaceByte (atr, 1, ATR_INTERFACE_BYTE_TA, &req[2]) != ATR_OK)	//PTS1 
					req[2] = 0x11; //defaults FI and DI to 1
				//req[3]=PPS_GetPCK(req,sizeof(req)-1); will be set by PPS_Exchange
				unsigned int len = sizeof(req);
				ret = PPS_Exchange (req, &len);
				if (ret == OK) {
					FI = req[2] >> 4;
					BYTE DI = req[2] & 0x0F;
					d = (double) (atr_d_table[DI]);
					PPS_success = TRUE;
					cs_debug("PTS Succesfull, selected protocol: T%i, F=%.0f, D=%.6f, N=%.0f\n", protocol_type, (double) atr_f_table[FI], d, n);
				}
				else
					cs_ddump(req,4,"PTS Failure, response:");
			}

			//FIXME Currently InitICC sets baudrate to 9600 for all T14 cards (=no switching); 
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

				cs_debug("No PTS %s, selected protocol T%i, F=%.0f, D=%.6f, N=%.0f\n", NeedsPTS?"happened":"needed", protocol_type, (double) atr_f_table[FI], d, n);
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
		return InitCard (atr, FI, d, n, deprecated);
	else
		return InitCard (atr, ATR_DEFAULT_FI, ATR_DEFAULT_D, n, deprecated);
}

/*
 * Not exported funtions definition
 */

static int PPS_Exchange (BYTE * params, unsigned *length)
{
	BYTE confirm[PPS_MAX_LENGTH];
	unsigned len_request, len_confirm;
	int ret;

	len_request = PPS_GetLength (params);
	params[len_request - 1] = PPS_GetPCK(params, len_request - 1);
	cs_debug_mask (D_IFD,"PTS: Sending request: %s", cs_hexdump(1, params, len_request));

	/* Send PPS request */
	call (ICC_Async_Transmit (len_request, params));

	/* Get PPS confirm */
	call (ICC_Async_Receive (2, confirm));
	len_confirm = PPS_GetLength (confirm);
	call (ICC_Async_Receive (len_confirm - 2, confirm + 2));

	cs_debug_mask(D_IFD, "PTS: Receiving confirm: %s", cs_hexdump(1, confirm, len_confirm));
	if ((len_request != len_confirm) || (memcmp (params, confirm, len_request)))
		ret = ERROR;
	else
		ret = OK;

	/* Copy PPS handsake */
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

static unsigned int ETU_to_ms(unsigned long WWT)
{
#define CHAR_LEN 10L //character length in ETU, perhaps should be 9 when parity = none?
	if (WWT > CHAR_LEN)
		WWT -= CHAR_LEN;
	else
		WWT = 0;
	double work_etu = 1000 / (double)current_baudrate;//FIXME sometimes work_etu should be used, sometimes initial etu
	return (unsigned int) WWT * work_etu * reader[ridx].cardmhz / reader[ridx].mhz;
}

static int ICC_Async_SetParity (unsigned short parity)
{
	switch(reader[ridx].typ) {
		case R_DB2COM1:
		case R_DB2COM2:
		case R_MOUSE:
			call (IO_Serial_SetParity (parity));
		break;
#if defined(LIBUSB)
		case R_SMART:
			reader[ridx].sr_config.inv= (convention == ATR_CONVENTION_INVERSE) ? 1: 0;
			reader[ridx].sr_config.parity=parity;
			call (SR_SetParity(&reader[ridx]));
			break;
#endif
		case R_INTERNAL:
			return OK;
		default:
			cs_log("ERROR ICC_Async_SetParity: unknow reader type %i",reader[ridx].typ);
			return ERROR;
	}
	return OK;
}

static int SetRightParity (void)
{
	//set right parity
	unsigned short parity = PARITY_EVEN;
	if (convention == ATR_CONVENTION_INVERSE)
		parity = PARITY_ODD;
	else if(protocol_type == ATR_PROTOCOL_TYPE_T14)
		parity = PARITY_NONE;
	
	call (ICC_Async_SetParity(parity));

#ifdef COOL
	if (reader[ridx].typ != R_INTERNAL)
#endif
#if defined(LIBUSB)
  if (reader[ridx].typ != R_SMART)
#endif
            IO_Serial_Flush();
	return OK;
}

static int InitCard (ATR * atr, BYTE FI, double d, double n, unsigned short deprecated)
{
	double P,I;
	double F;
    unsigned long BGT, edc, EGT, CGT, WWT = 0;
    unsigned int GT;
    unsigned long gt_ms;
		current_baudrate = DEFAULT_BAUDRATE;
    
	//set the amps and the volts according to ATR
	if (ATR_GetParameter(atr, ATR_PARAMETER_P, &P) != ATR_OK)
		P = 0;
	if (ATR_GetParameter(atr, ATR_PARAMETER_I, &I) != ATR_OK)
		I = 0;

	//set clock speed to max if internal reader
	if(reader[ridx].typ > R_MOUSE)
		if (reader[ridx].mhz == 357 || reader[ridx].mhz == 358) //no overclocking
			reader[ridx].mhz = atr_fs_table[FI] / 10000; //we are going to clock the card to this nominal frequency

	//set clock speed/baudrate must be done before timings
	//because current_baudrate is used in calculation of timings
	F =	(double) atr_f_table[FI];

	if (deprecated == 0)
		if (protocol_type != ATR_PROTOCOL_TYPE_T14) { //dont switch for T14
			unsigned long baud_temp = d * ICC_Async_GetClockRate () / F;
			if (reader[ridx].typ <= R_MOUSE)
				call (Phoenix_SetBaudrate (baud_temp));
			cs_debug_mask(D_IFD, "Setting baudrate to %lu", baud_temp);
			current_baudrate = baud_temp; //this is needed for all readers to calculate work_etu for timings
		}

	//set timings according to ATR
	read_timeout = 0;
	icc_timings.block_delay = 0;
	icc_timings.char_delay = 0;

	if (n == 255) //Extra Guard Time
		EGT = 0;
	else
		EGT = n;
	GT = EGT + 12; //Guard Time in ETU
	gt_ms = ETU_to_ms(GT);

	switch (protocol_type) {
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
			if (protocol_type == ATR_PROTOCOL_TYPE_T14)
				WWT >>= 1; //is this correct?
			
			read_timeout = ETU_to_ms(WWT);
			icc_timings.block_delay = gt_ms;
			icc_timings.char_delay = gt_ms;
			cs_debug("Setting timings: timeout=%u ms, block_delay=%u ms, char_delay=%u ms", read_timeout, icc_timings.block_delay, icc_timings.char_delay);
			cs_debug_mask (D_IFD,"Protocol: T=%i: WWT=%d, Clockrate=%lu\n", protocol_type, (int)(WWT), ICC_Async_GetClockRate());
			}
			break;
	 case ATR_PROTOCOL_TYPE_T1:
			{
				BYTE ta, tb, tc, cwi, bwi;
			
				// Set IFSC
				if (ATR_GetInterfaceByte (atr, 3, ATR_INTERFACE_BYTE_TA, &ta) == ATR_NOT_FOUND)
					ifsc = DEFAULT_IFSC;
				else if ((ta != 0x00) && (ta != 0xFF))
					ifsc = ta;
				else
					ifsc = DEFAULT_IFSC;
			
				// Towitoko does not allow IFSC > 251 //FIXME not sure whether this limitation still exists
				ifsc = MIN (ifsc, MAX_IFSC);
			
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
				CWT = (unsigned short) (((1<<cwi) + 11)); // in ETU
			
				// Set BWT = (2^BWI * 960 + 11) work etu
				BWT = (unsigned short)((1<<bwi) * 960 * 372 * 9600 / ICC_Async_GetClockRate() )	+ 11 ;
			
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
				ns = 1;

				cs_debug ("Protocol: T=1: IFSC=%d, CWT=%d etu, BWT=%d etu, BGT=%d etu, EDC=%s\n", ifsc, CWT, BWT, BGT, (edc == EDC_LRC) ? "LRC" : "CRC");

				read_timeout = ETU_to_ms(BWT);
				icc_timings.block_delay = ETU_to_ms(BGT);
				icc_timings.char_delay = ETU_to_ms(CGT);
				cs_debug("Setting timings: timeout=%u ms, block_delay=%u ms, char_delay=%u ms", read_timeout, icc_timings.block_delay, icc_timings.char_delay);
			}
			break;
	 default:
			return ERROR;
			break;
	}//switch

	call (SetRightParity ());

  //write settings to internal device
	if(reader[ridx].typ == R_INTERNAL) {
#ifdef SCI_DEV
		double F =	(double) atr_f_table[FI];
		unsigned long ETU = 0;
		//for Irdeto T14 cards, do not set ETU
		if (!(atr->hbn >= 6 && !memcmp(atr->hb, "IRDETO", 6) && protocol_type == ATR_PROTOCOL_TYPE_T14))
			ETU = F / d;
		call (Sci_WriteSettings (protocol_type, reader[ridx].mhz / 100, ETU, WWT, BWT, CWT, EGT, (unsigned char)P, (unsigned char)I));
#elif COOL
		call (Cool_SetClockrate(reader[ridx].mhz));
		call (Cool_WriteSettings (BWT, CWT, EGT, BGT));
#endif //COOL
	}
#if defined(LIBUSB)
	if (reader[ridx].typ == R_SMART)
		SR_WriteSettings(&reader[ridx], (unsigned short) atr_f_table[FI], (BYTE)d, (BYTE)EGT, (BYTE)protocol_type);
#endif
	cs_log("Maximum frequency for this card is formally %i Mhz, clocking it to %.2f Mhz", atr_fs_table[FI] / 1000000, (float) reader[ridx].mhz / 100);

	//IFS setting in case of T1
	if ((protocol_type == ATR_PROTOCOL_TYPE_T1) && (ifsc != DEFAULT_IFSC)) {
		APDU_Cmd * cmd;
		APDU_Rsp ** rsp;
		unsigned char tmp[] = { 0x21, 0xC1, 0x01, 0x00, 0x00 };
		tmp[3] = ifsc; // Information Field size
		tmp[4] = ifsc ^ 0xE1;
		cmd = APDU_Cmd_New (tmp, 5L);
		Protocol_T1_Command (cmd, rsp);
		APDU_Cmd_Delete (cmd);
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
