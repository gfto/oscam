/*
    protocol_t0.c
    Handling of ISO 7816 T=0 protocol

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../globals.h"
#include "defines.h"

#include "protocol_t0.h"
#include "atr.h"

/*
 * Not exported constants definition
 */

#define PROTOCOL_T0_MAX_NULLS          200
#define PROTOCOL_T0_DEFAULT_WI         10
#define PROTOCOL_T0_MAX_SHORT_COMMAND  260
#define PROTOCOL_T0_MAX_SHORT_RESPONSE 258

#define PROTOCOL_T14_MAX_NULLS          200
#define PROTOCOL_T14_DEFAULT_WI         10
#define PROTOCOL_T14_MAX_SHORT_COMMAND  260
#define PROTOCOL_T14_MAX_SHORT_RESPONSE 258

/* Timings in ATR are not used in T=0 cards */
/* #undef PROTOCOL_T0_USE_DEFAULT_TIMINGS */

/*
 * Not exported functions declaration
 */

static int Protocol_T0_Case2E (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp);

static int Protocol_T0_Case3E (unsigned char * command, APDU_Rsp ** rsp);

static int Protocol_T0_Case4E (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp);

static int Protocol_T0_ExchangeTPDU (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp);

/*
 * Exproted funtions definition
 */

int Protocol_T0_Command (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp)
{
	if (command_len < 5) //APDU_CASE_1 or malformed
		return ERROR;

	int cmd_case = APDU_Cmd_Case (command, command_len);
	switch (cmd_case) {
		case APDU_CASE_2E:
			return Protocol_T0_Case2E (command, command_len, rsp);
		case APDU_CASE_3E:
			return Protocol_T0_Case3E (command, rsp);
		case APDU_CASE_4E:
			return Protocol_T0_Case4E (command, command_len, rsp);
		case APDU_CASE_4S:
			command_len--; //FIXME this should change 4S to 2S/3S command
		case APDU_CASE_2S:
		case APDU_CASE_3S:
			return Protocol_T0_ExchangeTPDU(command, command_len, rsp);
		default:
			cs_debug_mask (D_IFD,"Protocol: T=0: Invalid APDU\n");
			return ERROR;
	}
}

/*
 * Not exported functions definition
 */


static int Protocol_T0_Case2E (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp)
{
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	APDU_Rsp *tpdu_rsp;
    ulong i;
	
	unsigned long Lc = (((unsigned long)(command[5]) << 8) | command[6]);
	if (Lc < 256)
	{
		/* MAP APDU onto command TPDU */
		memcpy(buffer, command, 4);
		buffer[4] = (BYTE) Lc;
		memcpy (buffer + 5, command + 7, buffer[4]);
		return Protocol_T0_ExchangeTPDU(buffer, buffer[4] + 5, rsp);
	}

		/* Prepare envelope TPDU */
		buffer[0] = command[0];
		buffer[1] = 0xC2;
		buffer[2] = 0x00;
		buffer[3] = 0x00;
		
		for (i = 0; i < command_len; i += buffer[4])
		{
			/* Create envelope command TPDU */
			buffer[4] = MIN (255, command_len - i);
			memcpy (buffer + 5, command + i, buffer[4]);
			call (Protocol_T0_ExchangeTPDU(buffer, buffer[4] + 5, (&tpdu_rsp)));
				/*  Card does support envelope command */
				if (APDU_Rsp_SW1 (tpdu_rsp) == 0x90)
				{
					/* This is not the last segment */
					if (buffer[4] + i < command_len)
						APDU_Rsp_Delete (tpdu_rsp); //delete response TPDU
					else
						(*rsp) = tpdu_rsp;// Map response TPDU onto APDU
				}	
				else /* Card does not support envelope command or error */
				{
					/* Map response tpdu onto APDU without change */
					(*rsp) = tpdu_rsp;
					break;
				}
		}
	
	return OK;
}


static int Protocol_T0_Case3E (unsigned char * command, APDU_Rsp ** rsp)
{
	int ret;
	BYTE buffer[5];
	APDU_Rsp *tpdu_rsp;
	long Lm, Lx;

	unsigned long Le = ((((unsigned long)(command[5]) << 8) | command[6]) == 0 ? 65536 : (((unsigned long)(command[5]) << 8) | command[6]));
	memcpy(buffer, command, 4);//Map APDU command onto TPDU

	if (Le <= 256)
	{
		buffer[4] = (BYTE)Le;
		return Protocol_T0_ExchangeTPDU (buffer, 5, rsp); //this was Case3S !!!
	}

	/* Map APDU onto command TPDU */
	buffer[4] = 0x00;
	call (Protocol_T0_ExchangeTPDU(buffer, 5 , (&tpdu_rsp)));

	if (APDU_Rsp_SW1 (tpdu_rsp) == 0x6C) {/* Le not accepted, La indicated */
		/* Map command APDU onto TPDU */
		memcpy (buffer, command, 4);
		buffer[4] = APDU_Rsp_SW2 (tpdu_rsp);

		/* Delete response TPDU */
		APDU_Rsp_Delete (tpdu_rsp);
		
		return Protocol_T0_ExchangeTPDU(buffer, 5, rsp); //Reissue command
	}
	
	(*rsp) = tpdu_rsp; //Map response TPDU onto APDU without change , also for SW1 = 0x67
	ret = OK;
	if (APDU_Rsp_SW1 (tpdu_rsp) == 0x61) {/* Command processed, Lx indicated */
		Lx = (APDU_Rsp_SW2 (tpdu_rsp) == 0x00) ? 256 : APDU_Rsp_SW2 (tpdu_rsp);
		Lm = Le - APDU_Rsp_DataLen (*rsp);
		
		/* Prepare Get Response TPDU */
		buffer[0] = command[0];
		buffer[1] = 0xC0;
		buffer[2] = 0x00;
		buffer[3] = 0x00;
		
		while (Lm > 0)
		{
			buffer[4] = (BYTE) MIN (Lm, Lx);
			call (Protocol_T0_ExchangeTPDU(buffer, 5, (&tpdu_rsp)));

			/* Append response TPDU to APDU  */
			if (APDU_Rsp_AppendData ((*rsp), tpdu_rsp) != APDU_OK)
			{
				ret = ERROR;
				APDU_Rsp_Delete (tpdu_rsp);
				break;
			}
			
			/* Delete response TPDU */
			APDU_Rsp_Delete (tpdu_rsp);
			
			Lm = Le - APDU_Rsp_DataLen (*rsp);
		}/* Lm == 0 */
	} 
	return ret;
}


static int Protocol_T0_Case4E (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp)
{
	int ret;
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	APDU_Rsp *tpdu_rsp;
	long Le;
	
	unsigned long Lc = (((unsigned long)(command[5]) << 8) | command[6]);
	/* 4E1 */
	if (Lc < 256) {
		/* Map APDU onto command TPDU */
		memcpy(buffer,command,4);
		buffer[4] = (BYTE) Lc;
		memcpy (buffer + 5, command, buffer[4]);
		ret = Protocol_T0_ExchangeTPDU(buffer, buffer[4] + 5, (&tpdu_rsp));
	}
	else /* 4E2 */
		ret = Protocol_T0_Case2E (command, command_len, (&tpdu_rsp));
	
	/* 4E1 a) b) and c) */
	if (ret == OK)
	{
		Le = ((((unsigned long)(command[command_len - 2]) << 8) | command[command_len - 1]) == 0 ? 65536 : (((unsigned long)(command[command_len - 2]) << 8) | command[command_len - 1]));
		if (APDU_Rsp_SW1 (tpdu_rsp) == 0x61)
		{
			/* Lm == (Le - APDU_Rsp_RawLen (tpdu_rsp)) == 0 */
			if (APDU_Rsp_SW2 (tpdu_rsp) != 0x00)
				Le = MIN(APDU_Rsp_SW2 (tpdu_rsp), Le);
			
			/* Delete response TPDU */
			APDU_Rsp_Delete (tpdu_rsp);
			
			/* Prepare extended Get Response APDU command */
			buffer[0] = command[0];
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			buffer[4] = 0x00;     /* B1 = 0x00 */
			buffer[5] = (BYTE) (Le >> 8);  /* B2 = BL-1 */
			buffer[6] = (BYTE) (Le & 0x00FF);      /* B3 = BL */
			ret = Protocol_T0_Case3E (buffer, rsp);
		}
		else if ((APDU_Rsp_SW1 (tpdu_rsp) & 0xF0) == 0x60)
		{
			/* Map response TPDU onto APDU without change */
			(*rsp) = tpdu_rsp;
		}
		else
		{
			/* Delete response TPDU */
			APDU_Rsp_Delete (tpdu_rsp);
			
			/* Prepare extended Get Response APDU command */
			buffer[0] = command[0];
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			buffer[4] = 0x00;     /* B1 = 0x00 */
			buffer[5] = (BYTE) Le >> 8;  /* B2 = BL-1 */
			buffer[6] = (BYTE) Le & 0x00FF;      /* B3 = BL */
			ret = Protocol_T0_Case3E (buffer, rsp);
		}
	}
	return ret;
}


static int Protocol_T0_ExchangeTPDU (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp)
{
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_RESPONSE];
	BYTE *data;
	long Lc, Le, sent, recv;
	int ret = OK, nulls, cmd_case;
	(*rsp) = NULL;//in case of error this will be returned
	
	cmd_case = APDU_Cmd_Case (command, command_len);
	switch (cmd_case) {
		case APDU_CASE_2S:
			Lc = command[4];
			Le = 0;
			data = command + 5;	
			break;
		case APDU_CASE_3S:
			Lc = 0;
			Le = command[4];
			data = NULL;	
			break;
		default:
			cs_debug_mask(D_TRACE, "ERROR: invalid cmd_case = %i in Protocol_T0_ExchangeTPDU",cmd_case);
			return ERROR;
	}
	call (ICC_Async_Transmit (5, command));		//Send header bytes
	
	/* Initialise counters */
	nulls = 0;
	sent = 0;
	recv = 0;
	
	/* 
	* Let's be a bit paranoid with buffer sizes within this loop
	* so it doesn't overflow reception and transmission buffers
	* if card does not strictly respect the protocol
	*/
	
	while (recv < PROTOCOL_T0_MAX_SHORT_RESPONSE)
	{
		call (ICC_Async_Receive (1, buffer + recv));				//Read one procedure byte
		
		/* NULL byte received */
		if (buffer[recv] == 0x60) {
			nulls++;
			if (nulls >= PROTOCOL_T0_MAX_NULLS) {								//Maximum number of nulls reached 
				cs_debug_mask(D_TRACE, "ERROR Protocol_T0_ExchangeTPDU: Maximum number of nulls reached:%i",nulls);
				return ERROR;
			}
		}
		else if ((buffer[recv] & 0xF0) == 0x60 || (buffer[recv] & 0xF0) == 0x90) /* SW1 byte received */
		{//printf("sw1\n");
			recv++;
			if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE) {
				cs_debug_mask(D_TRACE, "ERROR Protocol_T0_ExchangeTPDU: Maximum short response exceeded:%li",recv);
				return ERROR;
			}
			call (ICC_Async_Receive (1, buffer + recv));					//Read SW2 byte
			recv++;
			ret = OK;
			break;
		}
		else if ((buffer[recv] & 0x0E) == (command[1] & 0x0E)) /* ACK byte received */
		{//printf("ack\n");
			/* Reset null's counter */
			nulls = 0;
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S) {
				if (sent >= Lc) {
					cs_debug_mask(D_TRACE, "ERROR Protocol_T0_ExchangeTPDU ACK byte: sent=%li exceeds Lc=%li",sent, Lc);
					return ERROR;
				}
				call (ICC_Async_Transmit(MAX (Lc - sent, 0), data + sent)); /* Send remaining data bytes */
				sent = Lc;
				continue;
			}
			else /* Case 3 command: receive data */
			{
				if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE) {
					cs_debug_mask(D_TRACE, "ERROR Protocol_T0_ExchangeTPDU: Case 3 ACK - maximum short response exceeded:%li",recv);
					return ERROR;
				}
				
				/* 
				* Le <= PROTOCOL_T0_MAX_SHORT_RESPONSE - 2 for short commands 
				*/
				
				/* Read remaining data bytes */
				call (ICC_Async_Receive(MAX (Le - recv, 0), buffer + recv));
				recv = Le;
				continue;
			}
		}
		else if ((buffer[recv] & 0x0E) == ((~command[1]) & 0x0E)) /* ~ACK byte received */
		{//printf("~ack\n");
			nulls = 0;																								//Reset null's counter
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S) {
				if (sent >= Lc) {
					cs_debug_mask(D_TRACE, "ERROR Protocol_T0_ExchangeTPDU ~ACK byte: sent=%li exceeds Lc=%li",sent, Lc);
					return ERROR;
				}
				call (ICC_Async_Transmit (1, data + sent));							//Send next data byte
				sent++;
				continue;
			}
			else {/* Case 3 command: receive data */
				if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE) {
					cs_debug_mask(D_TRACE, "ERROR Protocol_T0_ExchangeTPDU: Case 3 ~ACK - maximum short response exceeded:%li",recv);
					return ERROR;
				}
				call (ICC_Async_Receive (1, buffer + recv));						//Read next data byte
				recv++;
				continue;
			}
		}
		else { /* Anything else received */
			cs_debug_mask(D_TRACE, "ERROR Protocol_T0_ExchangeTPDU: Received unexpected character %02X", buffer[recv]);
			return ERROR;
		}
	}//while
		
	(*rsp) = APDU_Rsp_New (buffer, recv);
	return OK;
}

int Protocol_T14_ExchangeTPDU (unsigned char * cmd_raw, unsigned long command_len, APDU_Rsp ** rsp)
{
	BYTE buffer[PROTOCOL_T14_MAX_SHORT_RESPONSE];
	long recv;
	int cmd_case;
	BYTE ixor = 0x3E;
	BYTE ixor1 = 0x3F;
	BYTE b1 = 0x01;
	int i;
	long cmd_len = (long) command_len;
	(*rsp) = NULL;//in case of error this is returned
	
	/* Parse APDU */
	cmd_case = APDU_Cmd_Case (cmd_raw, cmd_len);
	for(i=0; i<cmd_len; i++)
		ixor^=cmd_raw[i];
	
	/* Check case of command */
	if ((cmd_case != APDU_CASE_2S) && (cmd_case != APDU_CASE_3S)) {
		cs_debug_mask(D_TRACE, "ERROR: invalid cmd_case = %i in Protocol_T14_ExchangeTPDU",cmd_case);
		return ERROR;
	}
	
	if (reader[ridx].typ <= R_MOUSE) {
		call (ICC_Async_Transmit (1, &b1));						//send 0x01 byte
		call (ICC_Async_Transmit (cmd_len, cmd_raw));	//send apdu
		call (ICC_Async_Transmit (1, &ixor));					//Send xor byte
	}
	else {
		buffer[0] = 0x01;
		memcpy(buffer+1, cmd_raw, cmd_len);
		buffer[cmd_len+1] = ixor;
		
		/* Send apdu */
		call (ICC_Async_Transmit (cmd_len+2, buffer));//send apdu
	}
	
	if(cmd_raw[0] == 0x02 && cmd_raw[1] == 0x09)
		cs_sleepms(2500); //FIXME why wait?
	call (ICC_Async_Receive (8, buffer));				//Read one procedure byte
	recv = (long)buffer[7];
	if(recv)
		call (ICC_Async_Receive (recv, buffer + 8));
	call (ICC_Async_Receive (1, &ixor));
	for(i=0; i<8+recv; i++)		
		ixor1^=buffer[i];
	if(ixor1 != ixor) {
		cs_debug_mask(D_TRACE, "ERROR: invalid checksum = %02X expected %02X", ixor1, ixor);
		return ERROR;
	}
	memcpy(buffer + 8 + recv, buffer + 2, 2);
	(*rsp) = APDU_Rsp_New (buffer + 8, recv + 2);
	return OK;
}
