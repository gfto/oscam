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

static int Protocol_T0_Case2E (APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case3E (APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case4E (APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_ExchangeTPDU (APDU_Cmd * cmd, APDU_Rsp ** rsp);

/*
 * Exproted funtions definition
 */

int Protocol_T0_Command (APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int cmd_case;
	
	cmd_case = APDU_Cmd_Case (cmd);
	if (cmd_case != APDU_MALFORMED)
		cs_debug_mask (D_IFD,"Protocol: T=0 Case %d %s\n", (cmd_case & 0x0F), APDU_CASE_IS_EXTENDED (cmd_case)? "extended": "short");

	switch (cmd_case) {
		case APDU_CASE_2E:
			return Protocol_T0_Case2E (cmd, rsp);
		case APDU_CASE_3E:
			return Protocol_T0_Case3E (cmd, rsp);
		case APDU_CASE_4E:
			return Protocol_T0_Case4E (cmd, rsp);
		case APDU_CASE_1:
			cmd->command[4] = 0x00;
			cmd->length = 5;
			return Protocol_T0_ExchangeTPDU(cmd, rsp);
		case APDU_CASE_4S:
			cmd->length--;
		case APDU_CASE_2S:
		case APDU_CASE_3S:
			return Protocol_T0_ExchangeTPDU(cmd, rsp);
		default:
			cs_debug_mask (D_IFD,"Protocol: T=0: Invalid APDU\n");
			return ERROR;
	}
}

/*
 * Not exported functions definition
 */


static int Protocol_T0_Case2E (APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret = OK;
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	APDU_Cmd *tpdu_cmd;
	APDU_Rsp *tpdu_rsp;
    ulong i;
	
	if (APDU_Cmd_Lc (cmd) < 256)
	{
		/* MAP APDU onto command TPDU */
		buffer[0] = APDU_Cmd_Cla (cmd);
		buffer[1] = APDU_Cmd_Ins (cmd);
		buffer[2] = APDU_Cmd_P1 (cmd);
		buffer[3] = APDU_Cmd_P2 (cmd);
		buffer[4] = (BYTE) APDU_Cmd_Lc (cmd);
		
		memcpy (buffer + 5, APDU_Cmd_Data (cmd), buffer[4]);
		
		tpdu_cmd = APDU_Cmd_New (buffer, buffer[4] + 5);
		
		/* Send command TPDU */
		ret = Protocol_T0_ExchangeTPDU(tpdu_cmd, rsp);
		
		/* Delete command TPDU */
		APDU_Cmd_Delete (tpdu_cmd);
	}
	else
	{
		/* Prepare envelope TPDU */
		buffer[0] = APDU_Cmd_Cla (cmd);
		buffer[1] = 0xC2;
		buffer[2] = 0x00;
		buffer[3] = 0x00;
		
		for (i = 0; i < APDU_Cmd_RawLen (cmd); i += buffer[4])
		{
			/* Create envelope command TPDU */
			buffer[4] = MIN (255, APDU_Cmd_RawLen (cmd) - i);
			memcpy (buffer + 5, APDU_Cmd_Raw (cmd) + i, buffer[4]);
			
			tpdu_cmd = APDU_Cmd_New (buffer, buffer[4] + 5);
			
			/* Send envelope command TPDU */
			ret = Protocol_T0_ExchangeTPDU(tpdu_cmd, (&tpdu_rsp));
			
			/* Delete command TPDU */
			APDU_Cmd_Delete (tpdu_cmd);
			
			if (ret == OK)
			{
				/*  Card does support envelope command */
				if (APDU_Rsp_SW1 (tpdu_rsp) == 0x90)
				{
					/* This is not the last segment */
					if (buffer[4] + i < APDU_Cmd_RawLen (cmd))
					{
						/* Delete response TPDU */
						APDU_Rsp_Delete (tpdu_rsp);
					}
					else
					{
						/* Map response TPDU onto APDU */
						(*rsp) = tpdu_rsp;
					}
				}	
				else /* Card does not support envelope command or error */
				{
					/* Map response tpdu onto APDU without change */
					(*rsp) = tpdu_rsp;
					break;
				}
			}
			else
			{
				break;
			}
		}
	}
	
	return ret;
}


static int Protocol_T0_Case3E (APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	BYTE buffer[5];
	APDU_Cmd *tpdu_cmd;
	APDU_Rsp *tpdu_rsp;
	long Lm, Lx;
	
	if (APDU_Cmd_Le (cmd) <= 256)
	{
		/* Map APDU onto command TPDU */
		buffer[0] = APDU_Cmd_Cla (cmd);
		buffer[1] = APDU_Cmd_Ins (cmd);
		buffer[2] = APDU_Cmd_P1 (cmd);
		buffer[3] = APDU_Cmd_P2 (cmd);
		buffer[4] = (BYTE) APDU_Cmd_Le (cmd);
		
		tpdu_cmd = APDU_Cmd_New (buffer, 5);
		
		/* Send command TPDU */
		ret = Protocol_T0_ExchangeTPDU (tpdu_cmd, rsp); //this was Case3S !!!
		
		/* Delete command TPDU */
		APDU_Cmd_Delete (tpdu_cmd);
	}
	else
	{
		/* Map APDU onto command TPDU */
		buffer[0] = APDU_Cmd_Cla (cmd);
		buffer[1] = APDU_Cmd_Ins (cmd);
		buffer[2] = APDU_Cmd_P1 (cmd);
		buffer[3] = APDU_Cmd_P2 (cmd);
		buffer[4] = 0x00;
		
		tpdu_cmd = APDU_Cmd_New (buffer, 5);
		
		/* Send command TPDU */
		ret = Protocol_T0_ExchangeTPDU(tpdu_cmd, (&tpdu_rsp));
		
		/* Delete command TPDU */
		APDU_Cmd_Delete (tpdu_cmd);
		
		if (ret == OK)
		{
			/*  Le definitely not accepted */
			if (APDU_Rsp_SW1 (tpdu_rsp) == 0x67)
			{
				/* Map response APDU onto TPDU without change */
				(*rsp) = tpdu_rsp;
			}		
			else if (APDU_Rsp_SW1 (tpdu_rsp) == 0x6C) /* Le not accepted, La indicated */
			{
				/* Map command APDU onto TPDU */
				memcpy (buffer, APDU_Cmd_Raw (cmd), 4);
				buffer[4] = APDU_Rsp_SW2 (tpdu_rsp);
				
				tpdu_cmd = APDU_Cmd_New (buffer, 5);
				
				/* Delete response TPDU */
				APDU_Rsp_Delete (tpdu_rsp);
				
				/* Re-issue command TPDU */
				ret = Protocol_T0_ExchangeTPDU(tpdu_cmd, rsp);
				
				/* Delete command TPDU */
				APDU_Cmd_Delete (tpdu_cmd);
			}
			else if (APDU_Rsp_SW1 (tpdu_rsp) == 0x61) /* Command processed, Lx indicated */
			{
				/* Map response TPDU onto APDU */
				(*rsp) = tpdu_rsp;
				
				Lx = (APDU_Rsp_SW2 (tpdu_rsp) == 0x00) ? 256 : APDU_Rsp_SW2 (tpdu_rsp);
				Lm = APDU_Cmd_Le (cmd) - APDU_Rsp_DataLen (*rsp);
				
				/* Prepare Get Response TPDU */
				buffer[0] = APDU_Cmd_Cla (cmd);
				buffer[1] = 0xC0;
				buffer[2] = 0x00;
				buffer[3] = 0x00;
				
				while (Lm > 0)
				{
					buffer[4] = (BYTE) MIN (Lm, Lx);
					
					tpdu_cmd = APDU_Cmd_New (buffer, 5);
					
					/* Issue Get Response command TPDU */
					ret = Protocol_T0_ExchangeTPDU(tpdu_cmd, (&tpdu_rsp));
					
					/* Delete command TPDU */
					APDU_Cmd_Delete (tpdu_cmd);
					
					if (ret == OK)
					{
						/* Append response TPDU to APDU  */
						if (APDU_Rsp_AppendData ((*rsp), tpdu_rsp) != APDU_OK)
						{
							ret = ERROR;
							APDU_Rsp_Delete (tpdu_rsp);
							break;
						}
						
						/* Delete response TPDU */
						APDU_Rsp_Delete (tpdu_rsp);
					}
					else
					{
						break;
					}
					
					Lm = APDU_Cmd_Le (cmd) - APDU_Rsp_DataLen (*rsp);
				}/* Lm == 0 */
			} 
			else /* Le accepted: card has no more than 265 bytes or does not support Get Response */
			{
				/* Map response TPDU onto APDU without change */
				(*rsp) = tpdu_rsp;
			}
		}
	}
	
	return ret;
}


static int Protocol_T0_Case4E (APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	APDU_Cmd *tpdu_cmd, *gr_cmd;
	APDU_Rsp *tpdu_rsp;
	long Le;
	
	/* 4E1 */
	if (APDU_Cmd_Lc (cmd) < 256)
	{
		/* Map APDU onto command TPDU */
		buffer[0] = APDU_Cmd_Cla (cmd);
		buffer[1] = APDU_Cmd_Ins (cmd);
		buffer[2] = APDU_Cmd_P1 (cmd);
		buffer[3] = APDU_Cmd_P2 (cmd);
		buffer[4] = (BYTE) APDU_Cmd_Lc (cmd);
		memcpy (buffer + 5, APDU_Cmd_Data (cmd), buffer[4]);
		
		tpdu_cmd = APDU_Cmd_New (buffer, buffer[4] + 5);
		
		/* Send command TPDU */
		ret = Protocol_T0_ExchangeTPDU(tpdu_cmd, (&tpdu_rsp));
		
		/* Delete command TPDU */
		APDU_Cmd_Delete (tpdu_cmd);
	}
	else /* 4E2 */
	{
		ret = Protocol_T0_Case2E (cmd, (&tpdu_rsp));
	}
	
	/* 4E1 a) b) and c) */
	if (ret == OK)
	{
		if (APDU_Rsp_SW1 (tpdu_rsp) == 0x61)
		{
			/* Lm == (Le - APDU_Rsp_RawLen (tpdu_rsp)) == 0 */
			
			if (APDU_Rsp_SW2 (tpdu_rsp) != 0x00)
				Le = MIN(APDU_Rsp_SW2 (tpdu_rsp), APDU_Cmd_Le(cmd));
			else
				Le = APDU_Cmd_Le (cmd); 
			
			/* Delete response TPDU */
			APDU_Rsp_Delete (tpdu_rsp);
			
			/* Prepare extended Get Response APDU command */
			buffer[0] = APDU_Cmd_Cla (cmd);
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			buffer[4] = 0x00;     /* B1 = 0x00 */
			buffer[5] = (BYTE) (Le >> 8);  /* B2 = BL-1 */
			buffer[6] = (BYTE) (Le & 0x00FF);      /* B3 = BL */
			
			gr_cmd = APDU_Cmd_New (buffer, 7);
			
			/* Issue Case 3E get response command */ 
			ret = Protocol_T0_Case3E (gr_cmd, rsp);
			
			/* Delete Get Response command APDU */
			APDU_Cmd_Delete (gr_cmd);             
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
			buffer[0] = APDU_Cmd_Cla (cmd);
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			buffer[4] = 0x00;     /* B1 = 0x00 */
			buffer[5] = (BYTE) (APDU_Cmd_Le (cmd) >> 8);  /* B2 = BL-1 */
			buffer[6] = (BYTE) (APDU_Cmd_Le (cmd) & 0x00FF);      /* B3 = BL */
			
			gr_cmd = APDU_Cmd_New (buffer, 7);
			
			/* Issue Case 3E get response command */
			ret = Protocol_T0_Case3E (gr_cmd, rsp);
			
			/* Delete Get Response command APDU */
			APDU_Cmd_Delete (gr_cmd);
		}
	}
	return ret;
}


static int Protocol_T0_ExchangeTPDU (APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_RESPONSE];
	BYTE *data;
	long Lc, Le, sent, recv;
	int ret = OK, nulls, cmd_case;
	(*rsp) = NULL;//in case of error this will be returned
	
	/* Parse APDU */
	Lc = APDU_Cmd_Lc (cmd);
	Le = APDU_Cmd_Le (cmd);
	data = APDU_Cmd_Data (cmd);
	cmd_case = APDU_Cmd_Case (cmd);
	
	/* Check case of command */
	if ((cmd_case != APDU_CASE_2S) && (cmd_case != APDU_CASE_3S))
		return ERROR;
	
	call (ICC_Async_Transmit (5, APDU_Cmd_Header (cmd)));		//Send header bytes
	
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
			if (nulls >= PROTOCOL_T0_MAX_NULLS)								//Maximum number of nulls reached 
				return ERROR;
			continue;
		}
		else if ((buffer[recv] & 0xF0) == 0x60 || (buffer[recv] & 0xF0) == 0x90) /* SW1 byte received */
		{//printf("sw1\n");
			recv++;
			if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE)
				return ERROR;
			call (ICC_Async_Receive (1, buffer + recv));					//Read SW2 byte
			recv++;
			ret = OK;
			break;
		}
		else if ((buffer[recv] & 0x0E) == (APDU_Cmd_Ins (cmd) & 0x0E)) /* ACK byte received */
		{//printf("ack\n");
			/* Reset null's counter */
			nulls = 0;
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S) {
				if (sent >= Lc)
					return ERROR;
				if (ICC_Async_Transmit(MAX (Lc - sent, 0), data + sent)) /* Send remaining data bytes */
					return ERROR;
				sent = Lc;
				continue;
			}
			else /* Case 3 command: receive data */
			{
				if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE)
					return ERROR;
				
				/* 
				* Le <= PROTOCOL_T0_MAX_SHORT_RESPONSE - 2 for short commands 
				*/
				
				/* Read remaining data bytes */
				call (ICC_Async_Receive(MAX (Le - recv, 0), buffer + recv));
				recv = Le;
				continue;
			}
		}
		else if ((buffer[recv] & 0x0E) == ((~APDU_Cmd_Ins (cmd)) & 0x0E)) /* ~ACK byte received */
		{//printf("~ack\n");
			nulls = 0;																								//Reset null's counter
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S) {
				if (sent >= Lc)
					return ERROR;
				call (ICC_Async_Transmit (1, data + sent));							//Send next data byte
				sent++;
				continue;
			}
			else {/* Case 3 command: receive data */
				if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE)
					return ERROR;
				call (ICC_Async_Receive (1, buffer + recv));						//Read next data byte
				recv++;
				continue;
			}
		}
		else /* Anything else received */
			return ERROR;
	}//while
		
	(*rsp) = APDU_Rsp_New (buffer, recv);
	return OK;
}

int Protocol_T14_ExchangeTPDU (APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[PROTOCOL_T14_MAX_SHORT_RESPONSE];
	BYTE *cmd_raw;
	long recv, cmd_len;
	int cmd_case;
	BYTE ixor = 0x3E;
	BYTE ixor1 = 0x3F;
	BYTE b1 = 0x01;
	int i;
	(*rsp) = NULL;//in case of error this is returned
	
	/* Parse APDU */
	cmd_len = APDU_Cmd_Lc (cmd) + 5;
	cmd_raw = APDU_Cmd_Raw (cmd);
	cmd_case = APDU_Cmd_Case (cmd);
	for(i=0; i<cmd_len; i++)
		ixor^=cmd_raw[i];

	/* Check case of command */
	if ((cmd_case != APDU_CASE_2S) && (cmd_case != APDU_CASE_3S))
		return ERROR;
	
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
	{
#ifdef HAVE_NANOSLEEP
		struct timespec req_ts;
		
//			req_ts.tv_sec = 1;
//			req_ts.tv_nsec = 500000000;
		req_ts.tv_sec = 2;
		req_ts.tv_nsec = 500000000;
		nanosleep (&req_ts, NULL);  //FIXME why wait 2,5 sec?
#else
		usleep (999999L);
#endif
	}
	call (ICC_Async_Receive (8, buffer));				//Read one procedure byte
	recv = (long)buffer[7];
	if(recv)
		call (ICC_Async_Receive (recv, buffer + 8));
	call (ICC_Async_Receive (1, &ixor));
	for(i=0; i<8+recv; i++)		
		ixor1^=buffer[i];
	if(ixor1 != ixor)
		return ERROR;
	memcpy(buffer + 8 + recv, buffer + 2, 2);
	(*rsp) = APDU_Rsp_New (buffer + 8, recv + 2);
	return OK;
}
