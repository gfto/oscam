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

#include "defines.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


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

/*
 * Not exported functions declaration
 */

static void Protocol_T0_Clear (Protocol_T0 * t0);
static void Protocol_T14_Clear (Protocol_T14 * t14);

static int Protocol_T0_Case1 (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case2S (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);
static int Protocol_T14_Case2S (Protocol_T14 * t14, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case3S (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);
static int Protocol_T14_Case3S (Protocol_T14 * t14, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case4S (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case2E (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case3E (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_Case4E (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static int Protocol_T0_ExchangeTPDU (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp);
static int Protocol_T14_ExchangeTPDU (Protocol_T14 * t14, APDU_Cmd * cmd, APDU_Rsp ** rsp);

/*
 * Exproted funtions definition
 */

Protocol_T0 * Protocol_T0_New (void)
{
	Protocol_T0 *t0;
	
	t0 = (Protocol_T0 *) malloc (sizeof (Protocol_T0));
	
	if (t0 != NULL)
		Protocol_T0_Clear (t0);
	
	return t0;
}

Protocol_T14 * Protocol_T14_New (void)
{
	Protocol_T14 *t14;
	
	t14 = (Protocol_T14 *) malloc (sizeof (Protocol_T14));
	
	if (t14 != NULL)
		Protocol_T14_Clear (t14);
	
	return t14;
}

int Protocol_T0_Init (Protocol_T0 * t0, ICC_Async * icc, PPS_ProtocolParameters * params)
{
	ICC_Async_Timings timings;
	BYTE wi;
#ifndef PROTOCOL_T0_USE_DEFAULT_TIMINGS
	ATR *atr = ICC_Async_GetAtr (icc);
#endif
	
	/* Set ICC */
	t0->icc = icc;
	
	/* Integer value WI  = TC2, by default 10 */
#ifndef PROTOCOL_T0_USE_DEFAULT_TIMINGS
	if (ATR_GetInterfaceByte (atr, 2, ATR_INTERFACE_BYTE_TC, &(wi)) != ATR_OK)
#endif
	wi = PROTOCOL_T0_DEFAULT_WI;
	
	/* WWT = 960 * WI * (Fi / f) * 1000 milliseconds */
	t0->wwt = (long unsigned int) (960 * wi * (params->f / ICC_Async_GetClockRate (t0->icc)) * 1000);
	
	/* Set timings */
	ICC_Async_GetTimings (t0->icc, &timings);
	
	timings.block_timeout = t0->wwt;
	timings.char_timeout = t0->wwt;
	
	ICC_Async_SetTimings (t0->icc, &timings);
	
#ifdef DEBUG_PROTOCOL
	printf ("Protocol: T=0: WWT=%d, Clockrate=%lu\n", (int)(t0->wwt),ICC_Async_GetClockRate(t0->icc));
#endif
	
	return PROTOCOL_T0_OK;
}

int Protocol_T14_Init (Protocol_T14 * t14, ICC_Async * icc, PPS_ProtocolParameters * params)
{
	ICC_Async_Timings timings;
	BYTE wi;
#ifndef PROTOCOL_T14_USE_DEFAULT_TIMINGS
	ATR *atr = ICC_Async_GetAtr (icc);
#endif
	
	/* Set ICC */
	t14->icc = icc;
	
	/* Integer value WI  = TC2, by default 10 */
#ifndef PROTOCOL_T14_USE_DEFAULT_TIMINGS
	if (ATR_GetInterfaceByte (atr, 2, ATR_INTERFACE_BYTE_TC, &(wi)) != ATR_OK)
#endif
	wi = PROTOCOL_T14_DEFAULT_WI;
	
	/* WWT = 960 * WI * (Fi / f) * 1000 milliseconds */
	t14->wwt = (long unsigned int) (960 * wi * (params->f / ICC_Async_GetClockRate (t14->icc)) * 1000);
	t14->wwt >>= 1;
	
	/* Set timings */
	ICC_Async_GetTimings (t14->icc, &timings);
	
	timings.block_timeout = t14->wwt;
	timings.char_timeout = t14->wwt;
	
	ICC_Async_SetTimings (t14->icc, &timings);
	
#ifdef DEBUG_PROTOCOL
	printf ("Protocol: T=14: WWT=%d\n", (int)(t14->wwt));
#endif
	
	return PROTOCOL_T14_OK;
}

int Protocol_T0_Command (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int cmd_case, ret;
	
	cmd_case = APDU_Cmd_Case (cmd);
	
#ifdef DEBUG_PROTOCOL
	if (cmd_case != APDU_MALFORMED)
		printf ("Protocol: T=0 Case %d %s\n", (cmd_case & 0x0F), APDU_CASE_IS_EXTENDED (cmd_case)? "extended": "short");
#endif
	
	if (cmd_case == APDU_CASE_1)
		ret = Protocol_T0_Case1 (t0, cmd, rsp);
	else if (cmd_case == APDU_CASE_2S)
		ret = Protocol_T0_Case2S (t0, cmd, rsp);
	else if (cmd_case == APDU_CASE_3S)
		ret = Protocol_T0_Case3S (t0, cmd, rsp);
	else if (cmd_case == APDU_CASE_4S)
		ret = Protocol_T0_Case4S (t0, cmd, rsp);
	else if (cmd_case == APDU_CASE_2E)
		ret = Protocol_T0_Case2E (t0, cmd, rsp);
	else if (cmd_case == APDU_CASE_3E)
		ret = Protocol_T0_Case3E (t0, cmd, rsp);
	else if (cmd_case == APDU_CASE_4E)
		ret = Protocol_T0_Case4E (t0, cmd, rsp);
	else
	{
#ifdef DEBUG_PROTOCOL
		printf ("Protocol: T=0: Invalid APDU\n");
#endif
		ret = PROTOCOL_T0_ERROR;
	}
	
	return ret;
}

int Protocol_T14_Command (Protocol_T14 * t14, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int cmd_case, ret;
		
	cmd_case = APDU_Cmd_Case (cmd);
	
#ifdef DEBUG_PROTOCOL
	if (cmd_case != APDU_MALFORMED)
		printf ("Protocol: T=14 Case %d %s\n", (cmd_case & 0x0F), APDU_CASE_IS_EXTENDED (cmd_case)? "extended": "short");
#endif
	
	if (cmd_case == APDU_CASE_2S)
	{
		ret = Protocol_T14_Case2S (t14, cmd, rsp);
	}
	else if (cmd_case == APDU_CASE_3S)
	{
		ret = Protocol_T14_Case3S (t14, cmd, rsp);
	}
	else
	{
#ifdef DEBUG_PROTOCOL
		printf ("Protocol: T=14: Invalid APDU\n");
#endif
	ret = PROTOCOL_T14_ERROR;
	}
	
	return ret;
}

int Protocol_T0_Close (Protocol_T0 * t0)
{
	Protocol_T0_Clear (t0);
	
	return PROTOCOL_T0_OK;
}

int Protocol_T14_Close (Protocol_T14 * t14)
{
	Protocol_T14_Clear (t14);
	
	return PROTOCOL_T14_OK;
}

void Protocol_T0_Delete (Protocol_T0 * t0)
{
 	free (t0);
}

void Protocol_T14_Delete (Protocol_T14 * t14)
{
 	free (t14);
}

/*
 * Not exported functions definition
 */

static int Protocol_T0_Case1 (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	BYTE buffer[5];
	APDU_Cmd *tpdu_cmd;
	
	/* Map command APDU onto TPDU */
	memcpy (buffer, APDU_Cmd_Raw (cmd), 4);
	buffer[4] = 0x00;
	
	tpdu_cmd = APDU_Cmd_New (buffer, 5);
	
	/* Send command TPDU */
	ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, rsp);
	
	/* Delete command TPDU */
	APDU_Cmd_Delete (tpdu_cmd);
	
	return ret;
}


static int Protocol_T0_Case2S (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	
	/* Send command TPDU */
	ret = Protocol_T0_ExchangeTPDU (t0, cmd, rsp);
	
	return ret;
}

static int Protocol_T14_Case2S (Protocol_T14 * t14, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	
	/* Send command TPDU */
	ret = Protocol_T14_ExchangeTPDU (t14, cmd, rsp);
	
	return ret;
}

static int Protocol_T0_Case3S (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	APDU_Rsp *tpdu_rsp;
#ifdef PROTOCOL_T0_ISO
	BYTE buffer[5];
	APDU_Cmd *tpdu_cmd;
#endif
	
	/* Send command TPDU */
	ret = Protocol_T0_ExchangeTPDU (t0, cmd, (&tpdu_rsp));
	
	if (ret == PROTOCOL_T0_OK)
	{
#ifdef PROTOCOL_T0_ISO
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
			ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, rsp);
			
			/* Delete command TPDU */
			APDU_Cmd_Delete (tpdu_cmd);
			
			if (ret == PROTOCOL_T0_OK)
			{
				if (APDU_Rsp_DataLen ((*rsp)) > APDU_Cmd_Le (cmd))
				{
					/* Map response APDU onto TPDU */
					APDU_Rsp_TruncateData ((*rsp), APDU_Cmd_Le (cmd));
				}
			}
		}
		else if (APDU_Rsp_SW1 (tpdu_rsp) == 0x61) /* Command processed, Lx indicated */
		{
			/* MAP response TPDU onto APDU */
			(*rsp) = tpdu_rsp;
			
			/* Prepare Get Response TPDU */
			buffer[0] = APDU_Cmd_Cla (cmd);
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
	
			do
			{
				/* Issue Get Response command TPDU */
				buffer[4] = APDU_Rsp_SW2 (tpdu_rsp);
				tpdu_cmd = APDU_Cmd_New (buffer, 5);
				
				ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, (&tpdu_rsp));
				
				/* Delete command TPDU */
				APDU_Cmd_Delete (tpdu_cmd);
				
				if (ret == PROTOCOL_T0_OK)
				{
					/* Append response TPDU to APDU  */
					if (APDU_Rsp_AppendData ((*rsp), tpdu_rsp) != APDU_OK)
						ret = PROTOCOL_T0_ERROR;
					
					/* Delete response TPDU */
					APDU_Rsp_Delete (tpdu_rsp);
				}
			}
			while ((ret == PROTOCOL_T0_OK) && (APDU_Rsp_SW1 (*rsp) == 0x61));
	
			if (ret == PROTOCOL_T0_OK)
			{
				if (APDU_Rsp_DataLen ((*rsp)) > APDU_Cmd_Le (cmd))
				{
					/* Map response APDU onto TPDU */
					APDU_Rsp_TruncateData ((*rsp), APDU_Cmd_Le (cmd));
				}
			}
		}	
		else /* Le accepted */
		{
			/* Map response TPDU onto APDU without change */
			(*rsp) = tpdu_rsp;
		}
#else
	(*rsp) = tpdu_rsp;
#endif
	}
	
	return ret;
}

static int Protocol_T14_Case3S (Protocol_T14 * t14, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	
	/* Send command TPDU */
	ret = Protocol_T14_ExchangeTPDU (t14, cmd, rsp);
	
	return ret;
}

static int Protocol_T0_Case4S (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret;
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	APDU_Cmd *tpdu_cmd;
	APDU_Rsp *tpdu_rsp;
	
	/* Map command APDU onto TPDU */
	memcpy (buffer, APDU_Cmd_Raw (cmd), APDU_Cmd_RawLen (cmd) - 1);
	
	tpdu_cmd = APDU_Cmd_New (buffer, APDU_Cmd_RawLen (cmd) - 1);
	
	/* Send command TPDU */
	ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, (&tpdu_rsp));
	
	/* Delete command TPDU */
	APDU_Cmd_Delete (tpdu_cmd);
	
	if (ret == PROTOCOL_T0_OK)
	{
#ifdef PROTOCOL_T0_ISO
		/* Command accepted with information added */
		if (APDU_Rsp_SW1 (tpdu_rsp) == 0x61)
		{
			/* Prepare Get Reponse command TPDU */
			buffer[0] = APDU_Cmd_Cla (cmd);
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			
			if (APDU_Rsp_SW2 (tpdu_rsp) == 0x00)
				buffer[4] = (BYTE) APDU_Cmd_Le (cmd);
			else
				buffer[4] = MIN (APDU_Cmd_Le (cmd), APDU_Rsp_SW2 (tpdu_rsp));
			
			tpdu_cmd = APDU_Cmd_New (buffer, 5);
			
			/* Delete response TPDU */
			APDU_Rsp_Delete (tpdu_rsp);
			
			/* Issue Get Reponse command */
			ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, rsp);
			
			/* Delete command TPDU */
			APDU_Cmd_Delete (tpdu_cmd);
		}	
		else if ((APDU_Rsp_SW1 (tpdu_rsp) & 0xF0) == 0x60) /* Command not accepted */
		{
			/* Map response TPDU onto APDU without change */
			(*rsp) = tpdu_rsp;
		}
		else /* Command accepted */
		{
			/* Delete response TPDU */
			APDU_Rsp_Delete (tpdu_rsp);
			
			/* Prepare Get Reponse TPDU */
			buffer[0] = APDU_Cmd_Cla (cmd);
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			buffer[4] = (BYTE) APDU_Cmd_Le (cmd);
			
			tpdu_cmd = APDU_Cmd_New (buffer, 5);
			
			/* Issue Get Reponse command TPDU */
			ret = Protocol_T0_Case3S (t0, tpdu_cmd, rsp);
			
			/* Delete command TPDU */
			APDU_Cmd_Delete (tpdu_cmd);
		}
#else
		(*rsp) = tpdu_rsp;
#endif
	}
	
	return ret;
}


static int Protocol_T0_Case2E (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	int ret = PROTOCOL_T0_OK, i;
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	APDU_Cmd *tpdu_cmd;
	APDU_Rsp *tpdu_rsp;
	
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
		ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, rsp);
		
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
			ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, (&tpdu_rsp));
			
			/* Delete command TPDU */
			APDU_Cmd_Delete (tpdu_cmd);
			
			if (ret == PROTOCOL_T0_OK)
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


static int Protocol_T0_Case3E (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
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
		ret = Protocol_T0_Case3S (t0, tpdu_cmd, rsp);
		
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
		ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, (&tpdu_rsp));
		
		/* Delete command TPDU */
		APDU_Cmd_Delete (tpdu_cmd);
		
		if (ret == PROTOCOL_T0_OK)
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
				ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, rsp);
				
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
					ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, (&tpdu_rsp));
					
					/* Delete command TPDU */
					APDU_Cmd_Delete (tpdu_cmd);
					
					if (ret == PROTOCOL_T0_OK)
					{
						/* Append response TPDU to APDU  */
						if (APDU_Rsp_AppendData ((*rsp), tpdu_rsp) != APDU_OK)
						{
							ret = PROTOCOL_T0_ERROR;
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


static int Protocol_T0_Case4E (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
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
		ret = Protocol_T0_ExchangeTPDU (t0, tpdu_cmd, (&tpdu_rsp));
		
		/* Delete command TPDU */
		APDU_Cmd_Delete (tpdu_cmd);
	}
	else /* 4E2 */
	{
		ret = Protocol_T0_Case2E (t0, cmd, (&tpdu_rsp));
	}
	
	/* 4E1 a) b) and c) */
	if (ret == PROTOCOL_T0_OK)
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
			ret = Protocol_T0_Case3E (t0, gr_cmd, rsp);
			
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
			ret = Protocol_T0_Case3E (t0, gr_cmd, rsp);
			
			/* Delete Get Response command APDU */
			APDU_Cmd_Delete (gr_cmd);
		}
	}
	return ret;
}


static int Protocol_T0_ExchangeTPDU (Protocol_T0 * t0, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[PROTOCOL_T0_MAX_SHORT_RESPONSE];
	BYTE *data;
	long Lc, Le, sent, recv;
	int ret = PROTOCOL_T0_OK, nulls, cmd_case;
	
	/* Parse APDU */
	Lc = APDU_Cmd_Lc (cmd);
	Le = APDU_Cmd_Le (cmd);
	data = APDU_Cmd_Data (cmd);
	cmd_case = APDU_Cmd_Case (cmd);
	
	/* Check case of command */
	if ((cmd_case != APDU_CASE_2S) && (cmd_case != APDU_CASE_3S))
		return PROTOCOL_T0_ERROR;
	
	/* Initialise transmission */
	if (ICC_Async_BeginTransmission (t0->icc) != ICC_ASYNC_OK)
	{
		(*rsp) = NULL;
		return PROTOCOL_T0_ICC_ERROR;
	}
	
	/* Send header bytes */
	if (ICC_Async_Transmit (t0->icc, 5, APDU_Cmd_Header (cmd)) != ICC_ASYNC_OK)
	{
		ICC_Async_EndTransmission (t0->icc);
		
		(*rsp) = NULL;
		return PROTOCOL_T0_ICC_ERROR;
	}
	
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
		/* Read one procedure byte */
		if (ICC_Async_Receive (t0->icc, 1, buffer + recv) != ICC_ASYNC_OK)
		{
			ret = PROTOCOL_T0_ICC_ERROR;
			break;
		}
		
		/* NULL byte received */
		if (buffer[recv] == 0x60)
		{
			nulls++;
			
			/* Maximum number of nulls reached */
			if (nulls >= PROTOCOL_T0_MAX_NULLS)
			{
				ret = PROTOCOL_T0_NULL_ERROR;
				break;
			}
			
			continue;
		}
		else if ((buffer[recv] & 0xF0) == 0x60 || (buffer[recv] & 0xF0) == 0x90) /* SW1 byte received */
		{//printf("sw1\n");
			recv++;
			
			if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE)
				return PROTOCOL_T0_ERROR;
			
			/* Read SW2 byte */
			if (ICC_Async_Receive (t0->icc, 1, buffer + recv) != ICC_ASYNC_OK)
			{
				ret = PROTOCOL_T0_ICC_ERROR;
				break;
			}
			
			recv++;
			
			ret = PROTOCOL_T0_OK;
			break;
		}
		else if ((buffer[recv] & 0x0E) == (APDU_Cmd_Ins (cmd) & 0x0E)) /* ACK byte received */
		{//printf("ack\n");
			/* Reset null's counter */
			nulls = 0;
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S)
			{
				if (sent >= Lc)
					return PROTOCOL_T0_ERROR;
								
				if (ICC_Async_Transmit(t0->icc, MAX (Lc - sent, 0), data + sent) != ICC_ASYNC_OK) /* Send remaining data bytes */
				{
					ret = PROTOCOL_T0_ICC_ERROR;
					break;
				}
				
				sent = Lc;
				continue;
			}
			else /* Case 3 command: receive data */
			{
				if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE)
					return PROTOCOL_T0_ERROR;
				
				/* 
				* Le <= PROTOCOL_T0_MAX_SHORT_RESPONSE - 2 for short commands 
				*/
				
				/* Read remaining data bytes */
				if (ICC_Async_Receive(t0->icc, MAX (Le - recv, 0), buffer + recv) != ICC_ASYNC_OK)
				{//printf("error %d\n", (int)Le);
					ret = PROTOCOL_T0_ICC_ERROR;
					break;
				}
				
				recv = Le;
				continue;
			}
		}
		else if ((buffer[recv] & 0x0E) == ((~APDU_Cmd_Ins (cmd)) & 0x0E)) /* ~ACK byte received */
		{//printf("~ack\n");
			/* Reset null's counter */
			nulls = 0;
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S)
			{
				if (sent >= Lc)
					return PROTOCOL_T0_ERROR;
								
				/* Send next data byte */
				if (ICC_Async_Transmit (t0->icc, 1, data + sent) !=ICC_ASYNC_OK)
				{
					ret = PROTOCOL_T0_ICC_ERROR;
					break;
				}
				
				sent++;
				continue;
			}
			else /* Case 3 command: receive data */
			{
				if (recv >= PROTOCOL_T0_MAX_SHORT_RESPONSE)
					return PROTOCOL_T0_ERROR;
				
				/* Read next data byte */
				if (ICC_Async_Receive (t0->icc, 1, buffer + recv) != ICC_ASYNC_OK)
				{
					ret = PROTOCOL_T0_ICC_ERROR;
					break;
				}
				
				recv++;
				continue;
			}
		}
		else /* Anything else received */
		{//printf("hs\n");
			ret = PROTOCOL_T0_ERROR;
			break;
		}
	}
		
	if (ret == PROTOCOL_T0_OK)
		(*rsp) = APDU_Rsp_New (buffer, recv);
	else
		(*rsp) = NULL;
	
	/* End of transmission */
	if (ICC_Async_EndTransmission (t0->icc) != ICC_ASYNC_OK)
		return PROTOCOL_T0_ICC_ERROR;
	
	return (ret);
}

static int Protocol_T14_ExchangeTPDU (Protocol_T14 * t14, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[PROTOCOL_T14_MAX_SHORT_RESPONSE];
	BYTE *cmd_raw;
	long sent, recv, cmd_len;
	int ret = PROTOCOL_T14_OK, nulls, cmd_case;
	BYTE ixor = 0x3E;
	BYTE ixor1 = 0x3F;
	BYTE b1 = 0x01;
	int i;
	
	/* Parse APDU */
	cmd_len = APDU_Cmd_Lc (cmd) + 5;
	cmd_raw = APDU_Cmd_Raw (cmd);
	cmd_case = APDU_Cmd_Case (cmd);
	for(i=0; i<cmd_len; i++)
		ixor^=cmd_raw[i];

	/* Check case of command */
	if ((cmd_case != APDU_CASE_2S) && (cmd_case != APDU_CASE_3S))
		return PROTOCOL_T14_ERROR;
	
	/* Initialise transmission */
	if (ICC_Async_BeginTransmission (t14->icc) != ICC_ASYNC_OK)
	{
		(*rsp) = NULL;
		return PROTOCOL_T14_ICC_ERROR;
	}
	
	if(t14->icc->ifd->io->com!=RTYP_SCI)
	{
		/* Send 0x01 byte */
		if (ICC_Async_Transmit (t14->icc, 1, &b1) != ICC_ASYNC_OK)
		{
			ICC_Async_EndTransmission (t14->icc);
			
			(*rsp) = NULL;
			return PROTOCOL_T14_ICC_ERROR;
		}
		
		/* Send apdu */
		if (ICC_Async_Transmit (t14->icc, cmd_len, cmd_raw) != ICC_ASYNC_OK)
		{
			ICC_Async_EndTransmission (t14->icc);
			
			(*rsp) = NULL;
			return PROTOCOL_T14_ICC_ERROR;
		}
		
		/* Send xor byte */
		if (ICC_Async_Transmit (t14->icc, 1, &ixor) != ICC_ASYNC_OK)
		{
			ICC_Async_EndTransmission (t14->icc);
			
			(*rsp) = NULL;
			return PROTOCOL_T14_ICC_ERROR;
		}
	}
	else
	{
		buffer[0] = 0x01;
		memcpy(buffer+1, cmd_raw, cmd_len);
		buffer[cmd_len+1] = ixor;
		
		/* Send apdu */
		if (ICC_Async_Transmit (t14->icc, cmd_len+2, buffer) != ICC_ASYNC_OK)
		{
			ICC_Async_EndTransmission (t14->icc);
			
			(*rsp) = NULL;
			return PROTOCOL_T14_ICC_ERROR;
		}
	}
	
	/* Initialise counters */
	nulls = 0;
	sent = 0;
	recv = 0;
	
	
	
	/* 
	* Let's be a bit paranoid with buffer sizes within this loop
	* so it doesn't overflow reception and transmission buffers
	* if card does not strictly respect the protocol
	*/
	
	while (recv < PROTOCOL_T14_MAX_SHORT_RESPONSE)
	{
		if(cmd_raw[0] == 0x02 && cmd_raw[1] == 0x09)
		{
#ifdef HAVE_NANOSLEEP
			struct timespec req_ts;
		
//			req_ts.tv_sec = 1;
//			req_ts.tv_nsec = 500000000;
			req_ts.tv_sec = 2;
			req_ts.tv_nsec = 500000000;
			nanosleep (&req_ts, NULL);
#else
			usleep (999999L);
#endif
		}
		/* Read one procedure byte */
		if (ICC_Async_Receive (t14->icc, 8, buffer) != ICC_ASYNC_OK)
		{
			ret = PROTOCOL_T14_ICC_ERROR;
			break;
		}
		else
		{
			recv = (long)buffer[7];
			
			if(recv)
			{
				if (ICC_Async_Receive (t14->icc, recv, buffer + 8) != ICC_ASYNC_OK)
				{
					ret = PROTOCOL_T14_ICC_ERROR;
					break;
				}
			}
			
			if (ICC_Async_Receive (t14->icc, 1, &ixor) != ICC_ASYNC_OK)
			{
				ret = PROTOCOL_T14_ICC_ERROR;
				break;
			}

			for(i=0; i<8+recv; i++)		
				ixor1^=buffer[i];
				
			if(ixor1 != ixor)
			{
				ret = PROTOCOL_T14_ERROR;
				break;
			}
			
			
			
				
			ret = PROTOCOL_T14_OK;
			break;
		}
	}
		
	if (ret == PROTOCOL_T14_OK)
	{
		memcpy(buffer + 8 + recv, buffer + 2, 2);
		(*rsp) = APDU_Rsp_New (buffer + 8, recv + 2);
	}
	else
	{
		(*rsp) = NULL;
	}
	
	/* End of transmission */
	if (ICC_Async_EndTransmission (t14->icc) != ICC_ASYNC_OK)
		return PROTOCOL_T14_ICC_ERROR;
	
	return (ret);
}

static void Protocol_T0_Clear (Protocol_T0 * t0)
{
	t0->icc = NULL;
	t0->wwt = 0;
}

static void Protocol_T14_Clear (Protocol_T14 * t14)
{
	t14->icc = NULL;
	t14->wwt = 0;
}
