/*
    apdu.c
    ISO 7816-4 Application Layer PDU's handling

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
#include "apdu.h"
#include <stdlib.h>
#include <string.h>
#include "../globals.h"

/*
 * Not exported constants definiton 
 */

#define APDU_MIN_CMD_SIZE 	4	/* Min command size */
#define APDU_MIN_RSP_SIZE 	2	/* Min response size */
#define APDU_CMD_HEADER_SIZE	4	/* Size of the header */

/* 
 * Exported functions definition
 */

APDU_Cmd * APDU_Cmd_New (BYTE * data, unsigned long length)
{
	APDU_Cmd *apdu;
	
	if ((length > APDU_MAX_CMD_SIZE))
		return NULL;
	
	apdu = (APDU_Cmd *) malloc (sizeof (APDU_Cmd));
	
	if (apdu != NULL)
	{
		apdu->length = MAX (APDU_MIN_CMD_SIZE, length);
		apdu->command = (BYTE *) calloc (apdu->length, sizeof (BYTE));
		
		if (apdu->command != NULL)
		{
			memcpy (apdu->command, data, length);
			if (length < apdu->length)
				memset (apdu->command + length, 0, apdu->length - length);
		}
		else
		{
			free (apdu);
			apdu = NULL;
		}
	}
	
	return apdu;
}

void APDU_Cmd_Delete (APDU_Cmd * apdu)
{
	free (apdu->command);
	free (apdu);
}

int APDU_Cmd_Case (APDU_Cmd * apdu)
{
	BYTE B1;
	ushort B2B3;
	ulong L;
	int res;
	
	/* Calculate length of body */
	L = MAX(apdu->length - 4, 0);
	
	/* Case 1 */
	if (L == 0)
	{
		res = APDU_CASE_1;
	}
	else
	{
		/* Get first byte of body */
		B1 = apdu->command[4];
		
		if ((B1 != 0) && (L == (ulong)B1 + 1))
			res = APDU_CASE_2S;
		else if (L == 1)
			res = APDU_CASE_3S;
		else if ((B1 != 0) && (L == (ulong)B1 + 2))
			res = APDU_CASE_4S;
		else if ((B1 == 0) && (L>2))
		{
			/* Get second and third byte of body */
			B2B3 = (((ushort)(apdu->command[5]) << 8) | apdu->command[6]);
			
			if ((B2B3 != 0) && (L == (ulong)B2B3 + 3))
				res = APDU_CASE_2E;
			else if (L == 3)
				res = APDU_CASE_3E;
			else if ((B2B3 != 0) && (L == (ulong)B2B3 + 5))
				res = APDU_CASE_4E;
			else
				res = APDU_MALFORMED;
		}
		else
		{
			res = APDU_MALFORMED;
		}
	}
	
	return res;
}

BYTE  APDU_Cmd_Cla (APDU_Cmd * apdu)
{
	return apdu->command[0];
}

BYTE APDU_Cmd_Ins (APDU_Cmd * apdu)
{
	return apdu->command[1];
}

BYTE APDU_Cmd_P1 (APDU_Cmd * apdu)
{
	return apdu->command[2];
}

BYTE APDU_Cmd_P2 (APDU_Cmd * apdu)
{
	return apdu->command[3];
}

unsigned long APDU_Cmd_Lc (APDU_Cmd * apdu)
{
	int c;
	unsigned long res;
	
	c = APDU_Cmd_Case (apdu);
	
	if ((c == APDU_CASE_1) || (c == APDU_CASE_3S) || (c == APDU_CASE_3E))
		res = 0;
	else if ((c == APDU_CASE_2S) || (c == APDU_CASE_4S))
		res = apdu->command[4];
	else if ((c == APDU_CASE_2E) || (c == APDU_CASE_4E))
		res  = (((unsigned long)(apdu->command[5]) << 8) | apdu->command[6]);
	else
		res = 0;
	
	return res;
}

unsigned long APDU_Cmd_Le (APDU_Cmd * apdu)
{
	int c;
	unsigned long res;
	
	c = APDU_Cmd_Case (apdu);
	
	if ((c == APDU_CASE_1) || (c == APDU_CASE_2S) || (c == APDU_CASE_2E))
		res = 0;
	else if (c == APDU_CASE_3S)
//		res = ((apdu->command[4] == 0) ? 256: apdu->command[4]);
		res = apdu->command[4];
	else if (c == APDU_CASE_4S)
		res = ((apdu->command[apdu->length - 1] == 0) ? 256: apdu->command[apdu->length - 1]);
	else if (c == APDU_CASE_3E)
		res  = ((((unsigned long)(apdu->command[5]) << 8) | apdu->command[6]) == 0 ? 65536 : (((unsigned long)(apdu->command[5]) << 8) | apdu->command[6]));
	else if (c == APDU_CASE_4E)
		res  = ((((unsigned long)(apdu->command[apdu->length - 2]) << 8) | apdu->command[apdu->length - 1]) == 0 ? 65536 : (((unsigned long)(apdu->command[apdu->length - 2]) << 8) | apdu->command[apdu->length - 1]));
	else
		res = 0;
	
	return res;
}

bool  APDU_Cmd_Le_Available (APDU_Cmd * apdu)
{
	int c;
	bool res;
	
	c = APDU_Cmd_Case (apdu);
	
	if (c == APDU_CASE_3S)
		res = (apdu->command[4] == 0);
	else if (c  == APDU_CASE_4S)
		res  = (apdu->command[apdu->length - 1] == 0);
	else if (c == APDU_CASE_3E)
		res = ((((unsigned long)(apdu->command[5]) << 8) | apdu->command[6]) == 0);
	else if (c == APDU_CASE_4E)
		res = ((((unsigned long)(apdu->command[apdu->length - 2]) << 8) | apdu->command[apdu->length - 1]) == 0);
	else
		res = FALSE;
	
	return res;
}

BYTE * APDU_Cmd_Header (APDU_Cmd * apdu)
{
	return apdu->command;
}


BYTE * APDU_Cmd_Data (APDU_Cmd * apdu)
{
	int c;
	BYTE * res;
	
	c = APDU_Cmd_Case (apdu);
	
	if ((c == APDU_CASE_1) || (c == APDU_CASE_3S) || (c == APDU_CASE_3E))
		res = NULL;
	else if ((c == APDU_CASE_2S) || (c == APDU_CASE_4S))
		res = apdu->command + 5;
	else if ((c == APDU_CASE_2E) || (c == APDU_CASE_4E))
		res = apdu->command + 7;
	else
		res = NULL;
	
	return res;
}

BYTE * APDU_Cmd_Raw (APDU_Cmd * apdu)
{
	return apdu->command;
}

unsigned long APDU_Cmd_RawLen (APDU_Cmd * apdu)
{
	return apdu->length;
}

APDU_Rsp * APDU_Rsp_New (BYTE * data, unsigned long length)
{
	APDU_Rsp *apdu;
	
	if (length < APDU_MIN_RSP_SIZE)
		return NULL;
	
	apdu = (APDU_Rsp *) malloc (sizeof (APDU_Rsp));
	
	if (apdu != NULL)
	{
		apdu->length = length;
		apdu->response = (BYTE *) calloc (length, sizeof (BYTE));
		
		if (apdu->response != NULL)
		{
			memcpy (apdu->response, data, length);
		}
		else
		{
			free (apdu);
			apdu = NULL;
		}
	}
	
	return apdu;
}

void APDU_Rsp_Delete (APDU_Rsp * apdu)
{
	free (apdu->response);
	free (apdu);
}

BYTE APDU_Rsp_SW1 (APDU_Rsp * apdu)
{
	return (apdu->response[(apdu->length) - 2]);
}

BYTE APDU_Rsp_SW2 (APDU_Rsp * apdu)
{
	return (apdu->response[(apdu->length) - 1]);
}

unsigned long
APDU_Rsp_DataLen (APDU_Rsp * apdu)
{
	return (apdu->length - 2);
}

BYTE * APDU_Rsp_Data (APDU_Rsp * apdu)
{
	return apdu->response;
}

BYTE * APDU_Rsp_Raw (APDU_Rsp * apdu)
{
	return apdu->response;
}

unsigned long APDU_Rsp_RawLen (APDU_Rsp * apdu)
{
	return apdu->length;
}

void  APDU_Rsp_TruncateData (APDU_Rsp * apdu, unsigned long length)
{
	if ((length > 0) && ((signed long)length < (signed long)(apdu->length - 2)))
	{
		apdu->response[length] = APDU_Rsp_SW1 (apdu);
		apdu->response[length + 1] = APDU_Rsp_SW2 (apdu);
		apdu->length = length +2;
	}
}

int  APDU_Rsp_AppendData (APDU_Rsp * apdu1, APDU_Rsp * apdu2)
{
	BYTE * response;
	unsigned long length;
	int ret;
	
	length = APDU_Rsp_DataLen(apdu1) + APDU_Rsp_RawLen(apdu2);
	
	if ((length > 2) && (length <= APDU_MAX_RSP_SIZE))
	{
		response = (BYTE *) realloc (apdu1->response, length);
		
		if (response != NULL)
		{
			memcpy (response + APDU_Rsp_DataLen (apdu1), 
			APDU_Rsp_Raw (apdu2), APDU_Rsp_RawLen(apdu2));
			
			apdu1->response = response;
			apdu1->length = length;
			ret = APDU_OK;
		}	
		else
		{
			ret = APDU_MALFORMED;
		}
	}
	else
	{
		ret = APDU_MALFORMED;
	}
	
	return ret;
}
