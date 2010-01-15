/*
    cardterminal.c
    Card Terminal handling and CT-BCS functions

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
#include "cardterminal.h"
#include "atr.h"
#include <stdlib.h>
#include <string.h>

/*
 * Not exported constants definition
 */

#define CARDTERMINAL_RESETCT_BUFFER_SIZE	35
#define CARDTERMINAL_REQUESTICC_BUFFER_SIZE	35
#define CARDTERMINAL_GETSTATUS_BUFFER_SIZE	19
#define CARDTERMINAL_EJECTICC_BUFFER_SIZE	2
#define CARDTERMINAL_MANUFACTURER		"DETWK"

/* 
 * Not exported functions declaration
 */

static char CardTerminal_ResetCT (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp); 

static char CardTerminal_RequestICC (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static char CardTerminal_GetStatus (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static char CardTerminal_SetParity (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static char CardTerminal_EjectICC (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp);

static void CardTerminal_Clear (CardTerminal * ct);

/*
 * Exported functions definition
 */

CardTerminal * CardTerminal_New (void)
{
	CardTerminal *ct;
	
	ct = (CardTerminal *) malloc (sizeof (CardTerminal));
	
	if (ct != NULL)
		CardTerminal_Clear (ct);
	
	return ct;
}

char CardTerminal_Init (CardTerminal * ct, int reader_type, int mhz, int cardmhz)
{
	char ret;
	int i;
	
	/* Create a new IO_Serial */
	ct->io = IO_Serial_New (mhz, cardmhz);
	
	/* Memory error */
	if (ct->io == NULL)
		return ERR_MEMORY;
	
	/* Initialise serial port */
	if (ICC_Async_Device_Init ()) { 
		printf("ERROR in initializing device\n");
		return ERR_TRANS;
	}
	if (!IO_Serial_Init(ct->io, reader_type))
	{
		free (ct->io);
		ct->io = NULL;
		return ERR_TRANS;
	}
	
	/* Cearte all reader slots */
	ct->num_slots = 0;
	do
	{
		i = ct->num_slots++;
		
		/* Create one slot */
		ct->slots[i] = CT_Slot_New ();
		
		if (ct->slots[i] == NULL)
		{
			ret = ERR_MEMORY;
			break;
		}
		
		/* Initialise slot */
		ret = CT_Slot_Init (ct->slots[i], ct->io, i);
		
		if (ret != OK)
			break;
	}
	while (!CT_Slot_IsLast(ct->slots[i]));
	
	/* On error restore initial state */
	if (ret != OK)
	{
		while (ct->num_slots > 0)
		{
			if (ct->slots[i] != NULL)
			{
				CT_Slot_Delete (ct->slots[i]);
				ct->slots[i] = NULL;
			}
			
			ct->num_slots --;
			i--;
		}
		
		IO_Serial_Close (ct->io);
		free (ct->io);
		ct->io = NULL;
	}
#ifdef HAVE_PTHREAD_H
	else
	{
		pthread_mutex_init(&(ct->mutex), NULL);
	}
#endif
	return ret;
}

char CardTerminal_Command (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[CTBCS_MIN_RESPONSE_SIZE], cla, ins;
	long length;
	char ret;
	
	/* Get class of command */
	cla = APDU_Cmd_Cla (cmd);
	
	if (cla != CTBCS_CLA)
	{
		length = CTBCS_MIN_RESPONSE_SIZE;
		buffer[0] = CTBCS_SW1_WRONG_CLA;
		buffer[1] = CTBCS_SW2_WRONG_CLA;
		
		(*rsp) = APDU_Rsp_New (buffer, length);
		ret = OK;
	}
	else
	{
		/* Get instruction */
		ins = APDU_Cmd_Ins (cmd);
		
		/* Reset CT */
		if (ins == CTBCS_INS_RESET)
			ret = CardTerminal_ResetCT (ct, cmd, rsp);
		else if (ins == CTBCS_INS_REQUEST) /* Request ICC */
			ret = CardTerminal_RequestICC (ct, cmd, rsp);
		else if (ins == CTBCS_INS_STATUS) /* Get Status */
			ret = CardTerminal_GetStatus (ct, cmd, rsp);
		else if (ins == CTBCS_INS_PARITY) /* Get Status */
			ret = CardTerminal_SetParity (ct, cmd, rsp);
		else if (ins == CTBCS_INS_EJECT) /* Eject ICC */
			ret = CardTerminal_EjectICC (ct, cmd, rsp);
		else /* Wrong instruction */
		{
			length = CTBCS_MIN_RESPONSE_SIZE;
			buffer[0] = CTBCS_SW1_WRONG_INS;
			buffer[1] = CTBCS_SW2_WRONG_INS;
			
			(*rsp) = APDU_Rsp_New (buffer, length);
			ret = OK;
		}
	}
	
	return ret;
}

char CardTerminal_Close (CardTerminal * ct)
{
	char ret, aux;
	unsigned int i;
	
	ret = OK;
	
	for (i = 0; i < ct->num_slots; i++)
	{
		if (ct->slots[i] != NULL)
		{
			aux = CT_Slot_Close (ct->slots[i]);
			if (aux != OK)
			ret = aux;
			
			CT_Slot_Delete (ct->slots[i]);
		}
	}
	
	if (ct->io != NULL)
	{
		if (!IO_Serial_Close (ct->io))
			ret = ERR_TRANS;
		
		free (ct->io);
	}
	
	CardTerminal_Clear (ct);
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&(ct->mutex));
#endif
	return ret;
}

void CardTerminal_Delete (CardTerminal * ct)
{
	free (ct);
}

CT_Slot * CardTerminal_GetSlot (CardTerminal * ct, unsigned int number)
{
	if (number < (ct->num_slots))
		return ct->slots[number];
	
	return NULL;
}

#ifdef HAVE_PTHREAD_H
pthread_mutex_t * CardTerminal_GetMutex (CardTerminal * ct)
{
	return &(ct->mutex);
}
#endif

/* 
 * Not exported functions definition
 */

static char CardTerminal_ResetCT (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[CARDTERMINAL_RESETCT_BUFFER_SIZE], p1, p2;
	bool card, change;
	unsigned sn, length;
	void *atr;
	char ret = OK;
	
	/* Get functional unit */
	p1 = APDU_Cmd_P1 (cmd);
	
	/* Funcional unit is the card-terminal */
	if (p1 == CTBCS_P1_CT_KERNEL)
	{
		/* Get command cualifier */
		p2 = APDU_Cmd_P2 (cmd);
		
		/* Wrong command cualifier */
		if (p2 != CTBCS_P2_RESET_NO_RESP && p2 != CTBCS_P2_RESET_GET_ATR && p2 != CTBCS_P2_RESET_GET_HIST)
		{
			buffer[0] = CTBCS_SW1_WRONG_PARAM;
			buffer[1] = CTBCS_SW2_WRONG_PARAM;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return OK;
		}
		
		/* Close slots */
		for (sn = 0; sn < ct->num_slots; sn++)
		{
			/* Close this slot */
			ret = CT_Slot_Close (ct->slots[sn]);
			
			if (ret != OK)
			{
				buffer[0] = CTBCS_SW1_RESET_ERROR;
				buffer[1] = CTBCS_SW2_RESET_ERROR;
				
				(*rsp) = APDU_Rsp_New (buffer, 2);
				return ret;
			}
			
			/* Initialise this slot */
			ret = CT_Slot_Init (ct->slots[sn],ct->io,sn);
			
			if (ret != OK)
			{
				buffer[0] = CTBCS_SW1_RESET_ERROR;
				buffer[1] = CTBCS_SW2_RESET_ERROR;
				
				(*rsp) = APDU_Rsp_New (buffer, 2);
				return ret;
			}
		}
		
		length = 2;
		buffer[0] = CTBCS_SW1_RESET_CT_OK;
		buffer[1] = CTBCS_SW2_RESET_CT_OK;
	}
	else if ((p1 == CTBCS_P1_INTERFACE1) || (p1 == CTBCS_P1_INTERFACE2)) /* Funtional unit is an ICC */
	{
		/* Get slot number */
		sn = (p1 == CTBCS_P1_INTERFACE1) ? 0 : 1;
		
		if (!(sn < ct->num_slots))
		{
			buffer[0] = CTBCS_SW1_WRONG_PARAM;
			buffer[1] = CTBCS_SW2_WRONG_PARAM;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return ERR_INVALID;
		}
		
		/* Release the slot */
		ret = CT_Slot_Release (ct->slots[sn]);
		
		if (ret != OK)
		{
			buffer[0] = CTBCS_SW1_RESET_ERROR;
			buffer[1] = CTBCS_SW2_RESET_ERROR;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return ret;
		}
		
		/* Check for card */
		ret = CT_Slot_Check (ct->slots[sn], 0, &card, &change);
		
		if (ret != OK)
		{
			buffer[0] = CTBCS_SW1_RESET_ERROR;
			buffer[1] = CTBCS_SW2_RESET_ERROR;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return ret;
		}
		
		/* No card present */
		if (!card)
		{
			buffer[0] = CTBCS_SW1_RESET_ERROR;
			buffer[1] = CTBCS_SW2_RESET_ERROR;;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return OK;
		}
		
		/* Probe card type */
		if (APDU_Cmd_Lc (cmd) > 1)
			ret = CT_Slot_Probe (ct->slots[sn], APDU_Cmd_Data(cmd), APDU_Cmd_Lc(cmd));
		else
			ret = CT_Slot_Probe (ct->slots[sn], NULL, 0);
		
		if (ret != OK || (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_NULL))
		{
			buffer[0] = CTBCS_SW1_RESET_ERROR;
			buffer[1] = CTBCS_SW2_RESET_ERROR;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return ret;
		}
		
		/* Get command cualifier */
		p2 = APDU_Cmd_P2 (cmd);
		
		/* Do not return data */
		if (p2 == CTBCS_P2_RESET_NO_RESP)
		{
			if (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_ICC_ASYNC)
			{
				buffer[0] = CTBCS_SW1_RESET_ASYNC_OK;
				buffer[1] = CTBCS_SW2_RESET_ASYNC_OK;
				length = 2;
			}
			else
			{
				buffer[0] = CTBCS_SW1_RESET_SYNC_OK;
				buffer[1] = CTBCS_SW2_RESET_SYNC_OK;
				length = 2;
			}
		}
		else if (p2 == CTBCS_P2_RESET_GET_ATR) /* Return complete ATR of ICC */
		{
			atr = CT_Slot_GetAtr (ct->slots[sn]);
			
			if (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_ICC_ASYNC)
			{
				if (atr != NULL)
					ATR_GetRaw ((ATR *) atr, buffer, &length);
				else 
					length = 0;
				
				buffer[length] = CTBCS_SW1_RESET_ASYNC_OK;
				buffer[length + 1] = CTBCS_SW2_RESET_ASYNC_OK;
//				buffer[length + 1] = ct->slots[sn]->protocol_type;
				length += 2;
			}
		}
		else if (p2 == CTBCS_P2_RESET_GET_HIST) /* Return historical bytes of ATR */
		{
			atr = CT_Slot_GetAtr (ct->slots[sn]);
			
			if (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_ICC_ASYNC)
			{
				if (atr != NULL)
					ATR_GetHistoricalBytes ((ATR *) atr, buffer, &length);
				else
					length = 0;
				
				buffer[length] = CTBCS_SW1_RESET_ASYNC_OK;
				buffer[length + 1] = CTBCS_SW2_RESET_ASYNC_OK;
				length += 2;
			}
		}
		else /* Wrong command cualifier */
		{
			length = 2;
			buffer[0] = CTBCS_SW1_WRONG_PARAM;
			buffer[1] = CTBCS_SW2_WRONG_PARAM;
			ret = OK;
		}
	}
	else /* Wrong functional unit */
	{
		length = 2;
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		ret = OK;
	}
	
	(*rsp) = APDU_Rsp_New (buffer, length);
	return ret;
}

static char CardTerminal_RequestICC (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[CARDTERMINAL_REQUESTICC_BUFFER_SIZE], p1, p2;
	unsigned timeout, sn, length;
	bool card, change;
	void * atr;
	char ret;
	
	/* Get functional unit */
	p1 = APDU_Cmd_P1 (cmd);
	
	if ((p1 == CTBCS_P1_INTERFACE1) || (p1 == CTBCS_P1_INTERFACE2))
	{
		/* Get the slot number */
		sn = (p1 == CTBCS_P1_INTERFACE1) ? 0 : 1;
		
		if (CT_Slot_GetICCType (ct->slots[sn]) != CT_SLOT_NULL)
		{
			buffer[0] = CTBCS_SW1_REQUEST_CARD_PRESENT;
			buffer[1] = CTBCS_SW2_REQUEST_CARD_PRESENT;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return OK;
		}
		
		/* Get the card insertion timeout */
		if (APDU_Cmd_Lc (cmd) == 1)
			timeout = (APDU_Cmd_Data (cmd)[0]);
		else
			timeout = 0;
		
		/* Check for card */
		ret = CT_Slot_Check (ct->slots[sn], timeout, &card, &change);
		
		if (ret != OK)
		{
			buffer[0] = CTBCS_SW1_REQUEST_ERROR;
			buffer[1] = CTBCS_SW2_REQUEST_ERROR;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return ret;
		}
		
		/* No card present */
		if (!card)
		{
			buffer[0] = CTBCS_SW1_REQUEST_NO_CARD;
			buffer[1] = CTBCS_SW2_REQUEST_NO_CARD;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return OK;
		}
		
		/* Probe card type */
		if (APDU_Cmd_Lc (cmd) > 1)
			ret = CT_Slot_Probe (ct->slots[sn], APDU_Cmd_Data(cmd), APDU_Cmd_Lc(cmd));
		else
			ret = CT_Slot_Probe (ct->slots[sn], NULL, 0);
		
		if (ret != OK || (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_NULL))
		{
			buffer[0] = CTBCS_SW1_REQUEST_ERROR;
			buffer[1] = CTBCS_SW2_REQUEST_ERROR;
			
			(*rsp) = APDU_Rsp_New (buffer, 2);
			return ret;
		}
		
		/* Get command cualifier */
		p2 = APDU_Cmd_P2 (cmd);
		
		/* Do not return data */
		if (p2 == CTBCS_P2_REQUEST_NO_RESP)
		{
			if (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_ICC_ASYNC)
			{
				buffer[0] = CTBCS_SW1_REQUEST_ASYNC_OK;
				buffer[1] = CTBCS_SW2_REQUEST_ASYNC_OK;
				length = 2;
			}
			else
			{
				buffer[0] = CTBCS_SW1_REQUEST_SYNC_OK;
				buffer[1] = CTBCS_SW2_REQUEST_SYNC_OK;
				length = 2;
			}
		}
		else if (p2 == CTBCS_P2_REQUEST_GET_ATR) /* Return whole atr */
		{
			atr = CT_Slot_GetAtr (ct->slots[sn]);
			
			if (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_ICC_ASYNC)
			{
				if (atr != NULL)
					ATR_GetRaw ((ATR *) atr, buffer, &length);
				else
					length = 0;
				
				buffer[length] = CTBCS_SW1_REQUEST_ASYNC_OK;
				buffer[length + 1] = CTBCS_SW2_REQUEST_ASYNC_OK;
				length += 2;
			}
		}
		else if (p2 == CTBCS_P2_REQUEST_GET_HIST) /* Return historical bytes */
		{
			atr = CT_Slot_GetAtr (ct->slots[sn]);
			
			if (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_ICC_ASYNC)
			{
				if (atr != NULL)
				ATR_GetHistoricalBytes ((ATR *) atr, buffer, &length);
				else
				length = 0;
				
				buffer[length] = CTBCS_SW1_REQUEST_ASYNC_OK;
				buffer[length + 1] = CTBCS_SW2_REQUEST_ASYNC_OK;
				length += 2;
			}
		}
		else /* Wrong command cualifier */
		{
			length = 2;
			buffer[0] = CTBCS_SW1_WRONG_PARAM;
			buffer[1] = CTBCS_SW2_WRONG_PARAM;
			ret = OK;
		}
	}
	else /* Wrong functional unit */
	{
		length = 2;
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		ret = OK;
	}
	
	(*rsp) = APDU_Rsp_New (buffer, (long)length);
	return ret;
}

static char CardTerminal_GetStatus (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[CARDTERMINAL_GETSTATUS_BUFFER_SIZE], p1, p2;
	bool card, change;
	unsigned int i;
	unsigned length;
	char ret = OK;
	
	/* Get functional unit */
	p1 = APDU_Cmd_P1 (cmd);
	
	/* Wrong functional unit */
	if (p1 != CTBCS_P1_CT_KERNEL)
	{
		length = 2;
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		ret = OK;
	}
	
	/* Get command cualifier */
	p2 = APDU_Cmd_P2 (cmd);
	
	if (p2 == CTBCS_P2_STATUS_MANUFACTURER)
	{
		length = 17;
		
		/* CT Manufacturer */ 
		memcpy(buffer,CARDTERMINAL_MANUFACTURER,5);
		
		/* CT type */
		if (ct->slots[0] != NULL)
			CT_Slot_GetType(ct->slots[0], buffer + 5,5);
		
		/* CT version */
		memcpy(buffer+10,VERSION,5);
		
		buffer[15] = CTBCS_SW1_OK;
		buffer[16] = CTBCS_SW2_OK;
		ret = OK;
	}	
	else if (p2 == CTBCS_P2_STATUS_ICC)
	{
		for (i = 0; i < ct->num_slots; i++)
		{
			ret = CT_Slot_Check (ct->slots[i], 0, &card, &change);
			
			if (ret != OK)
			{
				/* There are no status bytes defined to be returned on error */
				(*rsp) = NULL;
				return ret;
			}
			
			/* Resynchronise the driver status with the actual status of slot */
			if ((CT_Slot_GetICCType (ct->slots[i]) != CT_SLOT_NULL) && (!card || change))
			{
				ret = CT_Slot_Release (ct->slots[i]);
				
				if (ret != OK)
				{
					(*rsp) = NULL;
					return ret;
				}
			}
			
			buffer[i] = card? CTBCS_DATA_STATUS_CARD_CONNECT: CTBCS_DATA_STATUS_NOCARD;
		}
		
		length = i+2;
		buffer[i] = CTBCS_SW1_OK;
		buffer[i+1] = CTBCS_SW2_OK;
	}
	else if (p2 == CTBCS_P2_STATUS_PROTOCOL)
	{
		for (i = 0; i < ct->num_slots; i++)
		{
			if(ct->slots[i]->protocol_type == CT_SLOT_PROTOCOL_T0)
				buffer[i] = 0x00;
			else if(ct->slots[i]->protocol_type == CT_SLOT_PROTOCOL_T1)		
				buffer[i] = 0x01;
			else if(ct->slots[i]->protocol_type == CT_SLOT_PROTOCOL_T14)		
				buffer[i] = 0x0E;
			else
				buffer[i] = 0xFF;
		}
		
		length = i+2;
		buffer[i] = CTBCS_SW1_OK;
		buffer[i+1] = CTBCS_SW2_OK;
		ret = OK;
	}
	else /* Wrong command cualifier */
	{
		length = 2;
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		ret = OK;
	}
	
	(*rsp) = APDU_Rsp_New (buffer, length);
	return ret;
}

static char CardTerminal_SetParity (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[2], p1, p2;
	unsigned length;
	char ret = OK;
	
	/* Get functional unit */
	p1 = APDU_Cmd_P1 (cmd);
	
	/* Wrong functional unit */
	if (p1 != CTBCS_P1_CT_KERNEL)
	{
		length = 2;
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		ret = OK;
	}
	
	/* Get command cualifier */
	p2 = APDU_Cmd_P2 (cmd);
	
	if (p2 == CTBCS_P2_PARITY_ODD)
	{
		length = 2;
		IO_Serial_SetParity (PARITY_ODD);	
		buffer[0] = CTBCS_SW1_OK;
		buffer[1] = CTBCS_SW2_OK;
		ret = OK;
	}	
	else if(p2 == CTBCS_P2_PARITY_EVEN)
	{
		length = 2;
		IO_Serial_SetParity (PARITY_EVEN);	
		buffer[0] = CTBCS_SW1_OK;
		buffer[1] = CTBCS_SW2_OK;
		ret = OK;
	}	
	else if (p2 == CTBCS_P2_PARITY_NONE)
	{
		length = 2;
		IO_Serial_SetParity (PARITY_NONE);	
		buffer[0] = CTBCS_SW1_OK;
		buffer[1] = CTBCS_SW2_OK;
		ret = OK;
	}	
	else /* Wrong command cualifier */
	{
		length = 2;
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		ret = OK;
	}
	
	(*rsp) = APDU_Rsp_New (buffer, length);
	return ret;
}

static char CardTerminal_EjectICC (CardTerminal * ct, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
	BYTE buffer[CARDTERMINAL_EJECTICC_BUFFER_SIZE], p1, p2;
	unsigned int sn, timeout;
	unsigned length;
	bool card, change;
	char ret;
	
	/* Get functional unit */
	p1 = APDU_Cmd_P1 (cmd);
	
	/* Wrong functional unit */
	if ((p1 != CTBCS_P1_INTERFACE1) && (p1 != CTBCS_P1_INTERFACE2))
	{
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		
		(*rsp) = APDU_Rsp_New (buffer, 2);
		return OK;
	}
	
	/* Get the slot number */
	sn = (p1 == CTBCS_P1_INTERFACE1) ? 0 : 1;
	
	if (!(sn < ct->num_slots))
	{
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		
		(*rsp) = APDU_Rsp_New (buffer, 2);
		return ERR_INVALID;
	}
	
	/* Get command cualifier */
	p2 = APDU_Cmd_P2 (cmd);
	
#if 0
	/* Wrong command cualifier */
	if (p2 != 0)
	{
		buffer[0] = CTBCS_SW1_WRONG_PARAM;
		buffer[1] = CTBCS_SW2_WRONG_PARAM;
		
		(*rsp) = APDU_Rsp_New (buffer, 2);
		return OK;
	}
#endif
	
	if (CT_Slot_GetICCType (ct->slots[sn]) == CT_SLOT_NULL)
	{
		buffer[0] = CTBCS_SW1_EJECT_OK;
		buffer[1] = CTBCS_SW2_EJECT_OK;
		
		(*rsp) = APDU_Rsp_New (buffer, 2);
		return OK;
	}
	
	/* Get the card removal timeout */
	if (APDU_Cmd_Lc (cmd) == 1)
		timeout = (unsigned int) (*APDU_Cmd_Data (cmd));
	else
		timeout = 0;
	
	/* Check for card removal */
	ret = CT_Slot_Check (ct->slots[sn], timeout, &card, &change);
	
	if (ret != OK)
	{
		(*rsp) = NULL;
		return ret;
	}
	
	/* Release ICC (always or only when card is removed?) */
	ret = CT_Slot_Release (ct->slots[sn]);
	
	if (ret != OK)
	{
		(*rsp) = NULL;
		return ret;
	}
	
	if (timeout != 0)
	{
		if (card)
		{
			buffer[0] = CTBCS_SW1_EJECT_NOT_REMOVED;      
			buffer[1] = CTBCS_SW2_EJECT_NOT_REMOVED;
			length = 2;
		}
		else
		{
			buffer[0] = CTBCS_SW1_EJECT_REMOVED;      
			buffer[1] = CTBCS_SW2_EJECT_REMOVED;
			length = 2;
		}
	}
	else
	{
		buffer[0] = CTBCS_SW1_EJECT_OK;;      
		buffer[1] = CTBCS_SW2_EJECT_OK;;
		length = 2;
	}
	
	(*rsp) = APDU_Rsp_New (buffer, length);
	return ret;
}

static void CardTerminal_Clear (CardTerminal * ct)
{
	int i;
	
	ct->io = NULL;
	ct->num_slots = 0;
	
	for (i = 0; i < CARDTERMINAL_MAX_SLOTS; i++)
		ct->slots[i] = NULL;
}
