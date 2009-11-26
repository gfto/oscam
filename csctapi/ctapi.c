/*
    ctapi.c
    CT-API interface implementation for multiple card-terminals

    This file is part of the Unix driver for Towitoko smartcard readers
    Copyright (C) 1998 1999 2000 Carlos Prados <cprados@yahoo.com>

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
#include "ctapi.h"
#include "ctbcs.h"
#include "ct_list.h"
#include "cardterminal.h"
#include "ct_slot.h"
#include <stdio.h>
#include <string.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

/* 
 * Not exported variables definition
 */

/* Linked list of card-terminals */
static CT_List *ct_list = NULL;

#ifdef HAVE_PTHREAD_H
static pthread_mutex_t ct_list_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/*
 * Exported functions definition
 */

char CT_init (unsigned short ctn, unsigned short pn,  unsigned long frequency, int reader_type)
{
	CardTerminal *ct;
	char ret;
	bool ct_list_empty;
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_lock (&ct_list_mutex);
#endif
	
	/* Check that ctn is not in use */
	if (CT_List_GetCardTerminal (ct_list, ctn) == NULL)
	{
		/* Create a new CardTerminal */
		ct = CardTerminal_New ();
		
		if (ct != NULL)
		{   
			/* Initialize CardTerminal */
			ret = CardTerminal_Init(ct, pn, frequency, reader_type);
			
			/* Add CardTerminal to list */
			if (ret == OK)
			{  
				/* See if list is initialised */
				ct_list_empty = (ct_list == NULL);
				
				if (ct_list_empty)
					ct_list = CT_List_New ();
				
				/* Add the CardTerminal to the list */
				if (!CT_List_AddCardTerminal (ct_list, ct, ctn))
				{
					CardTerminal_Close (ct);
					CardTerminal_Delete (ct);
					
					if (ct_list_empty)
					{
						CT_List_Delete (ct_list);
						ct_list = NULL;
					}
					
					ret = ERR_MEMORY;
				}
			}
			else
			{
				CardTerminal_Delete(ct);
			}
		}
		else
		{
			ret = ERR_MEMORY;
		}
	}
	else
	{
		ret = ERR_CT;
	}
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock (&ct_list_mutex);
#endif  
	
#ifdef DEBUG_CTAPI
	printf ("CTAPI: CT_init(ctn=%u, pn=%u)=%d\n", ctn, pn, ret);
#endif
	
	return ret;
}

char CT_close (unsigned short ctn)
{
	CardTerminal *ct;
	char ret;
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_lock (&ct_list_mutex);
#endif
	
	/* Get the card-terminal */
	ct = CT_List_GetCardTerminal (ct_list, ctn);
	
	if (ct != NULL)
	{    
		/* Close CardTerminal */
		ret = CardTerminal_Close(ct);
		
		/* Remove card-terminal from list */
		CT_List_RemoveCardTerminal (ct_list, ctn);
		
		/* Delete the list if there are no more card-terminals */
		if (CT_List_GetNumberOfElements (ct_list) == 0)
		{
			CT_List_Delete (ct_list);
			ct_list = NULL;
		}
	}
	else
	{
		ret = ERR_CT;
	}
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock (&ct_list_mutex);
#endif
	
#ifdef DEBUG_CTAPI
	printf ("CTAPI: CT_close(ctn=%d)=%u\n", ctn, ret);
#endif
	
	return ret;
}

char CT_data (unsigned short ctn, unsigned char *dad, unsigned char *sad, unsigned short lc, unsigned char *cmd, unsigned short *lr, unsigned char *rsp)
{
	CardTerminal *ct;
	CT_Slot *slot;
	APDU_Cmd *apdu_cmd;
	APDU_Rsp *apdu_rsp = NULL;
	int remain;
	unsigned char aux;
	char ret;
	
#ifdef DEBUG_CTAPI
	int i;
	
	printf ("CTAPI: CT_data(ctn=%u, *dad=0x%02X, *sad=0x%02X, lc=%u, *cmd={", ctn, *dad, *sad, lc);
	
	for (i=0; i<lc; i++)
		printf ("%02X ", cmd[i]);
	
	printf ("}, *lr=%u, rsp=[])\n", *lr); 
#endif
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_lock (&ct_list_mutex);
#endif
	
	/* Get card-terminal */
	ct = CT_List_GetCardTerminal (ct_list, ctn);
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock (&ct_list_mutex);
#endif
	
	if (ct != NULL)
	{
		/* Create a command APDU */
		apdu_cmd = APDU_Cmd_New (cmd, lc);
		
		if (apdu_cmd != NULL)
		{
			
#ifdef HAVE_PTHREAD_H
			pthread_mutex_lock (CardTerminal_GetMutex(ct));
#endif
			
			/* Command goes to the reader */
			if ((*dad) == 1)
			{
				/* CT-BCS command */
				ret = CardTerminal_Command (ct, apdu_cmd, &apdu_rsp);
				
				(*sad) = 1;
				(*dad) = (*sad);
			}	
			else /* Command goes to an ICC */
			{
				/* Get the slot */
				slot = CardTerminal_GetSlot(ct, ((*dad)==0)? 0: (*dad)-1);
				
				if (slot != NULL)
				{
					/* ICC command */
					ret = CT_Slot_Command (slot, apdu_cmd, &apdu_rsp);
					
					if (CT_Slot_GetICCType (slot) != CT_SLOT_NULL)
					{
						aux = (*sad);
						(*sad) = (*dad);
						(*dad) = aux;
					}
					else
					{
						(*dad) = (*sad);
						(*sad) = 1;
					}
				}
				else
				{
					/* Invalid DAD address */
					(*dad) = (*sad);
					(*sad) = 1;
					apdu_rsp = NULL;
					
					ret = ERR_INVALID;
				}
			}
			
#ifdef HAVE_PTHREAD_H
			pthread_mutex_unlock (CardTerminal_GetMutex(ct));
#endif
			
			if (apdu_rsp != NULL)
			{
				/* Copy APDU data to rsp */
				remain = MAX ((short)APDU_Rsp_RawLen(apdu_rsp) - (*lr),0);
				
				if (remain > 0)
					ret = ERR_MEMORY;
				
				(*lr) = MIN ((*lr), (short)APDU_Rsp_RawLen (apdu_rsp));
				
				memcpy (rsp, APDU_Rsp_Raw (apdu_rsp) + remain, (*lr));
				
				/* Delete response APDU */
				APDU_Rsp_Delete (apdu_rsp);
			}
			else 
			{
				(*lr) = 0;
			}
			
			/* Delete command APDU */
			APDU_Cmd_Delete (apdu_cmd);
		}
		else
		{
			ret = ERR_MEMORY;
		} 
	}   
	else
	{
		ret = ERR_CT;
	}
	
#ifdef DEBUG_CTAPI
	printf ("CTAPI: CT_data(ctn=%u, *dad=0x%02X, *sad=0x%02X, lc=%u, *cmd={}, *lr=%u, rsp={", ctn, *dad, *sad, lc, *lr);
	
	for (i=0; i<*lr; i++)
		printf ("%02X ", rsp[i]);
	
	printf ("})=%d\n", ret); 
#endif
	
	return ret;
}
