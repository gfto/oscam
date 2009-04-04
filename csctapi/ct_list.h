/*
    cl_list.c
    Definition of a linked list of card-terminals

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

#ifndef _CT_LIST_
#define _CT_LIST_

#include "defines.h"
#include "cardterminal.h"

/* 
 * Exported datatypes definition 
 */

/* Node of the list */
struct CT_List_Node
{
  unsigned short ctn;		/* Card Terminal number */
  CardTerminal *ct;		/* Card Terminal reference */
  struct CT_List_Node *next;	/* Next node of the list */
};

/* Linked list of card-terminals */
typedef struct
{
  struct CT_List_Node *first;	/* First element */
  struct CT_List_Node *last;	/* Last element */
  int elements;			/* Number of elements */
}
CT_List;

/* 
 * Exported functions declaration 
 */

/* Creates a new list of CardTerminals */
extern CT_List *
CT_List_New (void);

/* Adds a CardTerminal to a existing list */
extern bool
CT_List_AddCardTerminal (CT_List * list, CardTerminal * ct, unsigned short ctn);

/* Returns a CardTerminal by its number or NULL if not found */
extern CardTerminal * 
CT_List_GetCardTerminal (CT_List * list, unsigned short ctn);

/* Returns the number of CardTerminals in a list */
extern int 
CT_List_GetNumberOfElements (CT_List * list);

/* Removes a CardTerminal from a list by its number */
extern bool 
CT_List_RemoveCardTerminal (CT_List * list, unsigned short ctn);

/* Empties and removes a list */
extern void 
CT_List_Delete (CT_List * list);

#endif /* _CT_LIST_ */

