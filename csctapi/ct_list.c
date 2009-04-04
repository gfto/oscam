/*
    cl_list.c
    Implementation of a linked list of card-terminals

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

#include <stdlib.h>
#include "ct_list.h"

/* 
 * Exported functions definition
 */

extern CT_List *
CT_List_New (void)
{
  CT_List *aux;

  aux = (CT_List *) malloc (sizeof (CT_List));
  if (aux != NULL)
    {
      aux->first = NULL;
      aux->last = NULL;
      aux->elements = 0;
    }
  return (aux);
}

extern bool
CT_List_AddCardTerminal (CT_List * list, CardTerminal * ct, unsigned short ctn)
{
  struct CT_List_Node *node;

  if (list == NULL)
    return FALSE;

  node = (struct CT_List_Node *) malloc (sizeof (struct CT_List_Node));
  if (node != NULL)
  {
    node->ct = ct;
    node->ctn = ctn;
    node->next = NULL;
    if (list->first == NULL)
    {
      list->first = node;
      list->last = node;
    }
    else
    {
      list->last->next = node;
      list->last = node;
	  }
    list->elements++;
  }

  return (node != NULL);
}

extern CardTerminal *
CT_List_GetCardTerminal (CT_List * list, unsigned short ctn)
{
  struct CT_List_Node *node;
  CardTerminal *ct = NULL;

  if (list == NULL)
    return NULL;

  for (node = list->first; (node != NULL) && (ct == NULL); node = node->next)
    if (node->ctn == ctn)
      ct = node->ct;

  return ct;
}

extern int
CT_List_GetNumberOfElements (CT_List * list)
{
  if (list == NULL)
    return 0;

  return list->elements;
}

extern bool
CT_List_RemoveCardTerminal (CT_List * list, unsigned short ctn)
{
  struct CT_List_Node *current, *previous;
  bool found;

  if (list == NULL)
    return FALSE;

  previous = NULL;
  current = list->first;
  found = FALSE;

  while ((current != NULL) && (!found))
    {
      if (current->ctn == ctn)
	found = TRUE;
      else
	{
	  previous = current;
	  current = current->next;
	}
    }

  if (found)
    {
      if (current == list->first)
	list->first = current->next;
      else
	previous->next = current->next;

      if (current == list->last)
	list->last = previous;

      CardTerminal_Delete (current->ct);
      free (current);
      list->elements--;
    }

  return found;
}

extern void
CT_List_Delete (CT_List * list)
{
  struct CT_List_Node *node;

  if (list == NULL)
    return;

  while (list->first != NULL)
    {
      node = list->first;
      list->first = list->first->next;
      CardTerminal_Delete (node->ct);
      free (node);
    }
  free (list);
}
