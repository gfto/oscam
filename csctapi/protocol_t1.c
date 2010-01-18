/*
    protocol_t1.c
    Handling of ISO 7816 T=1 protocol
    
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
#include "protocol_t1.h"
#include "t1_block.h"

/*
 * Not exported constants definition
 */
#define PROTOCOL_T1_DEFAULT_IFSC        32
#define PROTOCOL_T1_DEFAULT_IFSD        32
#define PROTOCOL_T1_MAX_IFSC            251  /* Cannot send > 255 buffer */
#define PROTOCOL_T1_DEFAULT_CWI         13
#define PROTOCOL_T1_DEFAULT_BWI         4
#define PROTOCOL_T1_EDC_LRC             0
#define PROTOCOL_T1_EDC_CRC             1

/*
 * Not exported functions declaration
 */

static void 
Protocol_T1_Clear (Protocol_T1 * t1);

static int
Protocol_T1_SendBlock (T1_Block * block);

static int
Protocol_T1_ReceiveBlock (Protocol_T1 * t1, T1_Block ** block);

static int
Protocol_T1_UpdateBWT (unsigned short bwt);

/*
 * Exproted funtions definition
 */

Protocol_T1 *
Protocol_T1_New (void)
{
  Protocol_T1 *t1;

  t1 = (Protocol_T1 *) malloc (sizeof (Protocol_T1));

  if (t1 != NULL)
    Protocol_T1_Clear (t1);

  return t1;
}

int
Protocol_T1_Init (Protocol_T1 * t1, int selected_protocol)
{
  BYTE ta, tb, tc, cwi, bwi;
  unsigned long baudrate;
  double work_etu;
  int i;

  /* Set IFSC */
  if (ATR_GetInterfaceByte (atr, selected_protocol, ATR_INTERFACE_BYTE_TA, &ta) == ATR_NOT_FOUND)
    t1->ifsc = PROTOCOL_T1_DEFAULT_IFSC;
  else if ((ta != 0x00) && (ta != 0xFF))
    t1->ifsc = ta;
  else
    t1->ifsc = PROTOCOL_T1_DEFAULT_IFSC;

  /* Towitoko does not allow IFSC > 251 */
  t1->ifsc = MIN (t1->ifsc, PROTOCOL_T1_MAX_IFSC);

  /* Set IFSD */
  t1->ifsd = PROTOCOL_T1_DEFAULT_IFSD;

#ifndef PROTOCOL_T1_USE_DEFAULT_TIMINGS
  /* Calculate CWI and BWI */
  if (ATR_GetInterfaceByte (atr, selected_protocol, ATR_INTERFACE_BYTE_TB, &tb) == ATR_NOT_FOUND)
    {
#endif
      cwi  = PROTOCOL_T1_DEFAULT_CWI;
      bwi = PROTOCOL_T1_DEFAULT_BWI;
#ifndef PROTOCOL_T1_USE_DEFAULT_TIMINGS
    }
  else
    {
      cwi  = tb & 0x0F;
      bwi = (tb & 0xF0) >> 4;
    }
#endif
  
  /* Work etu  = (1000 / baudrate) milliseconds */
  ICC_Async_GetBaudrate (&baudrate);
  work_etu = 1000 / (double)baudrate;

  /* Set CWT = (2^CWI + 11) work etu */
  t1->cwt = 1;

  for (i = 0; i < cwi ; i++)
    t1->cwt *= 2;

  t1->cwt = (unsigned short) ((t1->cwt + 11) * work_etu);

  /* Set BWT = (2^BWI * 960 + 11) work etu */
  t1->bwt = 1;
  for (i = 0; i < bwi; i++)
    t1->bwt *= 2;

  t1->bwt = (unsigned short) ((t1->bwt * 960 + 11) * work_etu);

  /* Set BGT = 22 * work etu */
  t1->bgt = (unsigned short) (22 * work_etu);

  /* Set the error detection code type */
  if (ATR_GetInterfaceByte (atr, selected_protocol, ATR_INTERFACE_BYTE_TC, &tc) == ATR_NOT_FOUND)
    t1->edc = PROTOCOL_T1_EDC_LRC;
  else
    t1->edc = tc & 0x01;

  /* Set initial send sequence (NS) */
  t1->ns = 1;
  
  /* Set timings */
  icc_timings.block_timeout = t1->bwt;
  icc_timings.char_timeout = t1->cwt;
  icc_timings.block_delay = t1->bgt;
	ICC_Async_SetTimings ();

#ifdef DEBUG_PROTOCOL
  printf ("Protocol: T=1: IFSC=%d, IFSD=%d, CWT=%d, BWT=%d, BGT=%d, EDC=%s\n",
          t1->ifsc, t1->ifsd, t1->cwt, t1->bwt, t1->bgt,
          (t1->edc == PROTOCOL_T1_EDC_LRC) ? "LRC" : "CRC");
#endif

  return PROTOCOL_T1_OK;
}

int
Protocol_T1_Command (Protocol_T1 * t1, APDU_Cmd * cmd, APDU_Rsp ** rsp)
{
  T1_Block *block;
  BYTE *buffer, rsp_type, bytes, nr, wtx;
  unsigned short counter;
  int ret;
  bool more;
  if (APDU_Cmd_Ins(cmd) == T1_BLOCK_S_IFS_REQ)
    {
      BYTE inf = APDU_Cmd_P2(cmd);

      /* Create an IFS request S-Block */
      block = T1_Block_NewSBlock (T1_BLOCK_S_IFS_REQ, 1, &inf);

#ifdef DEBUG_PROTOCOL
      printf ("Protocol: Sending block S(IFS request, %d)\n", inf);
#endif
      /* Send IFSD request */
      ret = Protocol_T1_SendBlock (block);

      /* Delete block */
      T1_Block_Delete (block);

      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (t1, &block);

      if (ret == PROTOCOL_T1_OK)
        {
          rsp_type = T1_Block_GetType (block);

          /* Positive IFS Response S-Block received */
          if (rsp_type == T1_BLOCK_S_IFS_RES)
            {
              /* Update IFSD value */
              inf = (*T1_Block_GetInf (block));
              t1->ifsd = inf;
#ifdef DEBUG_PROTOCOL
              printf ("Protocol: Received block S(IFS response, %d)\n", inf);
#endif
            }
        }

      return ret;
    }

  /* Calculate the number of bytes to send */
  counter = 0;
  bytes = MIN (APDU_Cmd_RawLen (cmd), t1->ifsc);

  /* See if chaining is needed */
  more = (APDU_Cmd_RawLen (cmd) > t1->ifsc);

  /* Increment ns */
  t1->ns = (t1->ns + 1) %2;

  /* Create an I-Block */
  block = T1_Block_NewIBlock (bytes, APDU_Cmd_Raw (cmd), t1->ns, more);

#ifdef DEBUG_PROTOCOL
  printf ("Sending block I(%d,%d)\n", t1->ns, more);
#endif

  /* Send a block */
  ret = Protocol_T1_SendBlock (block);

  /* Delete I-block */
  T1_Block_Delete (block);

  while ((ret == PROTOCOL_T1_OK) && more)
    {
      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (t1, &block);

      if (ret == PROTOCOL_T1_OK)
        {
          rsp_type = T1_Block_GetType (block);

          /* Positive ACK R-Block received */
          if (rsp_type == T1_BLOCK_R_OK)
            {
#ifdef DEBUG_PROTOCOL
              printf ("Protocol: Received block R(%d)\n", T1_Block_GetNR (block));
#endif                   
              /* Delete block */
              T1_Block_Delete (block);
 
              /* Increment ns  */
              t1->ns = (t1->ns + 1) % 2;

              /* Calculate the number of bytes to send */
              counter += bytes;
              bytes = MIN (APDU_Cmd_RawLen (cmd) - counter, t1->ifsc);

              /* See if chaining is needed */
              more = (APDU_Cmd_RawLen (cmd) - counter > t1->ifsc);

              /* Create an I-Block */
              block =
                T1_Block_NewIBlock (bytes, APDU_Cmd_Raw (cmd) + counter,
                                    t1->ns, more);
#ifdef DEBUG_PROTOCOL
              printf ("Protocol: Sending block I(%d,%d)\n", t1->ns, more);
#endif
              /* Send a block */
              ret = Protocol_T1_SendBlock (block);

              /* Delete I-block */
              T1_Block_Delete (block);
            }
                                   
          else
            {
              /* Delete block */
              T1_Block_Delete (block);

              ret = PROTOCOL_T1_NOT_IMPLEMENTED;
            }
        }

      else
        {
          ret = PROTOCOL_T1_NOT_IMPLEMENTED;
        }
    }

  /* Reset counter */
  buffer = NULL;
  counter = 0;      
  more = TRUE;
  wtx = 0;
      
  while ((ret == PROTOCOL_T1_OK) && more)
    {
      if (wtx > 1)
        Protocol_T1_UpdateBWT (wtx * (t1->bwt));          

      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (t1, &block);

      if (wtx > 1)
        {
          Protocol_T1_UpdateBWT (t1->bwt);          
          wtx = 0;
        }

      if (ret == PROTOCOL_T1_OK)
        {
          rsp_type = T1_Block_GetType (block);

          if (rsp_type == T1_BLOCK_I)
            {
#ifdef DEBUG_PROTOCOL
              printf ("Protocol: Received block I(%d,%d)\n", 
              T1_Block_GetNS(block), T1_Block_GetMore (block));
#endif
              /* Calculate nr */
              nr = (T1_Block_GetNS (block) + 1) % 2;
                               
              /* Save inf field */
              bytes = T1_Block_GetLen (block);
	      buffer = (BYTE *) realloc(buffer, counter + bytes);
              memcpy (buffer + counter, T1_Block_GetInf (block), bytes);
              counter += bytes;

              /* See if chaining is requested */
              more = T1_Block_GetMore (block);

              /* Delete block */
              T1_Block_Delete (block);

              if (more)
                {
                  /* Create an R-Block */
                  block = T1_Block_NewRBlock (T1_BLOCK_R_OK, nr);
#ifdef DEBUG_PROTOCOL
                  printf ("Protocol: Sending block R(%d)\n", nr);
#endif                    
                  /* Send R-Block */
                  ret = Protocol_T1_SendBlock (block);

                  /* Delete I-block */
                  T1_Block_Delete (block);
                }
            }

          /* WTX Request S-Block received */ 
          else if (rsp_type == T1_BLOCK_S_WTX_REQ)
            {
              /* Get wtx multiplier */
              wtx = (*T1_Block_GetInf (block));
#ifdef DEBUG_PROTOCOL
              printf ("Protocol: Received block S(WTX request, %d)\n", wtx);
#endif                                  
              /* Delete block */
              T1_Block_Delete (block);
             
              /* Create an WTX response S-Block */
              block = T1_Block_NewSBlock (T1_BLOCK_S_WTX_RES, 1, &wtx);
#ifdef DEBUG_PROTOCOL
              printf ("Protocol: Sending block S(WTX response, %d)\n", wtx);
#endif                    
              /* Send WTX response */
              ret = Protocol_T1_SendBlock (block);
                  
              /* Delete block */
              T1_Block_Delete (block);
            }

          else
            {
              ret = PROTOCOL_T1_NOT_IMPLEMENTED;
            }
        }
    }

  if (ret == PROTOCOL_T1_OK)
    (*rsp) = APDU_Rsp_New (buffer, counter);

  if (buffer != NULL)
    free (buffer);

  return ret;
}

int
Protocol_T1_Close (Protocol_T1 * t1)
{
  Protocol_T1_Clear (t1);

  return PROTOCOL_T1_OK;
}

void
Protocol_T1_Delete (Protocol_T1 * t1)
{
  free (t1);
}

/*
 * Not exported functions definition
 */

static int
Protocol_T1_SendBlock (T1_Block * block)
{
  BYTE *buffer;
  int length, ret;

    {
      /* Send T=1 block */
      buffer = T1_Block_Raw (block);
      length = T1_Block_RawLen (block);

      if (ICC_Async_Transmit (length, buffer) != ICC_ASYNC_OK)
        {
          ret = PROTOCOL_T1_ICC_ERROR;
        }

      else
        ret = PROTOCOL_T1_OK;
    }

  return ret;
}

static int
Protocol_T1_ReceiveBlock (Protocol_T1 * t1, T1_Block ** block)
{
  BYTE buffer[T1_BLOCK_MAX_SIZE];
  int ret;

  /* Receive four mandatory bytes */
  if (ICC_Async_Receive (4, buffer) != ICC_ASYNC_OK)
    {
      ret = PROTOCOL_T1_ICC_ERROR;
      (*block) = NULL;
    }

  else
    {
      if (buffer[2] != 0x00)
        {
          /* Set timings to read the remaining block */
          Protocol_T1_UpdateBWT (t1->cwt);

          /* Receive remaining bytes */
          if (ICC_Async_Receive (buffer[2], buffer + 4) !=
              ICC_ASYNC_OK)
            {
              (*block) = NULL;
              ret = PROTOCOL_T1_ICC_ERROR;
            }

          else
            {
              (*block) = T1_Block_New (buffer, buffer[2] + 4);
              ret = PROTOCOL_T1_OK;
            }

          /* Restore timings */
          Protocol_T1_UpdateBWT (t1->bwt);
        }
      else
        {
          ret = PROTOCOL_T1_OK;
          (*block) = T1_Block_New (buffer, 4);
        }
    }

  return ret;
}

static void
Protocol_T1_Clear (Protocol_T1 * t1)
{
  t1->ifsc = 0;
  t1->ifsd = 0;
  t1->bgt = 0;
  t1->bwt = 0;
  t1->cwt = 0;
  t1->edc = 0;
  t1->ns = 0;
}

static int
Protocol_T1_UpdateBWT (unsigned short bwt)
{
  icc_timings.block_timeout = bwt;
	ICC_Async_SetTimings ();

  return PROTOCOL_T1_OK;
}
