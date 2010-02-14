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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../globals.h"
#include "defines.h"
#include "protocol_t1.h"
#include "t1_block.h"
#include "icc_async.h"

/* Timings in ATR are not used in T=1 cards */
/* #undef PROTOCOL_T1_USE_DEFAULT_TIMINGS */

/*
 * Not exported functions declaration
 */

static int Protocol_T1_SendBlock (T1_Block * block);

static int Protocol_T1_ReceiveBlock (T1_Block ** block);

/*
 * Exproted funtions definition
 */

int Protocol_T1_Command (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp)
{
  T1_Block *block;
  BYTE *buffer, rsp_type, bytes, nr, wtx;
  unsigned short counter;
  int ret;
  bool more;
  if (command[1] == T1_BLOCK_S_IFS_REQ)
    {
      BYTE inf = command[3];

      /* Create an IFS request S-Block */
      block = T1_Block_NewSBlock (T1_BLOCK_S_IFS_REQ, 1, &inf);
      cs_debug_mask (D_IFD,"Protocol: Sending block S(IFS request, %d)\n", inf);

      /* Send IFSD request */
      ret = Protocol_T1_SendBlock (block);

      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (&block);

      if (ret == OK)
        {
          rsp_type = T1_Block_GetType (block);

          /* Positive IFS Response S-Block received */
          if (rsp_type == T1_BLOCK_S_IFS_RES)
            {
              /* Update IFSD value */
              inf = (*T1_Block_GetInf (block));
              cs_debug_mask (D_IFD,"Protocol: Received block S(IFS response, %d)\n", inf);
            }
        }

      return ret;
    }

  /* Calculate the number of bytes to send */
  counter = 0;
  bytes = MIN (command_len, ifsc);

  /* See if chaining is needed */
  more = (command_len > ifsc);

  /* Increment ns */
  ns = (ns + 1) %2;

  /* Create an I-Block */
  block = T1_Block_NewIBlock (bytes, command, ns, more);
  cs_debug_mask (D_IFD,"Sending block I(%d,%d)\n", ns, more);

  /* Send a block */
  ret = Protocol_T1_SendBlock (block);

  while ((ret == OK) && more)
    {
      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (&block);

      if (ret == OK)
        {
          rsp_type = T1_Block_GetType (block);

          /* Positive ACK R-Block received */
          if (rsp_type == T1_BLOCK_R_OK)
            {
              cs_debug_mask (D_IFD,"Protocol: Received block R(%d)\n", T1_Block_GetNR (block));
              /* Delete block */
              T1_Block_Delete (block);
 
              /* Increment ns  */
              ns = (ns + 1) % 2;

              /* Calculate the number of bytes to send */
              counter += bytes;
              bytes = MIN (command_len - counter, ifsc);

              /* See if chaining is needed */
              more = (command_len - counter > ifsc);

              /* Create an I-Block */
              block =
                T1_Block_NewIBlock (bytes, command + counter,
                                    ns, more);
              cs_debug_mask (D_IFD,"Protocol: Sending block I(%d,%d)\n", ns, more);

              /* Send a block */
              ret = Protocol_T1_SendBlock (block);
            }
                                   
          else
            {
              /* Delete block */
              T1_Block_Delete (block);

              ret = ERROR; //not implemented
            }
        }

      else
        {
          ret = ERROR;//not implemented
        }
    }

  /* Reset counter */
  buffer = NULL;
  counter = 0;      
  more = TRUE;
  wtx = 0;
      
  while ((ret == OK) && more)
    {
      if (wtx > 1)
        ICC_Async_SetTimings (wtx * BWT);

      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (&block);

      if (wtx > 1)
        {
          ICC_Async_SetTimings (BWT);          
          wtx = 0;
        }

      if (ret == OK)
        {
          rsp_type = T1_Block_GetType (block);

          if (rsp_type == T1_BLOCK_I)
            {
              cs_debug_mask (D_IFD,"Protocol: Received block I(%d,%d)\n", 
              T1_Block_GetNS(block), T1_Block_GetMore (block));
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
                  cs_debug_mask (D_IFD,"Protocol: Sending block R(%d)\n", nr);

                  /* Send R-Block */
                  ret = Protocol_T1_SendBlock (block);
                }
            }

          /* WTX Request S-Block received */ 
          else if (rsp_type == T1_BLOCK_S_WTX_REQ)
            {
              /* Get wtx multiplier */
              wtx = (*T1_Block_GetInf (block));
              cs_debug_mask (D_IFD,"Protocol: Received block S(WTX request, %d)\n", wtx);

              /* Delete block */
              T1_Block_Delete (block);
             
              /* Create an WTX response S-Block */
              block = T1_Block_NewSBlock (T1_BLOCK_S_WTX_RES, 1, &wtx);
              cs_debug_mask (D_IFD,"Protocol: Sending block S(WTX response, %d)\n", wtx);

              /* Send WTX response */
              ret = Protocol_T1_SendBlock (block);
            }

          else
            {
              ret = ERROR;//not implemented
            }
        }
    }

  if (ret == OK)
    (*rsp) = APDU_Rsp_New (buffer, counter);

  if (buffer != NULL)
    free (buffer);

  return ret;
}

/*
 * Not exported functions definition
 */

static int Protocol_T1_SendBlock (T1_Block * block)
{
	int ret;
  ret = ICC_Async_Transmit (T1_Block_RawLen(block), T1_Block_Raw(block));
	T1_Block_Delete(block);
  return ret;
}

static int Protocol_T1_ReceiveBlock (T1_Block ** block)
{
  BYTE buffer[T1_BLOCK_MAX_SIZE];
  int ret;

  /* Receive four mandatory bytes */
  if (ICC_Async_Receive (4, buffer))
      ret = ERROR;
  else
      if (buffer[2] != 0x00) {
          /* Set timings to read the remaining block */
          ICC_Async_SetTimings (CWT);

          /* Receive remaining bytes */
          if (ICC_Async_Receive (buffer[2], buffer + 4))
              ret = ERROR;
          else {
              (*block) = T1_Block_New (buffer, buffer[2] + 4);
              ret = OK;
            }
          /* Restore timings */
          ICC_Async_SetTimings (BWT);
        }
      else {
          ret = OK;
          (*block) = T1_Block_New (buffer, 4);
        }

	if (ret == ERROR)
		(*block) = NULL;
  return ret;
}
