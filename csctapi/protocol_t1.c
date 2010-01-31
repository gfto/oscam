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

/*
 * Not exported functions declaration
 */

static int
Protocol_T1_SendBlock (T1_Block * block);

static int
Protocol_T1_ReceiveBlock (T1_Block ** block);

static int
Protocol_T1_UpdateBWT (unsigned short BWT);

/*
 * Exproted funtions definition
 */

int
Protocol_T1_Command (APDU_Cmd * cmd, APDU_Rsp ** rsp)
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

//#ifdef DEBUG_PROTOCOL
      cs_debug ("Protocol: Sending block S(IFS request, %d)\n", inf);
//#endif
      /* Send IFSD request */
      ret = Protocol_T1_SendBlock (block);

      /* Delete block */
      T1_Block_Delete (block);

      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (&block);

      if (ret == PROTOCOL_T1_OK)
        {
          rsp_type = T1_Block_GetType (block);

          /* Positive IFS Response S-Block received */
          if (rsp_type == T1_BLOCK_S_IFS_RES)
            {
              /* Update IFSD value */
              inf = (*T1_Block_GetInf (block));
//#ifdef DEBUG_PROTOCOL
              cs_debug ("Protocol: Received block S(IFS response, %d)\n", inf);
//#endif
            }
        }

      return ret;
    }

  /* Calculate the number of bytes to send */
  counter = 0;
  bytes = MIN (APDU_Cmd_RawLen (cmd), ifsc);

  /* See if chaining is needed */
  more = (APDU_Cmd_RawLen (cmd) > ifsc);

  /* Increment ns */
  ns = (ns + 1) %2;

  /* Create an I-Block */
  block = T1_Block_NewIBlock (bytes, APDU_Cmd_Raw (cmd), ns, more);

#ifdef DEBUG_PROTOCOL
  printf ("Sending block I(%d,%d)\n", ns, more);
#endif

  /* Send a block */
  ret = Protocol_T1_SendBlock (block);

  /* Delete I-block */
  T1_Block_Delete (block);

  while ((ret == PROTOCOL_T1_OK) && more)
    {
      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (&block);

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
              ns = (ns + 1) % 2;

              /* Calculate the number of bytes to send */
              counter += bytes;
              bytes = MIN (APDU_Cmd_RawLen (cmd) - counter, ifsc);

              /* See if chaining is needed */
              more = (APDU_Cmd_RawLen (cmd) - counter > ifsc);

              /* Create an I-Block */
              block =
                T1_Block_NewIBlock (bytes, APDU_Cmd_Raw (cmd) + counter,
                                    ns, more);
#ifdef DEBUG_PROTOCOL
              printf ("Protocol: Sending block I(%d,%d)\n", ns, more);
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
        Protocol_T1_UpdateBWT (wtx * BWT);

      /* Receive a block */
      ret = Protocol_T1_ReceiveBlock (&block);

      if (wtx > 1)
        {
          Protocol_T1_UpdateBWT (BWT);          
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

      if (ICC_Async_Transmit (length, buffer))
        {
          ret = PROTOCOL_T1_ICC_ERROR;
        }

      else
        ret = PROTOCOL_T1_OK;
    }

  return ret;
}

static int
Protocol_T1_ReceiveBlock (T1_Block ** block)
{
  BYTE buffer[T1_BLOCK_MAX_SIZE];
  int ret;

  /* Receive four mandatory bytes */
  if (ICC_Async_Receive (4, buffer))
    {
      ret = PROTOCOL_T1_ICC_ERROR;
      (*block) = NULL;
    }

  else
    {
      if (buffer[2] != 0x00)
        {
          /* Set timings to read the remaining block */
          Protocol_T1_UpdateBWT (CWT);

          /* Receive remaining bytes */
          if (ICC_Async_Receive (buffer[2], buffer + 4))
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
          Protocol_T1_UpdateBWT (BWT);
        }
      else
        {
          ret = PROTOCOL_T1_OK;
          (*block) = T1_Block_New (buffer, 4);
        }
    }

  return ret;
}

static int
Protocol_T1_UpdateBWT (unsigned short bwt)
{
	if (ICC_Async_SetTimings (bwt))
		return PROTOCOL_T1_ICC_ERROR;

  return PROTOCOL_T1_OK;
}
