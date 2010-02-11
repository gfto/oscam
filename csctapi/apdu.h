/*
    apdu.h
    Definitions for ISO 7816-4 Application Layer PDU's handling

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

#ifndef _APDU_
#define _APDU_

#include "defines.h"

/*
 * Exported constants definiton 
 */

/* Return codes */
#define APDU_OK			0	/* Parsing of APDU OK */
#define APDU_MALFORMED		5	/* Malformed APDU */

/* Types of APDU's */
#define APDU_CASE_1	0x0001	/* Nor send neither receive data */
#define APDU_CASE_2S	0x0002	/* Receive data (1..256) */
#define APDU_CASE_3S	0x0003	/* Send data (1..255) */
#define APDU_CASE_4S	0x0004	/* Send data (1..255) and receive data (1..256) */
#define APDU_CASE_2E	0x0102	/* Receive data (1..65536) */
#define APDU_CASE_3E	0x0103	/* Send data (1..65535) */
#define APDU_CASE_4E	0x0104	/* Send data (1..65535) and receive data (1..65536) */

/* Maximum sizes of buffers */
#define APDU_MAX_CMD_SIZE 	65545	/* Max command size */
#define APDU_MAX_RSP_SIZE 	65538	/* Max response size */

/*
 * Exported macros definition 
 */
#define APDU_CASE_IS_EXTENDED(c)	(((c) & 0x0100) == 0x0100)

/*
 * Exported data types definition
 */

/* Command APDU */
typedef struct
{
  BYTE *command;
  unsigned long length;
}
APDU_Cmd;

/* Response APDU */
typedef struct
{
  BYTE *response;
  unsigned long length;
}
APDU_Rsp;

/* 
 * Exported functions declaration
 */

/* Create a APDU_Cmd */
extern APDU_Cmd *APDU_Cmd_New (BYTE * data, unsigned long length);

/* Delete a APDU_Cmd */
extern void APDU_Cmd_Delete (APDU_Cmd * apdu);

/* Return the case of command */
extern int APDU_Cmd_Case (APDU_Cmd * apdu);

/* Return class of command */
extern BYTE APDU_Cmd_Cla (APDU_Cmd * apdu);

/* Return command instruction */
extern BYTE APDU_Cmd_Ins (APDU_Cmd * apdu);

/* Return first paramenter of command */
extern BYTE APDU_Cmd_P1 (APDU_Cmd * apdu);

/* Return second parameter of command */
extern BYTE APDU_Cmd_P2 (APDU_Cmd * apdu);

/* Return length of data sent */
extern unsigned long APDU_Cmd_Lc (APDU_Cmd * apdu);

/* Return length of data expected */
extern unsigned long APDU_Cmd_Le (APDU_Cmd * apdu);

/* Return a pointer to the header of the command */
extern BYTE *APDU_Cmd_Header (APDU_Cmd * apdu);

/* Return a pointer  to the data of the comamnd */
extern BYTE *APDU_Cmd_Data (APDU_Cmd * apdu);

/* Return a pointer to the whole command */
extern BYTE *APDU_Cmd_Raw (APDU_Cmd * apdu);

/* Return the length of the whole command */
extern unsigned long APDU_Cmd_RawLen (APDU_Cmd * apdu);

/* Create a APDU_Rsp */
extern APDU_Rsp *APDU_Rsp_New (BYTE * data, unsigned long length);

/* Delete a APDU_Rsp */
extern void APDU_Rsp_Delete (APDU_Rsp * apdu);

/* Return fitst status byte */
extern BYTE APDU_Rsp_SW1 (APDU_Rsp * apdu);

/* Return second status byte */
extern BYTE APDU_Rsp_SW2 (APDU_Rsp * apdu);

/* Return length of the data of the response */
extern unsigned long APDU_Rsp_DataLen (APDU_Rsp * apdu);

/* Return a pointer to the whole response */
extern BYTE *APDU_Rsp_Raw (APDU_Rsp * apdu);

/* Return the length of the whole response */
extern unsigned long APDU_Rsp_RawLen (APDU_Rsp * apdu);

/* Truncate size of response APDU */
extern void APDU_Rsp_TruncateData (APDU_Rsp * apdu, unsigned long length);

/* Adds one APDU at the end of the data bytes of an APDU */
extern int APDU_Rsp_AppendData (APDU_Rsp * apdu1, APDU_Rsp * apdu2);

#endif

