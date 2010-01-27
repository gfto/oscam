/*
    protocol_t1.h
    ISO 7816 T=1 Transport Protocol definitions 

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

#ifndef _PROTOCOL_T1_
#define _PROTOCOL_T1_

#include "defines.h"
#include "apdu.h"
#include "pps.h"

/*
 * Exported constants definition
 */

/* Return codes */
#define PROTOCOL_T1_OK                  0       /* Command OK */
#define PROTOCOL_T1_ICC_ERROR           2       /* ICC comunication error */
#define PROTOCOL_T1_ERROR               4       /* T=1 Protocol Error */
#define PROTOCOL_T1_NOT_IMPLEMENTED     7       /* Feture not implemented */

/*
 * Exported datatypes definition
 */

unsigned short ifsc;  /* Information field size for the ICC */
BYTE ns;              /* Send sequence number */
/*
 * Exported functions declaration
 */

/* Initialise a protocol handler */
extern int 
Protocol_T1_Init ();

/* Send a command and return a response */
extern int
Protocol_T1_Command (APDU_Cmd * cmd, APDU_Rsp ** rsp);

#endif /* _PROTOCOL_T1_ */
