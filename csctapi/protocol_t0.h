/*
    protocol_t0.h
    ISO 7816 T=0 Transport Protocol definitions 

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

#ifndef _PROTOCOL_T0_
#define _PROTOCOL_T0_

#include "defines.h"
#include "icc_async.h"
#include "apdu.h"
#include "pps.h"

/*
 * Exported constants definition
 */

/* Return codes */
#define PROTOCOL_T0_OK			0	/* Command OK */
#define PROTOCOL_T0_NULL_ERROR		1	/* Maximum NULL's reachec */
#define PROTOCOL_T0_ICC_ERROR		2	/* ICC comunication error */
#define PROTOCOL_T0_IFD_ERROR		3	/* IFD comunication error */
#define PROTOCOL_T0_ERROR		4	/* T=0 Protocol Error */

/* Return codes */
#define PROTOCOL_T14_OK			0	/* Command OK */
#define PROTOCOL_T14_NULL_ERROR		1	/* Maximum NULL's reachec */
#define PROTOCOL_T14_ICC_ERROR		2	/* ICC comunication error */
#define PROTOCOL_T14_IFD_ERROR		3	/* IFD comunication error */
#define PROTOCOL_T14_ERROR		4	/* T=0 Protocol Error */

/*
 * Exported datatypes definition
 */

/* T=0 Protocol handler */
typedef struct
{
  unsigned long wwt;		/* Work waiting time (ms) */
}
Protocol_T0;

/* T=14 Protocol handler */
typedef struct
{
  unsigned long wwt;		/* Work waiting time (ms) */
}
Protocol_T14;

/*
 * Exported functions declaration
 */

/* Create a new protocol handler */
extern Protocol_T0 *Protocol_T0_New (void);
extern Protocol_T14 *Protocol_T14_New (void);

/* Delete a protocol handler */
extern void Protocol_T0_Delete (Protocol_T0 * t0);
extern void Protocol_T14_Delete (Protocol_T14 * t14);

/* Initialise a protocol handler */
extern int Protocol_T0_Init (Protocol_T0 * t0, PPS_ProtocolParameters * params, int selected_protocol);
extern int Protocol_T14_Init (Protocol_T14 * t14, PPS_ProtocolParameters * params, int selected_protocol);

/* Send a command and return a response */
extern int Protocol_T0_Command (APDU_Cmd * cmd, APDU_Rsp ** rsp);
extern int Protocol_T14_Command (APDU_Cmd * cmd, APDU_Rsp ** rsp);

/* Close a protocol handler */
extern int Protocol_T0_Close (Protocol_T0 * t0);
extern int Protocol_T14_Close (Protocol_T14 * t14);

#endif /* _PROTOCOL_T0_ */

