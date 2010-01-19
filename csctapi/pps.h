/*
    pps.h
    Protocol Parameters Selection

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

#ifndef _PPS_
#define _PPS_

#include "defines.h"
#include "icc_async.h"

/*
 * Exported constants definition
 */

#define PPS_OK			0	/* Negotiation OK */
#define PPS_ICC_ERROR		1	/* Comunication error */
#define PPS_HANDSAKE_ERROR	2	/* Agreement not reached */
#define PPS_PROTOCOL_ERROR	3	/* Error starting protocol */
#define PPS_MAX_LENGTH		6
/*
 * Exported data types definition
 */

typedef struct
{
  BYTE FI;
  double d;
  double n;
  BYTE t;
}
PPS_ProtocolParameters;

void *protocol;
PPS_ProtocolParameters parameters;

/*
 * Exported functions declaration
 */

/* Create PPS context */
extern void PPS_New ();

/* Perform protcol type selection and return confirm */
extern int PPS_Perform (BYTE * params, unsigned *length);

/* Get protocol parameters */
extern PPS_ProtocolParameters *PPS_GetProtocolParameters ();

#endif /* _PPS_ */
