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

/* Send a command and return a response */
int Protocol_T0_Command (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp);
int Protocol_T14_ExchangeTPDU (unsigned char * command, unsigned long command_len, APDU_Rsp ** rsp);

#endif /* _PROTOCOL_T0_ */

