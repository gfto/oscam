/*
    icc_async.h
    Asynchronous integrated circuit cards handling functions

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

#ifndef _ICC_ASYNC_
#define _ICC_ASYNC_

#include "atr.h"
#include "icc_async_exports.h"

/*
 * Exported constants definition
 */

/* Return codes */
#ifdef OS_CYGWIN32
#undef Ok
#undef ERROR
#endif

#define OK		0
#define ERROR	1

#define ATR_TIMEOUT				1000
#define DEFAULT_BAUDRATE	9600

/*
 * Exported types definition
 */


/* Initialization and Deactivation */
int ICC_Async_Activate (struct s_reader *reader, ATR * newatr, unsigned short deprecated);
int ICC_Async_Close (struct s_reader *reader);
int ICC_Async_Device_Init (struct s_reader *reader);

/* Attributes */
int ICC_Async_SetTimings (struct s_reader * reader, unsigned wait_etu);
int ICC_Async_GetStatus (struct s_reader *reader, int * has_card);


/* Operations */
int ICC_Async_CardWrite (struct s_reader *reader, unsigned char *cmd, unsigned short lc, unsigned char *rsp, unsigned short *lr);
int ICC_Async_Transmit (struct s_reader *reader, unsigned size, BYTE * buffer);
int ICC_Async_Receive (struct s_reader *reader, unsigned size, BYTE * buffer);

#define apdu2resp \
	{ \
		int remain; \
		bool err = FALSE; \
		if (apdu_rsp != NULL) { \
			remain = MAX ((short)APDU_Rsp_RawLen(apdu_rsp) - (*lr),0); \
			if (remain > 0) { \
				cs_log("MEMORY ERROR"); \
				err = TRUE; \
			} \
			(*lr) = MIN ((*lr), (short)APDU_Rsp_RawLen (apdu_rsp)); \
			memcpy (rsp, APDU_Rsp_Raw (apdu_rsp) + remain, (*lr)); \
			APDU_Rsp_Delete (apdu_rsp); \
		} \
		else  \
			(*lr) = 0; \
		if (err) { \
			cs_log("ERROR creating APDU response"); \
			return ERROR; \
		} \
	}

#endif /* _ICC_ASYNC_ */

