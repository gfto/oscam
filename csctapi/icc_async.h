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

//declare locking stuff for sc8in1 reader
static pthread_mutex_t sc8in1_lock; //semaphore for SC8in1, FIXME should not be global, but one per SC8in1

/* Initialization and Deactivation */
int32_t ICC_Async_Activate (struct s_reader *reader, ATR * newatr, uint16_t deprecated);
int32_t ICC_Async_Close (struct s_reader *reader);
int32_t ICC_Async_Device_Init (struct s_reader *reader);

/* Attributes */
int32_t ICC_Async_SetTimings (struct s_reader * reader, uint32_t wait_etu);
int32_t ICC_Async_GetStatus (struct s_reader *reader, int32_t * has_card);


/* Operations */
int32_t ICC_Async_CardWrite (struct s_reader *reader, unsigned char *cmd, uint16_t lc, unsigned char *rsp, uint16_t *lr);
int32_t ICC_Async_Transmit (struct s_reader *reader, uint32_t size, BYTE * buffer);
int32_t ICC_Async_Receive (struct s_reader *reader, uint32_t size, BYTE * buffer);

#endif /* _ICC_ASYNC_ */

