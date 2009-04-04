/*
    defines.h

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

#ifndef DEFINES_H
#define DEFINES_H

/*
 * Get configuration information
 */

// #ifdef HAVE_CONFIG_H
#include "config.h"
// #endif

/*
 * Boolean constants
 */

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

/*
 * Type definitions
 */

typedef unsigned char BYTE;
#ifndef __cplusplus
typedef int bool;
#endif
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef unsigned char *PUCHAR;
typedef char *STR;
typedef unsigned long ULONG;
typedef ULONG RESPONSECODE;
typedef ULONG *PULONG;
typedef ULONG DWORD;
typedef void *PVOID;

/*
 * Utility macros
 */

#ifndef MAX
#define MAX(a,b)	((a)>(b)?(a):(b))
#endif

#ifndef MIN
#define MIN(a,b)	((a)<(b)?(a):(b))
#endif

/* Invert order of bits in a byte: b7->b0, b0->b7 */
#ifndef INVERT_BYTE
#define INVERT_BYTE(a)		((((a) << 7) & 0x80) | \
				(((a) << 5) & 0x40) | \
				(((a) << 3) & 0x20) | \
				(((a) << 1) & 0x10) | \
				(((a) >> 1) & 0x08) | \
				(((a) >> 3) & 0x04) | \
				(((a) >> 5) & 0x02) | \
				(((a) >> 7) & 0x01))
#endif

#define	RTYP_STD	1
#define RTYP_SCI	2
#define RTYP_DB2COM1	3
#define RTYP_DB2COM2	4
#endif /* DEFINES_H */
