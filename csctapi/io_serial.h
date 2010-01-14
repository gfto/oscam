/*
    io_serial.h
    Serial port input/output definitions

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

#ifndef _IO_SERIAL_
#define _IO_SERIAL_

#include "defines.h"

#define IO_Serial_DTR_Set(io) IO_Serial_DTR_RTS(io, 1, 1)
#define IO_Serial_DTR_Clr(io) IO_Serial_DTR_RTS(io, 1, 0)
#define IO_Serial_RTS_Set(io) IO_Serial_DTR_RTS(io, 0, 1)
#define IO_Serial_RTS_Clr(io) IO_Serial_DTR_RTS(io, 0, 0)
/* 
 * Exported constants definition
 */

/* Type of parity of the serial device */
#define IO_SERIAL_PARITY_ODD		1
#define IO_SERIAL_PARITY_EVEN		2
#define IO_SERIAL_PARITY_NONE		3

/* Values for the modem lines */
#define IO_SERIAL_HIGH			1
#define IO_SERIAL_LOW			0

/* Maximum size of PnP Com ID */
#define IO_SERIAL_PNPID_SIZE 		256

/*
 * Exported datatypes definition
 */

/* IO_Serial exported datatype */
typedef struct
{
	int fd;				/* Handle of the serial device */
	/* Settings that can be modified */
	unsigned long input_bitrate;
	unsigned long  output_bitrate;
	unsigned bits;
	unsigned stopbits;
	int parity;
	int dtr;
	int rts;	
	/* end settings that can be modified */
	int reader_type;
	BYTE PnP_id[IO_SERIAL_PNPID_SIZE];	/* PnP Id of the serial device */
	unsigned PnP_id_size;			/* Length of PnP Id */
	int wr;
	int mhz;			/* mhz specified in config = actual reader clock speed */
	int cardmhz;			/* mhz specified in config = standard (non overclocked) clock speed of card*/
}
IO_Serial;

/* 
 * Exported functions declaration
 */

/* IO_Serial creation and deletion */
//extern void IO_Serial_Reopen (IO_Serial * io);
extern void IO_Serial_Flush (IO_Serial * io);
extern IO_Serial *IO_Serial_New (int mhz, int cardmhz);
extern void IO_Serial_Delete (IO_Serial * io);

/* Initialization and closing */
extern bool IO_Serial_Init (IO_Serial * io, int reader_type);
extern bool IO_Serial_Close (IO_Serial * io);

/* Transmission properties */
extern bool IO_Serial_SetProperties (IO_Serial * io);
extern bool IO_Serial_GetProperties (IO_Serial * io);
extern bool IO_Serial_DTR_RTS(IO_Serial * io, int, int);
#if defined(TUXBOX) && defined(PPC)
extern void IO_Serial_Ioctl_Lock(int);
#else
#define IO_Serial_Ioctl_Lock(b) {} //FIXME ugly !!
#endif

/* Input and output */
extern bool IO_Serial_Read (IO_Serial * io, unsigned timeout, unsigned size, BYTE * data);
extern bool IO_Serial_Write (IO_Serial * io, unsigned delay, unsigned size, BYTE * data);

/* Serial port atributes */
extern unsigned IO_Serial_GetCom (IO_Serial * io);
extern void IO_Serial_GetPnPId (IO_Serial * io, BYTE * pnp_id, unsigned *length);

#endif /* IO_SERIAL */
