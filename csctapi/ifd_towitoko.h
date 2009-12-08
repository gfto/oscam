/*
    ifd_towitoko.h
    Interface device handling functions definitions.
    An IFD object represents on of the slots within a drive.
    All chipdrives but Twin have one IFD per drive and serial port.

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

#ifndef _IFD_TOWITOKO_
#define _IFD_TOWITOKO_

#include "defines.h"
#include "atr.h"
#include "mc_global.h"

/* 
 * Exported constants definition
 */

/* Return Codes */
#define IFD_TOWITOKO_OK                 0	/* OK */
#define IFD_TOWITOKO_IO_ERROR           1	/* I/O Error */
#define IFD_TOWITOKO_CHK_ERROR          2	/* Checksum error */
#define IFD_TOWITOKO_PARAM_ERROR        3	/* Parameter error */
#define IFD_TOWITOKO_UNSUPPORTED        4	/* Action not supported by IFD
						   hardware */

/* Slots: Only Chipdrive twin has slot B */
#define IFD_TOWITOKO_SLOT_A             0x01	/* Chipdrive slot A */
#define IFD_TOWITOKO_SLOT_B             0x02	/* Chipdrive twin slot B */
#define IFD_TOWITOKO_SLOT_MULTICAM      0x00	/* Multicam */

/* Reader types */
#define IFD_TOWITOKO_CHIPDRIVE_EXT_II   0x88
#define IFD_TOWITOKO_CHIPDRIVE_EXT_I    0x84
#define IFD_TOWITOKO_CHIPDRIVE_INT      0x90
#define IFD_TOWITOKO_KARTENZWERG        0x80
#define IFD_TOWITOKO_KARTENZWERG_II     0x64
#define IFD_TOWITOKO_CHIPDRIVE_MICRO    0x61
#define IFD_TOWITOKO_MULTICAM		0x21
#define IFD_TOWITOKO_UNKNOWN            0x00

/* Card status */
#define IFD_TOWITOKO_NOCARD_NOCHANGE    0x00
#define IFD_TOWITOKO_CARD_NOCHANGE      0x40
#define IFD_TOWITOKO_NOCARD_CHANGE      0x80
#define IFD_TOWITOKO_CARD_CHANGE        0xC0
#define IFD_TOWITOKO_CARD(status)       (((status) & 0x40) == 0x40)
#define IFD_TOWITOKO_CHANGE(status)     (((status) & 0x80) == 0x80)

/* Led Color */
#define IFD_TOWITOKO_LED_OFF            0x00
#define IFD_TOWITOKO_LED_RED            0x01
#define IFD_TOWITOKO_LED_GREEN          0x02
#define IFD_TOWITOKO_LED_YELLOW         0x03

/* IFD parity */
//#define IFD_TOWITOKO_PARITY_ODD         0x80
//#define IFD_TOWITOKO_PARITY_EVEN        0x40
#define IFD_TOWITOKO_PARITY_ODD         1
#define IFD_TOWITOKO_PARITY_EVEN        2
#define IFD_TOWITOKO_PARITY_NONE        3

/* ICC types */
#define IFD_TOWITOKO_I2C_SHORT          0
#define IFD_TOWITOKO_I2C_LONG           1
#define IFD_TOWITOKO_2W                 2
#define IFD_TOWITOKO_3W                 3
#define IFD_TOWITOKO_ASYNC              4

/* Maximum size of Pin */
#define IFD_TOWITOKO_PIN_SIZE           3

/*
 * Exported Datatypes
 */

typedef struct
{
  unsigned block_delay;		/* Delay (ms) after starting to transmit */
  unsigned char_delay;		/* Delay (ms) after transmiting sucesive chars */
  unsigned block_timeout;	/* Max timeout (ms) to receive firtst char */
  unsigned char_timeout;	/* Max timeout (ms) to receive sucesive characters */
}
IFD_Timings;

/* Interface Device Handler */
typedef struct
{
  IO_Serial *io;		/* Handle of serial device */
  BYTE slot;			/* Chipdrive Twin Slot */
  BYTE type;			/* Reader type code */
  BYTE firmware;		/* Reader firmware version */
  
  unsigned short status;
}
IFD_Towitoko;

typedef IFD_Towitoko IFD;

/*
 * Exported functions declaration
 */

/* Create and Delete an IFD */
extern IFD *IFD_Towitoko_New (void);
extern void IFD_Towitoko_Delete (IFD * ifd);

/* Handling of the drive associated with this IFD */
extern int IFD_Towitoko_Init (IFD * ifd, IO_Serial * io, BYTE slot);
extern int IFD_Towitoko_Close (IFD * ifd);

/* Handling of this IFD */
extern int IFD_Towitoko_SetBaudrate (IFD * ifd, unsigned long baudrate);
extern int IFD_Towitoko_GetBaudrate (IFD * ifd, unsigned long *baudrate);
extern int IFD_Towitoko_SetParity (IFD * ifd, BYTE parity);
extern int IFD_Towitoko_SetLED (IFD * ifd, BYTE color);
extern int IFD_Towitoko_GetStatus (IFD * ifd, BYTE * status);

/* General handling of ICC inserted in this IFD */
extern int IFD_Towitoko_ActivateICC (IFD * ifd);
extern int IFD_Towitoko_DeactivateICC (IFD * ifd);

/* Asynchronous ICC handling functions */
extern int IFD_Towitoko_ResetAsyncICC (IFD * ifd, ATR ** atr);
extern int IFD_Towitoko_Transmit (IFD * ifd, IFD_Timings * timings, unsigned size, BYTE * buffer);
extern int IFD_Towitoko_Receive (IFD * ifd, IFD_Timings * timings, unsigned size, BYTE * buffer);

/* Atributes of the drive associated with this IFD */
extern BYTE IFD_Towitoko_GetType (IFD * ifd);
extern BYTE IFD_Towitoko_GetFirmware (IFD * ifd);
extern unsigned IFD_Towitoko_GetNumSlots (IFD * ifd);
extern unsigned long IFD_Towitoko_GetMaxBaudrate (IFD * ifd);
extern void IFD_Towitoko_GetDescription (IFD * ifd, BYTE * desc, unsigned length);

/* Atributes of this IFD */
extern BYTE IFD_Towitoko_GetSlot (IFD * ifd);

#endif /* _IFD_TOWITOKO_ */
