/*
		ifd_phoenix.c
		This module provides IFD handling functions for Smartmouse/Phoenix reader.
*/

#include <stdio.h>
//#include <time.h>
//#include <string.h>
//#include "ioctls.h"
#include "../globals.h"
#include "atr.h"
#include "ifd_towitoko.h" //FIXME
#include <termios.h>

#define OK 		1 
#define ERROR 0

#define IFD_TOWITOKO_MAX_TRANSMIT 255
#define IFD_TOWITOKO_ATR_TIMEOUT   800

int Phoenix_Init ()
{
	return OK;
}

int Phoenix_GetStatus (int * status)
{
	int in;
	unsigned int modembits=0;
	extern int oscam_card_detect; //FIXME kill global variable
	if (ioctl(reader[ridx].handle, TIOCMGET,&modembits)<0)
		return ERROR;
	switch(oscam_card_detect&0x7f)
	{
		case	0: in=(modembits & TIOCM_CAR);	break;
		case	1: in=(modembits & TIOCM_DSR);	break;
		case	2: in=(modembits & TIOCM_CTS);	break;
		case	3: in=(modembits & TIOCM_RNG);	break;
		default: in=0;		// dummy
	}
	if (!(oscam_card_detect&0x80))
		in=!in;
	*status = in;
	return OK;
}

int Phoenix_Reset (ATR ** atr)
{	 
		return OK;
}

int Phoenix_Transmit (BYTE * buffer, unsigned size, IFD_Timings * timings)
{
	unsigned block_delay, char_delay, sent=0, to_send = 0;

#ifdef DEBUG_IFD
	printf ("IFD: Transmit: ");
	for (sent = 0; sent < size; sent++)
	printf ("%X ", buffer[sent]);
	printf ("\n");
#endif

#define IFD_TOWITOKO_DELAY 0

	/* Calculate delays */
	char_delay = IFD_TOWITOKO_DELAY + timings->char_delay;
	block_delay = IFD_TOWITOKO_DELAY + timings->block_delay;

#ifdef USE_GPIO
	if (gpio_detect) set_gpio1(0);
#endif
	for (sent = 0; sent < size; sent = sent + to_send) 
	{
		/* Calculate number of bytes to send */
		to_send = MIN(size, IFD_TOWITOKO_MAX_TRANSMIT);
				
		/* Send data */
		if ((sent == 0) && (block_delay != char_delay))
		{
			if (!IO_Serial_Write (block_delay, 1, buffer))
				return ERROR;
			
			if (!IO_Serial_Write (char_delay, to_send-1, buffer+1))
				return ERROR;
		}
		else
		{
			if (!IO_Serial_Write (char_delay, to_send, buffer+sent))
				return ERROR;
		}
	}
#ifdef USE_GPIO
	if (gpio_detect) set_gpio1(1);
#endif
	return OK;
}

int Phoenix_Receive (BYTE * buffer, unsigned size, IFD_Timings * timings)
{
	unsigned char_timeout, block_timeout;
#ifdef DEBUG_IFD
	int i;
#endif

#define IFD_TOWITOKO_TIMEOUT             1000

	/* Calculate timeouts */
	char_timeout = IFD_TOWITOKO_TIMEOUT + timings->char_timeout;
	block_timeout = IFD_TOWITOKO_TIMEOUT + timings->block_timeout;
#ifdef USE_GPIO
	if (gpio_detect) set_gpio1(0);
#endif
	if (block_timeout != char_timeout)
	{
		/* Read first byte using block timeout */
		if (!IO_Serial_Read (block_timeout, 1, buffer))
			return ERROR;
		
		if (size > 1)
		{
			/* Read remaining data bytes using char timeout */
			if (!IO_Serial_Read (char_timeout, size - 1, buffer + 1))
				return ERROR;
		}
	}
	else
	{
		/* Read all data bytes with the same timeout */
		if (!IO_Serial_Read (char_timeout, size, buffer))
			return ERROR;
	}
#ifdef USE_GPIO
	if (gpio_detect) set_gpio1(1);
#endif
	
#ifdef DEBUG_IFD
	printf ("IFD: Receive: ");
	for (i = 0; i < size; i++)
	printf ("%X ", buffer[i]);
	printf ("\n");
#endif
	
	return OK;
}

int Phoenix_SetBaudrate (unsigned long baudrate)
{
	if(reader[ridx].typ == R_INTERNAL)
		return OK;

#ifdef DEBUG_IFD
	printf ("IFD: Setting baudrate to %lu\n", baudrate);
#endif
	if (reader[ridx].baudrate	== baudrate)
		return OK;

	/* Get current settings */
	struct termios tio;
	if (tcgetattr (reader[ridx].handle, &tio) != 0)
		return ERROR;
	
	//write baudrate here!
	if (!IO_Serial_SetBitrate (baudrate, &tio))
		return ERROR;
	
	if (!IO_Serial_SetProperties(tio))
		return ERROR;
	
	reader[ridx].baudrate = baudrate;
	
	return OK;
}
