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
#include <termios.h>
#include "ifd.h" //FIXME kill this after IFD timings

#define OK 		1
#define ERROR 0

#define IFD_TOWITOKO_MAX_TRANSMIT 255
#define IFD_TOWITOKO_ATR_TIMEOUT   800
#define IFD_TOWITOKO_BAUDRATE            9600

#ifdef USE_GPIO	//felix: definition of gpio functions
int gpio_outen,gpio_out,gpio_in;
unsigned int pin,gpio;
int gpio_detect=0;

static void set_gpio(int level)
{		
	read(gpio_outen, &gpio, sizeof(gpio));
	gpio |= pin;
	write(gpio_outen, &gpio, sizeof(gpio));

	read(gpio_out, &gpio, sizeof(gpio));
	if (level>0)
		gpio|=pin;
	else
		gpio&=~pin;
	write(gpio_out, &gpio, sizeof(gpio));
}

static void set_gpio_input(void)
{
	read(gpio_outen, &gpio, sizeof(gpio));			
	gpio &= ~pin;
	write(gpio_outen, &gpio, sizeof(gpio));
}

static int get_gpio(void)
{
	set_gpio_input();
	read(gpio_in, &gpio, sizeof(gpio));
	return ((int)((gpio&pin)?1:0));
}
#endif


int Phoenix_Init ()
{
#ifdef USE_GPIO	//felix: define gpio number used for card detect and reset. ref to globals.h				
	if (reader[ridx].detect>4)
	{
		gpio_detect=reader[ridx].detect-4;
		pin = 1<<gpio_detect;
		gpio_outen=open("/dev/gpio/outen",O_RDWR);
		gpio_out=open("/dev/gpio/out",O_RDWR);
		gpio_in=open("/dev/gpio/in",O_RDWR);
		set_gpio_input();
	}
#endif
	
#ifdef DEBUG_IFD
	printf ("IFD: Initializing com=%d\n",  reader[ridx].typ);
#endif
	
	if(reader[ridx].typ == R_INTERNAL) //not sure whether this should be moved in front of GPIO part
		return OK;
	
	/* Default serial port settings */
	if (!IO_Serial_SetParams (IFD_TOWITOKO_BAUDRATE, 8, PARITY_EVEN, 2, IO_SERIAL_HIGH, IO_SERIAL_LOW))
	{
		reader[ridx].status = 0;//added this one because it seemed logical
		return ERROR;
	}
		
	if (!Phoenix_SetBaudrate(IFD_TOWITOKO_BAUDRATE))
	{
		reader[ridx].status = 0;
		return ERROR;
	}
	
	if (!IO_Serial_SetParity (PARITY_EVEN))
	{
		reader[ridx].status = 0;
		return ERROR;
	}
	
	IO_Serial_Flush();
	return OK;
}

int Phoenix_GetStatus (int * status)
{
#ifdef USE_GPIO  //felix: detect card via defined gpio
 if (gpio_detect)
		*status=get_gpio();
 else
#endif
 {
	unsigned int modembits=0;
	if (ioctl(reader[ridx].handle, TIOCMGET,&modembits)<0)
		return ERROR;
	switch(reader[ridx].detect&0x7f)
	{
		case	0: *status=(modembits & TIOCM_CAR);	break;
		case	1: *status=(modembits & TIOCM_DSR);	break;
		case	2: *status=(modembits & TIOCM_CTS);	break;
		case	3: *status=(modembits & TIOCM_RNG);	break;
		default: *status=0;		// dummy
	}
	if (!(reader[ridx].detect&0x80))
		*status=!*status;
 }
 return OK;
}

int Phoenix_Reset (ATR ** atr)
{	

#ifdef DEBUG_IFD
	printf ("IFD: Resetting card:\n");
#endif

		int ret;
		int i;
		int parity[3] = {PARITY_EVEN, PARITY_ODD, PARITY_NONE};
#ifdef HAVE_NANOSLEEP
		struct timespec req_ts;
		req_ts.tv_sec = 0;
		req_ts.tv_nsec = 50000000;
#endif
		
		(*atr) = NULL;
		for(i=0; i<3; i++) {
			IO_Serial_Flush();
			if (!IO_Serial_SetParity (parity[i]))
				return ERROR;

			ret = ERROR;
			IO_Serial_Ioctl_Lock(1);
#ifdef USE_GPIO
			if (gpio_detect)
				set_gpio(0);
			else
#endif
				IO_Serial_RTS_Set();
#ifdef HAVE_NANOSLEEP
			nanosleep (&req_ts, NULL);
#else
			usleep (50000L);
#endif
#ifdef USE_GPIO  //felix: set card reset hi (inactive)
			if (gpio_detect) {
				set_gpio_input();
			}
			else
#endif
				IO_Serial_RTS_Clr();
			IO_Serial_Ioctl_Lock(0);
			(*atr) = ATR_New ();
			if(ATR_InitFromStream ((*atr), IFD_TOWITOKO_ATR_TIMEOUT) == ATR_OK)
				ret = OK;
			// Succesfully retrieve ATR
			if (ret == OK)
				break;
			else
			{
				ATR_Delete (*atr);
				(*atr) = NULL;
			}
		}
		IO_Serial_Flush();

/*
		//PLAYGROUND faking ATR for test purposes only
		//
		// sky 919 unsigned char atr_test[] = { 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x0E, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x49, 0x54, 0x02, 0x00, 0x00 };
		// HD+ unsigned char atr_test[] = { 0x3F, 0xFF, 0x95, 0x00, 0xFF, 0x91, 0x81, 0x71, 0xFE, 0x47, 0x00, 0x44, 0x4E, 0x41, 0x53, 0x50, 0x31, 0x34, 0x32, 0x20, 0x52, 0x65, 0x76, 0x47, 0x43, 0x34, 0x63 };
		// S02 = irdeto unsigned char atr_test[] = { 0x3B, 0x9F, 0x21, 0x0E, 0x49, 0x52, 0x44, 0x45, 0x54, 0x4F, 0x20, 0x41, 0x43, 0x53, 0x03};
		//cryptoworks 	unsigned char atr_test[] = { 0x3B, 0x78, 0x12, 0x00, 0x00, 0x65, 0xC4, 0x05, 0xFF, 0x8F, 0xF1, 0x90, 0x00 };
		ATR_Delete(*atr); //throw away actual ATR
		(*atr) = ATR_New ();
		ATR_InitFromArray ((*atr), atr_test, sizeof(atr_test));
		//END OF PLAYGROUND
*/
		
		return ret;
}

int Phoenix_Transmit (BYTE * buffer, unsigned size, unsigned int block_delay, unsigned int char_delay)
{
	unsigned sent=0, to_send = 0;

#ifdef DEBUG_IFD
	printf ("IFD: Transmit: ");
	for (sent = 0; sent < size; sent++)
	printf ("%X ", buffer[sent]);
	printf ("\n");
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
	return OK;
}

int Phoenix_Receive (BYTE * buffer, unsigned size, unsigned int block_timeout, unsigned int char_timeout)
{
#define IFD_TOWITOKO_TIMEOUT             1000

	/* Calculate timeouts */
	char_timeout += IFD_TOWITOKO_TIMEOUT;
	block_timeout += IFD_TOWITOKO_TIMEOUT;
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
	
#ifdef DEBUG_IFD
	int i;
	printf ("IFD: Receive: ");
	for (i = 0; i < size; i++)
	printf ("%X ", buffer[i]);
	printf ("\n");
#endif
	
	return OK;
}

int Phoenix_SetBaudrate (unsigned long baudrate)
{
#ifdef DEBUG_IFD
	printf ("IFD: Setting baudrate to %lu\n", baudrate);
#endif
	if ((reader[ridx].typ != R_INTERNAL) && (reader[ridx].baudrate	!= baudrate))
	{
		/* Get current settings */
		struct termios tio;
		if (tcgetattr (reader[ridx].handle, &tio) != 0)
			return ERROR;
	
		//write baudrate here!
		if (!IO_Serial_SetBitrate (baudrate, &tio))
			return ERROR;
	
		if (!IO_Serial_SetProperties(tio))
			return ERROR;
	}
	reader[ridx].baudrate = baudrate;
	return OK;
}

int Phoenix_Close ()
{
#ifdef USE_GPIO //felix: close dev if card detected
	if(gpio_detect) 
	{
		close(gpio_outen);
		close(gpio_out);
		close(gpio_in);
	}
#endif
	
#ifdef DEBUG_IFD
	printf ("IFD: Closing slot\n");
#endif
	
	reader[ridx].status = 0;
	return OK;
}
