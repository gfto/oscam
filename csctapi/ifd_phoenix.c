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
#include "ifd_phoenix.h"
#include "icc_async.h"
#include "io_serial.h"

#define MAX_TRANSMIT			255
#define PHOENIX_MAX_ATR_SIZE		40

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
	if (gpio&pin)
		return OK;
	else
		return ERROR;
}
#endif


int Phoenix_Init (struct s_reader * reader)
{
		call (IO_Serial_InitPnP (reader));
		IO_Serial_Flush(reader);

#ifdef USE_GPIO	//felix: define gpio number used for card detect and reset. ref to globals.h				
	if (reader->detect>4)
	{
		gpio_detect=reader->detect-4;
		pin = 1<<gpio_detect;
		gpio_outen=open("/dev/gpio/outen",O_RDWR);
		gpio_out=open("/dev/gpio/out",O_RDWR);
		gpio_in=open("/dev/gpio/in",O_RDWR);
		set_gpio_input();
	}
#endif
	
	cs_debug_mask (D_IFD, "IFD: Initializing reader %s type=%d\n",  reader->label, reader->typ);
	
	/* Default serial port settings */
	if (reader->atr[0] == 0) {
		call (IO_Serial_SetParams (reader, DEFAULT_BAUDRATE, 8, PARITY_EVEN, 2, IO_SERIAL_HIGH, IO_SERIAL_LOW));
		IO_Serial_Flush(reader);
	}
	return OK;
}

int Phoenix_GetStatus (struct s_reader * reader, int * status)
{
#ifdef USE_GPIO  //felix: detect card via defined gpio
 if (gpio_detect)
		*status=!get_gpio();
 else
#endif
 {
	unsigned int modembits=0;
	call (ioctl(reader->handle, TIOCMGET,&modembits)<0);
	switch(reader->detect&0x7f)
	{
		case	0: *status=(modembits & TIOCM_CAR);	break;
		case	1: *status=(modembits & TIOCM_DSR);	break;
		case	2: *status=(modembits & TIOCM_CTS);	break;
		case	3: *status=(modembits & TIOCM_RNG);	break;
		default: *status=0;		// dummy
	}
	if (!(reader->detect&0x80))
		*status=!*status;
 }
 return OK;
}

int Phoenix_Reset (struct s_reader * reader, ATR * atr)
{	
		cs_debug_mask (D_IFD, "IFD: Resetting card:\n");
		int ret;
		int i;
		unsigned char buf[PHOENIX_MAX_ATR_SIZE];
		int parity[3] = {PARITY_EVEN, PARITY_ODD, PARITY_NONE};
		call (Phoenix_SetBaudrate (reader, DEFAULT_BAUDRATE));
		for(i=0; i<3; i++) {
#ifndef OS_CYGWIN32
			/* 
			* Pause for 200ms as this might help with the PL2303.
			* Some users reporting that this breaks cygwin, so we exclude this.
			*/
			cs_sleepms(200);
#endif
			IO_Serial_Flush(reader);
			call (IO_Serial_SetParity (reader, parity[i]));

			ret = ERROR;
			cs_sleepms(500); //smartreader in mouse mode needs this
			IO_Serial_Ioctl_Lock(reader, 1);
#ifdef USE_GPIO
			if (gpio_detect)
				set_gpio(0);
			else
#endif
				IO_Serial_RTS_Set(reader);
#ifdef OS_CYGWIN32
			/* 
			* Pause for 200ms as this might help with the PL2303.
			* Some users reporting that this breaks cygwin, so we went back to 50ms.
			*/
			cs_sleepms(50);
#else
			cs_sleepms(200);
#endif

#ifdef USE_GPIO  //felix: set card reset hi (inactive)
			if (gpio_detect) {
				set_gpio_input();
			}
			else
#endif
				IO_Serial_RTS_Clr(reader);
#ifndef OS_CYGWIN32
			/* 
			* Pause for 200ms as this might help with the PL2303.
			* Some users reporting that this breaks cygwin, so we exclude this.
			*/
			cs_sleepms(200);
#endif
			IO_Serial_Ioctl_Lock(reader, 0);

			int n=0;
			while(n<PHOENIX_MAX_ATR_SIZE && !IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n))
				n++;
			if(n==0) {
				cs_log("WARNING: 0 characters found in ATR");
				//FIXME: No parity switching was done if we exit here
				//return ERROR;
		  }
			if (ATR_InitFromArray (atr, buf, n) == ATR_OK)
				ret = OK;
			// Succesfully retrieve ATR
			if (ret == OK)
				break;
		}
		IO_Serial_Flush(reader);

/*
		//PLAYGROUND faking ATR for test purposes only
		//
		// sky 919 unsigned char atr_test[] = { 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x0E, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x49, 0x54, 0x02, 0x00, 0x00 };
		// HD+ unsigned char atr_test[] = { 0x3F, 0xFF, 0x95, 0x00, 0xFF, 0x91, 0x81, 0x71, 0xFE, 0x47, 0x00, 0x44, 0x4E, 0x41, 0x53, 0x50, 0x31, 0x34, 0x32, 0x20, 0x52, 0x65, 0x76, 0x47, 0x43, 0x34, 0x63 };
		// S02 = irdeto unsigned char atr_test[] = { 0x3B, 0x9F, 0x21, 0x0E, 0x49, 0x52, 0x44, 0x45, 0x54, 0x4F, 0x20, 0x41, 0x43, 0x53, 0x03};
		// conax unsigned char atr_test[] = { 0x3B, 0x24, 0x00, 0x30, 0x42, 0x30, 0x30 };
		//cryptoworks 	unsigned char atr_test[] = { 0x3B, 0x78, 0x12, 0x00, 0x00, 0x65, 0xC4, 0x05, 0xFF, 0x8F, 0xF1, 0x90, 0x00 };
		ATR_InitFromArray (atr, atr_test, sizeof(atr_test));
		//END OF PLAYGROUND
*/
		
		return ret;
}

int Phoenix_Transmit (struct s_reader * reader, BYTE * buffer, unsigned size, unsigned int block_delay, unsigned int char_delay)
{
	unsigned sent=0, to_send = 0;

	for (sent = 0; sent < size; sent = sent + to_send)
	{
		/* Calculate number of bytes to send */
		to_send = MIN(size, MAX_TRANSMIT);
				
		/* Send data */
		if ((sent == 0) && (block_delay != char_delay))
		{
			call (IO_Serial_Write (reader, block_delay, 1, buffer));
			call (IO_Serial_Write (reader, char_delay, to_send-1, buffer+1));
		}
		else
			call (IO_Serial_Write (reader, char_delay, to_send, buffer+sent));
	}
	return OK;
}

int Phoenix_Receive (struct s_reader * reader, BYTE * buffer, unsigned size, unsigned int timeout)
{
#define IFD_TOWITOKO_TIMEOUT             1000

	/* Read all data bytes with the same timeout */
	call (IO_Serial_Read (reader, timeout + IFD_TOWITOKO_TIMEOUT, size, buffer));
	return OK;
}

int Phoenix_SetBaudrate (struct s_reader * reader, unsigned long baudrate)
{
	cs_debug_mask (D_IFD, "IFD: Phoenix Setting baudrate to %lu\n", baudrate);
	if (reader->current_baudrate	!= baudrate)
	{
		/* Get current settings */
		struct termios tio;
		call (tcgetattr (reader->handle, &tio) != 0);
		call (IO_Serial_SetBitrate (reader, baudrate, &tio));
#ifndef OS_CYGWIN32
		/* 
		* Pause for 200ms as this might help with the PL2303.
		* Some users reporting that this breaks cygwin, so we exclude this.
		*/
	        cs_sleepms(200);
#endif
		call (IO_Serial_SetProperties(reader, tio));
#ifndef OS_CYGWIN32
		/* 
		* Pause for 200ms as this might help with the PL2303.
		* Some users reporting that this breaks cygwin, so we exclude this.
		*/
	        cs_sleepms(200);
#endif
	}
	reader->current_baudrate = baudrate; //so if update fails, reader->current_baudrate is not changed either
	return OK;
}

int Phoenix_Close (struct s_reader * reader)
{
#ifdef USE_GPIO //felix: close dev if card detected
	if(gpio_detect) 
	{
		close(gpio_outen);
		close(gpio_out);
		close(gpio_in);
	}
#endif
	IO_Serial_Close(reader);
	cs_debug_mask (D_IFD, "IFD: Closing phoenix device %s", reader->device);
	return OK;
}
