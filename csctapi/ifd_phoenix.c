/*
		ifd_phoenix.c
		This module provides IFD handling functions for Smartmouse/Phoenix reader.
*/
#include <stdio.h>
#include "../globals.h"
#include "atr.h"
#include <termios.h>
#include "ifd_phoenix.h"
#include "icc_async.h"
#include "io_serial.h"

#define MAX_TRANSMIT			255

#ifdef USE_GPIO	//felix: definition of gpio functions
#define pin (1<<(reader->detect-4))
int gpio_outen,gpio_out,gpio_in;
unsigned int gpio;

static void set_gpio(struct s_reader * reader, int level)
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

static void set_gpio_input(struct s_reader * reader)
{
	read(gpio_outen, &gpio, sizeof(gpio));			
	gpio &= ~pin;
	write(gpio_outen, &gpio, sizeof(gpio));
}

static int get_gpio(struct s_reader * reader)
{
	set_gpio_input(reader);
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
		gpio_outen=open("/dev/gpio/outen",O_RDWR);
		gpio_out=open("/dev/gpio/out",O_RDWR);
		gpio_in=open("/dev/gpio/in",O_RDWR);
		set_gpio_input(reader);
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
	if (reader->detect>4)
		*status=!get_gpio(reader);
	else
#endif
	{
		unsigned int modembits=0;
	        if (ioctl(reader->handle, TIOCMGET, &modembits) < 0) {
	                cs_log("ERROR Phoenix_GetStatus: ioctl error in card detection for %s", reader->label);
	                return ERROR;
	        }
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
		unsigned char buf[ATR_MAX_SIZE];
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
			if (reader->detect>4)
				set_gpio(reader, 0);
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
			if (reader->detect>4) {
				set_gpio_input(reader);
			}
			else
#endif
				IO_Serial_RTS_Clr(reader);

			cs_sleepms(50);
			IO_Serial_Ioctl_Lock(reader, 0);

			int n=0;
			while(n<ATR_MAX_SIZE && !IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n))
				n++;
			if(n==0)
				continue;
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
	reader->current_baudrate = baudrate; //so if update fails, reader->current_baudrate is not changed either
	return OK;
}

int Phoenix_Close (struct s_reader * reader)
{
	cs_debug_mask (D_IFD, "IFD: Closing phoenix device %s", reader->device);
#ifdef USE_GPIO //felix: close dev if card detected
	if(reader->detect>4) 
	{
		close(gpio_outen);
		close(gpio_out);
		close(gpio_in);
	}
#endif
	IO_Serial_Close(reader);
	return OK;
}


int Phoenix_FastReset (struct s_reader * reader, int delay)
{
    IO_Serial_Ioctl_Lock(reader, 1);
#ifdef USE_GPIO
    if (reader->detect>4)
        set_gpio(reader, 0);
    else
#endif
        IO_Serial_RTS_Set(reader);

    cs_sleepms(delay);

#ifdef USE_GPIO  //felix: set card reset hi (inactive)
    if (reader->detect>4) {
        set_gpio_input(reader);
    }
    else
#endif
        IO_Serial_RTS_Clr(reader);

    IO_Serial_Ioctl_Lock(reader, 0);
    
    cs_sleepms(50);

    IO_Serial_Flush(reader);
    return 0;

}

static int mouse_init(struct s_reader *reader) {
	cs_log("mouse_test init");
	reader->handle = open (reader->device,  O_RDWR | O_NOCTTY| O_NONBLOCK);
	if (reader->handle < 0) {
		cs_log("ERROR opening device %s",reader->device);
		return ERROR;
	}
	if (Phoenix_Init(reader)) {
		cs_log("ERROR: Phoenix_Init returns error");
		Phoenix_Close (reader);
		return ERROR;
	}
	return OK;
}

static int mouse_receive(struct s_reader *reader, unsigned char *data, unsigned int size) {
	return Phoenix_Receive(reader, data, size, reader->read_timeout);
}

static int mouse_transmit(struct s_reader *reader, unsigned char *sent, unsigned int size) {
	return Phoenix_Transmit(reader, sent, size, reader->block_delay, reader->char_delay);
}

#if defined(WITH_STAPI)
static int stapi_init(struct s_reader *reader) {
	return STReader_Open(reader->device, &reader->stsmart_handle);
}

static int stapi_getstatus(struct s_reader *reader, int *in) {
	return STReader_GetStatus(reader->stsmart_handle, in);
}

static int stapi_reset(struct s_reader *reader, ATR *atr) {
	return STReader_Reset(reader->stsmart_handle, atr);
}

static int stapi_transmit(struct s_reader *reader, unsigned char *sent, unsigned int size) {
	return STReader_Transmit(reader->stsmart_handle, sent, size);
}

static int stapi_receive(struct s_reader *reader, unsigned char *data, unsigned int size) {
	return STReader_Receive(reader->stsmart_handle, data, size);
}

static int stapi_close(struct s_reader *reader) {
	return STReader_Close(reader->stsmart_handle);
}

static int stapi_setprotocol(struct s_reader *reader, unsigned char *params, unsigned *length, uint len_request) {
	return STReader_SetProtocol(reader->stsmart_handle, params, length, len_request);
}

static int stapi_writesettings(struct s_reader *reader, unsigned long ETU, unsigned long EGT, unsigned char P, unsigned char I, unsigned short Fi, unsigned char Di, unsigned char Ni) {
	return STReader_SetClockrate(reader->stsmart_handle);
}

void cardreader_stapi(struct s_cardreader *crdr)
{
	strcpy(crdr->desc, "stapi");
	crdr->reader_init	= stapi_init;
	crdr->get_status	= stapi_getstatus;
	crdr->activate	= stapi_reset;
	crdr->transmit	= stapi_transmit;
	crdr->receive		= stapi_receive;
	crdr->close		= stapi_close;
	crdr->set_protocol	= stapi_setprotocol;
	crdr->write_settings = stapi_writesettings;
	crdr->typ		= R_INTERNAL;
	int max_clock_speed	= 1;
}
#endif

void cardreader_mouse(struct s_cardreader *crdr) 
{
	strcpy(crdr->desc, "mouse_test");
	crdr->reader_init	= mouse_init;
	crdr->get_status	= Phoenix_GetStatus;
	crdr->activate	= Phoenix_Reset;
	crdr->transmit	= mouse_transmit;
	crdr->receive		= mouse_receive;
	crdr->close		= Phoenix_Close;
	crdr->set_parity	= IO_Serial_SetParity;
	crdr->set_baudrate	= Phoenix_SetBaudrate;
	crdr->typ		= R_MOUSE;
	crdr->flush		= 1;
	crdr->need_inverse	= 1;
	crdr->read_written	= 1;
}
