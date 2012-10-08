/*
		ifd_phoenix.c
		This module provides IFD handling functions for Smartmouse/Phoenix reader.
*/

#include "../globals.h"
#ifdef WITH_CARDREADER
#include "../oscam-time.h"
#include "atr.h"
#include <termios.h>
#include "ifd_phoenix.h"
#include "icc_async.h"
#include "io_serial.h"

#define MAX_TRANSMIT			255

#define GPIO_PIN (1 << (reader->detect - 4))

static void set_gpio(struct s_reader * reader, int32_t level)
{
	int ret = 0;

	ret |= read(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));
	reader->gpio |= GPIO_PIN;
	ret |= write(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));

	ret |= read(reader->gpio_out, &reader->gpio, sizeof(reader->gpio));
	if (level > 0)
		reader->gpio |= GPIO_PIN;
	else
		reader->gpio &= ~GPIO_PIN;
	ret |= write(reader->gpio_out, &reader->gpio, sizeof(reader->gpio));

	rdr_debug_mask(reader, D_IFD, "%s level: %d ret: %d", __func__, level, ret);
}

static void set_gpio_input(struct s_reader * reader)
{
	int ret = 0;
	ret |= read(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));
	reader->gpio &= ~GPIO_PIN;
	ret |= write(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));
	rdr_debug_mask(reader, D_IFD, "%s ret:%d", __func__, ret);
}

static int32_t get_gpio(struct s_reader * reader)
{
	int ret = 0;
	set_gpio_input(reader);
	ret = read(reader->gpio_in, &reader->gpio, sizeof(reader->gpio));
	rdr_debug_mask(reader, D_IFD, "%s ok:%d ret:%d", __func__, reader->gpio & GPIO_PIN, ret);
	if (reader->gpio & GPIO_PIN)
		return OK;
	else
		return ERROR;
}

int32_t Phoenix_Init (struct s_reader * reader)
{
		if (IO_Serial_InitPnP (reader)) return ERROR;
		IO_Serial_Flush(reader);

	// define reader->gpio number used for card detect and reset. ref to globals.h
	if (use_gpio(reader))
	{
		reader->gpio_outen = open("/dev/gpio/outen", O_RDWR);
		reader->gpio_out   = open("/dev/gpio/out",   O_RDWR);
		reader->gpio_in    = open("/dev/gpio/in",    O_RDWR);
		rdr_debug_mask(reader, D_IFD, "init gpio_outen:%d gpio_out:%d gpio_in:%d",
			reader->gpio_outen, reader->gpio_out, reader->gpio_in);
		set_gpio_input(reader);
	}

	rdr_debug_mask(reader, D_IFD, "Initializing reader type=%d", reader->typ);

	/* Default serial port settings */
	if (reader->atr[0] == 0) {
        if(IO_Serial_SetParams (reader, DEFAULT_BAUDRATE, 8, PARITY_EVEN, 2, IO_SERIAL_HIGH, IO_SERIAL_LOW)) return ERROR;
		IO_Serial_Flush(reader);
	}
	return OK;
}

int32_t Phoenix_GetStatus (struct s_reader * reader, int32_t * status)
{
	// detect card via defined reader->gpio
	if (use_gpio(reader))
		*status = !get_gpio(reader);
	else
	{
		uint32_t modembits=0;
	        if (ioctl(reader->handle, TIOCMGET, &modembits) < 0) {
	                rdr_log(reader, "ERROR: %s: ioctl error in card detection", __func__);
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

int32_t Phoenix_Reset (struct s_reader * reader, ATR * atr)
{
		rdr_debug_mask(reader, D_IFD, "Resetting card");
		int32_t ret;
		int32_t i;
		unsigned char buf[ATR_MAX_SIZE];
		int32_t parity[3] = {PARITY_EVEN, PARITY_ODD, PARITY_NONE};

		if ( ! reader->ins7e11_fast_reset ) {
			call (Phoenix_SetBaudrate (reader, DEFAULT_BAUDRATE));
		}
		else {
			rdr_log(reader, "Doing fast reset");
		}

		for(i=0; i<3; i++) {
#if !defined(__CYGWIN__)
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
			if (use_gpio(reader))
				set_gpio(reader, 0);
			else
				IO_Serial_RTS_Set(reader);
#if defined(__CYGWIN__)
			/*
			* Pause for 200ms as this might help with the PL2303.
			* Some users reporting that this breaks cygwin, so we went back to 50ms.
			*/
			cs_sleepms(50);
#else
			cs_sleepms(200);
#endif

			// felix: set card reset hi (inactive)
			if (use_gpio(reader))
				set_gpio_input(reader);
			else
				IO_Serial_RTS_Clr(reader);

			cs_sleepms(50);
			IO_Serial_Ioctl_Lock(reader, 0);

			int32_t n=0;
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

int32_t Phoenix_Transmit (struct s_reader * reader, BYTE * buffer, uint32_t size, uint32_t block_delay, uint32_t char_delay)
{
	uint32_t sent=0, to_send = 0;

	for (sent = 0; sent < size; sent = sent + to_send)
	{
		/* Calculate number of bytes to send */
		to_send = MIN(size, MAX_TRANSMIT);

		/* Send data */
		if ((sent == 0) && (block_delay != char_delay))
		{
			if(IO_Serial_Write (reader, block_delay, 1, buffer)) return ERROR;
			if(IO_Serial_Write (reader, char_delay, to_send-1, buffer+1)) return ERROR;
		}
		else
			if (IO_Serial_Write (reader, char_delay, to_send, buffer+sent)) return ERROR;
	}
	return OK;
}

int32_t Phoenix_Receive (struct s_reader * reader, BYTE * buffer, uint32_t size, uint32_t timeout)
{
#define IFD_TOWITOKO_TIMEOUT             1000

	/* Read all data bytes with the same timeout */
	if (reader->mhz >2000){
		if(IO_Serial_Read (reader, timeout + reader->read_timeout, size, buffer)) return ERROR;
	}
	else{
		if(IO_Serial_Read (reader, timeout + IFD_TOWITOKO_TIMEOUT, size, buffer)) return ERROR;
	}
	return OK;
}

int32_t Phoenix_SetBaudrate (struct s_reader * reader, uint32_t baudrate)
{
	rdr_debug_mask(reader, D_IFD, "Phoenix setting baudrate to %u", baudrate);

	/* Get current settings */
	struct termios tio;
	call (tcgetattr (reader->handle, &tio) != 0);
	call (IO_Serial_SetBitrate (reader, baudrate, &tio));
#if !defined(__CYGWIN__)
	/*
	* Pause for 200ms as this might help with the PL2303.
	* Some users reporting that this breaks cygwin, so we exclude this.
	*/
        cs_sleepms(200);
#endif
	call (IO_Serial_SetProperties(reader, tio));
#if !defined(__CYGWIN__)
	/*
	* Pause for 200ms as this might help with the PL2303.
	* Some users reporting that this breaks cygwin, so we exclude this.
	*/
        cs_sleepms(200);
#endif
	reader->current_baudrate = baudrate; //so if update fails, reader->current_baudrate is not changed either
	return OK;
}

int32_t Phoenix_Close (struct s_reader * reader)
{
	rdr_debug_mask(reader, D_IFD, "Closing phoenix device %s", reader->device);
	if (use_gpio(reader))
	{
		if (reader->gpio_outen > -1)
			close(reader->gpio_outen);
		if (reader->gpio_out > -1)
			close(reader->gpio_out);
		if (reader->gpio_in > -1)
			close(reader->gpio_in);
	}
	IO_Serial_Close(reader);
	return OK;
}

/*
int32_t Phoenix_FastReset (struct s_reader * reader, int32_t delay)
{
    IO_Serial_Ioctl_Lock(reader, 1);
    if (use_gpio(reader))
        set_gpio(reader, 0);
    else
        IO_Serial_RTS_Set(reader);

    cs_sleepms(delay);

    // set card reset hi (inactive)
    if (use_gpio(reader))
        set_gpio_input(reader);
    else
        IO_Serial_RTS_Clr(reader);

    IO_Serial_Ioctl_Lock(reader, 0);

    cs_sleepms(50);

    IO_Serial_Flush(reader);
    return 0;

}
*/
static int32_t mouse_init(struct s_reader *reader) {
	rdr_log(reader, "mouse_test init");
	reader->handle = open (reader->device,  O_RDWR | O_NOCTTY| O_NONBLOCK);
	if (reader->handle < 0) {
		rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)",
			reader->device, errno, strerror(errno));
		return ERROR;
	}
	if (Phoenix_Init(reader)) {
		rdr_log(reader, "ERROR: Phoenix_Init returns error");
		Phoenix_Close (reader);
		return ERROR;
	}
	return OK;
}

static int32_t mouse_receive(struct s_reader *reader, unsigned char *data, uint32_t size) {
	return Phoenix_Receive(reader, data, size, reader->read_timeout);
}

static int32_t mouse_transmit(struct s_reader *reader, unsigned char *sent, uint32_t size) {
	return Phoenix_Transmit(reader, sent, size, reader->block_delay, reader->char_delay);
}

void cardreader_mouse(struct s_cardreader *crdr)
{
	crdr->desc		= "mouse_test";
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
#endif
