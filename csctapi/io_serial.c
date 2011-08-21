   /*
    io_serial.c
    Serial port input/output functions

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

#include "../globals.h"
#ifdef OS_HPUX
#include <sys/modem.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_POLL
#include <sys/poll.h>
#else
#include <sys/signal.h>
#include <sys/types.h>
#endif
#include <sys/ioctl.h>

#ifdef OS_LINUX
#include <linux/serial.h>
#endif

#include "defines.h"
#include "io_serial.h"
#include "mc_global.h"
#include "icc_async.h"

#define IO_SERIAL_FILENAME_LENGTH 	32

/*
 * Internal functions declaration
 */

static int32_t IO_Serial_Bitrate(int32_t bitrate);

bool IO_Serial_WaitToRead (struct s_reader * reader, uint32_t delay_ms, uint32_t timeout_ms);

static bool IO_Serial_WaitToWrite (struct s_reader * reader, uint32_t delay_ms, uint32_t timeout_ms);

#if defined(TUXBOX) && defined(PPC)
void IO_Serial_Ioctl_Lock(struct s_reader * reader, int32_t flag)
{
  static int32_t oscam_sem=0;
  if ((reader->typ != R_DB2COM1) && (reader->typ != R_DB2COM2)) return;
  if (!flag)
    oscam_sem=0;
  else while (oscam_sem!=reader->typ)
  {
    while (oscam_sem)
			if (reader->typ == R_DB2COM1)
				cs_sleepms(6);
			else
				cs_sleepms(8);
    oscam_sem=reader->typ;
    cs_sleepms(1);
  }
}

static bool IO_Serial_DTR_RTS_dbox2(struct s_reader * reader, int32_t * dtr, int32_t * rts)
{
  int32_t rc;
  uint16_t msr;
  uint32_t mbit;
  uint16_t rts_bits[2]={ 0x10, 0x800};
  uint16_t dtr_bits[2]={0x100,     0};
  int32_t mcport = (reader->typ == R_DB2COM2);

  if ((rc=ioctl(reader->fdmc, GET_PCDAT, &msr))>=0)
  {
    if (dtr)		// DTR
    {
      cs_debug_mask(D_DEVICE, "IO: multicam.o DTR:%s\n", *dtr ? "set" : "clear"); fflush(stdout);
      if (dtr_bits[mcport])
      {
        if (*dtr)
          msr&=(uint16_t)(~dtr_bits[mcport]);
        else
          msr|=dtr_bits[mcport];
        rc=ioctl(reader->fdmc, SET_PCDAT, &msr);
      }
      else
        rc=0;		// Dummy, can't handle using multicam.o
    }
    if (rts)		// RTS
    {
      cs_debug_mask(D_DEVICE, "IO: multicam.o RTS:%s\n", *rts ? "set" : "clear"); fflush(stdout);
      if (*rts)
        msr&=(uint16_t)(~rts_bits[mcport]);
      else
        msr|=rts_bits[mcport];
      rc=ioctl(reader->fdmc, SET_PCDAT, &msr);
    }
  }
	if (rc<0)
		return ERROR;
	return OK;
}
#endif

bool IO_Serial_DTR_RTS(struct s_reader * reader, int32_t * dtr, int32_t * rts)
{
#if defined(TUXBOX) && defined(PPC)
	if ((reader->typ == R_DB2COM1) || (reader->typ == R_DB2COM2))
		return(IO_Serial_DTR_RTS_dbox2(reader, dtr, rts));
#endif

	uint32_t msr;
	uint32_t mbit;
  
  if(dtr)
  {
    mbit = TIOCM_DTR;
#if defined(TIOCMBIS) && defined(TIOBMBIC)
    if (ioctl (reader->handle, *dtr ? TIOCMBIS : TIOCMBIC, &mbit) < 0)
      return ERROR;
#else
    if (ioctl(reader->handle, TIOCMGET, &msr) < 0)
      return ERROR;
    if (*dtr)
      msr|=mbit;
    else
      msr&=~mbit;
    if (ioctl(reader->handle, TIOCMSET, &msr)<0)
      return ERROR;
#endif
    cs_debug_mask(D_DEVICE, "IO: Setting %s=%i", "DTR", *dtr);
  }  

  if(rts)
  {
    mbit = TIOCM_RTS;
#if defined(TIOCMBIS) && defined(TIOBMBIC)
    if (ioctl (reader->handle, *rts ? TIOCMBIS : TIOCMBIC, &mbit) < 0)
      return ERROR;
#else
    if (ioctl(reader->handle, TIOCMGET, &msr) < 0)
      return ERROR;
    if (*rts)
      msr|=mbit;
    else
      msr&=~mbit;
    if (ioctl(reader->handle, TIOCMSET, &msr)<0)
      return ERROR;
#endif
    cs_debug_mask(D_DEVICE, "IO: Setting %s=%i", "RTS", *rts);
  }  

	return OK;
}

/*
 * Public functions definition
 */

bool IO_Serial_SetBitrate (struct s_reader * reader, uint32_t bitrate, struct termios * tio)
{
   /* Set the bitrate */
#ifdef OS_LINUX
  //FIXME workaround for Smargo until native mode works
  if ((reader->mhz == reader->cardmhz) && (reader->smargopatch != 1) && IO_Serial_Bitrate(bitrate) != B0)
#else
  if(IO_Serial_Bitrate(bitrate) == B0)
  {
    cs_log("Baudrate %u not supported", bitrate);
    return ERROR;
  }
  else
#endif
  { //no overclocking
    cfsetospeed(tio, IO_Serial_Bitrate(bitrate));
    cfsetispeed(tio, IO_Serial_Bitrate(bitrate));
    cs_debug_mask(D_DEVICE, "standard baudrate: cardmhz=%d mhz=%d -> effective baudrate %u", reader->cardmhz, reader->mhz, bitrate);
  }
#ifdef OS_LINUX
  else
  { //over or underclocking
    /* these structures are only available on linux as fas as we know so limit this code to OS_LINUX */
    struct serial_struct nuts;
    ioctl(reader->handle, TIOCGSERIAL, &nuts);
    int32_t custom_baud_asked = bitrate * reader->mhz / reader->cardmhz;
    nuts.custom_divisor = (nuts.baud_base + (custom_baud_asked/2))/ custom_baud_asked;
		int32_t custom_baud_delivered =  nuts.baud_base / nuts.custom_divisor;
    cs_debug_mask(D_DEVICE, "custom baudrate: cardmhz=%d mhz=%d custom_baud=%d baud_base=%d divisor=%d -> effective baudrate %d", 
	                      reader->cardmhz, reader->mhz, custom_baud_asked, nuts.baud_base, nuts.custom_divisor, custom_baud_delivered);
		int32_t baud_diff = custom_baud_delivered - custom_baud_asked;
		if (baud_diff < 0)
			baud_diff = (-baud_diff);
		if (baud_diff  > 0.05 * custom_baud_asked) {
			cs_log("WARNING: your card is asking for custom_baudrate = %i, but your configuration can only deliver custom_baudrate = %i",custom_baud_asked, custom_baud_delivered);
			cs_log("You are over- or underclocking, try OSCam when running your reader at normal clockspeed as required by your card, and setting mhz and cardmhz parameters accordingly.");
			if (nuts.baud_base <= 115200)
				cs_log("You are probably connecting your reader via a serial port, OSCam has more flexibility switching to custom_baudrates when using an USB->serial converter, preferably based on FTDI chip.");
		}
    nuts.flags &= ~ASYNC_SPD_MASK;
    nuts.flags |= ASYNC_SPD_CUST;
    ioctl(reader->handle, TIOCSSERIAL, &nuts);
    cfsetospeed(tio, IO_Serial_Bitrate(38400));
    cfsetispeed(tio, IO_Serial_Bitrate(38400));
  }
#endif
	return OK;
}

bool IO_Serial_SetParams (struct s_reader * reader, uint32_t bitrate, uint32_t bits, int32_t parity, uint32_t stopbits, int32_t dtr, int32_t rts)
{
	 struct termios newtio;
	
	 if(reader->typ == R_INTERNAL)
			return ERROR;
	 
	 memset (&newtio, 0, sizeof (newtio));

	if (IO_Serial_SetBitrate (reader, bitrate, & newtio))
		return ERROR;
				
	 /* Set the character size */
	 switch (bits)
	 {
		case 5:
			newtio.c_cflag |= CS5;
			break;
		
		case 6:
			newtio.c_cflag |= CS6;
			break;
		
		case 7:
			newtio.c_cflag |= CS7;
			break;
		
		case 8:
			newtio.c_cflag |= CS8;
			break;
	}
	
	/* Set the parity */
	switch (parity)
	{
		case PARITY_ODD:
			newtio.c_cflag |= PARENB;
			newtio.c_cflag |= PARODD;
			break;
		
		case PARITY_EVEN:	
			newtio.c_cflag |= PARENB;
			newtio.c_cflag &= ~PARODD;
			break;
		
		case PARITY_NONE:
			newtio.c_cflag &= ~PARENB;
			break;
	}
	
	/* Set the number of stop bits */
	switch (stopbits)
	{
		case 1:
			newtio.c_cflag &= (~CSTOPB);
			break;
		case 2:
			newtio.c_cflag |= CSTOPB;
			break;
	}
	
	/* Selects raw (non-canonical) input and output */
	newtio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	newtio.c_oflag &= ~OPOST;
#if 1
	newtio.c_iflag |= IGNPAR;
	/* Ignore parity errors!!! Windows driver does so why shouldn't I? */
#endif
	/* Enable receiver, hang on close, ignore control line */
	newtio.c_cflag |= CREAD | HUPCL | CLOCAL;
	
	/* Read 1 byte minimun, no timeout specified */
	newtio.c_cc[VMIN] = 1;
	newtio.c_cc[VTIME] = 0;

	if (IO_Serial_SetProperties(reader, newtio))
		return ERROR;

	reader->current_baudrate = bitrate;

	IO_Serial_Ioctl_Lock(reader, 1);
	IO_Serial_DTR_RTS(reader, &dtr, &rts);
	IO_Serial_Ioctl_Lock(reader, 0);
	return OK;
}

bool IO_Serial_SetProperties (struct s_reader * reader, struct termios newtio)
{
   if(reader->typ == R_INTERNAL)
      return ERROR;

	if (tcsetattr (reader->handle, TCSANOW, &newtio) < 0)
		return ERROR;
//	tcflush(reader->handle, TCIOFLUSH);
//	if (tcsetattr (reader->handle, TCSAFLUSH, &newtio) < 0)
//		return ERROR;

  int32_t mctl;
	if (ioctl (reader->handle, TIOCMGET, &mctl) >= 0) {
		mctl &= ~TIOCM_RTS; //should be mctl |= TIOCM_RTS; for readers with reversed polarity reset
		ioctl (reader->handle, TIOCMSET, &mctl);
	}
	else
		cs_log("WARNING: Failed to reset reader %s", reader->label);

	cs_debug_mask(D_DEVICE, "IO: Setting properties\n");
	return OK;
}

int32_t IO_Serial_SetParity (struct s_reader * reader, BYTE parity)
{
	if(reader->typ == R_INTERNAL)
		return OK;

	if ((parity != PARITY_EVEN) && (parity != PARITY_ODD) && (parity != PARITY_NONE))
		return ERROR;

	struct termios tio;
	int32_t current_parity;
	// Get current parity
	if (tcgetattr (reader->handle, &tio) != 0)
	  return ERROR;

	if (((tio.c_cflag) & PARENB) == PARENB)
	{
		if (((tio.c_cflag) & PARODD) == PARODD)
			current_parity = PARITY_ODD;
		else
			current_parity = PARITY_EVEN;
	}
	else
	{
		current_parity = PARITY_NONE;
	}

	cs_debug_mask(D_IFD, "IFD: Setting parity from %s to %s\n",
		current_parity == PARITY_ODD ? "Odd" :
		current_parity == PARITY_NONE ? "None" :
		current_parity == PARITY_EVEN ? "Even" : "Invalid",
		parity == PARITY_ODD ? "Odd" :
		parity == PARITY_NONE ? "None" :
		parity == PARITY_EVEN ? "Even" : "Invalid");
	
	if (current_parity != parity)
	{

		// Set the parity
		switch (parity)
		{
			case PARITY_ODD:
				tio.c_cflag |= PARENB;
				tio.c_cflag |= PARODD;
				break;
			
			case PARITY_EVEN:	
				tio.c_cflag |= PARENB;
				tio.c_cflag &= ~PARODD;
				break;
			
			case PARITY_NONE:
				tio.c_cflag &= ~PARENB;
				break;
		}
		if (IO_Serial_SetProperties (reader, tio))
			return ERROR;
	}

	return OK;
}

void IO_Serial_Flush (struct s_reader * reader)
{
	BYTE b;

  tcflush(reader->handle, TCIOFLUSH);
	while(!IO_Serial_Read(reader, 1000, 1, &b));
}

void IO_Serial_Sendbreak(struct s_reader * reader, int32_t duration)
{
	tcsendbreak (reader->handle, duration);
}

bool IO_Serial_Read (struct s_reader * reader, uint32_t timeout, uint32_t size, BYTE * data)
{
	BYTE c;
	uint32_t count = 0;
#ifdef SH4
	bool readed;
	struct timeval tv, tv_spent;
#endif
	
	if((reader->typ != R_INTERNAL) && (reader->written>0))
	{
		BYTE buf[256];
		int32_t n = reader->written;
		reader->written = 0;
	
		if(IO_Serial_Read (reader, timeout, n, buf))
			return ERROR;
	}
	
	for (count = 0; count < size ; count++)
	{
#ifdef SH4
		gettimeofday(&tv,0);
		memcpy(&tv_spent,&tv,sizeof(struct timeval));
		readed=FALSE;
		while( (((tv_spent.tv_sec-tv.tv_sec)*1000) + ((tv_spent.tv_usec-tv.tv_usec)/1000L))<timeout )
 		{
 			if (read (reader->handle, &c, 1) == 1)
 			{
 				readed=TRUE;
				break;
 			}
 			gettimeofday(&tv_spent,0);
		}
		if(!readed) {
			cs_ddump_mask(D_DEVICE, data, count, "IO: Receiving:");
			return ERROR;
		}
#else
		if (!IO_Serial_WaitToRead (reader, 0, timeout))
		{
			if (read (reader->handle, &c, 1) != 1)
			{
				cs_ddump_mask(D_DEVICE, data, count, "IO: Receiving:");
				cs_log("ERROR in IO_Serial_Read (errno=%d %s)", errno, strerror(errno));
				//tcflush (reader->handle, TCIFLUSH);
				return ERROR;
			}
		}
		else
		{
			cs_ddump_mask(D_DEVICE, data, count, "IO: Receiving:");
			cs_debug_mask(D_DEVICE, "TIMEOUT in IO_Serial_Read");
			//tcflush (reader->handle, TCIFLUSH);
			return ERROR;
		}
#endif
		data[count] = c;
	}
	cs_ddump_mask(D_DEVICE, data, count, "IO: Receiving:");
	return OK;
}

bool IO_Serial_Write (struct s_reader * reader, uint32_t delay, uint32_t size, const BYTE * data)
{
	uint32_t count, to_send, i_w;
	BYTE data_w[512];
	
	/* Discard input data from previous commands */
//	tcflush (reader->handle, TCIFLUSH);
	
	for (count = 0; count < size; count += to_send)
	{
//		if(reader->typ == R_INTERNAL)
//			to_send = 1;
//		else
			to_send = (delay? 1: size);
		
		if (!IO_Serial_WaitToWrite (reader, delay, 1000))
		{
			for (i_w=0; i_w < to_send; i_w++)
				data_w [i_w] = data [count + i_w];
			uint32_t u = write (reader->handle, data_w, to_send);
			if (u != to_send)
			{
				cs_log("ERROR in IO_Serial_Write u=%d to_send=%d (errno=%d %s)", u, to_send, errno, strerror(errno));
				if ((reader->typ != R_INTERNAL && reader->crdr.active==0) || (reader->crdr.active==1 && reader->crdr.read_written==1))
					reader->written += u;
				//tcflush (reader->handle, TCIFLUSH);
				return ERROR;
			}
			
			if ((reader->typ != R_INTERNAL && reader->crdr.active==0) || (reader->crdr.active==1 && reader->crdr.read_written==1))
				reader->written += to_send;
			
			cs_ddump_mask(D_DEVICE, data_w+count, to_send, "IO: Sending: ");
		}
		else
		{
			cs_log("TIMEOUT in IO_Serial_Write");
			//tcflush (reader->handle, TCIFLUSH);
			return ERROR;
		}
	}
	return OK;
}

bool IO_Serial_Close (struct s_reader * reader)
{
	
	cs_debug_mask(D_DEVICE, "IO: Closing serial port %s\n", reader->device);
	cs_sleepms(100); // maybe a dirty fix for the restart problem posted by wonderdoc
#if defined(TUXBOX) && defined(PPC)
	if(reader->fdmc >= 0) close(reader->fdmc);
#endif
	if (reader->handle >= 0 && close (reader->handle) != 0)
		return ERROR;
	
	reader->written = 0;
	
	return OK;
}

/*
 * Internal functions definition
 */

static int32_t IO_Serial_Bitrate(int32_t bitrate)
{
	static const struct BaudRates { int32_t real; speed_t apival; } BaudRateTab[] = {
#ifdef B230400
		{ 230400, B230400 },
#endif
#ifdef B115200
		{ 115200, B115200 },
#endif
#ifdef B76800	
		{ 76800, B76800 },
#endif
#ifdef B57600
		{  57600, B57600  },
#endif
#ifdef B38400
		{  38400, B38400  },
#endif
#ifdef B28800
		{  28800, B28800  },
#endif
#ifdef B19200
		{  19200, B19200  },
#endif
#ifdef B14400
		{  14400, B14400  },
#endif
#ifdef B9600
		{   9600, B9600   },
#endif
#ifdef B7200
		{   7200, B7200   },
#endif
#ifdef B4800
		{   4800, B4800   },
#endif
#ifdef B2400
		{   2400, B2400   },
#endif
#ifdef B1200
		{   1200, B1200   },
#endif
#ifdef B600
        {    600, B600    },
#endif
#ifdef B300
        {    300, B300    },
#endif
#ifdef B200
		{    200, B200    },
#endif
#ifdef B150
		{    150, B150    },
#endif
#ifdef B134
		{    134, B134    },
#endif
#ifdef B110
		{    110, B110    },
#endif
#ifdef B75
		{     75, B75     },
#endif
#ifdef B50
		{     50, B50     },
#endif
		};

	int32_t i;
	
	for(i=0; i<(int)(sizeof(BaudRateTab)/sizeof(struct BaudRates)); i++)
	{
		int32_t b=BaudRateTab[i].real;
		int32_t d=((b-bitrate)*10000)/b;
		if(abs(d)<=350)
		{
			return BaudRateTab[i].apival;
		}
	}
	return B0;
}

bool IO_Serial_WaitToRead (struct s_reader * reader, uint32_t delay_ms, uint32_t timeout_ms)
{
   fd_set rfds;
   fd_set erfds;
   struct timeval tv;
   int32_t select_ret;
   int32_t in_fd;
   
   if (delay_ms > 0)
      cs_sleepms (delay_ms);
   
   in_fd=reader->handle;
   
   FD_ZERO(&rfds);
   FD_SET(in_fd, &rfds);
   
   FD_ZERO(&erfds);
   FD_SET(in_fd, &erfds);
   
   tv.tv_sec = timeout_ms/1000;
   tv.tv_usec = (timeout_ms % 1000) * 1000L;

	while (1) {
		select_ret = select(in_fd+1, &rfds, NULL,  &erfds, &tv);
		if (select_ret==-1) {
			cs_log("ERROR in IO_Serial_WaitToRead: (errno=%d %s)", errno, strerror(errno));
			if (errno==EINTR) {
				//try again in case of Interrupted system call
				continue;
			} else
				return ERROR;
		}
		if (select_ret==0) {
			cs_debug_mask(D_DEVICE, "TIMEOUT in IO_Serial_WaitToRead");
			return ERROR;
		}
		break;
   	}

	if (FD_ISSET(in_fd, &erfds)) {
		cs_log("ERROR in IO_Serial_WaitToRead: fd is in error fds, (errno=%d %s)", errno, strerror(errno));
		return ERROR;
	}

	if (FD_ISSET(in_fd,&rfds))
		return OK;
	else
		return ERROR;
}

static bool IO_Serial_WaitToWrite (struct s_reader * reader, uint32_t delay_ms, uint32_t timeout_ms)
{
   fd_set wfds;
   fd_set ewfds;
   struct timeval tv;
   int32_t select_ret;
   int32_t out_fd;
   
#ifdef SCI_DEV
   if(reader->typ == R_INTERNAL)
      return OK;
#endif
		
   if (delay_ms > 0)
      cs_sleepms(delay_ms);

   out_fd=reader->handle;
    
   FD_ZERO(&wfds);
   FD_SET(out_fd, &wfds);
   
   FD_ZERO(&ewfds);
   FD_SET(out_fd, &ewfds);
   
   tv.tv_sec = timeout_ms/1000L;
   tv.tv_usec = (timeout_ms % 1000) * 1000L;

   select_ret = select(out_fd+1, NULL, &wfds, &ewfds, &tv);

   if(select_ret==-1)
   {
	cs_log("ERROR in IO_Serial_WaitToWrite: select_ret=%i, errno=%d", select_ret, errno);
	return ERROR;
   }

   if (FD_ISSET(out_fd, &ewfds))
   {
	cs_log("ERROR in IO_Serial_WaitToWrite: fd is in error fds, (errno=%d %s)", errno, strerror(errno));
	return ERROR;
   }

   if (FD_ISSET(out_fd,&wfds))
		 return OK;
	 else
		 return ERROR;
}

bool IO_Serial_InitPnP (struct s_reader * reader)
{
	uint32_t PnP_id_size = 0;
	BYTE PnP_id[IO_SERIAL_PNPID_SIZE];	/* PnP Id of the serial device */

  if (IO_Serial_SetParams (reader, 1200, 7, PARITY_NONE, 1, IO_SERIAL_HIGH, IO_SERIAL_LOW))
		return ERROR;

	while ((PnP_id_size < IO_SERIAL_PNPID_SIZE) && !IO_Serial_Read (reader, 200, 1, &(PnP_id[PnP_id_size])))
      PnP_id_size++;

		return OK;
}
