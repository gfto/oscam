#include <stdio.h>
#include "../globals.h"
#include "atr.h"
#include <termios.h>
#include "ifd_phoenix.h"
#include "icc_async.h"
#include "io_serial.h"

#ifdef OS_CYGWIN32
#undef OK
#undef ERROR
#undef LOBYTE
#undef HIBYTE
#endif

#define OK 0
#define ERROR 1
#define LOBYTE(w) ((BYTE)((w) & 0xff))
#define HIBYTE(w) ((BYTE)((w) >> 8))

#define DELAY 50

static int smargo_set_settings(struct s_reader *reader, int freq, unsigned char T, unsigned char inv, unsigned short Fi, unsigned char Di, unsigned char Ni) {
	int ret = 0;
	unsigned short freqk = (freq * 10);
	uchar data[4];
	struct termios term;

	tcgetattr(reader->handle, &term);
	term.c_cflag &= ~CSIZE;
	term.c_cflag |= CS5;
	tcsetattr(reader->handle, TCSANOW, &term);

	cs_debug_mask(D_DEVICE, "Smargo: sending F=%04X (%d), D=%02X (%d), Freq=%04X (%d), N=%02X (%d), T=%02X (%d), inv=%02X (%d) to smartreader",Fi, Fi, Di, Di, freqk, freqk, Ni, Ni, T, T, inv, inv);

	if (T!=14 || freq == 369) {
		data[0]=0x01;
		data[1]=HIBYTE(Fi);
		data[2]=LOBYTE(Fi);
		data[3]=Di;
		ret = IO_Serial_Write(reader, 0, 4, data);

		cs_sleepms(DELAY);
	}

	data[0]=0x02;
	data[1]=HIBYTE(freqk);
	data[2]=LOBYTE(freqk);
	ret = IO_Serial_Write(reader, 0, 3, data);

	cs_sleepms(DELAY);

	data[0]=0x03;
	data[1]=Ni;
	ret = IO_Serial_Write(reader, 0, 2, data);

	cs_sleepms(DELAY);

	data[0]=0x04;
	data[1]=T;
	ret = IO_Serial_Write(reader, 0, 2, data);

	cs_sleepms(DELAY);

	data[0]=0x05;
	data[1]=0; //always done by oscam
	ret = IO_Serial_Write(reader, 0, 2, data);

	cs_sleepms(DELAY);

	tcgetattr(reader->handle, &term);
	term.c_cflag &= ~CSIZE;
	term.c_cflag |= CS8;
	tcsetattr(reader->handle, TCSANOW, &term);

	return OK;
}

static int smargo_writesettings(struct s_reader *reader, unsigned long UNUSED(ETU), unsigned long UNUSED(EGT), unsigned char UNUSED(P), unsigned char UNUSED(I), unsigned short Fi, unsigned char Di, unsigned char Ni) {
	smargo_set_settings(reader, reader->mhz, reader->protocol_type == 1 ? 0 : reader->protocol_type , reader->convention, Fi, Di, Ni);
	return OK;
}


static int smargo_init(struct s_reader *reader) {
	cs_log("smargo init");
	reader->handle = open (reader->device,  O_RDWR);
	if (reader->handle < 0) {
		cs_log("ERROR opening device %s",reader->device);
		return ERROR;
	}

	return OK;
}

static int smargo_reset(struct s_reader *reader, ATR *atr) {
	cs_debug_mask(D_IFD, "Smargo: Resetting card:");
	int ret=ERROR;
	int i;
	unsigned char buf[ATR_MAX_SIZE];

	int parity[4] = {PARITY_EVEN, PARITY_ODD, PARITY_NONE, PARITY_EVEN};

	for(i=0; i<4; i++) {
		if (i==3) // hack for irdeto cards
			smargo_set_settings(reader, 600, 1, 0, 618, 1, 0);
		else
			smargo_set_settings(reader, 357, 0, 0, 372, 1, 0);

		call (IO_Serial_SetParity (reader, parity[i]));

		IO_Serial_RTS_Set(reader);
		cs_sleepms(150);
		IO_Serial_RTS_Clr(reader);

		int n=0;
		while(n<ATR_MAX_SIZE && !IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n))
			n++;
		
		if(n==0 || buf[0]==0)
			continue;

		cs_ddump_mask(D_IFD, buf, n, "Smargo ATR:");

		if((buf[0]!=0x3B && buf[0]!=0x03 && buf[0]!=0x3F) || (buf[1]==0xFF && buf[2]==0x00))
			continue; // this is not a valid ATR

		if (ATR_InitFromArray (atr, buf, n) == ATR_OK)
			ret = OK;

		if (ret == OK)
			break;
	}

	return ret;
}

static int smargo_receive(struct s_reader *reader, unsigned char *data, unsigned int size) {
	return Phoenix_Receive(reader, data, size, reader->read_timeout);
}

static int smargo_transmit(struct s_reader *reader, unsigned char *sent, unsigned int size) {
	return Phoenix_Transmit(reader, sent, size, 0, 0);
}

void cardreader_smargo(struct s_cardreader *crdr) 
{
	strcpy(crdr->desc, "smargo");
	crdr->reader_init	= smargo_init;
	crdr->get_status	= Phoenix_GetStatus;
	crdr->activate	= smargo_reset;
	crdr->transmit	= smargo_transmit;
	crdr->receive		= smargo_receive;
	crdr->close		= Phoenix_Close;
	crdr->write_settings = smargo_writesettings;
	crdr->typ		= R_MOUSE;

	crdr->need_inverse	= 1;
}
