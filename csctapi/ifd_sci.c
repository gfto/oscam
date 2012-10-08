/*
		ifd_sci.c
		This module provides IFD handling functions for SCI internal reader.
*/

#include "ifd_sci.h"
#include "io_serial.h"
#ifdef WITH_CARDREADER

#include <stdio.h>
#include <time.h>
#include <sys/ioctl.h>
#include "../oscam-time.h"
#include "sci_global.h"
#include "sci_ioctl.h"
#include "string.h"
#if defined(__SH4__)
#include <fcntl.h> 
#endif

#define ATR_TIMEOUT   800

#define OK 		0 
#define ERROR 1

int32_t Sci_GetStatus (struct s_reader * reader, int32_t * status)
{
	call (ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, status)<0);
	return OK;
}

int32_t Sci_Reset (struct s_reader * reader, ATR * atr)
{
	rdr_debug_mask(reader, D_IFD, "Reset internal cardreader!");
	unsigned char buf[SCI_MAX_ATR_SIZE];
	int32_t n = 0;
	SCI_PARAMETERS params;
	
	memset(&params,0,sizeof(SCI_PARAMETERS));
	
	params.ETU = 372; //initial ETU (in iso this parameter F)
	params.EGT = 3; //initial guardtime should be 0 (in iso this is parameter N)
	params.fs = 5; //initial cardmhz should be 1 (in iso this is parameter D)
	params.T = 0;
	if (reader->mhz > 2000) { // PLL based reader
		params.ETU = 372;
		params.EGT = 0;
		params.fs = (int32_t) (reader->mhz / 100.0 + 0.5); /* calculate divider for 1 MHz  */
		params.T = 0;
	}
	if (reader->mhz == 8300) { /* PLL based reader DM7025 */
		params.ETU = 372;
		params.EGT = 0;
		params.fs = 16; /* read from table setting for 1 MHz:
		params.fs = 6 for cardmhz = 5.188 Mhz
		params.fs = 7 for cardmhz = 4.611 MHz
		params.fs = 8 for cardmhz = 3.953 MHz
		params.fs = 9 for cardmhz = 3.609 MHz
		params.fs = 10 for cardmhz = 3.192 MHz
		params.fs = 11 for cardmhz = 2.965 MHz
		params.fs = 12 for cardmhz = 2.677 MHz
		params.fs = 13 for cardmhz = 2.441 MHz
		params.fs = 14 for cardmhz = 2.306 MHz
		params.fs = 15 for cardmhz = 2.128 MHz
		params.fs = 16 for cardmhz = 1.977 MHz */
		params.T = 0;
	}
	call (ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params)!=0);
	call (ioctl(reader->handle, IOCTL_SET_RESET)<0);
#if defined(__powerpc__)
    // looks like PPC box need a delay here. From the data provided we need at least 140ms at 3.57MHz so I'll chose 150ms to be safe
    rdr_debug_mask(reader, D_IFD, "Extra delay for PPC box between reset and IO_Serial_Read for the ATR");
    cs_sleepms(150);
#endif
	uint32_t timeout = ATR_TIMEOUT;
	if (reader->mhz > 2000)           // pll readers use timings in us
		timeout = timeout * 1000;
	while(n<SCI_MAX_ATR_SIZE)
	{
		if (IO_Serial_Read(reader, timeout, 1, buf+n)){
			rdr_debug_mask(reader, D_IFD, "Got a timeout!");
			break;   // read atr response to end
		}
		
	n++;
	}

	if ((buf[0] !=0x3B) && (buf[0] != 0x3F) && (n>9 && !memcmp(buf+4, "IRDETO", 6))) //irdeto S02 reports FD as first byte on dreambox SCI, not sure about SH4 or phoenix
		buf[0] = 0x3B;
	
	if(n==0) {
		rdr_debug_mask(reader, D_IFD, "ERROR: 0 characters found in ATR");
		return ERROR;
	}
	call(!ATR_InitFromArray (atr, buf, n) == ATR_OK);
	{
		cs_sleepms(50);
		call (ioctl(reader->handle, IOCTL_SET_ATR_READY)<0);
		return OK;
	}
}

int32_t Sci_WriteSettings (struct s_reader * reader, BYTE T, uint32_t fs, uint32_t ETU, uint32_t WWT, uint32_t BWT, uint32_t CWT, uint32_t EGT, unsigned char P, unsigned char I)
{
	//int32_t n;
	SCI_PARAMETERS params;
	//memset(&params,0,sizeof(SCI_PARAMETERS));
	call (ioctl(reader->handle, IOCTL_GET_PARAMETERS, &params) < 0 );

	params.T = T;
	params.fs = fs;

	//for Irdeto T14 cards, do not set ETU
	if (ETU)
		params.ETU = ETU;
	params.EGT = EGT;
	params.WWT = WWT;
	params.BWT = BWT;
	params.CWT = CWT;
	if (P)
		params.P = P;
	if (I)
		params.I = I;

	rdr_debug_mask(reader, D_IFD, "Setting reader T=%d fs=%d ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d",
		(int)params.T, params.fs, (int)params.ETU, (int)params.WWT,
		(int)params.CWT, (int)params.BWT, (int)params.EGT,
		(int)params.clock_stop_polarity, (int)params.check,
		(int)params.P, (int)params.I, (int)params.U);

	call (ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params)!=0);
	return OK;
}

#if defined(__SH4__)
#define __IOCTL_CARD_ACTIVATED IOCTL_GET_IS_CARD_PRESENT
#else
#define __IOCTL_CARD_ACTIVATED IOCTL_GET_IS_CARD_ACTIVATED
#endif

int32_t Sci_Activate (struct s_reader * reader)
{
		rdr_debug_mask(reader, D_IFD, "Activating card");
		uint32_t in = 1;

	rdr_debug_mask(reader, D_IFD, "Is card activated?");
	if (ioctl(reader->handle, __IOCTL_CARD_ACTIVATED, &in) < 0) {
		rdr_debug_mask(reader, D_IFD, "ioctl returned: %u", in);
		rdr_debug_mask(reader, D_IFD, "Is card present?");
		call(ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, &in) < 0);
	}
	rdr_debug_mask(reader, D_IFD, "ioctl returned: %u", in);

		if(in)
			cs_sleepms(50);
		else
			return ERROR;
		return OK;
}

int32_t Sci_Deactivate (struct s_reader * reader)
{
	rdr_debug_mask(reader, D_IFD, "Deactivating card");
	int32_t in;
		
	if (ioctl(reader->handle, __IOCTL_CARD_ACTIVATED, &in) < 0)
		call(ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, &in) < 0);
			
	if(in)
		call (ioctl(reader->handle, IOCTL_SET_DEACTIVATE)<0);
	return OK;
}


int32_t Sci_FastReset (struct s_reader *reader)
{
	unsigned char buf[SCI_MAX_ATR_SIZE];
	int32_t n = 0;

	call (ioctl(reader->handle, IOCTL_SET_RESET)<0);

    cs_sleepms(50);
    // flush atr from buffer
	uint32_t timeout = ATR_TIMEOUT;
	if (reader->mhz > 2000)           // pll readers use timings in us
		timeout = timeout * 1000;
	while(n<SCI_MAX_ATR_SIZE && !IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n))
	{
		n++;
	}


    call (ioctl(reader->handle, IOCTL_SET_ATR_READY)<0);

    return 0;
}

#endif
