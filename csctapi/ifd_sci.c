/*
		ifd_sci.c
		This module provides IFD handling functions for SCI internal reader.
*/

#include "../globals.h"

#ifdef WITH_CARDREADER

#include "../oscam-time.h"

#include "atr.h"
#include "ifd_sci.h"
#include "io_serial.h"
#include "sci_global.h"
#include "sci_ioctl.h"

#define ATR_TIMEOUT   800

#define OK 		0 
#define ERROR 1
int32_t statusreturn = 0;
int32_t Sci_GetStatus (struct s_reader * reader, int32_t * status)
{
	ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, status);
	return OK;
}

int32_t Sci_Reset(struct s_reader * reader, ATR * atr)
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
	ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params);
	ioctl(reader->handle, IOCTL_SET_RESET, 1);
	uint32_t timeout = ATR_TIMEOUT;
	
	do {
		ioctl(reader->handle, IOCTL_GET_ATR_STATUS, &statusreturn);
		rdr_debug_mask(reader, D_IFD, "Waiting for card ATR Response...");
	}
		while (statusreturn);
	
	if (reader->mhz > 2000)           // pll readers use timings in us
		timeout = timeout * 1000;
	if (IO_Serial_Read(reader, timeout, 1, buf+n)){ //read first char of atr
		rdr_debug_mask(reader, D_IFD, "ERROR: no characters found in ATR");
		return ERROR;
	}
	int32_t inverse = 0; // card is using inversion?
	if (buf[0] == 0x03){
		inverse = 1;
		buf[n] = ~(INVERT_BYTE (buf[n]));
	}
	n++;
	if (IO_Serial_Read(reader, timeout, 1, buf+n)){
		rdr_debug_mask(reader, D_IFD, "ERROR: only 1 character found in ATR");
		return ERROR;
	}
	if (inverse) buf[n] = ~(INVERT_BYTE (buf[n]));
	int32_t TDi = buf[n];
	int32_t historicalbytes = TDi &0x0F;
	rdr_debug_mask(reader, D_IFD, "ATR historicalbytes should be: %d", historicalbytes);
	n++;
	while (n < SCI_MAX_ATR_SIZE){
		if ((TDi | 0xEF) == 0xFF){  //TA Present
			if (IO_Serial_Read(reader, timeout, 1, buf+n)) break;
			if (inverse) buf[n] = ~(INVERT_BYTE (buf[n]));
			rdr_debug_mask(reader, D_IFD, "TA: %02X",buf[n]);
			n++;
		}
		if ((TDi | 0xDF) == 0xFF){	 //TB Present
			if (IO_Serial_Read(reader, timeout, 1, buf+n)) break;
			if (inverse) buf[n] = ~(INVERT_BYTE (buf[n]));
			rdr_debug_mask(reader, D_IFD, "TB: %02X",buf[n]);
			n++;
		}
		if ((TDi | 0xBF) == 0xFF){	 //TC Present
			if (IO_Serial_Read(reader, timeout, 1, buf+n)) break;
			if (inverse) buf[n] = ~(INVERT_BYTE (buf[n]));
			rdr_debug_mask(reader, D_IFD, "TC: %02X",buf[n]);
			n++;
		}
		if ((TDi | 0x7F) == 0xFF){	//TD Present, more than 1 protocol?
			if (IO_Serial_Read(reader, timeout, 1, buf+n)) break;
			if (inverse) buf[n] = ~(INVERT_BYTE (buf[n]));
			rdr_debug_mask(reader, D_IFD, "TDi %02X",buf[n]);
			TDi = buf[n];
			n++;
		}
		else break;
	}
	int32_t atrlength = 0;
	atrlength += n;
	atrlength += historicalbytes;
	rdr_debug_mask(reader, D_IFD, "Total ATR Length including %d historical bytes should be: %d",historicalbytes,atrlength);
	
	while(n<atrlength){
		if (IO_Serial_Read(reader, timeout, 1, buf+n)) break; // ppcold always returns timeout on last atr char!	
		n++;
		if (inverse) buf[n] = ~(INVERT_BYTE (buf[n]));
	}
	ioctl(reader->handle, IOCTL_SET_ATR_READY, 1);
	rdr_debug_mask(reader, D_IFD, "Total ATR characters read is: %d",n);
		
	if ((buf[0] !=0x3B) && (buf[0] != 0x3F) && (n>9 && !memcmp(buf+4, "IRDETO", 6))) //irdeto S02 reports FD as first byte on dreambox SCI, not sure about SH4 or phoenix
		buf[0] = 0x3B;
		
	if(ATR_InitFromArray (atr, buf, n) == ATR_OK) return OK;
	return ERROR;
}

int32_t Sci_WriteSettings (struct s_reader * reader, unsigned char T, uint32_t fs, uint32_t ETU, uint32_t WWT, uint32_t BWT, uint32_t CWT, uint32_t EGT, unsigned char P, unsigned char I)
{
	//int32_t n;
	SCI_PARAMETERS params;
	//memset(&params,0,sizeof(SCI_PARAMETERS));
	ioctl(reader->handle, IOCTL_GET_PARAMETERS, &params);
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

	ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params);
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
	ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, &in);
	ioctl(reader->handle, __IOCTL_CARD_ACTIVATED, &in);
	return OK;
}

int32_t Sci_Deactivate (struct s_reader * reader)
{
	rdr_debug_mask(reader, D_IFD, "Deactivating card");
	ioctl(reader->handle, IOCTL_SET_DEACTIVATE);	
	return OK;
}


int32_t Sci_FastReset (struct s_reader *reader)
{
	unsigned char buf[SCI_MAX_ATR_SIZE];
	int32_t n = 0;

	ioctl(reader->handle, IOCTL_SET_RESET, 1);
	
	do {
		ioctl(reader->handle, IOCTL_GET_ATR_STATUS, &statusreturn);
		rdr_debug_mask(reader, D_IFD, "Waiting for card ATR Response...");
	}
		while (statusreturn);
	// flush atr from buffer
	uint32_t timeout = ATR_TIMEOUT;
	if (reader->mhz > 2000)           // pll readers use timings in us
		timeout = timeout * 1000;
	while(n<SCI_MAX_ATR_SIZE && !IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n))
	{
		n++;
	}
    ioctl(reader->handle, IOCTL_SET_ATR_READY);
    return OK;
}

#endif
