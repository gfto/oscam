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
	cs_debug_mask(D_IFD,"IFD: Reset internal cardreader!");
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
		int32_t divider = 0; // calculate divider for 1 mhz, calculate PLL divider ugly fast fix -> FIX ME!!!!
			double cardclock1, cardclock2;

			while (divider != reader->mhz/100){
				divider++;																		
				cardclock1 = reader->mhz / divider;
				divider++;
				cardclock2 = reader->mhz / (divider);	
				if ((cardclock1 > 100) && (cardclock2 > 100)) continue;
				if ( abs(cardclock1 - 100) > abs(cardclock2 - 100) ) break;
				divider--;
				break;
			}
		params.fs = divider; 
		params.T = 0;
	}
	call (ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params)!=0);
	call (ioctl(reader->handle, IOCTL_SET_RESET)<0);
#if defined(__powerpc__)
    // looks like PPC box need a delay here. From the data provided we need at least 140ms at 3.57MHz so I'll chose 150ms to be safe
    cs_debug_mask(D_IFD,"IFD: Extra delay for PPC box between reset and IO_Serial_Read for the ATR");
    cs_sleepms(150);
#endif
	while(n<SCI_MAX_ATR_SIZE)
	{
		if (IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n)) break;   // read atr response to end
		n++;
	}

	if ((buf[0] !=0x3B) && (buf[0] != 0x3F) && (n>9 && !memcmp(buf+4, "IRDETO", 6))) //irdeto S02 reports FD as first byte on dreambox SCI, not sure about SH4 or phoenix
		buf[0] = 0x3B;
	
	if(n==0) {
		cs_debug_mask(D_IFD,"IFD: ERROR: 0 characters found in ATR");
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

	cs_debug_mask(D_IFD, "IFD: Setting reader %s: T=%d fs=%d ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d", reader->label, (int)params.T, params.fs, (int)params.ETU, (int)params.WWT, (int)params.CWT, (int)params.BWT, (int)params.EGT, (int)params.clock_stop_polarity, (int)params.check, (int)params.P, (int)params.I, (int)params.U);

	call (ioctl(reader->handle, IOCTL_SET_PARAMETERS, &params)!=0);
	return OK;
}

int32_t Sci_Activate (struct s_reader * reader)
{
		cs_debug_mask(D_IFD, "IFD: Activating card");
		int32_t in;

	cs_debug_mask(D_IFD, "IFD: Is card activated?");
	if (ioctl(reader->handle, IOCTL_GET_IS_CARD_ACTIVATED, &in) < 0) {
		cs_debug_mask(D_IFD, "IFD: Is card present?");
		call(ioctl(reader->handle, IOCTL_GET_IS_CARD_PRESENT, &in) < 0);
	}

		if(in)
			cs_sleepms(50);
		else
			return ERROR;
		return OK;
}

int32_t Sci_Deactivate (struct s_reader * reader)
{
	cs_debug_mask(D_IFD, "IFD: Deactivating card");
	int32_t in;
		
	if (ioctl(reader->handle, IOCTL_GET_IS_CARD_ACTIVATED, &in) < 0)
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
	while(n<SCI_MAX_ATR_SIZE && !IO_Serial_Read(reader, ATR_TIMEOUT, 1, buf+n))
	{
		n++;
	}


    call (ioctl(reader->handle, IOCTL_SET_ATR_READY)<0);

    return 0;
}

#endif
