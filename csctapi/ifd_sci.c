/*
		ifd_sci.c
		This module provides IFD handling functions for SCI internal reader.
*/

#include "ifd_sci.h"

#ifdef SCI_DEV

#include <stdio.h>
#include <time.h>
#include <sys/ioctl.h>
#include "sci_global.h"
#include "sci_ioctl.h"
#include "string.h"
#ifdef SH4
#include <fcntl.h> 
#endif
#include "../globals.h"

#define ATR_TIMEOUT   800

#define OK 		0 
#define ERROR 1

int Sci_Init ()
{
}

int Sci_GetStatus (int handle, int * status)
{
	int in;
	call (ioctl(handle, IOCTL_GET_IS_CARD_PRESENT, status)<0);
	return OK;
}

int Sci_Reset (ATR * atr)
{
	unsigned char buf[SCI_MAX_ATR_SIZE];
	int n = 0;
	SCI_PARAMETERS params;
	
	memset(&params,0,sizeof(SCI_PARAMETERS));
	
	params.ETU = 372; 
	params.EGT = 3; //not sure why this value is chosen
	params.fs = 5;
	params.T = 0;
	
	call (ioctl(reader[ridx].handle, IOCTL_SET_PARAMETERS, &params)!=0);
	call (ioctl(reader[ridx].handle, IOCTL_SET_RESET)<0);

	while(n<SCI_MAX_ATR_SIZE && !IO_Serial_Read(ATR_TIMEOUT, 1, buf+n))
	{
		n++;
	}

	if ((buf[0] !=0x3B) && (buf[0] != 0x3F) && (n>9 && !memcmp(buf+4, "IRDETO", 6))) //irdeto S02 reports FD as first byte on dreambox SCI, not sure about SH4 or phoenix
		buf[0] = 0x3B;
	
	if(n==0) {
		cs_log("ERROR: 0 characters found in ATR");
		return ERROR;
	}
	call(!ATR_InitFromArray (atr, buf, n) == ATR_OK);
	{
		cs_sleepms(50);
		call (ioctl(reader[ridx].handle, IOCTL_SET_ATR_READY)<0);
		return OK;
	}
}

int Sci_WriteSettings (BYTE T, unsigned long fs, unsigned long ETU, unsigned long WWT, unsigned long BWT, unsigned long CWT, unsigned long EGT, unsigned char P, unsigned char I)
{
	//int n;
	SCI_PARAMETERS params;
	//memset(&params,0,sizeof(SCI_PARAMETERS));
	call (ioctl(reader[ridx].handle, IOCTL_GET_PARAMETERS, &params) < 0 );

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

	cs_debug("Setting T=%d fs=%lu mhz ETU=%d WWT=%d CWT=%d BWT=%d EGT=%d clock=%d check=%d P=%d I=%d U=%d", (int)params.T, params.fs, (int)params.ETU, (int)params.WWT, (int)params.CWT, (int)params.BWT, (int)params.EGT, (int)params.clock_stop_polarity, (int)params.check, (int)params.P, (int)params.I, (int)params.U);

	call (ioctl(reader[ridx].handle, IOCTL_SET_PARAMETERS, &params)!=0);
	return OK;
}

int Sci_Activate ()
{
	cs_debug_mask(D_IFD, "IFD: Activating card");
		int in;

#if defined(TUXBOX) && (defined(MIPSEL) || defined(PPC) || defined(SH4))
		call (ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_PRESENT, &in)<0);
#else
		call (ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_ACTIVATED, &in)<0);
#endif
			
		if(in)
			cs_sleepms(50);
		else
			return ERROR;
		return OK;
}

int Sci_Deactivate ()
{
	cs_debug_mask(D_IFD, "IFD: Deactivating card");
	int in;
		
#if defined(TUXBOX) && (defined(MIPSEL) || defined(PPC) || defined(SH4))
	call (ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_PRESENT, &in)<0);
#else
	call (ioctl(reader[ridx].handle, IOCTL_GET_IS_CARD_ACTIVATED, &in)<0);
#endif
			
	if(in)
		call (ioctl(reader[ridx].handle, IOCTL_SET_DEACTIVATE)<0);
	return OK;
}

#endif
