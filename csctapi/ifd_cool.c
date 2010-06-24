#ifdef COOL
/*
		ifd_cool.c
		This module provides IFD handling functions for Coolstream internal reader.
*/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include"ifd_cool.h"
#include"../globals.h"
#include"icc_async.h"

void * handle;

unsigned char cardbuffer[256];
int cardbuflen = 0;

int Cool_Init ()
{
 	if (cnxt_kal_initialize ())
		return FALSE;

	if (cnxt_drv_init ())
		return FALSE;

	if (cnxt_smc_init (NULL) != 1)
		return FALSE;
	
	int reader = 0;
	if (cnxt_smc_open (&handle, &reader))
		return FALSE;

	return OK;
}


int Cool_GetStatus (int * in)
{
	int state;
	call (cnxt_smc_get_state(handle, &state));
	//state = 0 no card, 1 = not ready, 2 = ready
	if (state)
		*in = 1; //CARD, even if not ready report card is in, or it will never get activated
	else
		*in = 0; //NOCARD
	return OK;
}

int Cool_Reset (ATR * atr)
{
	call (Cool_SetClockrate(357));

	//reset card
	int timeout = 5000; // Timout in ms?
	call (cnxt_smc_reset_card (handle, ATR_TIMEOUT, NULL, NULL));

    cs_sleepms(50);

	int n = 40;
	unsigned char buf[40];
	call (cnxt_smc_get_atr (handle, buf, &n));
		
	call (!ATR_InitFromArray (atr, buf, n) == ATR_OK);
	{
		cs_sleepms(50);
		return OK;
	}
}

int Cool_Transmit (BYTE * sent, unsigned size)
{ 
	cardbuflen = 256;//it needs to know max buffer size to respond?
	call (cnxt_smc_read_write(handle, FALSE, sent, size, cardbuffer, &cardbuflen, 50, 0));
	//call (cnxt_smc_read_write(handle, FALSE, sent, size, cardbuffer, &cardbuflen, read_timeout, 0));
	cs_ddump(sent, size, "COOL IO: Transmit: ");
	return OK;
}

int Cool_Receive (BYTE * data, unsigned size)
{ 
	if (size > cardbuflen)
		size = cardbuflen; //never read past end of buffer
	memcpy(data,cardbuffer,size);
	cardbuflen -= size;
	memmove(cardbuffer,cardbuffer+size,cardbuflen);
	cs_ddump(data, size, "COOL IO: Receive: ");
	return OK;
}	

int Cool_SetClockrate (int mhz)
{
	typedef unsigned long u_int32;
	u_int32 clk;
	clk = mhz * 10000;
	call (cnxt_smc_set_clock_freq (handle, clk));
	cs_debug("COOL: Clock succesfully set to %i0 kHz", mhz);
	return OK;
}

int Cool_WriteSettings (unsigned long BWT, unsigned long CWT, unsigned long EGT, unsigned long BGT)
{
	struct
	{
		unsigned short  CardActTime;   //card activation time (in clock cycles = 1/54Mhz)
		unsigned short  CardDeactTime; //card deactivation time (in clock cycles = 1/54Mhz)
		unsigned short  ATRSTime;			//ATR first char timeout in clock cycles (1/f)
		unsigned short  ATRDTime;			//ATR duration in ETU
		unsigned long	  BWT;
		unsigned long   CWT;
		unsigned char   EGT;
		unsigned char   BGT;
	} params;
	params.BWT = BWT;
	params.CWT = CWT;
	params.EGT = EGT;
	params.BGT = BGT;
	call (cnxt_smc_set_config_timeout(handle, params));
	cs_debug("COOL WriteSettings OK");
	return OK;
}

int Cool_FastReset ()
{
	int n = 40;
	unsigned char buf[40];

	//reset card
	call (cnxt_smc_reset_card (handle, ATR_TIMEOUT, NULL, NULL));

    cs_sleepms(50);

	call (cnxt_smc_get_atr (handle, buf, &n));

    return 0;
}

#endif
