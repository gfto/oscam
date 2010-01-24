#ifdef COOL
/*
		ifd_cool.c
		This module provides IFD handling functions for Coolstream internal reader.
*/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include"ifd_cool.h"

#define OK 		1 
#define ERROR 0

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
/*	
	if (Cool_SetBaudrate(mhz) != OK)
		return ERROR;*/

	return OK;
}


int Cool_GetStatus (int * in)
{
	int state;
	if (cnxt_smc_get_state(handle, &state))
		return ERROR;
	//state = 0 no card, 1 = not ready, 2 = ready
	if (state)
		*in = 1; //CARD, even if not ready report card is in, or it will never get activated
	else
		*in = 0; //NOCARD
	return OK;
}

int Cool_Reset (ATR * atr)
{
	if (!Cool_SetBaudrate(357))
		return ERROR;

	//reset card
	int timeout = 5000; // Timout in ms?
	if (cnxt_smc_reset_card (handle, timeout, NULL, NULL))
		return ERROR;

	int n = 40;
	unsigned char buf[40];
	if (cnxt_smc_get_atr (handle, buf, &n))
		return ERROR;
		
	if(ATR_InitFromArray (atr, buf, n) == ATR_OK)
	{
		struct timespec req_ts;
		req_ts.tv_sec = 0;
		req_ts.tv_nsec = 50000000;
		nanosleep (&req_ts, NULL);
		return OK;
	}
	else
		return ERROR;
}

int Cool_Transmit (BYTE * sent, unsigned size)
{ 
#define TIMEOUT 4000 //max 4294
	cardbuflen = 256;//it needs to know max buffer size to respond?
	if (cnxt_smc_read_write(handle, FALSE, sent, size, cardbuffer, &cardbuflen, TIMEOUT, 0))
		return ERROR;

#ifdef DEBUG_IFD
	//usually done in IFD_Towitoko, for COOL do it here
	printf ("COOLIFD: Transmit: ");
	int i;
	for (i = 0; i < size; i++)
		printf ("%X ", sent[i]);
	printf ("\n");
#endif
	return OK;
}

int Cool_Receive (BYTE * data, unsigned size)
{ 
	if (size > cardbuflen)
		size = cardbuflen; //never read past end of buffer
	memcpy(data,cardbuffer,size);
	cardbuflen -= size;
	memmove(cardbuffer,cardbuffer+size,cardbuflen);

#ifdef DEBUG_IFD
	int i;
	printf ("COOLIFD: Receive: "); //I think
	for (i = 0; i < size; i++)
		printf ("%X ", data[i]);
	printf ("\n");
	fflush(stdout);
#endif
	return OK;
}	

int Cool_SetBaudrate (int mhz)
{
	typedef unsigned long u_int32;
	u_int32 clk;
	clk = mhz * 10000;
	if (cnxt_smc_set_clock_freq (handle, clk))
		return ERROR;
	return OK;
}
#endif
