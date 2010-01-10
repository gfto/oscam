#ifdef COOL
/*
		ifd_cool.c
		This module provides IFD handling functions for Coolstream internal reader.
*/

#include <stdio.h>
#include <time.h>
#include"ifd_cool.h"
/*
#include "io_serial.h"
#include "sci_global.h"
#include "sci_ioctl.h"
*/

// these should be called from icc, t0, cardterminal etc. like this:
// switch (reader[ridx].type) {
//	 case INTERN:
// #ifdef COOL
//		 Cool_Init();
//		 break;
// #endif
// #ifdef SCI_DEV
// //still in towitoko shit
// #endif
//	 case SMART:
//	 case MOUSE:
//		 IFD_Towitoko_Init(ifd, io, slot);
//		 break;
//	 default:
//		 return ERROR;
// }
// all other IFD_Towitoko functions should be
// -eliminated (like SetLed or administrative jobs)
// -rewritten eg. setparity should become a call to getproperties, setproperties
// ActivateICC should call ResetICC automagically
// DeactivateICC for symmetry and cleanup
//

#define OK 		1 
#define ERROR 0

void * handle;

unsigned char cardbuffer[256];
int cardbuflen = 0;

int Cool_Init ()
{
	//initialize properties(input_bitrate, output_bitrate, bits, stopbits, parity,dtr, rts) of device to default values
	//initialize ifd settings
	//and get reader info
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

/*
int Cool_GetStatus (BYTE * result)
{ 
// return status : 0 -start, 1 - card, 2- no card

	//extern int cnxt_smc_get_state();
	return OK;
}
*/
int Cool_Reset (ATR ** atr)
{
printf("Entering coolreset");
fflush(stdout);
	//reset needs clock to be reset by hand
	typedef unsigned long u_int32;
	u_int32 clk;
	clk = 357*10000; // MHZ
	if (cnxt_smc_set_clock_freq(handle, clk))
		return ERROR;

	//reset card
	int timeout = 5000; // Timout in ms?
	if (cnxt_smc_reset_card (handle, timeout, NULL, NULL))
		return ERROR;

	int n = 40;
	//int atr_len = 40;
	unsigned char buf[40];
	if (cnxt_smc_get_atr (handle, buf, &n))
		return ERROR;
	//atr_len = n;
//	atr = buf;
	/////////////
		(*atr) = ATR_New ();
		if(ATR_InitFromArray ((*atr), buf, n) == ATR_OK)
		{
			struct timespec req_ts;
			req_ts.tv_sec = 0;
			req_ts.tv_nsec = 50000000;
			nanosleep (&req_ts, NULL);
#ifdef SCI_DEV
			if (ioctl(ifd->io->fd, IOCTL_SET_ATR_READY)<0)
				return ERROR;
#endif
			return OK;
		}
		else
		{
			ATR_Delete (*atr);
			(*atr) = NULL;
			return ERROR;
		}
	///////////
}
/*
int Cool_DeactivateICC ()
{
#ifdef DEBUG_IFD
	printf ("IFD: Deactivating card\n");
#endif
/*
		int in;
		
#if defined(TUXBOX) && (defined(MIPSEL) || defined(PPC) || defined(SH4))
		if(ioctl(ifd->io->fd, IOCTL_GET_IS_CARD_PRESENT, &in)<0)
#else
		if(ioctl(ifd->io->fd, IOCTL_GET_IS_CARD_ACTIVATED, &in)<0)
#endif
			return IFD_TOWITOKO_IO_ERROR;
			
		if(in)
		{
			if(ioctl(ifd->io->fd, IOCTL_SET_DEACTIVATE)<0)
				return IFD_TOWITOKO_IO_ERROR;
		}
*/		
/*
	return OK;
}
*/

int Cool_Transmit (BYTE * sent, unsigned size)
{ 
#define TIMEOUT 4000 //max 4294
	cardbuflen = 256;//it needs to know max buffer size to respond?
  int rc = cnxt_smc_read_write(handle, FALSE, sent, size, cardbuffer, &cardbuflen, TIMEOUT, 0);

#ifdef DEBUG_IFD
  //usually done in IFD_Towitoko, for COOL do it here
	printf ("COOLIFD: Transmit: ");
	int i;
	for (i = 0; i < size; i++)
	  printf ("%X ", sent[i]);
	printf ("\n");
#endif

	//FIXME implement rc
}

int Cool_Receive (BYTE * buffer, unsigned size)
{ //receive	buffer to SC
	//memcpy(buffer,cardbuffer,cardbuflen);
	//size = cardbuflen;

#ifdef DEBUG_IFD
	int i;
	printf ("IFD: Receive: "); //I think
	for (i = 0; i < size; i++)
		printf ("%X ", buffer[i]);
	printf ("\n");
#endif

	return OK;
}	

int Cool_SetBaudrate (int mhz)
{
	typedef unsigned long u_int32;
	u_int32 clk;
	//clk = 357 * 10000;		// MHZ
	clk = mhz * 10000;	// MHZ
	if (cnxt_smc_set_clock_freq (handle, clk))
		return ERROR;
	return OK;
}
#endif
