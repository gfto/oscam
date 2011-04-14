#ifdef COOL
/*
		ifd_cool.c
		This module provides IFD handling functions for Coolstream internal reader.
*/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include"ifd_cool.h"
#include"../globals.h"
#include"icc_async.h"

struct s_coolstream_reader {
	void      *handle; //device handle for coolstream
	char      cardbuffer[256];
	int32_t		cardbuflen;
};

#define specdev() \
 ((struct s_coolstream_reader *)cur_client()->reader->spec_dev)

int32_t Cool_Init (char *device)
{
	cnxt_smc_init (NULL); //not sure whether this should be in coolapi_open_all
	int32_t reader_nb = 0;
	// this is to stay compatible with older config.
	if(strlen(device))
		reader_nb=atoi((const char *)device);
	if(reader_nb>1) {
		// there are only 2 readers in the coolstream : 0 or 1
		cs_log("Coolstream reader device can only be 0 or 1");
		return FALSE;
	}
	cur_client()->reader->spec_dev=malloc(sizeof(struct s_coolstream_reader));
	if (cnxt_smc_open (&specdev()->handle, &reader_nb))
		return FALSE;
	specdev()->cardbuflen = 0;
	return OK;
}


int32_t Cool_GetStatus (int32_t * in)
{
	int32_t state;
	int32_t ret = cnxt_smc_get_state(specdev()->handle, &state);
	if (ret) {
		cs_log("COOLSTREAM return code = %i", ret);
		return ERROR;
	}
	//state = 0 no card, 1 = not ready, 2 = ready
	if (state)
		*in = 1; //CARD, even if not ready report card is in, or it will never get activated
	else
		*in = 0; //NOCARD
	return OK;
}

int32_t Cool_Reset (ATR * atr)
{
	call (Cool_SetClockrate(357));

	//reset card
	int32_t timeout = 5000; // Timout in ms?
	call (cnxt_smc_reset_card (specdev()->handle, ATR_TIMEOUT, NULL, NULL));
	cs_sleepms(50);
	int32_t n = 40;
	unsigned char buf[40];
	call (cnxt_smc_get_atr (specdev()->handle, buf, &n));
		
	call (!ATR_InitFromArray (atr, buf, n) == ATR_OK);
	{
		cs_sleepms(50);
		return OK;
	}
}

int32_t Cool_Transmit (BYTE * sent, uint32_t size)
{ 
	specdev()->cardbuflen = 256;//it needs to know max buffer size to respond?
	call (cnxt_smc_read_write(specdev()->handle, FALSE, sent, size, specdev()->cardbuffer, &specdev()->cardbuflen, 50, 0));
	//call (cnxt_smc_read_write(specdev()->handle, FALSE, sent, size, specdev()->cardbuffer, &specdev()->cardbuflen, read_timeout, 0));
	cs_ddump_mask(D_DEVICE, sent, size, "COOL IO: Transmit: ");
	return OK;
}

int32_t Cool_Receive (BYTE * data, uint32_t size)
{ 
	if (size > specdev()->cardbuflen)
		size = specdev()->cardbuflen; //never read past end of buffer
	memcpy(data, specdev()->cardbuffer, size);
	specdev()->cardbuflen -= size;
	memmove(specdev()->cardbuffer, specdev()->cardbuffer+size, specdev()->cardbuflen);
	cs_ddump_mask(D_DEVICE, data, size, "COOL IO: Receive: ");
	return OK;
}	

int32_t Cool_SetClockrate (int32_t mhz)
{
	uint32_t clk;
	clk = mhz * 10000;
	call (cnxt_smc_set_clock_freq (specdev()->handle, clk));
	cs_debug_mask(D_DEVICE, "COOL: Clock succesfully set to %i0 kHz", mhz);
	return OK;
}

int32_t Cool_WriteSettings (uint32_t BWT, uint32_t CWT, uint32_t EGT, uint32_t BGT)
{
	//this code worked with old cnxt_lnx.ko, but prevented nagra cards from working with new cnxt_lnx.ko
/*	struct
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
	call (cnxt_smc_set_config_timeout(specdev()->handle, params));
	cs_debug_mask(D_DEVICE, "COOL WriteSettings OK");*/ 
	return OK;
}

int32_t Cool_FastReset ()
{
	int32_t n = 40;
	unsigned char buf[40];

	//reset card
	call (cnxt_smc_reset_card (specdev()->handle, ATR_TIMEOUT, NULL, NULL));
	cs_sleepms(50);
	call (cnxt_smc_get_atr (specdev()->handle, buf, &n));

    return 0;
}

int32_t Cool_Close (void)
{
	call(cnxt_smc_close (specdev()->handle));
	NULLFREE(cur_client()->reader->spec_dev);
	call(cnxt_kal_terminate()); //should call this only once in a thread
	cnxt_drv_term();
	return OK;
}

#endif
