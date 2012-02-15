#include"../globals.h"
#ifdef WITH_CARDREADER
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
#include"icc_async.h"

#define READ_WRITE_TRANSMIT_TIMEOUT				50

struct s_coolstream_reader {
	void      *handle; //device handle for coolstream
	char      cardbuffer[256];
	int32_t		cardbuflen;
	int32_t		read_write_transmit_timeout;
};

#define specdev() \
 ((struct s_coolstream_reader *)reader->spec_dev)

int32_t Cool_Init (struct s_reader *reader)
{
	char *device = reader->device;
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
	reader->spec_dev=malloc(sizeof(struct s_coolstream_reader));
	if (cnxt_smc_open (&specdev()->handle, &reader_nb, NULL, NULL))
		return FALSE;

	call(cnxt_smc_enable_flow_control(specdev()->handle));
	specdev()->cardbuflen = 0;
	if (reader->cool_timeout_init > 0) {
		cs_debug_mask(D_DEVICE,"%s init timeout set to cool_timeout_init = %i", reader->label, reader->cool_timeout_init);
		specdev()->read_write_transmit_timeout = reader->cool_timeout_init;
	} else {
		cs_debug_mask(D_DEVICE,"No init timeout for reader %s specified - using default init timeout (%i). If you encounter any problems while card init try to use the reader parameter cool_timeout_init = 500", reader->label, READ_WRITE_TRANSMIT_TIMEOUT);
		specdev()->read_write_transmit_timeout = READ_WRITE_TRANSMIT_TIMEOUT;
	}
	return OK;
}


int32_t Cool_GetStatus (struct s_reader *reader, int32_t * in)
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

int32_t Cool_Reset (struct s_reader *reader, ATR * atr)
{
	//set freq to reader->cardmhz if necessary
	uint32_t clk;
	call (cnxt_smc_get_clock_freq (specdev()->handle, &clk));
	if (clk/10000 != reader->cardmhz) {
		cs_debug_mask(D_DEVICE,"COOL: %s clock freq: %i, scheduling change to %i for card reset", reader->label, clk, reader->cardmhz*10000);
		call (Cool_SetClockrate(reader, reader->cardmhz));
	} 

	//reset card
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

int32_t Cool_Transmit (struct s_reader *reader, BYTE * sent, uint32_t size)
{ 
	specdev()->cardbuflen = 256;//it needs to know max buffer size to respond?

	call (cnxt_smc_read_write(specdev()->handle, FALSE, sent, size, specdev()->cardbuffer, &specdev()->cardbuflen, specdev()->read_write_transmit_timeout, 0));
	//call (cnxt_smc_read_write(specdev()->handle, FALSE, sent, size, specdev()->cardbuffer, &specdev()->cardbuflen, read_timeout, 0));

	cs_ddump_mask(D_DEVICE, sent, size, "COOL IO: Transmit: ");	
	return OK;
}

int32_t Cool_Set_Transmit_Timeout(struct s_reader *reader, uint32_t set)
{ 
	//set=0 (init), set=1(after init)
	if (set == 1) {
		if (reader->cool_timeout_after_init > 0) {
			specdev()->read_write_transmit_timeout = reader->cool_timeout_after_init;
			cs_debug_mask(D_DEVICE,"%s timeout set to cool_timeout_after_init = %i", reader->label, reader->cool_timeout_after_init);
		} else {
			if (reader->read_timeout > 50) {
				cs_log("ATTENTION: The calculated timeout after init value (%i) is greater than 50 which probably leads to a slow card response. We are going to use the reader parameter cool_timeout_after_init = 50.", reader->read_timeout);
				cs_log("If you encounter any problems try a higher value. If you have no problems try a value below to get a faster card response.");
				specdev()->read_write_transmit_timeout = 50;
			} else {
				cs_debug_mask(D_DEVICE,"no timeout for reader %s specified - using calculated timeout after init (%i)", reader->label, reader->read_timeout);
				specdev()->read_write_transmit_timeout = reader->read_timeout;
			}
		}
	} else {
		if (reader->cool_timeout_init > 0) {
			specdev()->read_write_transmit_timeout = reader->cool_timeout_init;
		} else {
			specdev()->read_write_transmit_timeout = READ_WRITE_TRANSMIT_TIMEOUT;
		}
	}
	return OK;
}

int32_t Cool_Receive (struct s_reader *reader, BYTE * data, uint32_t size)
{ 
	if (size > specdev()->cardbuflen)
		size = specdev()->cardbuflen; //never read past end of buffer
	memcpy(data, specdev()->cardbuffer, size);
	specdev()->cardbuflen -= size;
	memmove(specdev()->cardbuffer, specdev()->cardbuffer+size, specdev()->cardbuflen);
	cs_ddump_mask(D_DEVICE, data, size, "COOL IO: Receive: ");
	return OK;
}	

int32_t Cool_SetClockrate (struct s_reader *reader, int32_t mhz)
{
	uint32_t clk;
	clk = mhz * 10000;
	call (cnxt_smc_set_clock_freq (specdev()->handle, clk));
	call (Cool_FastReset(reader));
	cs_debug_mask(D_DEVICE, "COOL: %s clock succesfully set to %i",reader->label, clk);
	return OK;
}

int32_t Cool_WriteSettings (struct s_reader *reader, uint32_t BWT, uint32_t CWT, uint32_t EGT, uint32_t BGT)
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

	//set freq back to reader->mhz if necessary
	uint32_t clk;
	call (cnxt_smc_get_clock_freq (specdev()->handle, &clk));
	if (clk/10000 != reader->mhz) {
		cs_debug_mask(D_DEVICE,"COOL: %s clock freq: %i, scheduling change to %i", reader->label, clk, reader->mhz*10000);
		call (Cool_SetClockrate(reader, reader->mhz));
	} 

	return OK;
}

int32_t Cool_FastReset (struct s_reader *reader)
{
	int32_t n = 40;
	unsigned char buf[40];

	//reset card
	call (cnxt_smc_reset_card (specdev()->handle, ATR_TIMEOUT, NULL, NULL));
	cs_sleepms(50);
	call (cnxt_smc_get_atr (specdev()->handle, buf, &n));

    return 0;
}

int32_t Cool_FastReset_With_ATR (struct s_reader *reader, ATR * atr)
{
	int32_t n = 40;
	unsigned char buf[40];

	//reset card
	call (cnxt_smc_reset_card (specdev()->handle, ATR_TIMEOUT, NULL, NULL));
	cs_sleepms(50);
	call (cnxt_smc_get_atr (specdev()->handle, buf, &n));

	call (!ATR_InitFromArray (atr, buf, n) == ATR_OK);
	{
		cs_sleepms(50);
		return OK;
	}
}

int32_t Cool_Close (struct s_reader *reader)
{
	call(cnxt_smc_close (specdev()->handle));
	NULLFREE(reader->spec_dev);
	call(cnxt_kal_terminate()); //should call this only once in a thread
	cnxt_drv_term();
	return OK;
}

#endif
#endif

