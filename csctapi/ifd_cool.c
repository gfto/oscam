/*
 This module provides IFD handling functions for Coolstream internal reader.
*/

#include"../globals.h"

#ifdef CARDREADER_INTERNAL_COOLAPI
#include "../extapi/coolapi.h"
#include "../oscam-string.h"
#include "../oscam-time.h"
#include "atr.h"

#define OK 0
#define ERROR 1

extern int32_t cool_kal_opened;

struct s_coolstream_reader {
	void      *handle; //device handle for coolstream
	uint8_t     cardbuffer[512];
	uint32_t	cardbuflen;
	int32_t		read_write_transmit_timeout;
};

#define specdev() \
 ((struct s_coolstream_reader *)reader->spec_dev)

static int32_t Cool_Init (struct s_reader *reader)
{
	char *device = reader->device;
	int32_t reader_nb = 0;
	// this is to stay compatible with older config.
	if(strlen(device))
		reader_nb=atoi((const char *)device);
	if(reader_nb>1) {
		// there are only 2 readers in the coolstream : 0 or 1
		rdr_log(reader, "Coolstream reader device can only be 0 or 1");
		return 0;
	}
	if (!cs_malloc(&reader->spec_dev, sizeof(struct s_coolstream_reader)))
		return 0;
	if (cnxt_smc_open (&specdev()->handle, &reader_nb, NULL, NULL))
		return 0;

	int32_t ret = cnxt_smc_enable_flow_control(specdev()->handle, 1);
	coolapi_check_error("cnxt_smc_enable_flow_control", ret);

	specdev()->cardbuflen = 0;
	if (reader->cool_timeout_init > 0) {
		rdr_debug_mask(reader, D_DEVICE, "init timeout set to cool_timeout_init = %i", reader->cool_timeout_init);
		specdev()->read_write_transmit_timeout = reader->cool_timeout_init;
	} else {
		rdr_debug_mask(reader, D_DEVICE, "No init timeout specified - using value from ATR. If you encounter any problems while card init try to use the reader parameter cool_timeout_init = 500");
		specdev()->read_write_transmit_timeout = -1;
	}
	return OK;
}

static int32_t Cool_FastReset (struct s_reader *reader)
{
	int32_t n = ATR_MAX_SIZE, ret;
	unsigned char buf[ATR_MAX_SIZE];

	//reset card
	ret = cnxt_smc_reset_card (specdev()->handle, ATR_TIMEOUT, NULL, NULL);
	coolapi_check_error("cnxt_smc_reset_card", ret);
	cs_sleepms(50);
	ret = cnxt_smc_get_atr (specdev()->handle, buf, &n);
	coolapi_check_error("cnxt_smc_get_atr", ret);

	return OK;
}

static int32_t Cool_SetClockrate (struct s_reader *reader, int32_t mhz)
{
        uint32_t clk;
        clk = mhz * 10000;
        int32_t ret = cnxt_smc_set_clock_freq (specdev()->handle, clk);
        coolapi_check_error("cnxt_smc_set_clock_freq", ret);
        call (Cool_FastReset(reader));
        rdr_debug_mask(reader, D_DEVICE, "COOL: clock succesfully set to %i", clk);
        return OK;
}

static int32_t Cool_Set_Transmit_Timeout(struct s_reader *reader, uint32_t set)
{
	//set=0 (init), set=1(after init)
	if (set) {
		if (reader->cool_timeout_after_init > 0) {
			specdev()->read_write_transmit_timeout = reader->cool_timeout_after_init;
			rdr_debug_mask(reader, D_DEVICE, "timeout set to cool_timeout_after_init = %i", reader->cool_timeout_after_init);
		} else {
			specdev()->read_write_transmit_timeout = -1;
			rdr_debug_mask(reader, D_DEVICE, "no cool_timeout_after_init value set, using value from ATR");
		}
	} else {
		if (reader->cool_timeout_init > 0) {
			specdev()->read_write_transmit_timeout = reader->cool_timeout_init;
			rdr_debug_mask(reader, D_DEVICE, "timeout set to cool_timeout_init = %i", reader->cool_timeout_after_init);
		} else {
			specdev()->read_write_transmit_timeout = -1;
			rdr_debug_mask(reader, D_DEVICE, "no cool_timeout_init value set, using value from ATR");
		}
	}
	return OK;
}

static int32_t Cool_GetStatus (struct s_reader *reader, int32_t * in)
{
	if (cool_kal_opened) {
		int32_t state;
		int32_t ret = cnxt_smc_get_state(specdev()->handle, &state);
		if (ret) {
			coolapi_check_error("cnxt_smc_get_state", ret);
			return ERROR;
		}
		//state = 0 no card, 1 = not ready, 2 = ready
		if (state)
			*in = 1; //CARD, even if not ready report card is in, or it will never get activated
		else
			*in = 0; //NOCARD
	} else {
		*in = 0;
	}
	return OK;
}

static int32_t Cool_Reset (struct s_reader *reader, ATR * atr)
{
	int32_t ret;

	if (!reader->ins7e11_fast_reset) {
		//set freq to reader->cardmhz if necessary
		uint32_t clk;

		ret = cnxt_smc_get_clock_freq (specdev()->handle, &clk);
		coolapi_check_error("cnxt_smc_get_clock_freq", ret);
		if (clk/10000 != (uint32_t)reader->cardmhz) {
			rdr_debug_mask(reader, D_DEVICE, "COOL: clock freq: %i, scheduling change to %i for card reset",
					clk, reader->cardmhz*10000);
			call (Cool_SetClockrate(reader, reader->cardmhz));
		}
	}
	else {
		rdr_debug_mask(reader, D_DEVICE, "fast reset needed, restoring transmit parameter for coolstream device %s", reader->device);
		call(Cool_Set_Transmit_Timeout(reader, 0));
		rdr_log(reader, "Doing fast reset");
	}

	//reset card
	ret = cnxt_smc_reset_card (specdev()->handle, ATR_TIMEOUT, NULL, NULL);
	coolapi_check_error("cnxt_smc_reset_card", ret);
	cs_sleepms(50);
	int32_t n = ATR_MAX_SIZE;
	unsigned char buf[ATR_MAX_SIZE];
	ret = cnxt_smc_get_atr (specdev()->handle, buf, &n);
	coolapi_check_error("cnxt_smc_get_atr", ret);

	call (!ATR_InitFromArray (atr, buf, n) != ERROR);
	{
		cs_sleepms(50);
		return OK;
	}
}

static int32_t Cool_Transmit (struct s_reader *reader, unsigned char * sent, uint32_t size, uint32_t UNUSED(delay), uint32_t timeout)
{
	int32_t ret;
	specdev()->cardbuflen = 512;//it needs to know max buffer size to respond?

	if (specdev()->read_write_transmit_timeout == -1)
		ret = cnxt_smc_read_write(specdev()->handle, 0, sent, size, specdev()->cardbuffer, &specdev()->cardbuflen, timeout, NULL);
	else
		ret = cnxt_smc_read_write(specdev()->handle, 0, sent, size, specdev()->cardbuffer, &specdev()->cardbuflen, specdev()->read_write_transmit_timeout, NULL);
	coolapi_check_error("cnxt_smc_read_write", ret);

	rdr_ddump_mask(reader, D_DEVICE, sent, size, "COOL Transmit:");
	return OK;
}

static int32_t Cool_Receive (struct s_reader *reader, unsigned char * data, uint32_t size, uint32_t UNUSED(delay), uint32_t UNUSED(timeout))
{
	if (size > specdev()->cardbuflen)
		size = specdev()->cardbuflen; //never read past end of buffer
	memcpy(data, specdev()->cardbuffer, size);
	specdev()->cardbuflen -= size;
	memmove(specdev()->cardbuffer, specdev()->cardbuffer+size, specdev()->cardbuflen);
	rdr_ddump_mask(reader, D_DEVICE, data, size, "COOL Receive:");
	return OK;
}

static int32_t Cool_WriteSettings (struct s_reader *reader, uint32_t UNUSED(BWT), uint32_t UNUSED(CWT), uint32_t UNUSED(EGT), uint32_t UNUSED(BGT))
{
	//first set freq back to reader->mhz if necessary
	uint32_t clk;
	int32_t ret = cnxt_smc_get_clock_freq (specdev()->handle, &clk);
	coolapi_check_error("cnxt_smc_get_clock_freq", ret);
	if (clk/10000 != (uint32_t)reader->mhz) {
		rdr_debug_mask(reader, D_DEVICE, "COOL: clock freq: %i, scheduling change to %i", clk, reader->mhz * 10000);
		call (Cool_SetClockrate(reader, reader->mhz));
	}

	//driver sets values in ETU automatically (except read_write_transmit_timeout)
	//... but lets see what the driver did
	uint16_t F;
	uint8_t D;
	ret = cnxt_smc_get_F_D_factors(specdev()->handle, &F, &D);
	coolapi_check_error("cnxt_smc_get_F_D_factors", ret);
	char *protocol;
	CNXT_SMC_COMM comm;
	ret = cnxt_smc_get_comm_parameters(specdev()->handle, &comm);
	coolapi_check_error("cnxt_smc_get_comm_parameters", ret);
	if (comm.protocol==0x01)
		protocol = "T0";
	else if (comm.protocol==0x02)
		protocol = "T1";
	else if (comm.protocol==0x04)
		protocol = "T14";
	else
		protocol = "unknown";

	rdr_log(reader, "Driver Settings: Convention=%s, Protocol=%s, FI=%i, F=%i, N=%i, DI=%i, D=%i, PI1=%i, PI2=%i, II=%i, TXRetries=%i, RXRetries=%i, FilterProtocolBytes=%i", comm.convention ? "Inverse" : "Direct", protocol, comm.FI, F, comm.N, comm.DI, D, comm.PI1, comm.PI2, comm.II, comm.retries.TXRetries, comm.retries.RXRetries, comm.filterprotocolbytes);

	CNXT_SMC_TIMEOUT timeout;
	ret = cnxt_smc_get_config_timeout(specdev()->handle, &timeout);
	coolapi_check_error("cnxt_smc_get_config_timeout", ret);
	rdr_log(reader, "Driver Settings: CardActTime=%i, CardDeactTime=%i, ATRSTime=%i, ATRDTime=%i, BLKTime=%i, CHTime=%i, CHGuardTime=%i, BKGuardTime=%i", timeout.CardActTime, timeout.CardDeactTime, timeout.ATRSTime, timeout.ATRDTime, timeout.BLKTime, timeout.CHTime, timeout.CHGuardTime, timeout.BKGuardTime);

	return OK;
}

static int32_t Cool_Close (struct s_reader *reader)
{
	if (cool_kal_opened) {
		int32_t ret = cnxt_smc_close (specdev()->handle);
		coolapi_check_error("cnxt_smc_close", ret);
	}
	NULLFREE(reader->spec_dev);
	return OK;
}

static int32_t cool_write_settings2(struct s_reader *reader, uint32_t EGT, uint32_t BGT)
{
	call (Cool_WriteSettings (reader, reader->BWT, reader->CWT, EGT, BGT));
	return OK;
}

static void cool_set_transmit_timeout(struct s_reader *reader)
{
	rdr_debug_mask(reader, D_DEVICE, "init done - modifying timeout for coolstream internal device %s", reader->device);
	Cool_Set_Transmit_Timeout(reader, 1);
}

void cardreader_internal_cool(struct s_cardreader *crdr)
{
	crdr->desc         = "internal";
	crdr->typ          = R_INTERNAL;
	crdr->max_clock_speed = 1;
	crdr->reader_init  = Cool_Init;
	crdr->get_status   = Cool_GetStatus;
	crdr->activate     = Cool_Reset;
	crdr->transmit     = Cool_Transmit;
	crdr->receive      = Cool_Receive;
	crdr->close        = Cool_Close;
	crdr->write_settings2 = cool_write_settings2;
	crdr->set_transmit_timeout = cool_set_transmit_timeout;
	crdr->timings_in_etu	= 1;
}

#endif
