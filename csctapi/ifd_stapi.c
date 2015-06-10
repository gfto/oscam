#include "../globals.h"

#if defined(CARDREADER_STAPI) || defined(CARDREADER_STAPI5)
#include "atr.h"
#include "../oscam-string.h"

/* These functions are implemented in liboscam_stapi.a */
extern int32_t STReader_Open(char *device, uint32_t *stsmart_handle);
extern int32_t STReader_GetStatus(uint32_t stsmart_handle, int32_t *in);
extern int32_t STReader_Reset(uint32_t stsmart_handle, ATR *atr);
extern int32_t STReader_Transmit(uint32_t stsmart_handle, unsigned char *sent, uint32_t size);
extern int32_t STReader_Receive(uint32_t stsmart_handle, unsigned char *data, uint32_t size);
extern int32_t STReader_Close(uint32_t stsmart_handle);
extern int32_t STReader_SetProtocol(uint32_t stsmart_handle, unsigned char *params, unsigned *length, uint32_t len_request);
extern int32_t STReader_SetClockrate(uint32_t stsmart_handle);

#ifdef CARDREADER_STAPI5
/* These functions are implemented in liboscam_stapi5.a */
extern char *STReader_GetRevision(void);
#endif

#define OK 0
#define ERROR 1

struct stapi_data
{
	uint32_t stapi_handle;
};

static int32_t stapi_init(struct s_reader *reader)
{
	if(!cs_malloc(&reader->crdr_data, sizeof(struct stapi_data)))
		{ return ERROR; }
	struct stapi_data *crdr_data = reader->crdr_data;
	
#ifdef CARDREADER_STAPI5	
	STReader_GetRevision();
#endif
	
	return STReader_Open(reader->device, &crdr_data->stapi_handle);
}

static int32_t stapi_getstatus(struct s_reader *reader, int32_t *in)
{
	struct stapi_data *crdr_data = reader->crdr_data;
	return STReader_GetStatus(crdr_data->stapi_handle, in);
}

static int32_t stapi_reset(struct s_reader *reader, ATR *atr)
{
	struct stapi_data *crdr_data = reader->crdr_data;
	return STReader_Reset(crdr_data->stapi_handle, atr);
}

static int32_t stapi_transmit(struct s_reader *reader, unsigned char *sent, uint32_t size, uint32_t UNUSED(expectedlen), uint32_t delay, uint32_t timeout)   // delay + timeout not in use (yet)!
{
	(void) delay; // delay not in use (yet)!
	(void) timeout; // timeout not in use (yet)!
	struct stapi_data *crdr_data = reader->crdr_data;
	return STReader_Transmit(crdr_data->stapi_handle, sent, size);
}

static int32_t stapi_receive(struct s_reader *reader, unsigned char *data, uint32_t size, uint32_t delay, uint32_t timeout)   // delay + timeout not in use (yet)!
{
	(void) delay; // delay not in use (yet)!
	(void) timeout; // timeout not in use (yet)!
	struct stapi_data *crdr_data = reader->crdr_data;
	return STReader_Receive(crdr_data->stapi_handle, data, size);
}

static int32_t stapi_close(struct s_reader *reader)
{
	struct stapi_data *crdr_data = reader->crdr_data;
	return STReader_Close(crdr_data->stapi_handle);
}

static int32_t stapi_setprotocol(struct s_reader *reader, unsigned char *params, unsigned *length, uint32_t len_request)
{
	struct stapi_data *crdr_data = reader->crdr_data;
	return STReader_SetProtocol(crdr_data->stapi_handle, params, length, len_request);
}

static int32_t stapi_writesettings(struct s_reader *reader, struct s_cardreader_settings *s)
{
	(void)s;
	struct stapi_data *crdr_data = reader->crdr_data;
	return STReader_SetClockrate(crdr_data->stapi_handle);
}

const struct s_cardreader cardreader_stapi =
{
	.desc           = "stapi",
	.typ            = R_INTERNAL,
	.reader_init    = stapi_init,
	.get_status     = stapi_getstatus,
	.activate       = stapi_reset,
	.transmit       = stapi_transmit,
	.receive        = stapi_receive,
	.close          = stapi_close,
	.set_protocol   = stapi_setprotocol,
	.write_settings = stapi_writesettings,
};

#endif
