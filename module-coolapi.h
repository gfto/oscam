#ifndef _MODULE_COOLAPI_H_
#define _MODULE_COOLAPI_H_

#include "module-dvbapi.h"

extern int32_t cool_kal_opened;

#define MAX_CA_DEVICES 4

struct cool_dmx
{
	int32_t		opened;
	int32_t		filter_attached;
	int32_t		fd;
	unsigned char   buffer[4096];
	void *		buffer1;
	void *		buffer2;
	void *	 	channel;
	void *		filter;
	unsigned char   filter16[16];
	unsigned char   mask16[16];
	void *		device;
	int32_t		pid;
	pthread_mutex_t	mutex;
	int32_t 	demux_id;
	int32_t 	demux_index;
	int32_t 	filter_num;
};
typedef struct cool_dmx dmx_t;

typedef struct
{
	int32_t  type;
	uint32_t size;
	int32_t unknown1;
	int16_t unknown2;
	int32_t unknown3;
	int32_t unknown[4];
} buffer_open_arg_t;

typedef struct
{
	int32_t type;
	int32_t unknown[2];
} channel_open_arg_t;

typedef struct
{
	uint32_t number;
	int32_t unknown1;
	int32_t unknown2;
	int32_t unknown3;
	int32_t unknown4;
	int32_t unknown5;
	int32_t unknown6;
	int32_t unknown[6];
} device_open_arg_t;

typedef struct
{
	uint32_t length;
	unsigned char filter[12];
	unsigned char mask[12];
	int32_t unknown[16];
} filter_set_t;

typedef struct
{
	int32_t unk;
	int32_t type;
	int32_t unknown[4];
	uint32_t len;
} dmx_callback_data_t;

/* These functions are implemented in libnxp */
int32_t cnxt_cbuf_init(void *);
int32_t cnxt_cbuf_open(void **handle, buffer_open_arg_t * arg, void *, void *);
int32_t cnxt_cbuf_get_used(void *buffer, uint32_t * bytes_used);
int32_t cnxt_cbuf_attach(void *handle, int32_t type, void * channel);
int32_t cnxt_cbuf_detach(void *handle, int32_t type, void * channel);
int32_t cnxt_cbuf_close(void * handle);
int32_t cnxt_cbuf_read_data(void * handle, void *buffer, uint32_t size, uint32_t * ret_size);
int32_t cnxt_cbuf_flush(void * handle, int);

void cnxt_kal_initialize(void);
void cnxt_kal_terminate(void);
void cnxt_drv_init(void);
void cnxt_drv_term(void);

int32_t cnxt_dmx_init(void *);
int32_t cnxt_dmx_open(void **device, device_open_arg_t *arg, void *, void *);
int32_t cnxt_dmx_close(void * handle);
int32_t cnxt_dmx_channel_open(void * device, void **channel, channel_open_arg_t * arg, void * callback, void *);
int32_t cnxt_dmx_channel_close(void * channel);
int32_t cnxt_dmx_open_filter(void * handle, void *flt);
int32_t cnxt_dmx_set_filter(void * handle, filter_set_t * arg, void *);
int32_t cnxt_dmx_close_filter(void * filter);
int32_t cnxt_dmx_channel_attach(void * channel, int32_t param1, int32_t param2, void * buffer);
int32_t cnxt_dmx_channel_detach(void * channel, int32_t param1, int32_t param2, void * buffer);
int32_t cnxt_dmx_channel_attach_filter(void * channel, void * filter);
int32_t cnxt_dmx_channel_detach_filter(void * channel, void * filter);
int32_t cnxt_dmx_set_channel_buffer(void * channel, int32_t param1, void * buffer);
int32_t cnxt_dmx_set_channel_pid(void * channel, uint32_t pid);
int32_t cnxt_dmx_get_channel_from_pid(void * device, uint16_t pid, void * channel);
int32_t cnxt_dmx_set_channel_key(void * channel, int32_t param1, uint32_t parity, unsigned char *cw, uint32_t len);
int32_t cnxt_dmx_channel_ctrl(void * channel, int32_t param1, int32_t param2);

int32_t cnxt_smc_init(void *);

/* Local coolapi functions */
void coolapi_open(void);
void coolapi_open_all(void);
void coolapi_close_all(void);
int32_t coolapi_set_filter (int32_t fd, int32_t num, int32_t pid, unsigned char * flt, unsigned char * mask);
int32_t coolapi_remove_filter (int32_t fd, int32_t num);
int32_t coolapi_open_device (int32_t demux_index, int32_t demux_id);
int32_t coolapi_close_device(int32_t fd);
int32_t coolapi_read(dmx_t * dmx, uint32_t len);
int32_t coolapi_write_cw(int32_t mask, uint16_t *STREAMpids, int32_t count, ca_descr_t * ca_descr);
int32_t coolapi_set_pid (int32_t demux_id, int32_t num, int32_t index, int32_t pid);

/* Error checking */
static const char* const cnxt_status[] = {
			"CNXT_STATUS_OK",
			"CNXT_STATUS_ALREADY_INIT",
			"CNXT_STATUS_NOT_INIT",
			"CNXT_STATUS_INTERNAL_ERROR",
			"CNXT_STATUS_BAD_HANDLE",
			"CNXT_STATUS_BAD_PARAMETER",
			"CNXT_STATUS_BAD_LENGTH",
			"CNXT_STATUS_BAD_UNIT",
			"CNXT_STATUS_RESOURCE_ERROR",
			"CNXT_STATUS_CLOSED_HANDLE",
			"CNXT_STATUS_TIMEOUT",
			"CNXT_STATUS_NOT_ATTACHED",
			"CNXT_STATUS_NOT_SUPPORTED",
			"CNXT_STATUS_REOPENED_HANDLE",
			"CNXT_STATUS_INVALID",
			"CNXT_STATUS_DESTROYED",
			"CNXT_STATUS_DISCONNECTED",
			"CNXT_STATUS_BUSY",
			"CNXT_STATUS_IN_USE",
			"CNXT_STATUS_CANCELLED",
			"CNXT_STATUS_UNDEFINED",
			"CNXT_STATUS_UNKNOWN",
			"CNXT_STATUS_NOT_FOUND",
			"CNXT_STATUS_NOT_AVAILABLE",
			"CNXT_STATUS_NOT_COMPATIBLE",
			"CNXT_STATUS_NOT_IMPLEMENTED",
			"CNXT_STATUS_EMPTY",
			"CNXT_STATUS_FULL",
			"CNXT_STATUS_FAILURE",
			"CNXT_STATUS_ALREADY_ATTACHED",
			"CNXT_STATUS_ALREADY_DONE",
			"CNXT_STATUS_ASLEEP",
			"CNXT_STATUS_BAD_ATTACHMENT",
			"CNXT_STATUS_BAD_COMMAND",
			"CNXT_STATUS_BAD_GPIO",
			"CNXT_STATUS_BAD_INDEX",
			"CNXT_STATUS_BAD_MODE",
			"CNXT_STATUS_BAD_PID",
			"CNXT_STATUS_BAD_PLANE",
			"CNXT_STATUS_BAD_PTR",
			"CNXT_STATUS_BAD_RECT",
			"CNXT_STATUS_BAD_RGN_HANDLE",
			"CNXT_STATUS_BAD_SIZE",
			"CNXT_STATUS_INT_HANDLED",
			"CNXT_STATUS_INT_NOT_HANDLED",
			"CNXT_STATUS_NOT_SET",
			"CNXT_STATUS_NOT_HOOKED",
			"CNXT_STATUS_CC_NOT_ENABLED",
			"CNXT_STATUS_CLOSED_RGN",
			"CNXT_STATUS_COMPLETE",
			"CNXT_STATUS_DEMOD_ERROR",
			"CNXT_STATUS_INVALID_NODE",
			"CNXT_STATUS_DUPLICATE_NODE",
			"CNXT_STATUS_HARDWARE_NOT_FOUND",
			"CNXT_STATUS_HDCP_AUTH_FAILED",
			"CNXT_STATUS_HDCP_BAD_BKSV",
			"CNXT_STATUS_ILLEGAL_OPERATION",
			"CNXT_STATUS_INCOMPATIBLE_FORMATS",
			"CNXT_STATUS_INVALID_DEVICE",
			"CNXT_STATUS_INVALID_EDGE",
			"CNXT_STATUS_INVALID_NUMBER",
			"CNXT_STATUS_INVALID_STATE",
			"CNXT_STATUS_INVALID_TYPE",
			"CNXT_STATUS_NO_BUFFER",
			"CNXT_STATUS_NO_DESTINATION_BUF",
			"CNXT_STATUS_NO_OSD",
			"CNXT_STATUS_NO_PALETTE",
			"CNXT_STATUS_NO_ACK",
			"CNXT_STATUS_RECEIVER_HDMI_INCAPABLE",
			"CNXT_STATUS_RECEIVER_NOT_ATTACHED",
			"CNXT_STATUS_ADJUSTED",
			"CNXT_STATUS_CLIPPED",
			"CNXT_STATUS_CLIPRECT_ADJUSTED",
			"CNXT_STATUS_NOT_ALIGNED",
			"CNXT_STATUS_FIXUP_OK",
			"CNXT_STATUS_FIXUP_OPTION_ERROR",
			"CNXT_STATUS_FIXUP_ZERO_RECT",
			"CNXT_STATUS_UNABLE_TO_FIXUP_AND_PRESERVE",
			"CNXT_STATUS_UNABLE_TO_FIXUP_X",
			"CNXT_STATUS_UNABLE_TO_FIXUP_Y",
			"CNXT_STATUS_OUT_OF_BOUNDS",
			"CNXT_STATUS_OUTSIDE_CLIP_RECT",
			"CNXT_STATUS_RECT_CLIPPED",
			"CNXT_STATUS_RECT_ENCLOSED",
			"CNXT_STATUS_RECT_FIXED_UP",
			"CNXT_STATUS_RECT_INCLUDES",
			"CNXT_STATUS_RECT_NO_OVERLAP",
			"CNXT_STATUS_RECT_OVERLAP",
			"CNXT_STATUS_RECT_ZERO_AREA",
			"CNXT_STATUS_SERVICE_LIST_NOT_READY",
			"CNXT_STATUS_SERVICE_LIST_READY",
			"CNXT_STATUS_STOPPED",
			"CNXT_STATUS_SUSPENDED",
			"CNXT_STATUS_TERMINATED",
			"CNXT_STATUS_TOO_MUCH_DATA",
			"CNXT_STATUS_WIPE_NONE",
			"CNXT_STATUS_NOT_STOPPED",
			"CNXT_STATUS_INT_NOT_COMPLETE",
			"CNXT_STATUS_NOT_ALLOWED",
			"CNXT_STATUS_DUPLICATE_PID",
			"CNXT_STATUS_MAX_FILTERS_ATTACHED",
			"CNXT_STATUS_HW_NOT_READY",
			"CNXT_STATUS_OUTPUT_BUF_FULL",
			"CNXT_STATUS_REJECTED",
			"CNXT_STATUS_INVALID_PID",
			"CNXT_STATUS_EOF",
			"CNXT_STATUS_BOF",
			"CNXT_STATUS_MISSING_DATA"
};

#define check_error(label, ret) 					\
{ 									\
        if(ret != 0) { 							\
		if (ret > 107) { 					\
		        cs_log("[%s:%d] %s: API ERROR %d (UNKNOWN)",	\
			__FUNCTION__, __LINE__ ,			\
			label, ret);					\
		} else {						\
		        cs_log("[%s:%d] %s: API ERROR %d (%s)",		\
			__FUNCTION__, __LINE__ ,			\
			label, ret, cnxt_status[ret]);			\
		}							\
	}								\
}

#endif
