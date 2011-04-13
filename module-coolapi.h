#ifndef _COOL_DEMUX_
#define _COOL_DEMUX_

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

int32_t cnxt_cbuf_init(void *);
int32_t cnxt_cbuf_open(void **handle, buffer_open_arg_t * arg, void *, void *);
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

#endif
