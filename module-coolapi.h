#ifndef _COOL_DEMUX_
#define _COOL_DEMUX_

typedef struct
{
        int  type;
        unsigned int size;
        int unknown1;
        short unknown2;
        int unknown3;
	int unknown[4];
} buffer_open_arg_t;

typedef struct
{
   int type;
   int unknown[2];
} channel_open_arg_t;

typedef struct
{
	unsigned int number;
	int unknown1;
	int unknown2;
	int unknown3;
	int unknown4;
	int unknown5;
	int unknown6;
	int unknown[6];
} device_open_arg_t;

typedef struct
{
   unsigned int length;
   unsigned char filter[12];
   unsigned char mask[12];
   int unknown[16];
} filter_set_t;

typedef struct
{
   int unk;
   int type;
   int unknown[4];
   unsigned int len;
} dmx_callback_data_t;

int cnxt_cbuf_init(void *);
int cnxt_cbuf_open(void **handle, buffer_open_arg_t * arg, void *, void *);
int cnxt_cbuf_attach(void *handle, int type, void * channel);
int cnxt_cbuf_detach(void *handle, int type, void * channel);
int cnxt_cbuf_close(void * handle);
int cnxt_cbuf_read_data(void * handle, void *buffer, unsigned int size, unsigned int * ret_size);
int cnxt_cbuf_flush(void * handle, int);

void cnxt_kal_initialize(void);
void cnxt_kal_terminate(void);
void cnxt_drv_init(void);
void cnxt_drv_term(void);

int cnxt_dmx_init(void *);
int cnxt_dmx_open(void **device, device_open_arg_t *arg, void *, void *);
int cnxt_dmx_close(void * handle);
int cnxt_dmx_channel_open(void * device, void **channel, channel_open_arg_t * arg, void * callback, void *);
int cnxt_dmx_channel_close(void * channel);
int cnxt_dmx_open_filter(void * handle, void *flt); 
int cnxt_dmx_set_filter(void * handle, filter_set_t * arg, void *);
int cnxt_dmx_close_filter(void * filter);
int cnxt_dmx_channel_attach(void * channel, int param1, int param2, void * buffer);
int cnxt_dmx_channel_detach(void * channel, int param1, int param2, void * buffer);
int cnxt_dmx_channel_attach_filter(void * channel, void * filter);
int cnxt_dmx_channel_detach_filter(void * channel, void * filter);
int cnxt_dmx_set_channel_buffer(void * channel, int param1, void * buffer);
int cnxt_dmx_set_channel_pid(void * channel, unsigned int pid);
int cnxt_dmx_get_channel_from_pid(void * device, unsigned short pid, void * channel);
int cnxt_dmx_set_channel_key(void * channel, int param1, unsigned int parity, unsigned char *cw, unsigned int len);
int cnxt_dmx_channel_ctrl(void * channel, int param1, int param2);

#endif
