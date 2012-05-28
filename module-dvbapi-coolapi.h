#ifndef _MODULE_COOLAPI_H_
#define _MODULE_COOLAPI_H_

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
int32_t cnxt_cbuf_open(void **handle, buffer_open_arg_t * arg, void *, void *);
int32_t cnxt_dmx_open(void **device, device_open_arg_t *arg, void *, void *);
int32_t cnxt_dmx_channel_open(void * device, void **channel, channel_open_arg_t * arg, void * callback, void *);
int32_t cnxt_dmx_set_filter(void * handle, filter_set_t * arg, void *);

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

#endif
