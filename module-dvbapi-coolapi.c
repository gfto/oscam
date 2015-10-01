/* Reversed from libcoolstream.so, this comes without any warranty */

#define MODULE_LOG_PREFIX "dvbcool"

#include "globals.h"

#if defined(HAVE_DVBAPI) && (defined(WITH_SU980) || defined(WITH_COOLAPI2) || defined(WITH_COOLAPI))
#include "extapi/coolapi.h"

#include "module-dvbapi.h"
#include "module-dvbapi-coolapi.h"
#include "oscam-string.h" 


#define MAX_COOL_DMX 4

//kronos-Plattform (Coolsterem ZEE²)
//#define MAX_COOL_DMX 3


#define DMX_MAX_FILTERS_PER_CHAN 16
#define DMX_MAX_CHANNELS_PER_DMX 192
//#define MAX_COOL_DMX_FILTERS 128
 
struct s_cool_chanhandle;

typedef struct s_cool_filter
{
	int32_t     fd;
	struct s_cool_chanhandle *chanhandle;
	void       *filter;
	int32_t     filter_num;
	uchar       filter16[16];
	uchar       mask16[16];
} S_COOL_FILTER;

typedef struct s_cool_chanhandle
{
	int32_t     pid;
	void       *buffer1; // filter Cbuf 1
	void       *buffer2; // filter Cbuf 2
	void       *channel;
 	int32_t     demux_index;
	struct s_cool_dmxhandle *dmx_handle;
	uint32_t    allocated_filters;
} S_COOL_CHANHANDLE;

typedef struct s_cool_dmxhandle
{
	void       *handle;
	uint32_t    allocated_channels;
} S_COOL_DMXHANDLE;

struct cool_dmx
{
	int32_t     pid;
	int32_t     opened;
	int32_t     fd;
	pthread_mutex_t mutex;
	int32_t     filter_num;
	int32_t     demux_id;
	int32_t     type;
};
typedef struct cool_dmx dmx_t;

typedef struct
{
	int32_t  type;
	uint32_t size;
#ifdef HAVE_COOLAPI2
	uint32_t  ptsbufsize;
#endif
	int32_t unknown1;
	int16_t unknown2;
	int32_t hwm;
	int32_t lwm;
	int32_t unknown5;
	int32_t unknown6;
	int32_t poolid;
#ifdef HAVE_COOLAPI2
	uint32_t unit;
#endif
} buffer_open_arg_t;

typedef struct
{
	int32_t type;
	int32_t unknown[2];
} channel_open_arg_t;

// Nevis : 13
// Apollo: 13
typedef struct
{
	uint32_t number;
	int32_t unknown1; // channel source
	int32_t unknown2; // mcard cap
	int32_t unknown3; // descrambler type
	int32_t unknown4; // support legacy NDS
	int32_t unknown5;
	int32_t unknown6;
	int32_t unknown[6];
} device_open_arg_t;

typedef struct
{
	uint32_t    length;
	uint8_t     filter[18]; //strange: initialization with max 18 possible but length limited to 12
	uint8_t     mask[18];
	uint8_t     nmask[18];
	int8_t      fvernum;
	int8_t      crcchange;
	int8_t      keeprbytes;
	int32_t     mode;
} filter_set_t;


typedef enum
{
	CONTINUOUS_ACQUIRE   = 0,
	ONE_SHOT_ACQUIRE,
	TOGGLE_ACQUIRE
} DATA_ACQUIRE_MODE;

typedef enum
{
	DATA_ACQUIRED = 1,
	CHANNEL_TIMEOUT,
	CRC_ERROR,
	BUF_OVERFLOW,
	PES_ERROR,
	COPY_DONE,
	CHANNEL_INFO
} DATA_ACQUIRE_STATUS;

typedef struct
{
	uint32_t PTSLow;
	uint32_t PTSHi;
} DMX_PTS;

typedef struct
{
	void                *channel;
	DATA_ACQUIRE_STATUS  type;
	//
	DMX_PTS              ptssnapshot;
	void                 *buf;
	uint32_t             start;
	//
	DATA_ACQUIRE_MODE    mode;
	uint32_t             len;
	uint16_t             num;
	void                *filters[DMX_MAX_FILTERS_PER_CHAN];
	void                *tags[DMX_MAX_FILTERS_PER_CHAN];
} dmx_callback_data_t;

/* These functions are implemented in libnxp */
extern int32_t cnxt_cbuf_open(void **handle, buffer_open_arg_t *arg, void *, void *);
extern int32_t cnxt_dmx_open(void **device, device_open_arg_t *arg, void *, void *);
extern int32_t cnxt_dmx_channel_open(void *device, void **channel, channel_open_arg_t *arg, void *callback, void *);
extern int32_t cnxt_dmx_set_filter(void *handle, filter_set_t *arg, void *);
extern int32_t cnxt_dmx_channel_suspend(void *handle, int32_t enable);

/* Local coolapi functions */
static int32_t coolapi_read(dmx_t *dmx, dmx_callback_data_t *dataa, uchar *buffer);

static int8_t dmx_opened;
int32_t  cool_kal_opened = 0;

static S_COOL_DMXHANDLE dmx_handles[MAX_COOL_DMX];
static dmx_t cdemuxes[MAX_COOL_DMX][MAX_FILTER];
static pthread_mutex_t demux_lock = PTHREAD_MUTEX_INITIALIZER;
extern void *dvbapi_client;

static LLIST   *ll_cool_filter     = NULL;
static LLIST   *ll_cool_chanhandle = NULL;

#define COOLDEMUX_FD(device, num) (('O' << 24) | ('S' << 16) | (device << 8) | num)
#define COOLDEMUX_DMX_DEV(fd) (((fd) >> 8) & 0xFF)
#define COOLDEMUX_FLT_IDX(fd) (((fd) >> 0) & 0xFF)
#define COOLDEMUX_IS_VALID_FD(fd) ((((fd) & 0xFF000000) == ('O' << 24)) && \
				   (((fd) & 0x00FF0000) == ('S' << 16)))

#define COOLDEMUX_DATA_RECEIVED		1
#define COOLDEMUX_CHANNEL_TIMEOUT	2
#define COOLDEMUX_CRC_ERROR		3
#define COOLDEMUX_BUFF_OVERFLOW		4

static dmx_t *find_demux(int32_t fd, int32_t dmx_dev_num)
{
	if(dmx_dev_num < 0 || dmx_dev_num >= MAX_COOL_DMX)
	{
		cs_log("Invalid demux %d", dmx_dev_num);
		return NULL;
	}

	dmx_t *dmx;
	int32_t i;

	if(fd == 0) // DEMUX FILTER ALLOCATE
	{
		for(i = 0; i < MAX_FILTER; i++)
		{
			dmx = &cdemuxes[dmx_dev_num][i];
			if(!dmx->opened)
			{
				dmx->fd = COOLDEMUX_FD(dmx_dev_num, i);
				cs_log_dbg(D_DVBAPI, "opening new fd: %08x", dmx->fd);
				return dmx;
			}
		}
		cs_log_dbg(D_DVBAPI, "ERROR: no free demux found");
		return NULL;
	}

	if (!COOLDEMUX_IS_VALID_FD(fd))
	{
		cs_log_dbg(D_DVBAPI, "ERROR: invalid FD");
		return NULL;
	}

	dmx_dev_num = COOLDEMUX_DMX_DEV(fd);
	for(i = 0; i < MAX_FILTER; i++)
	{
		dmx = &cdemuxes[dmx_dev_num][i];
		if(dmx->fd == fd)
		{
			return dmx;
		}
	}

	cs_log_dbg(D_DVBAPI, "ERROR: CANT FIND Demux %08x", fd);

	return NULL;
}

int32_t coolapi_get_filter_num(int32_t fd)
{
	if (!COOLDEMUX_IS_VALID_FD(fd))
	{
		cs_log_dbg(D_DVBAPI, "ERROR: invalid FD");
		return -1;
	}

	return cdemuxes[COOLDEMUX_DMX_DEV(fd)][COOLDEMUX_FLT_IDX(fd)].filter_num;
}

static S_COOL_CHANHANDLE *find_chanhandle(int32_t demux_index, int32_t pid)
{
	// Find matching channel, if it exists.
	if(ll_count(ll_cool_chanhandle) > 0)
	{
		LL_ITER itr = ll_iter_create(ll_cool_chanhandle);
		S_COOL_CHANHANDLE *handle_item;

		while((handle_item = ll_iter_next(&itr)))
		{
			if(handle_item->demux_index == demux_index && handle_item->pid == pid)
			{
				return handle_item;
			}
		}
	}

	return NULL;
}

static int32_t remove_chanhandle(S_COOL_CHANHANDLE *handle)
{
	// Find matching channel, if it exists.
	if(ll_count(ll_cool_chanhandle) > 0)
	{
		LL_ITER itr = ll_iter_create(ll_cool_chanhandle);
		S_COOL_CHANHANDLE *handle_item;

		while((handle_item = ll_iter_next(&itr)))
		{
			if(handle_item == handle)
			{
				ll_iter_remove_data(&itr);
				return 0;
			}
		}
	}

	return -1;
}

static S_COOL_FILTER  *find_filter_by_chanhandle(S_COOL_CHANHANDLE *chanhandle, int32_t filter_num)
{
	// Find matching channel, if it exists.
	if(ll_count(ll_cool_filter) > 0)
	{
		LL_ITER itr = ll_iter_create(ll_cool_filter);
		S_COOL_FILTER *filter_item;

		while((filter_item = ll_iter_next(&itr)))
		{
			if(filter_item->chanhandle == chanhandle && filter_item->filter_num == filter_num)
			{
				return filter_item;
			}
		}
	}

	return NULL;
}

static S_COOL_FILTER  *find_filter_by_channel(void *channel, int32_t filter_num)
{
	// Find matching channel, if it exists.
	if(ll_count(ll_cool_filter) > 0)
	{
		LL_ITER itr = ll_iter_create(ll_cool_filter);
		S_COOL_FILTER *filter_item;

		while((filter_item = ll_iter_next(&itr)))
		{
			if(filter_item->chanhandle &&
			    filter_item->chanhandle->channel == channel &&
			    filter_item->filter_num == filter_num)
			{
				return filter_item;
			}
		}
	}

	return NULL;
}

static int32_t remove_filter(S_COOL_FILTER *filter_handle)
{
	if(ll_count(ll_cool_filter) > 0)
	{
		LL_ITER itr = ll_iter_create(ll_cool_filter);
		S_COOL_FILTER *filter_item;

		while((filter_item = ll_iter_next(&itr)))
		{
			if(filter_item == filter_handle)
			{
				ll_iter_remove_data(&itr);
				return 0;
			}
		}
	}

	return -1;
}

static void coolapi_read_data(dmx_t *dmx, dmx_callback_data_t *data)
{
	if(!dmx)
	{
		cs_log_dbg(D_DVBAPI, "handle is NULL!");
		return;
	}

	int32_t ret;
	uchar buffer[4096];

	SAFE_SETSPECIFIC(getclient, dvbapi_client);
	SAFE_MUTEX_LOCK(&dmx->mutex);
	memset(buffer, 0, sizeof(buffer));
	ret = coolapi_read(dmx, data, buffer);
	SAFE_MUTEX_UNLOCK(&dmx->mutex);
	
	if(ret > -1) {
		uint16_t filters = data->num;
		uint16_t flt;

		for (flt = 0; flt < filters; flt++) {
			uint32_t n = (uint32_t)data->tags[flt];
			S_COOL_FILTER *filter = find_filter_by_channel(data->channel, n);

			if (!filter || data->filters[flt] != filter->filter)
			{
				cs_log_dbg(D_DVBAPI, "filter not found in notification!!!!");
				continue;
			}

			dvbapi_process_input(dmx->demux_id, n, buffer, data->len);
		}
	}
}

static void dmx_callback(void *channel, dmx_t *dmx, int32_t type, dmx_callback_data_t *data)
{
	if(!dmx)
	{
		cs_log_dbg(D_DVBAPI, "wrong dmx pointer !!!");
		return;
	}

	if(data == NULL)
		return;

	if (channel != data->channel)
		return;

	switch(type)
	{
#ifdef WITH_COOLAPI2
	case 0x11:
#else
	case 0x0E:
#endif
		if(data->type == COOLDEMUX_DATA_RECEIVED && data->len > 0) {
			coolapi_read_data(dmx, data);
		} else if(data->type == COOLDEMUX_CRC_ERROR && data->len > 0) {
			cs_log_dbg(D_DVBAPI, "CRC error !!!");
			cnxt_cbuf_removed_data(data->buf, data->len);
		} else if(data->type == COOLDEMUX_BUFF_OVERFLOW) {
			cs_log_dbg(D_DVBAPI, "OVERFLOW !!!");
		} else {
			cs_log_dbg(D_DVBAPI, "unknown callback data %d len %d", data->type, data->len);
		}
		break;
	default:
		break;
	}
}

int32_t coolapi_set_filter(int32_t fd, int32_t num, int32_t pid, uchar *flt, uchar *mask, int32_t type)
{
	dmx_t *dmx = find_demux(fd, 0);
	if(!dmx)
	{
		cs_log_dbg(D_DVBAPI, "dmx is NULL!");
		return -1;
	}

	int32_t result, channel_found;
	SAFE_MUTEX_LOCK(&dmx->mutex);

	// Find matching channel, if it exists.
	S_COOL_CHANHANDLE *handle_item = find_chanhandle(COOLDEMUX_DMX_DEV(fd), pid);
	if(!handle_item)
	{
		// No channel was found, allocate one
		buffer_open_arg_t bufarg;
		int32_t uBufferSize = 8192 + 64;
		/* Mark that we did not find any open channel on this PID */
		channel_found = 0;

		if(!cs_malloc(&handle_item, sizeof(S_COOL_CHANHANDLE)))
		{
			return -1;
		}

		memset(&bufarg, 0, sizeof(bufarg));

#ifdef HAVE_COOLAPI2
		bufarg.poolid = 5
#endif
		bufarg.type = 3;
		bufarg.size = uBufferSize;
		bufarg.hwm = (uBufferSize * 7) / 8;

		result = cnxt_cbuf_open(&handle_item->buffer1, &bufarg, NULL, NULL);
		coolapi_check_error("cnxt_cbuf_open", result);
		bufarg.type = 0;

#ifdef HAVE_COOLAPI2
		bufarg.poolid = 0
#endif
		result = cnxt_cbuf_open(&handle_item->buffer2, &bufarg, NULL, NULL);
		coolapi_check_error("cnxt_cbuf_open", result);

		channel_open_arg_t chanarg;
		memset(&chanarg, 0, sizeof(channel_open_arg_t));
		
		chanarg.type = 4;
		result = cnxt_dmx_channel_open(dmx_handles[COOLDEMUX_DMX_DEV(fd)].handle, &handle_item->channel, &chanarg, dmx_callback, dmx);
		coolapi_check_error("cnxt_dmx_channel_open", result);

		result = cnxt_dmx_set_channel_buffer(handle_item->channel, 0, handle_item->buffer1);
		coolapi_check_error("cnxt_dmx_set_channel_buffer", result);

		result = cnxt_dmx_channel_attach(handle_item->channel, 0xB, 0, handle_item->buffer2);
		coolapi_check_error("cnxt_dmx_channel_attach", result);

		result = cnxt_cbuf_attach(handle_item->buffer2, 2, handle_item->channel);
		coolapi_check_error("cnxt_cbuf_attach", result);

		result = cnxt_dmx_set_channel_pid(handle_item->channel, pid);
		coolapi_check_error("cnxt_dmx_set_channel_pid", result);

		result = cnxt_cbuf_flush(handle_item->buffer1, 0);
		coolapi_check_error("cnxt_cbuf_flush", result);
		result = cnxt_cbuf_flush(handle_item->buffer2, 0);
		coolapi_check_error("cnxt_cbuf_flush", result);

		handle_item->pid            = pid;
		handle_item->dmx_handle     = &dmx_handles[COOLDEMUX_DMX_DEV(fd)];
		dmx_handles[COOLDEMUX_DMX_DEV(fd)].allocated_channels++;
		ll_append(ll_cool_chanhandle, handle_item);

		cs_log_dbg(D_DVBAPI, "opened new channel %x", (int32_t) handle_item->channel);;
	}
	else
	{
		channel_found = 1;
	}

	cs_log_dbg(D_DVBAPI, "setting new filter fd=%08x demux=%d channel=%x num=%d pid=%04x flt=%x mask=%x", fd, COOLDEMUX_DMX_DEV(fd), (int32_t) handle_item->channel, num, pid, flt[0], mask[0]);
	void *filter_handle = NULL;
	filter_set_t filterset;
	int32_t has_filter = 0;

	S_COOL_FILTER *filter_item = find_filter_by_chanhandle(handle_item, num);
	if (filter_item && type == dmx->type && pid == dmx->pid &&
	    (memcmp(flt, filter_item->filter16, 16) || memcmp(mask, filter_item->mask16, 16)))
	{
		cs_log_dbg(D_DVBAPI, "setting new filter fd=%08x demux=%d channel=%x num=%d pid=%04x flt=%x mask=%x, filter exists.. modifying", fd, COOLDEMUX_DMX_DEV(fd), (int32_t) handle_item->channel, num, pid, flt[0], mask[0]);
		filter_handle = filter_item->filter;

		has_filter = 1;

		memcpy(filter_item->filter16, flt, 16);
		memcpy(filter_item->mask16, mask, 16);
	}
	else
	{
		dmx->pid = pid;
		dmx->type = type;
		dmx->filter_num = num;
		result = cnxt_dmx_open_filter(dmx_handles[COOLDEMUX_DMX_DEV(fd)].handle, &filter_handle);
		coolapi_check_error("cnxt_dmx_open_filter", result);

		if(!cs_malloc(&filter_item, sizeof(S_COOL_FILTER)))
		{
			SAFE_MUTEX_UNLOCK(&dmx->mutex);
			return -1;
		}

		// fill filter item
		filter_item->fd = fd;
		filter_item->filter = filter_handle;
		filter_item->filter_num = num;
		filter_item->chanhandle = handle_item;
		memcpy(filter_item->filter16, flt, 16);
		memcpy(filter_item->mask16, mask, 16);

		//add filter item
		ll_append(ll_cool_filter, filter_item);
		// increase allocated filters
		handle_item->allocated_filters++;
	}

	if (has_filter)
	{
		result = cnxt_dmx_channel_suspend(handle_item->channel, 1);
		coolapi_check_error("cnxt_dmx_channel_suspend", result);
		result = cnxt_dmx_channel_detach_filter(handle_item->channel, filter_handle);
		coolapi_check_error("cnxt_dmx_channel_detach_filter", result);
	}

	memset(&filterset, 0, sizeof(filterset));
	filterset.length = 12;
	memcpy(filterset.filter, flt, 16);
	memcpy(filterset.mask, mask, 16);

	result = cnxt_dmx_set_filter(filter_handle, &filterset, (void *)num);
	coolapi_check_error("cnxt_dmx_set_filter", result);

	result = cnxt_dmx_channel_attach_filter(handle_item->channel, filter_handle);
	coolapi_check_error("cnxt_dmx_channel_attach_filter", result);

	if (has_filter)
	{
		result = cnxt_dmx_channel_suspend(handle_item->channel, 0);
		coolapi_check_error("cnxt_dmx_channel_suspend", result);
	}

	if(!channel_found)
	{
		// Start channel
		result = cnxt_dmx_channel_ctrl(handle_item->channel, 2, 0);
		coolapi_check_error("cnxt_dmx_channel_ctrl", result);
	}

	SAFE_MUTEX_UNLOCK(&dmx->mutex);

	return 0;
}

int32_t coolapi_remove_filter(int32_t fd, int32_t num)
{
	void * channel = NULL;
	void * filter = NULL;

	dmx_t *dmx = find_demux(fd, 0);
	if(!dmx)
	{
		cs_log_dbg(D_DVBAPI, "dmx is NULL!");
		return -1;
	}

	if(dmx->pid <= 0)
		{ return -1; }

	int32_t result;

	SAFE_MUTEX_LOCK(&dmx->mutex);

	// Find matching channel, if it exists.
	S_COOL_CHANHANDLE *handle_item = find_chanhandle(COOLDEMUX_DMX_DEV(fd), dmx->pid);
	if (!handle_item)
	{
		SAFE_MUTEX_UNLOCK(&dmx->mutex);
		cs_log_dbg(D_DVBAPI, "removing filter fd=%08x num=%d pid=%04xcfailed, channel does not exist.", fd, num, dmx->pid);
		return -1;
	}

	channel = handle_item->channel;
	cs_log_dbg(D_DVBAPI, "removing filter fd=%08x num=%d pid=%04x on channel=%p", fd, num, dmx->pid, channel);


	S_COOL_FILTER *filter_item = find_filter_by_chanhandle(handle_item, num);
	if(filter_item)
	{
		result = cnxt_dmx_channel_suspend(channel, 1);
		coolapi_check_error("cnxt_dmx_channel_suspend", result);
		result = cnxt_dmx_channel_detach_filter(channel, filter_item->filter);
		coolapi_check_error("cnxt_dmx_channel_detach_filter", result);
#if 0
		result = cnxt_dmx_close_filter(filter_item->filter);
		coolapi_check_error("cnxt_dmx_close_filter", result);
#endif
		filter = filter_item->filter;
		remove_filter(filter_item);
		handle_item->allocated_filters--;
	}
	else
	{
		SAFE_MUTEX_UNLOCK(&dmx->mutex);
		cs_log_dbg(D_DVBAPI, "removing filter fd=%08x num=%d pid=%04x on channel=%x failed, channel does not exist.", fd, num, dmx->pid, (int32_t) handle_item->channel);
		return -1;
	}

	if (!handle_item->allocated_filters)
	{
		result = cnxt_dmx_channel_ctrl(channel, 0, 0);
		coolapi_check_error("cnxt_dmx_channel_ctrl", result);
		cs_log_dbg(D_DVBAPI, "closing channel %x", (int32_t) channel);
		
		result = cnxt_dmx_set_channel_pid(channel, 0x1FFF);
		coolapi_check_error("cnxt_dmx_set_channel_pid", result);

		result = cnxt_cbuf_flush(handle_item->buffer1, 0);
		coolapi_check_error("cnxt_cbuf_flush", result);

		result = cnxt_cbuf_flush(handle_item->buffer2, 0);
		coolapi_check_error("cnxt_cbuf_flush", result);

		result = cnxt_cbuf_detach(handle_item->buffer2, 2, channel);
		coolapi_check_error("cnxt_cbuf_detach", result);
		
		result = cnxt_dmx_channel_detach(channel, 0xB, 0, handle_item->buffer1);
		coolapi_check_error("cnxt_dmx_channel_detach", result);

#if 0
		result = cnxt_dmx_channel_close(channel);
		coolapi_check_error("cnxt_dmx_channel_close", result);
#endif

		result = cnxt_cbuf_close(handle_item->buffer2);
		coolapi_check_error("cnxt_cbuf_close", result);

		result = cnxt_cbuf_close(handle_item->buffer1);
		coolapi_check_error("cnxt_cbuf_close", result);
		handle_item->channel = NULL;
		handle_item->buffer1 = NULL;
		handle_item->buffer2 = NULL;
		remove_chanhandle(handle_item);
		dmx_handles[COOLDEMUX_DMX_DEV(fd)].allocated_channels--;
		dmx->pid = -1;
	} else {
		result = cnxt_dmx_channel_suspend(channel, 0);
		coolapi_check_error("cnxt_dmx_channel_suspend", result);
		channel = NULL;
	}

	SAFE_MUTEX_UNLOCK(&dmx->mutex);
	if (filter) {
		result = cnxt_dmx_close_filter(filter);
		coolapi_check_error("cnxt_dmx_close_filter", result);
 	}
	if (channel) {
		result = cnxt_dmx_channel_close(channel);
		coolapi_check_error("cnxt_dmx_channel_close", result);
	}

	return 0;
}

int32_t coolapi_open_device(int32_t demux_index, int32_t demux_id)
{
	dmx_t *dmx;

	SAFE_MUTEX_LOCK(&demux_lock);

	dmx = find_demux(0, demux_index);
	if(!dmx)
	{
		SAFE_MUTEX_UNLOCK(&demux_lock);
		cs_log("no free demux found");
		return 0;
	}

	if(!ll_cool_filter)
		{ ll_cool_filter = ll_create("ll_cool_filter"); }

	if(!ll_cool_chanhandle)
		{ ll_cool_chanhandle = ll_create("ll_cool_chanhandle"); }

	dmx->demux_id = demux_id;
	dmx->pid = -1;

	//dmx->device = dmx_handles[demux_index].handle;
	dmx->opened = 1;

	pthread_mutexattr_t attr;
	SAFE_MUTEXATTR_INIT(&attr);
	SAFE_MUTEXATTR_SETTYPE(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
	SAFE_MUTEX_INIT(&dmx->mutex, &attr);

	SAFE_MUTEX_UNLOCK(&demux_lock);

	return dmx->fd;
}

int32_t coolapi_close_device(int32_t fd)
{
	dmx_t *dmx = find_demux(fd, 0);
	if(!dmx)
	{
		cs_log_dbg(D_DVBAPI, "dmx is NULL!");
		SAFE_MUTEX_UNLOCK(&demux_lock);
		return -1;
	}

	cs_log_dbg(D_DVBAPI, "closing fd=%08x", fd);
	dmx->opened = 0;
	pthread_mutex_destroy(&dmx->mutex);

	memset(dmx, 0, sizeof(dmx_t));
	return 0;
}

/* write cw to all demuxes in mask with passed index */
int32_t coolapi_write_cw(int32_t mask, uint16_t *STREAMpids, int32_t count, ca_descr_t *ca_descr)
{
	int32_t i, idx = ca_descr->index;
	int32_t result;
	void *channel;

	cs_log_dbg(D_DVBAPI, "cw%d: mask %d index %d pid count %d", ca_descr->parity, mask, idx, count);
	for(i = 0; i < count; i++)
	{
		int32_t pid = STREAMpids[i];
		int32_t j;
		for(j = 0; j < MAX_COOL_DMX; j++)
		{
			if(mask & (1 << j))
			{
				result = cnxt_dmx_get_channel_from_pid(dmx_handles[j].handle, pid, &channel);
				if(result == 0)
				{
					cs_log_dbg(D_DVBAPI, "Found demux %d channel %x for pid %04x", j, (int32_t) channel, pid);
					result = cnxt_dmx_set_channel_key(channel, 0, ca_descr->parity, ca_descr->cw, 8);
					coolapi_check_error("cnxt_dmx_set_channel_key", result);
					if(result != 0)
					{
						cs_log("set_channel_key failed for demux %d pid %04x", j, pid);
					}
				}
			}
		}
	}
	return 0;
}

static int32_t coolapi_read(dmx_t *dmx, dmx_callback_data_t *data, uchar *buffer)
{
	if(!dmx)
	{
		cs_log_dbg(D_DVBAPI, "dmx is NULL!");
		return -1;
	}

	int32_t result;
	uint32_t done = 0, toread, len = data->len;
	uint32_t bytes_used = 0;

	//cs_log_dbg(D_DVBAPI, "dmx channel %x pid %x len %d",  (int) dmx->channel, dmx->pid, len);

	result = cnxt_cbuf_get_used(data->buf, &bytes_used);
	coolapi_check_error("cnxt_cbuf_get_used", result);
	if(bytes_used == 0)
		{ return -1; }

	result = cnxt_cbuf_read_data(data->buf, buffer, 3, &done);
	coolapi_check_error("cnxt_cbuf_read_data", result);

	if(done != 3)
		{ return -1; }

	toread = ((buffer[1] << 8) | buffer[2]) & 0xFFF;
	if((toread + 3) > len)
		{ return -1; }
	result = cnxt_cbuf_read_data(data->buf, buffer + 3, toread, &done);
	coolapi_check_error("cnxt_cbuf_read_data", result);
	if(done != toread)
		{ return -1; }
	done += 3;

	//cs_log_dbg(D_DVBAPI, "bytes read %d\n", done);

	return 0;
}

static void coolapi_dmx_open(void)
{
	int32_t result = 0;
	device_open_arg_t devarg;

	if(!dmx_opened)
	{
		int32_t i;

		cs_log_dbg(D_DVBAPI, "Open Coolstream DMX API");

		memset(&devarg, 0, sizeof(device_open_arg_t));

		devarg.unknown1 = 1;
		devarg.unknown3 = 3;
		devarg.unknown6 = 1;
		for(i = 0; i < MAX_COOL_DMX; i++)
		{
			devarg.number = i;
			result = cnxt_dmx_open(&dmx_handles[i].handle, &devarg, NULL, NULL);
			coolapi_check_error("cnxt_dmx_open", result);
		}
		dmx_opened = 1;
	}
}

static void coolapi_dmx_close(void)
{
	if(dmx_opened)
	{
		int32_t result;
		int32_t i;

		for(i = 0; i < MAX_COOL_DMX; i++)
		{
			result = cnxt_dmx_close(dmx_handles[i].handle);
			coolapi_check_error("cnxt_dmx_close", result);
			dmx_handles[i].handle = NULL;
		}
		dmx_opened = 0;
	}
}

static void coolapi_start_api(void);
static void coolapi_stop_api(void);

void coolapi_open_all(void)
{
	SAFE_MUTEX_LOCK(&demux_lock);

	coolapi_start_api();
	cool_kal_opened = 1;
	coolapi_dmx_open();

	SAFE_MUTEX_UNLOCK(&demux_lock);
}

void coolapi_close_all(void)
{
	SAFE_MUTEX_LOCK(&demux_lock);

	if(!dmx_opened) {
		SAFE_MUTEX_UNLOCK(&demux_lock);
		return;
	}

	int32_t i, j;

	for(i = 0; i < MAX_COOL_DMX; i++)
	{
		for(j = 0; j < MAX_FILTER; j++)
		{
			if(cdemuxes[i][j].fd > 0)
			{
				coolapi_remove_filter(cdemuxes[i][j].fd, cdemuxes[i][j].filter_num);
				coolapi_close_device(cdemuxes[i][j].fd);
			}
		}
	}

	coolapi_dmx_close();
	coolapi_stop_api();
	cool_kal_opened = 0;

	SAFE_MUTEX_UNLOCK(&demux_lock);
}
#endif

#if defined(HAVE_DVBAPI) && (defined(WITH_SU980) || defined(WITH_COOLAPI2))
#include "extapi/coolapi.h"
extern void cnxt_css_drv_init(void);
extern void cnxt_css_drv_term(void);
extern void cnxt_smc_term(void);

static void coolapi_start_api(void)
{
	cnxt_kal_initialize();
	cnxt_css_drv_init();
	cnxt_cbuf_init(NULL);
	cnxt_dmx_init(NULL);
	cnxt_smc_init(NULL);
}

static void coolapi_stop_api(void)
{
	cnxt_css_drv_term();
	cnxt_kal_terminate();
}
#elif defined(HAVE_DVBAPI) && defined(WITH_COOLAPI)
static void coolapi_start_api(void)
{
	cnxt_kal_initialize();
	cnxt_drv_init();
	cnxt_smc_init(NULL);
}

static void coolapi_stop_api(void)
{
	cnxt_kal_terminate();
	cnxt_drv_term();
}
#endif
