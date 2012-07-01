/* Reversed from libcoolstream.so, this comes without any warranty */

#include "globals.h"

#if defined(HAVE_DVBAPI) && defined(WITH_COOLAPI)

#include "coolapi.h"

#include "module-dvbapi.h"
#include "module-dvbapi-coolapi.h"

static int dmx_opened = 0;
int32_t cool_kal_opened = 0;

static void * dmx_device[MAX_CA_DEVICES];
static dmx_t cdemuxes[MAX_CA_DEVICES][MAX_FILTER];

extern void * dvbapi_client;

#define COOLDEMUX_FD(device, num) (('O' << 24) | ('S' << 16) | (device << 8) | num)
#define COOLDEMUX_DMX_DEV(fd) (((fd) >> 8) & 0xFF)
#define COOLDEMUX_DMX(fd) ((fd) & 0xFF)

static dmx_t *find_demux(int32_t fd, int32_t dmx_dev_num)
{
	int32_t i, idx;

	if(dmx_dev_num < 0 || dmx_dev_num >= MAX_CA_DEVICES) {
		cs_log("Invalid demux %d", dmx_dev_num);
		return NULL;
	}
	idx = dmx_dev_num;

	if(fd == 0) {
		for(i = 0; i < MAX_FILTER; i++) {
			if (!cdemuxes[idx][i].opened) {
				cdemuxes[idx][i].fd = COOLDEMUX_FD(dmx_dev_num, i);
				cs_debug_mask(D_DVBAPI, "opening new fd: %08x", cdemuxes[idx][i].fd);
				cdemuxes[idx][i].demux_index = dmx_dev_num;
				return &cdemuxes[idx][i];
			}
		}
		cs_debug_mask(D_DVBAPI, "ERROR: no free demux found");
		return NULL;
	}

	idx = COOLDEMUX_DMX_DEV(fd);
	for(i = 0; i < MAX_FILTER; i++) {
		if(cdemuxes[idx][i].fd == fd)
			return &cdemuxes[idx][i];
	}

	cs_debug_mask(D_DVBAPI, "ERROR: CANT FIND Demux %x", fd);

	return NULL;
}

void coolapi_read_data(dmx_t * dmx, int32_t len)
{
	if(!dmx) {
		cs_debug_mask(D_DVBAPI, "handle is NULL!");
		return;
	}

	int32_t ret;
	
	pthread_setspecific(getclient, dvbapi_client);
	pthread_mutex_lock(&dmx->mutex);
	memset(dmx->buffer,0,4096);	
	ret = coolapi_read(dmx, len);
	pthread_mutex_unlock(&dmx->mutex);
	if (!ret)
		dvbapi_process_input(dmx->demux_id, dmx->filter_num, dmx->buffer, len);
}

static void dmx_callback(void * unk, dmx_t * dmx, int32_t type, void * data)
{
	dmx_callback_data_t * cdata = (dmx_callback_data_t *) data;
	//FIXME
	unk = unk;

	if(!dmx) {
		cs_debug_mask(D_DVBAPI, "wrong dmx pointer !!!");
		return;
	}
	if(cdata != NULL) {
		switch(type) {
			case 0xE:
				if(cdata->type == 1) {
					coolapi_read_data(dmx, cdata->len);
				} else
					cs_debug_mask(D_DVBAPI, "unknown callback data %d len %d", cdata->type, cdata->len);
				break;
			default:
				break;

		}
	}
}

int32_t coolapi_set_filter (int32_t fd, int32_t num, int32_t pid, unsigned char * flt, unsigned char * mask)
{
	int32_t result;
	filter_set_t filter;

	dmx_t * dmx =  find_demux(fd, 0);

	if(!dmx) {
		cs_debug_mask(D_DVBAPI, "dmx is NULL!");
		return -1;
	}

	dmx->filter_num = num;
	cs_debug_mask(D_DVBAPI, "fd %08x demux %d channel %x num %d pid %x flt %x mask %x", fd, dmx->demux_index, (int) dmx->channel, num, pid, flt[0], mask[0]);

	memset(&filter, 0, sizeof(filter));

	memcpy(dmx->filter16, flt, 16);
	memcpy(dmx->mask16, mask, 16);
	filter.length = 12;
	memcpy(filter.filter, flt, 12);
	memcpy(filter.mask, mask, 12);

	pthread_mutex_lock(&dmx->mutex);
	if(dmx->filter == NULL) {
		dmx->filter_attached = 0;
		result = cnxt_dmx_open_filter(dmx->device, &dmx->filter);
		coolapi_check_error("cnxt_dmx_open_filter", result);
	}

	result = cnxt_dmx_set_filter(dmx->filter, &filter, NULL);
	coolapi_check_error("cnxt_dmx_set_filter", result);

	if(!dmx->filter_attached) {
		result = cnxt_dmx_channel_attach_filter(dmx->channel, dmx->filter);
		coolapi_check_error("cnxt_dmx_channel_attach_filter", result);
		dmx->filter_attached = 1;
	}

	if(dmx->pid != pid) {
		result = cnxt_dmx_set_channel_pid(dmx->channel, pid);
		coolapi_check_error("cnxt_dmx_set_channel_pid", result);
	}

	result = cnxt_cbuf_flush (dmx->buffer1, 0);
	coolapi_check_error("cnxt_cbuf_flush", result);
	result = cnxt_cbuf_flush (dmx->buffer2, 0);
	coolapi_check_error("cnxt_cbuf_flush", result);

	result = cnxt_dmx_channel_ctrl(dmx->channel, 2, 0);

	// we need more than one filter for an EMM-PID, so we exclude the annoying CNXT_STATUS_DUPLICATE_PID (Code 99) which is just a notification and not an error
	if (result != 99)
		coolapi_check_error("cnxt_dmx_channel_ctrl", result);

	dmx->pid = pid;
	pthread_mutex_unlock(&dmx->mutex);
	return 0;
}

int32_t coolapi_remove_filter (int32_t fd, int32_t num)
{
	int32_t result;
	dmx_t * dmx = find_demux(fd, 0);
	if(!dmx) {
		 cs_debug_mask(D_DVBAPI, "dmx is NULL!");
		 return -1;
	}

	if(dmx->pid <= 0)
		return -1;

        cs_debug_mask(D_DVBAPI, "fd %08x channel %x num %d pid %x opened %s", fd, (int) dmx->channel, num, dmx->pid, dmx->opened ? "yes" : "no");

	pthread_mutex_lock(&dmx->mutex);
	result = cnxt_dmx_channel_ctrl(dmx->channel, 0, 0);
	coolapi_check_error("cnxt_dmx_channel_ctrl", result);

	result = cnxt_dmx_set_channel_pid(dmx->channel, 0x1FFF);
	coolapi_check_error("cnxt_dmx_set_channel_pid", result);

	result = cnxt_cbuf_flush (dmx->buffer1, 0);
	coolapi_check_error("cnxt_cbuf_flush", result);
	result = cnxt_cbuf_flush (dmx->buffer2, 0);
	coolapi_check_error("cnxt_cbuf_flush", result);
	pthread_mutex_unlock(&dmx->mutex);

	dmx->pid = -1;
	return 0;
}

int32_t coolapi_open_device (int32_t demux_index, int32_t demux_id)
{
	int32_t result = 0;
	buffer_open_arg_t bufarg;
	channel_open_arg_t chanarg;
	int32_t uBufferSize = 8256;
	dmx_t * dmx;

	coolapi_open();

	dmx = find_demux(0, demux_index);
	if(dmx == 0) {
		cs_log("no free demux found");
		return 0;
	}

	dmx->demux_index = demux_index;
	dmx->demux_id = demux_id;
	dmx->pid = -1;

	memset(&bufarg, 0, sizeof(bufarg));

	dmx->device = dmx_device[demux_index];
	dmx->opened = 1;

	bufarg.type = 3;
	bufarg.size = uBufferSize;
	bufarg.unknown3 = (uBufferSize * 7) / 8;

	result = cnxt_cbuf_open(&dmx->buffer1, &bufarg, NULL, NULL);
	coolapi_check_error("cnxt_cbuf_open", result);

	bufarg.type = 0;

	result = cnxt_cbuf_open(&dmx->buffer2, &bufarg, NULL, NULL);
	coolapi_check_error("cnxt_cbuf_open", result);

	memset(&chanarg, 0, sizeof(channel_open_arg_t));
	chanarg.type = 4;

	result = cnxt_dmx_channel_open(dmx->device, &dmx->channel, &chanarg, dmx_callback, dmx);
	coolapi_check_error("cnxt_dmx_channel_open", result);

	result = cnxt_dmx_set_channel_buffer(dmx->channel, 0, dmx->buffer1);
	coolapi_check_error("cnxt_dmx_set_channel_buffer", result);

	result = cnxt_dmx_channel_attach(dmx->channel, 0xB, 0, dmx->buffer2);
	coolapi_check_error("cnxt_dmx_channel_attach", result);

	result = cnxt_cbuf_attach(dmx->buffer2, 2, dmx->channel);
	coolapi_check_error("cnxt_cbuf_attach", result);

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
	pthread_mutex_init(&dmx->mutex, &attr);

	cs_debug_mask(D_DVBAPI, "fd %08x demux #%d demux_id %d channel %x", dmx->fd, demux_index, demux_id, (int) dmx->channel);
	return dmx->fd;
}

int32_t coolapi_close_device(int32_t fd)
{
	int32_t result;
	dmx_t * dmx = find_demux(fd, 0);
	if(!dmx) {
		cs_debug_mask(D_DVBAPI, "dmx is NULL!");
		return -1;
	}
  	cs_debug_mask(D_DVBAPI, "fd %08x channel %x pid %x", fd, (int) dmx->channel, dmx->pid);

	pthread_mutex_lock(&dmx->mutex);
	if(dmx->filter != NULL) {
		result = cnxt_dmx_channel_detach_filter(dmx->channel, dmx->filter);
		coolapi_check_error("cnxt_dmx_channel_detach_filter", result);
		result = cnxt_dmx_close_filter(dmx->filter);
		coolapi_check_error("cnxt_dmx_close_filter", result);
		dmx->filter = NULL;
		dmx->filter_attached = 0;
	}

	result = cnxt_cbuf_detach(dmx->buffer2, 2, dmx->channel);
	coolapi_check_error("cnxt_cbuf_detach", result);
	result = cnxt_dmx_channel_detach(dmx->channel, 0xB, 0, dmx->buffer2);
	coolapi_check_error("cnxt_dmx_channel_detach", result);

	result = cnxt_dmx_channel_detach(dmx->channel, 0xB, 0, dmx->buffer1);
	coolapi_check_error("cnxt_dmx_channel_detach", result);
	result = cnxt_dmx_channel_close(dmx->channel);
	coolapi_check_error("cnxt_dmx_channel_close", result);

	result = cnxt_cbuf_close(dmx->buffer2);
	coolapi_check_error("cnxt_cbuf_close", result);

	result = cnxt_cbuf_close(dmx->buffer1);
	coolapi_check_error("cnxt_cbuf_close", result);

	dmx->opened = 0;
	pthread_mutex_unlock(&dmx->mutex);
	pthread_mutex_destroy(&dmx->mutex);

	memset(dmx, 0, sizeof(dmx_t));
	return 0;
}

/* write cw to all demuxes in mask with passed index */
int32_t coolapi_write_cw(int32_t mask, uint16_t *STREAMpids, int32_t count, ca_descr_t * ca_descr)
{
        int32_t i, index = ca_descr->index;
        int32_t result;
        void * channel;

	cs_debug_mask(D_DVBAPI, "cw%d: mask %d index %d pid count %d", ca_descr->parity, mask, index, count);
	for(i = 0; i < count; i++) {
		int32_t pid = STREAMpids[i]; 
		int32_t j;
		for(j = 0; j < 3; j++) {
			if(mask & (1 << j))
			{
				result = cnxt_dmx_get_channel_from_pid(dmx_device[j], pid, &channel);
				if(result == 0) {
					cs_debug_mask(D_DVBAPI, "Found demux %d channel %x for pid %x", j, (int) channel, pid);
					result = cnxt_dmx_set_channel_key(channel, 0, ca_descr->parity, ca_descr->cw, 8);
					coolapi_check_error("cnxt_dmx_set_channel_key", result);
					if(result != 0) {
						cs_log("set_channel_key failed for demux %d pid 0x%x", j, pid);
					}
				}
			}
		}
	}
        return 0;
}

int32_t pattern_matching(unsigned char * buff, int32_t len, dmx_t * dmx)
{
	if(!dmx) {
		cs_debug_mask(D_DVBAPI, "dmx is NULL!");
		return 0;
	}

	int32_t i,j,found;

	if (((buff[0] ^ dmx->filter16[0]) & dmx->mask16[0]) != 0)
		return 0;

	for (i = 0; i < len; i++) {
		if (len - i >= 16) {
			found = 1;
			for (j = 1; j < 16 && found == 1; j++) {
				if (((buff[i+j] ^ dmx->filter16[j]) & dmx->mask16[j]) != 0)
					found = 0;
			}
		}
		if (found)
			return 1;
	}
	return 0;
}

int32_t coolapi_read(dmx_t * dmx, uint32_t len)
{
	if(!dmx) {
		cs_debug_mask(D_DVBAPI, "dmx is NULL!");
		return -1;
	}

	int32_t result;
	uint32_t done = 0, toread;
	unsigned char * buff = &dmx->buffer[0];
	uint32_t bytes_used = 0;

	//cs_debug_mask(D_DVBAPI, "dmx channel %x pid %x len %d",  (int) dmx->channel, dmx->pid, len);

	result = cnxt_cbuf_get_used(dmx->buffer2, &bytes_used);
	coolapi_check_error("cnxt_cbuf_get_used", result);
	if(bytes_used == 0) 
		return -1;

	result = cnxt_cbuf_read_data(dmx->buffer2, buff, 3, &done);
	coolapi_check_error("cnxt_cbuf_read_data", result);

	if(done != 3)
		return -1;

	toread = ((buff[1] << 8) | buff[2]) & 0xFFF;
	if((toread+3) > len)
		return -1;
	result = cnxt_cbuf_read_data(dmx->buffer2, buff+3, toread, &done);
	coolapi_check_error("cnxt_cbuf_read_data", result);
	if(done != toread)
		return -1;
	done += 3;

	//cs_debug_mask(D_DVBAPI, "bytes read %d\n", done);

	//coolstream supports only a 12 bytes demux filter so we need to compare all 16 bytes
	if (pattern_matching(buff,len,dmx))
		return 0;
	else
		return -1;
}

void coolapi_open_all(void)
{
	cnxt_kal_initialize();
	cnxt_drv_init();
	cnxt_smc_init (NULL);
	cool_kal_opened = 1;
}

void coolapi_open(void)
{
	int32_t result = 0;
	device_open_arg_t devarg;

        if(!dmx_opened) { 
                int32_t i;

		cs_log("Open coolstream dmx api");
                cnxt_cbuf_init(NULL);
                cnxt_dmx_init(NULL);

                memset(&devarg, 0, sizeof(device_open_arg_t));

                devarg.unknown1 = 1;
                devarg.unknown3 = 3;
                devarg.unknown6 = 1;
                for(i = 0; i < MAX_CA_DEVICES; i++) {
                        devarg.number = i;
                        result = cnxt_dmx_open (&dmx_device[i], &devarg, NULL, NULL);
                        coolapi_check_error("cnxt_dmx_open", result);
                }
                dmx_opened = 1;
        }
}

void coolapi_close_all(void)
{
	int32_t result;
	int32_t i, j;

	if(dmx_opened) {
		for(i = 0; i < MAX_CA_DEVICES; i++) {
			for(j = 0; j < MAX_FILTER; j++) {
				if(cdemuxes[i][j].fd > 0) {
					coolapi_remove_filter(cdemuxes[i][j].fd, cdemuxes[i][j].filter_num);
					coolapi_close_device(cdemuxes[i][j].fd);
				}
			}
		}
		for(i = 0; i < MAX_CA_DEVICES; i++) {
			result = cnxt_dmx_close(dmx_device[i]);
			coolapi_check_error("cnxt_dmx_close", result);
			dmx_device[i] = NULL;
		}
	}
	cool_kal_opened = 0;
	cnxt_kal_terminate();
	cnxt_drv_term();
}
#endif
