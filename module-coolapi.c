/* Reversed from libcoolstream.so, this comes without any warranty */

#ifdef COOL
#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "module-coolapi.h"

#define MAX_PIDS 20
#define MAX_FILTER 10

#define MAX_DEMUX 3

int cooldebug = 0;
static bool dmx_opened = false;

#define dprintf(fmt, args...)                           \
do {                                                    \
        if (cooldebug) {                                \
                fprintf(stdout, "#### [%s:%s:%d] " fmt, \
                                __FILE__, __FUNCTION__, \
                                __LINE__ , ## args);    \
		fflush(stdout);				\
	}						\
} while (0)

#define check_error(label, ret) \
{ \
        if(ret != 0) { \
                printf("[%s:%d] %s: API ERROR %d\n",	\
		__FUNCTION__, __LINE__ ,		\
		label, ret);				\
		fflush(stdout);				\
	}						\
}

typedef struct ca_descr {
        unsigned int index;
        unsigned int parity;    /* 0 == even, 1 == odd */
        unsigned char cw[8];
} ca_descr_t;

struct cool_dmx
{
	bool		opened;
	bool		filter_attached;
	int		fd;
	void *		buffer1;
	void *		buffer2;
	void *	 	channel;
	void *		filter;
	void *		device;
	int		pid;
	pthread_mutex_t	mutex;
	int 		demux_id;
	int 		demux_index;
	int 		filter_num;
};
typedef struct cool_dmx dmx_t;

static void * dmx_device[MAX_DEMUX];
static dmx_t cdemuxes[MAX_DEMUX][MAX_FILTER];

int coolapi_read(int fd, unsigned char * buffer, unsigned int len);
void coolapi_open();

extern void dvbapi_process_input(int demux_num, int filter_num, unsigned char *buffer, int len);
extern pthread_key_t getclient;
extern void * dvbapi_client;

#define COOLDEMUX_FD(device, num) (('O' << 24) | ('S' << 16) | (device << 8) | num)
#define COOLDEMUX_DMX_DEV(fd) (((fd) >> 8) & 0xFF)
#define COOLDEMUX_DMX(fd) ((fd) & 0xFF)

static dmx_t *find_demux(int fd, int dmx_dev_num)
{
	int i, idx;

	if(dmx_dev_num < 0 || dmx_dev_num >= MAX_DEMUX) {
		printf("Invalid demux %d\n", dmx_dev_num);
		return NULL;
	}
	idx = dmx_dev_num;

	if(fd == 0) {
		for(i = 0; i < MAX_FILTER; i++) {
			if (cdemuxes[idx][i].opened == false) {
				cdemuxes[idx][i].fd = COOLDEMUX_FD(dmx_dev_num, i);
				dprintf("opening new fd: %08x\n", cdemuxes[idx][i].fd);
				cdemuxes[idx][i].demux_index = dmx_dev_num;
				return &cdemuxes[idx][i];
			}
		}
		dprintf("ERROR: no free demux found\n");
		return NULL;
	}

	idx = COOLDEMUX_DMX_DEV(fd);
	for(i = 0; i < MAX_FILTER; i++) {
		if(cdemuxes[idx][i].fd == fd)
			return &cdemuxes[idx][i];
	}

	dprintf("ERROR: CANT FIND Demux %x\n", fd);

	return NULL;
}

void coolapi_read_data(int fd, int len)
{
	int ret;
	unsigned char buffer[4096];
	dmx_t * dmx =  find_demux(fd, 0);

	if(!dmx) {
		dprintf("handle is NULL!\n");
		return;
	}

	pthread_mutex_lock(&dmx->mutex);
	pthread_setspecific(getclient, dvbapi_client);
	ret = coolapi_read(dmx->fd, buffer, len);
	pthread_mutex_unlock(&dmx->mutex);
	dvbapi_process_input(dmx->demux_id, dmx->filter_num, buffer, len);
}

static void dmx_callback(void * unk, dmx_t * dmx, int type, void * data)
{
	dmx_callback_data_t * cdata = (dmx_callback_data_t *) data;
	unk = unk;

	if(!dmx) {
		dprintf("wrong dmx pointer !!!\n");
		return;
	}
	if(cdata != NULL) {
		switch(type) {
			case 0xE:
				if(cdata->type == 1) {
					coolapi_read_data(dmx->fd, cdata->len);
				} else
					dprintf("unknown callback data %d len %d\n", cdata->type, cdata->len);
				break;
			default:
				break;

		}
	}
}

int coolapi_set_filter (int fd, int num, int pid, unsigned char * flt, unsigned char * mask)
{
	int result;
	filter_set_t filter;

	dmx_t * dmx =  find_demux(fd, 0);

	if(!dmx) {
		dprintf("dmx is NULL!\n");
		return -1;
	}

	dmx->filter_num = num;
	dprintf("fd %08x demux %d channel %x num %d pid %x flt %x mask %x\n", fd, dmx->demux_index, (int) dmx->channel, num, pid, flt[0], mask[0]);

	memset(&filter, 0, sizeof(filter));

	filter.length = 12;
	memcpy(filter.filter, flt, 12);
	memcpy(filter.mask, mask, 12);

	pthread_mutex_lock(&dmx->mutex);
	if(dmx->filter == NULL) {
		dmx->filter_attached = false;
		result = cnxt_dmx_open_filter(dmx->device, &dmx->filter);
		check_error ("cnxt_dmx_open_filter", result);
	}

	result = cnxt_dmx_set_filter(dmx->filter, &filter, NULL);
	check_error ("cnxt_dmx_set_filter", result);

	if(!dmx->filter_attached) {
		result = cnxt_dmx_channel_attach_filter(dmx->channel, dmx->filter);
		check_error ("cnxt_dmx_channel_attach_filter", result);
	}

	if(dmx->pid != pid) {
		result = cnxt_dmx_set_channel_pid(dmx->channel, pid);
		check_error ("cnxt_dmx_set_channel_pid", result);
	}

	result = cnxt_cbuf_flush (dmx->buffer1, 0);
	check_error ("cnxt_cbuf_flush", result);
	result = cnxt_cbuf_flush (dmx->buffer2, 0);
	check_error ("cnxt_cbuf_flush", result);

	result = cnxt_dmx_channel_ctrl(dmx->channel, 2, 0);
	check_error ("cnxt_dmx_channel_ctrl", result);
	dmx->pid = pid;
	pthread_mutex_unlock(&dmx->mutex);
	return 0;
}

int coolapi_remove_filter (int fd, int num)
{
	int result;
	dmx_t * dmx = find_demux(fd, 0);
	if(!dmx) {
		 dprintf("dmx is NULL!\n");
		 return -1;
	}

	if(dmx->pid <= 0)
		return -1;

        dprintf("fd %08x channel %x num %d pid %x opened %s\n", fd, (int) dmx->channel, num, dmx->pid, dmx->opened ? "yes" : "no");

	pthread_mutex_lock(&dmx->mutex);
	result = cnxt_dmx_channel_ctrl(dmx->channel, 0, 0);
	check_error ("cnxt_dmx_channel_ctrl", result);

	result = cnxt_dmx_set_channel_pid(dmx->channel, 0x1FFF);
	check_error ("cnxt_dmx_set_channel_pid", result);

	result = cnxt_cbuf_flush (dmx->buffer1, 0);
	check_error ("cnxt_cbuf_flush", result);
	result = cnxt_cbuf_flush (dmx->buffer2, 0);
	check_error ("cnxt_cbuf_flush", result);
	pthread_mutex_unlock(&dmx->mutex);

	dmx->pid = -1;
	return 0;
}

int coolapi_open_device (int demux_index, int demux_id)
{
	int result = 0;
	buffer_open_arg_t bufarg;
	channel_open_arg_t chanarg;
	int uBufferSize = 8256;
	dmx_t * dmx;

	coolapi_open();

	dmx = find_demux(0, demux_index);
	if(dmx == 0) {
		printf("no free demux found\n");
		return 0;
	}

	dmx->demux_index = demux_index;
	dmx->demux_id = demux_id;
	dmx->pid = -1;

	memset(&bufarg, 0, sizeof(bufarg));

	dmx->device = dmx_device[demux_index];
	dmx->opened = true;

	bufarg.type = 3;
	bufarg.size = uBufferSize;
	bufarg.unknown3 = (uBufferSize * 7) / 8;

	result = cnxt_cbuf_open(&dmx->buffer1, &bufarg, NULL, NULL);
	check_error ("cnxt_cbuf_open", result);

	bufarg.type = 0;

	result = cnxt_cbuf_open(&dmx->buffer2, &bufarg, NULL, NULL);
	check_error ("cnxt_cbuf_open", result);

	memset(&chanarg, 0, sizeof(channel_open_arg_t));
	chanarg.type = 4;

	result = cnxt_dmx_channel_open(dmx->device, &dmx->channel, &chanarg, dmx_callback, dmx);
	check_error ("cnxt_dmx_channel_open", result);

	result = cnxt_dmx_set_channel_buffer(dmx->channel, 0, dmx->buffer1);
	check_error ("cnxt_dmx_set_channel_buffer", result);

	result = cnxt_dmx_channel_attach(dmx->channel, 0xB, 0, dmx->buffer2);
	check_error ("cnxt_dmx_channel_attach", result);

	result = cnxt_cbuf_attach(dmx->buffer2, 2, dmx->channel);
	check_error ("cnxt_cbuf_attach", result);

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK_NP);
	pthread_mutex_init(&dmx->mutex, &attr);

	dprintf("fd %08x demux #%d demux_id %d channel %x\n", dmx->fd, demux_index, demux_id, (int) dmx->channel);
	return dmx->fd;
}

int coolapi_close_device(int fd)
{
	int result;
	dmx_t * dmx = find_demux(fd, 0);
	if(!dmx) {
		dprintf("dmx is NULL!\n");
		return -1;
	}
  	dprintf("fd %08x channel %x pid %x\n", fd, (int) dmx->channel, dmx->pid);

	if(dmx->filter != NULL) {
		result = cnxt_dmx_channel_detach_filter(dmx->channel, dmx->filter);
		check_error ("cnxt_dmx_channel_detach_filter", result);
		result = cnxt_dmx_close_filter(dmx->filter);
		check_error ("cnxt_dmx_close_filter", result);
		dmx->filter = NULL;
		dmx->filter_attached = false;
	}

	result = cnxt_cbuf_detach(dmx->buffer2, 2, dmx->channel);
	check_error ("cnxt_cbuf_detach", result);
	result = cnxt_dmx_channel_detach(dmx->channel, 0xB, 0, dmx->buffer2);
	check_error ("cnxt_dmx_channel_detach", result);

	result = cnxt_dmx_channel_detach(dmx->channel, 0xB, 0, dmx->buffer1);
	check_error ("cnxt_dmx_channel_detach", result);
	result = cnxt_dmx_channel_close(dmx->channel);
	check_error ("cnxt_dmx_channel_close", result);

	result = cnxt_cbuf_close(dmx->buffer2);
	check_error ("cnxt_cbuf_close", result);

	result = cnxt_cbuf_close(dmx->buffer1);
	check_error ("cnxt_cbuf_close", result);

	dmx->opened = false;

	pthread_mutex_destroy(&dmx->mutex);

	memset(dmx, 0, sizeof(dmx_t));
	return 0;
}

/* write cw to all demuxes in mask with passed index */
int coolapi_write_cw(int mask, unsigned short *STREAMpids, int count, ca_descr_t * ca_descr)
{
        int i, index = ca_descr->index;
        int result;
        void * channel;

	dprintf("cw%d: mask %d index %d pid count %d\n", ca_descr->parity, mask, index, count);
	for(i = 0; i < count; i++) {
		int pid = STREAMpids[i]; 
		int j;
		for(j = 0; j < 3; j++) {
			if(mask & (1 << j))
			{
				result = cnxt_dmx_get_channel_from_pid(dmx_device[j], pid, &channel);
				if(result == 0) {
					dprintf("Found demux %d channel %x for pid %x\n", j, (int) channel, pid);
					result = cnxt_dmx_set_channel_key(channel, 0, ca_descr->parity, ca_descr->cw, 8);
					check_error ("cnxt_dmx_set_channel_key", result);
					if(result != 0) {
						printf("set_channel_key failed for demux %d pid 0x%x\n", j, pid);
					}
				}
			}
		}
	}
        return 0;
}

int coolapi_read(int fd, unsigned char * buffer, unsigned int len)
{
	int result;
	unsigned int done = 0, toread;
	unsigned char * buff = &buffer[0];

	dmx_t * dmx = find_demux(fd, 0);
	if(!dmx) {
		dprintf("dmx is NULL!\n");
		return 0;
	}
	dprintf("dmx channel %x pid %x len %d\n",  (int) dmx->channel, dmx->pid, len);

	result = cnxt_cbuf_read_data(dmx->buffer2, buff, 3, &done);
	check_error ("cnxt_cbuf_read_data", result);

	if(done != 3)
		return 0;

	toread = ((buff[1] << 8) | buff[2]) & 0xFFF;
	if((toread+3) > len)
		return 0;
	result = cnxt_cbuf_read_data(dmx->buffer2, buff+3, toread, &done);
	check_error ("cnxt_cbuf_read_data", result);
	if(done != toread)
		return 0;
	done += 3;

	dprintf ("bytes read %d\n", done);
	return done;
}

void coolapi_open()
{
	int result = 0;
	device_open_arg_t devarg;

        if(!dmx_opened) { 
                int i;

		printf("Open coolstream dmx api\n");

                cnxt_kal_initialize();
                cnxt_drv_init();
                cnxt_cbuf_init(NULL);
                cnxt_dmx_init(NULL);

                memset(&devarg, 0, sizeof(device_open_arg_t));

                devarg.unknown1 = 1;
                devarg.unknown3 = 3;
                devarg.unknown6 = 1;
                for(i = 0; i < MAX_DEMUX; i++) {
                        devarg.number = i;
                        result = cnxt_dmx_open (&dmx_device[i], &devarg, NULL, NULL);
                        check_error ("cnxt_dmx_open", result);
                }
                dmx_opened = true;
        }
}

void coolapi_close_all()
{
	int result;
	int i, j;
	dprintf("\n");

	if(!dmx_opened)
		return;

	for(i = 0; i < MAX_DEMUX; i++) {
		for(j = 0; j < MAX_FILTER; j++) {
			if(cdemuxes[i][j].fd > 0) {
				coolapi_remove_filter(cdemuxes[i][j].fd, cdemuxes[i][j].filter_num);
				coolapi_close_device(cdemuxes[i][j].fd);
			}
		}
	}
	for(i = 0; i < MAX_DEMUX; i++) {
		result = cnxt_dmx_close(dmx_device[i]);
		check_error ("cnxt_dmx_close", result);
		dmx_device[i] = NULL;
	}
	dprintf("\n");
	cnxt_kal_terminate();
	dprintf("\n");
	cnxt_drv_term();
	dprintf("\n");
}
#endif
