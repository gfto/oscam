/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "globals.h"  //HAVE_DVBAPI is set here so must be included before ifdef 

#ifdef HAVE_DVBAPI

#include <sys/un.h>


#define BUFSIZE 512
#define MAX_DEMUX 5
#define MAX_CAID 50
#define ECM_PIDS 20

static int listenfd = -1;

typedef struct ECMPIDS
{
	unsigned short CA_PID;
	unsigned short CA_System_ID;
	unsigned short EMM_PID;
} ECMPIDSTYPE;

typedef struct demux_s
{
	unsigned short demux_index;
	unsigned short demux_ecm_fd;
	unsigned short demux_emm_fd;
	unsigned short cadev_index;
	unsigned short ca_fd;
	unsigned short active;
	unsigned short ECMpidcount;
	ECMPIDSTYPE ECMpids[ECM_PIDS];
	unsigned short program_number;
	unsigned short ca_system_id;
	unsigned short ca_pid;
	unsigned int provider_id;
	unsigned short emm_pid;
	unsigned short STREAMpidcount;
	unsigned short STREAMpids[ECM_PIDS];
	unsigned char buffer_cache_dmx[12];
	unsigned char lastcw0[8];
	unsigned char lastcw1[8];
} DEMUXTYPE;
#define DMX_FILTER_SIZE 16

//dvbapi 1
typedef struct dmxFilter
{
	uint8_t 	filter[DMX_FILTER_SIZE];
	uint8_t 	mask[DMX_FILTER_SIZE];
} dmxFilter_t;

struct dmxSctFilterParams
{
	uint16_t		    pid;
	dmxFilter_t		     filter;
	uint32_t		     timeout;
	uint32_t		     flags;
#define DMX_CHECK_CRC	    1
#define DMX_ONESHOT	    2
#define DMX_IMMEDIATE_START 4
#define DMX_BUCKET	    0x1000	/* added in 2005.05.18 */
#define DMX_KERNEL_CLIENT   0x8000
};

#define DMX_START1		  _IOW('o',41,int)
#define DMX_STOP1		  _IOW('o',42,int)
#define DMX_SET_FILTER1 	  _IOW('o',43,struct dmxSctFilterParams *)


//dbox2+ufs
typedef struct dmx_filter
{
	uint8_t  filter[DMX_FILTER_SIZE];
	uint8_t  mask[DMX_FILTER_SIZE];
	uint8_t  mode[DMX_FILTER_SIZE];
} dmx_filter_t;


struct dmx_sct_filter_params
{
	uint16_t	    pid;
	dmx_filter_t	    filter;
	uint32_t	    timeout;
	uint32_t	    flags;
#define DMX_CHECK_CRC	    1
#define DMX_ONESHOT	    2
#define DMX_IMMEDIATE_START 4
#define DMX_KERNEL_CLIENT   0x8000
};

typedef struct ca_descr {
	unsigned int index;
	unsigned int parity;	/* 0 == even, 1 == odd */
	unsigned char cw[8];
} ca_descr_t;

typedef struct ca_pid {
	unsigned int pid;
	int index;		/* -1 == disable*/
} ca_pid_t;

#define DMX_START		 _IO('o', 41)
#define DMX_STOP		 _IO('o', 42)
#define DMX_SET_FILTER		 _IOW('o', 43, struct dmx_sct_filter_params)

#define CA_SET_DESCR	  _IOW('o', 134, ca_descr_t)
#define CA_SET_PID	  _IOW('o', 135, ca_pid_t)

DEMUXTYPE demux[MAX_DEMUX];

unsigned short global_caid_list[MAX_CAID];
CAIDTAB prioritytab,ignoretab;

#define BOX_COUNT 2
struct box_devices
{
	char ca_device_path[32];
	char demux_device_path[32];
	char cam_socket_path[32];
};

struct box_devices devices[BOX_COUNT] = {
	/* dreambox (dvb-api-3)*/	{ "/dev/dvb/adapter0/ca%d", "/dev/dvb/adapter0/demux%d", "/var/tmp/camd.socket" },
	/* dreambox (dvb-api-1)*/	{ "/dev/dvb/card0/ca%d", "/dev/dvb/card0/demux%d", "/var/tmp/camd.socket" }
};

int selected_box=-1;
int selected_api=-1;

int dvbapi_set_filter(int dmx_fd, int api, unsigned short pid, unsigned char filt, unsigned char mask, int timeout)
{
	int ret=-1;

	cs_debug("dvbapi: set filter pid:%04x, value:%04x",pid, filt);

	switch(api)
	{
		case 0:
			api=api;
			struct dmx_sct_filter_params sFP2;

			memset(&sFP2,0,sizeof(sFP2));

			sFP2.pid			= pid;
			sFP2.timeout			= timeout;
			sFP2.flags			= DMX_IMMEDIATE_START;
			sFP2.filter.filter[0]	= filt;
			sFP2.filter.mask[0]		= mask;
			ret=ioctl(dmx_fd, DMX_SET_FILTER, &sFP2);

			break;
		case 1:
			api=api;
			struct dmxSctFilterParams sFP1;

			memset(&sFP1,0,sizeof(sFP1));

			sFP1.pid			= pid;
			sFP1.timeout			= timeout;
			sFP1.flags			= DMX_IMMEDIATE_START;
			sFP1.filter.filter[0]	= filt;
			sFP1.filter.mask[0]		= mask;
			ret=ioctl(dmx_fd, DMX_SET_FILTER1, &sFP1);

			break;
		default:
			break;
	}

	if (ret < 0)
		cs_debug("dvbapi: could not start demux filter (Errno: %d)", errno);

	return ret;
}


int dvbapi_check_array(unsigned short *array, int len, unsigned short match)
{
	int i;
	for (i=0; i<len; i++) {
		if (array[i]==match) {
			return i;
		}
	}
	return -1;
}

int dvbapi_detect_api()
{
	int num_apis=2;
	int i,devnum=-1;
	int apinum=-1;
	int dmx_fd=0;

	char device_path[128];

	for (i=0;i<BOX_COUNT;i++)
	{
		sprintf(device_path, devices[i].demux_device_path, 0);
		if ((dmx_fd = open(device_path, O_RDWR)) > 0) {
			devnum=i;
			break;
		}
	}

	if (dmx_fd < 0) return 0;

	int ret=0;

	for (i=0;i<num_apis;i++)
	{
		ret=dvbapi_set_filter(dmx_fd, i, 0x0001, 0x01, 0xFF, 1);

		if (ret >= 0)
		{
			apinum=i;
			break;
		}
	}
	close(dmx_fd);

	selected_box=devnum;
	selected_api=apinum;
	cs_debug("dvbapi: Detected %s Api: %d", device_path, apinum);

	return 1;
}

int dvbapi_read_device(int dmx_fd, unsigned char *buf, int length, int debug)
{
	int len, rc;
	struct pollfd pfd[1];

	pfd[0].fd = dmx_fd;
	pfd[0].events = (POLLIN | POLLPRI);

	rc = poll(pfd, 1, 5000);
	if (rc<1)
		return -1;

	len = read(dmx_fd, buf, length);

	if (len==-1)
		cs_log("dvbapi: read error %d", errno);

	if (debug==1)
		cs_debug("dvbapi: Read %d bytes from demux", len);

	return len;
}

int dvbapi_open_device(int index_demux, int type)
{
	int dmx_fd,i;
	int ca_offset=0;
	char device_path[128];

	if (type==0)
		sprintf(device_path, devices[selected_box].demux_device_path, demux[index_demux].demux_index);
	else
	{
		if (strcmp(cfg->dvbapi_boxtype, "ufs910")==0 || strcmp(cfg->dvbapi_boxtype, "dbox2")==0)
			ca_offset=1;

		sprintf(device_path, devices[selected_box].ca_device_path, demux[index_demux].cadev_index+ca_offset);
	}

	if ((dmx_fd = open(device_path, O_RDWR)) < 0) {
		if (type==1 && errno==16) // ca device already open
			for (i=0;i<MAX_DEMUX;i++)
				if (demux[i].cadev_index==demux[index_demux].cadev_index && demux[i].ca_fd>0)
					dmx_fd=demux[i].ca_fd;

		if (dmx_fd<=0)
			cs_debug("dvbapi: error opening device %s (Errno: %d)", device_path, errno);
	}

	cs_debug("dvbapi: DEVICE open (%s)", device_path);
	return dmx_fd;
}

int dvbapi_stop_filter(int demux_index, int type)
{
	int dmx_fd;

	if (type==0) {
		dmx_fd=demux[demux_index].demux_ecm_fd;
	} else {
		dmx_fd=demux[demux_index].demux_emm_fd;
	}

	ioctl(dmx_fd,DMX_STOP);
	return 1;
}

unsigned long dvbapi_get_provid(int demux_index, unsigned short pid)
{
	unsigned char buf[BUFSIZE];
	int dmx_fd, len;

	dmx_fd=demux[demux_index].demux_emm_fd;

	dvbapi_set_filter(dmx_fd, selected_api, pid, 0x80, 0xF0, 4000);

	len=dvbapi_read_device(dmx_fd, buf, BUFSIZE, 1);

	if (len > 0) {
		unsigned long provid = (buf[10] << 8) | buf[11];
		return provid;
	}

	return 0;
}

unsigned short dvbapi_get_single_ecm(int demux_index, unsigned short caid, unsigned short pid, unsigned long provid)
{
	unsigned char buf[BUFSIZE];
	int dmx_fd, len;

	dmx_fd=demux[demux_index].demux_ecm_fd;

	dvbapi_set_filter(dmx_fd, selected_api, pid, 0x80, 0xF0, 2000);

	len=dvbapi_read_device(dmx_fd, buf, BUFSIZE, 1);

	if (len > 0) {
		ECM_REQUEST *er;

		if (!(er=get_ecmtask()))
			return 0;

		er->srvid = demux[demux_index].program_number;
		er->caid  = caid;
		er->pid   = pid;
		er->prid  = provid;

		er->l=len;
		memcpy(er->ecm, buf, er->l);

		get_cw(er);

		memcpy(demux[demux_index].buffer_cache_dmx, buf, 12);
	}
	return 0;
}

void dvbapi_parse_cat(int demux_index)
{
	unsigned char buf[BUFSIZE];
	unsigned short i, j;
	int dmx_fd, len;

	dmx_fd=demux[demux_index].demux_emm_fd;

	dvbapi_set_filter(dmx_fd, selected_api, 0x0001, 0x01, 0xFF, 2000);

	len=dvbapi_read_device(dmx_fd, buf, BUFSIZE, 1);

	if (len<=0)
		return;

	cs_ddump(buf, len, "cat:");

	for (i = 8; i < (((buf[1] & 0x0F) << 8) | buf[2]) - 1; i += buf[i + 1] + 2)
	{
		if (buf[i] != 0x09) continue;
		unsigned short cat_sys_id=(((buf[i + 2] & 0x1F) << 8) | buf[i + 3]);
		unsigned short emm_pid=(((buf[i + 4] & 0x1F) << 8) | buf[i + 5]);
		cs_debug("cat: ca_system_id: %04x\temm_pid %04x", cat_sys_id, emm_pid);
		for (j=0;j<demux[demux_index].ECMpidcount;j++) {
			if (demux[demux_index].ECMpids[j].CA_System_ID==(((buf[i + 2] & 0x1F) << 8) | buf[i + 3])) {
				demux[demux_index].ECMpids[j].EMM_PID=emm_pid;
				break;
			}
		}
	}

	dvbapi_stop_filter(demux_index, 1);

	return;
}

void dvbapi_stop_descrambling(int demux_id)
{
	int i;

	cs_debug("dvbapi: Stop descrambling CAID: %04x", demux[demux_id].ca_system_id);

	demux[demux_id].ca_system_id=0;
	demux[demux_id].ca_pid=0;
	demux[demux_id].emm_pid=0;
	demux[demux_id].provider_id=0;
	demux[demux_id].demux_index=-1;
	demux[demux_id].program_number=0;

	if (demux[demux_id].demux_ecm_fd>0) {
		dvbapi_stop_filter(demux_id, 0);
		close(demux[demux_id].demux_ecm_fd);
		demux[demux_id].demux_ecm_fd=0;
	}

	if (demux[demux_id].demux_emm_fd>0) {
		dvbapi_stop_filter(demux_id, 1);
		close(demux[demux_id].demux_emm_fd);
		demux[demux_id].demux_emm_fd=0;
	}

	if (demux[demux_id].ca_fd>0) {
		for (i=0;i<demux[demux_id].STREAMpidcount;i++)
		{
			ca_pid_t ca_pid2;
			memset(&ca_pid2,0,sizeof(ca_pid2));
			ca_pid2.pid = demux[demux_id].STREAMpids[i];
			ca_pid2.index = -1;
			if (ioctl(demux[demux_id].ca_fd, CA_SET_PID, &ca_pid2)==-1)
				cs_debug("dvbapi: Error Stream Unset SET_PID");
		}

		int needed=0;
		for (i=0;i<MAX_DEMUX;i++) {
			if (demux[demux_id].ca_fd==demux[i].ca_fd && i != demux_id)
				needed=1;
		}
		if (needed==0) {
			close(demux[demux_id].ca_fd);
			cs_debug("dvbapi: closing ca device");
		}
		demux[demux_id].ca_fd=0;
	}

	return;
}

void dvbapi_stop_descrambling_all(int demux_index)
{
	int j;
	for (j=0;j<MAX_DEMUX;j++) {
		if (demux[j].demux_index != demux_index)
			continue;

		dvbapi_stop_descrambling(j);
	}

	return;
}

void dvbapi_start_descrambling(int demux_index, unsigned short caid, unsigned short capid, unsigned long provider_id)
{
	int i;

	cs_log("dvbapi: Start descrambling CAID: %04x", caid);

	demux[demux_index].ca_pid=capid;
	demux[demux_index].ca_system_id=caid;
	demux[demux_index].provider_id=provider_id;

	int camfd=dvbapi_open_device(demux_index,1);
	if (camfd<=0) {
		return;
	}

	demux[demux_index].ca_fd=camfd;

	for (i=0;i<demux[demux_index].STREAMpidcount;i++)
	{
		ca_pid_t ca_pid2;
		memset(&ca_pid2,0,sizeof(ca_pid2));
		ca_pid2.pid = demux[demux_index].STREAMpids[i];
		ca_pid2.index = demux_index;
		if (ioctl(camfd, CA_SET_PID, &ca_pid2)==-1)
			cs_debug("dvbapi: Error Stream SET_PID");
	}

}

void dvbapi_try_descrambling (int demux_index)
{
	int n;
	unsigned int program_number;

	program_number=demux[demux_index].program_number;
	for (n=0; n<demux[demux_index].ECMpidcount; n++) {

		if (demux[demux_index].ca_system_id!=0) // got valid cw -> stop trying
			break;

		if (program_number!=demux[demux_index].program_number) //channel change -> stop trying
			break;

		dvbapi_stop_filter(demux_index,0);

		cs_debug("dvbapi: trying CA_System_ID: %04x CA_PID: %04x EEM_PID: %04x", demux[demux_index].ECMpids[n].CA_System_ID, demux[demux_index].ECMpids[n].CA_PID, demux[demux_index].ECMpids[n].EMM_PID);

		//grep emm provid
		unsigned long provid=0;

		int pid=dvbapi_check_array(prioritytab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[n].CA_System_ID);
		if (pid>=0) {
			if (prioritytab.mask[pid]>0)
				provid=prioritytab.mask[pid];
		}

		if (cfg->dvbapi_au==1) {
			dvbapi_stop_filter(demux_index,1);
			if (demux[demux_index].ECMpids[n].EMM_PID>0)
				provid=dvbapi_get_provid(demux_index, demux[demux_index].ECMpids[n].EMM_PID);
		}

		//grep ecm
		dvbapi_get_single_ecm(demux_index, demux[demux_index].ECMpids[n].CA_System_ID, demux[demux_index].ECMpids[n].CA_PID, provid);

		cs_sleepms(3000); //try next if no cw for .. secs
	}
}

void dvbapi_process_emm (int demux_index, unsigned char *buffer, unsigned int len) 
{
	int i;
	EMM_PACKET epg;
	cs_debug("dvbapi: EMM Type: 0x%02x caid: %04x", buffer[0],demux[demux_index].ca_system_id);
	cs_ddump(buffer, len, "emm:");

	//force emm output
	reader[ridx].logemm=9999;

	memset(&epg, 0, sizeof(epg));
	epg.caid[0] = (uchar)(demux[demux_index].ca_system_id>>8);
	epg.caid[1] = (uchar)(demux[demux_index].ca_system_id);

	epg.provid[1] = (uchar)(demux[demux_index].provider_id>>16);
	epg.provid[2] = (uchar)(demux[demux_index].provider_id>>8);
	epg.provid[3] = (uchar)(demux[demux_index].provider_id);

	epg.l=len;
	memcpy(epg.emm, buffer, epg.l);

	for (i=0;i<CS_MAXREADER;i++) {
		if (reader[i].caid[0] == demux[demux_index].ca_system_id) {
			client[cs_idx].au=i;
//			memcpy(epg.hexserial, reader[client[cs_idx].au].hexserial, 8);
		}
	}
	do_emm(&epg);
}

void *thread_descrambling(void *di)
{
	int demux_index=(int)di;
	int dmx1_fd,dmx2_fd=0,n=30,k=0;
	unsigned int program_number;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	cs_debug("dvbapi: Start descrambling Thread %d", demux_index);

	dmx1_fd = dvbapi_open_device(demux_index,0); //ECM
	demux[demux_index].demux_ecm_fd=dmx1_fd;
	
	if (cfg->dvbapi_au==1) {
		dmx2_fd = dvbapi_open_device(demux_index,0); //EMM,CAT
		demux[demux_index].demux_emm_fd=dmx2_fd;
		dvbapi_parse_cat(demux_index);
	}

	program_number=demux[demux_index].program_number;

	while(1) {
		if (demux[demux_index].ca_system_id!=0) // got valid cw -> stop trying
			break;

		if (program_number!=demux[demux_index].program_number) //channel change -> new thread
			return 0;

		if (n>=30)
		{
			if (demux[demux_index].ca_system_id==0)
				dvbapi_try_descrambling(demux_index);
			n=0;
			k++;
			continue;
		}
		n++;

		if (k==5) // give up
			return 0;

		cs_sleepms(10000);
	}

	struct pollfd pfd2[2];
	int rc,len,i,pfdcount;
	unsigned char buffer[BUFSIZE];

	while(1) {
		pfdcount=0;

		if (program_number!=demux[demux_index].program_number || demux[demux_index].ca_system_id==0) //channel change -> new thread
			break;

		if (demux[demux_index].demux_ecm_fd>0) {
			pfd2[pfdcount].fd = demux[demux_index].demux_ecm_fd;
			pfd2[pfdcount].events = (POLLIN | POLLPRI);
			pfdcount++;
		} else break;
		if (cfg->dvbapi_au==1) {
			if (demux[demux_index].demux_emm_fd>0) {
				pfd2[pfdcount].fd = demux[demux_index].demux_emm_fd;
				pfd2[pfdcount].events = (POLLIN | POLLPRI);
				pfdcount++;
			} else break;
		}

		rc=poll(pfd2, pfdcount, 3000);

		if (rc<0)
			break;

		for (i = 0; i < pfdcount; i++) {
			if (pfd2[i].revents & (POLLIN | POLLPRI)) {

				if ((len=dvbapi_read_device(pfd2[i].fd, buffer, BUFSIZE, 0)) <= 0)
					continue;

				if (pfd2[i].fd==demux[demux_index].demux_ecm_fd) {
					//ECM

					if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
						continue;

					if (buffer[0] == 0x80 || buffer[0] == 0x81)
					{
						if (memcmp(buffer, demux[demux_index].buffer_cache_dmx, 12) != 0) {
							memcpy(demux[demux_index].buffer_cache_dmx, buffer, 12);
							cs_debug("Read %d bytes\tTable-id: %02x\tCA section length: %d", len, buffer[0], len);

							ECM_REQUEST *er;

							if (!(er=get_ecmtask()))
								continue;

							er->srvid = demux[demux_index].program_number;
							er->caid  = demux[demux_index].ca_system_id;
							er->prid  = demux[demux_index].provider_id;

							er->l=len;
							memcpy(er->ecm, buffer, er->l);

							get_cw(er);
						}
					}
				}
				if (pfd2[i].fd==demux[demux_index].demux_emm_fd) {
					dvbapi_process_emm(demux_index, buffer, len);
				}
			}
		}
	}

	cs_debug("dvbapi: Stop descrambling Thread %d", demux_index);

	pthread_detach(pthread_self());
	pthread_exit(0);
}



void dvbapi_resort_ecmpids(int demux_index)
{
	ECMPIDSTYPE tmppids[ECM_PIDS];
	ECMPIDSTYPE tmppids2[ECM_PIDS];

	int tmppidcount=0,tmppid2count=0,n;

	int i,k,j;

	for (i=0;i<MAX_CAID;i++)
		global_caid_list[i]=0;

	k=0;
	for (i=0;i<CS_MAXREADER;i++) {
		for (j=0;j<16;j++) {
			if (reader[i].caid[j] != 0) {
				if (k+1>=MAX_CAID) break;
				global_caid_list[k]=reader[i].caid[j];
				k++;				
			}
		}
	}
	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		if (dvbapi_check_array(ignoretab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[n].CA_System_ID)>=0) {
			cs_debug("-> ignore %04x", demux[demux_index].ECMpids[n].CA_System_ID);
		} else if (dvbapi_check_array(global_caid_list, MAX_CAID, demux[demux_index].ECMpids[n].CA_System_ID)>=0) {
			cs_debug("-> caid list %04x", demux[demux_index].ECMpids[n].CA_System_ID);
			tmppids[tmppidcount]=demux[demux_index].ECMpids[n];
			tmppidcount++;
		} else if (dvbapi_check_array(prioritytab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[n].CA_System_ID)>=0) {
			cs_debug("-> priority %04x", demux[demux_index].ECMpids[n].CA_System_ID);
			tmppids[tmppidcount]=demux[demux_index].ECMpids[n];
			tmppidcount++;
		} else {
			tmppids2[tmppid2count]=demux[demux_index].ECMpids[n];
			tmppid2count++;
		}
	}

	for (n=0;n<tmppid2count;n++) {
		tmppids[tmppidcount]=tmppids2[n];
		tmppidcount++;
	}

	for (n=0; n<tmppidcount; n++) {
		demux[demux_index].ECMpids[n]=tmppids[n];
	}

	demux[demux_index].ECMpidcount=tmppidcount;
	cs_debug("dvbapi: ECMpidscount is now %d", demux[demux_index].ECMpidcount);

	return;
}

void dvbapi_parse_descriptor(int demux_id, int i, unsigned int info_length, unsigned char *buffer) {
	//int ca_pmt_cmd_id = buffer[i + 5];
	unsigned int descriptor_length=0;
	ushort added,j,n;

	for (j = 0; j < info_length - 1; j += descriptor_length + 2) {
		descriptor_length = buffer[i + j + 7];
		int descriptor_ca_system_id = (buffer[i + j + 8] << 8) | buffer[i + j + 9];
		int descriptor_ca_pid = ((buffer[i + j + 10] & 0x1F) << 8) | buffer[i + j + 11];

		cs_debug("typ: %02x\tca_system_id: %04x\t ca_pid: %04x", buffer[i + j + 6], descriptor_ca_system_id, descriptor_ca_pid);

		if (buffer[i + j + 6] == 0x09) {
			added=0;
			for (n=0;n<demux[demux_id].ECMpidcount;n++) {
				if (demux[demux_id].ECMpids[n].CA_System_ID==descriptor_ca_system_id)
					added=1;
			}
			if (added==0) {
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CA_PID=descriptor_ca_pid;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CA_System_ID=descriptor_ca_system_id;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].EMM_PID=0;
				demux[demux_id].ECMpidcount++;
			}
		}
	}
}

// from tuxbox camd
int dvbapi_parse_capmt(unsigned char *buffer, unsigned int length)
{
	unsigned short i, u;
	unsigned short ca_mask=0x01, demux_index2=0x00;

	int ca_pmt_list_management = buffer[0];
	unsigned int program_number = (buffer[1] << 8) | buffer[2];
	int program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	switch (ca_pmt_list_management)
	{
		case 0x01:
			//(first)
			break;
		case 0x03:
			//default (only)
			break;
		case 0x04:
			//(add)
			break;
		default:
			//FIXME?? (unknown)
			break;
	}

	if (buffer[17]==0x82 && buffer[18]==0x02) {
		//enigma2
		ca_mask = buffer[19];
		demux_index2 = buffer[20];
	} else {
		//neutrino workaround
		dvbapi_stop_descrambling_all(0);
	}

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].demux_index==demux_index2 && demux[i].program_number==((buffer[1] << 8) | buffer[2])) { // already descrambling prog on this device
			if (demux[i].active==1) {
				//remove any inactive program
				for (u=0;u<MAX_DEMUX;u++) {
					if (demux[u].demux_index==demux_index2 && demux[u].active==0)
						dvbapi_stop_descrambling(u);
					demux[u].active=0;
				}
			} else
				demux[i].active=1;
			return 0;
		}
	}

	//get free id
	int demux_id=-1;
	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].program_number==0)
		{
			demux_id=i;
			break;
		}
	}

	if (demux_id<0) {
		cs_log("dvbapi: error no free id (MAX_DEMUX)");
		return 0;
	}

	cs_ddump(buffer, length, "capmt:");
	cs_log("dvbapi: new program number: %04x", program_number);
	//cs_debug("program_info_length: %d", program_info_length);

	demux[demux_id].program_number=((buffer[1] << 8) | buffer[2]);
	demux[demux_id].demux_index=demux_index2;
	demux[demux_id].ECMpidcount=0;
	demux[demux_id].STREAMpidcount=0;
	demux[demux_id].active=1;
	demux[demux_id].cadev_index=demux_index2;

	for (i=0;i<8;i++) {
		if (ca_mask & (1 << i)) {
			demux[demux_id].cadev_index=i;
			break;
       	}
	}

	cs_debug("dvbapi: demux index: %d ca index: %d", demux[demux_id].demux_index, demux[demux_id].cadev_index);

	//CA_PIDS for all streams
	if (program_info_length != 0) {
		dvbapi_parse_descriptor(demux_id, 1, program_info_length, buffer);
	}

	//CA_PIDs for a single stream
	unsigned int es_info_length=0;
	for (i = program_info_length + 6; i < length; i += es_info_length + 5)
	{
		int stream_type = buffer[i];
		unsigned short elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug("stream_type: %02x\telementary_pid: %04x\tes_info_length: %04x", stream_type, elementary_pid, es_info_length);

		demux[demux_id].STREAMpids[demux[demux_id].STREAMpidcount]=elementary_pid;
		demux[demux_id].STREAMpidcount++;

		if (es_info_length != 0) {
			dvbapi_parse_descriptor(demux_id, i, es_info_length, buffer);
		}
	}

	cs_debug("dvbapi: Found %d ECMpids and %d STREAMpids in PMT", demux[demux_id].ECMpidcount);

	if (demux[demux_id].ECMpidcount>0) {
		dvbapi_resort_ecmpids(demux_id);
		if (demux[demux_id].ECMpidcount>0) {
			pthread_t p3;
			if (pthread_create(&p3, NULL, thread_descrambling, (void*)demux_id))
				cs_log("dvbapi: pthread error");
		}
	}

	return 0;
}


void dvbapi_handlesockmsg (unsigned char *buffer, unsigned int len) {
	unsigned int val=0, size=0, i, k;

	//cs_dump(buffer, len, "handlesockmsg:");
	for (k = 0; k < len; k += 3 + size + val) {
		if (buffer[0+k] != 0x9F || buffer[1+k] != 0x80) {
			cs_log("dvbapi: unknown socket command: %02x", buffer[0+k]);
			return;
		}

		if (buffer[3+k] & 0x80) {
			val = 0;
			size = buffer[3+k] & 0x7F;
			for (i = 0; i < size; i++)
				val = (val << 8) | buffer[i + 1 + 3 + k];
			size++;
		} else	{
			val = buffer[3+k] & 0x7F;
			size = 1;
		}

		switch(buffer[2+k]) {
			case 0x32:
				dvbapi_parse_capmt(buffer + 3 + size, val);
				break;
			case 0x3f:
				//9F 80 3f 04 83 02 00 <demux index>
				cs_ddump(buffer, len, "capmt 3f:");
				int demux_index=buffer[7+k];
				dvbapi_stop_descrambling_all(demux_index);
				break;
			default:
				cs_log("dvbapi: handlesockmsg() unknown command");
				cs_dump(buffer, len, "unknown command:");
				break;
		}
	}
}

int dvbapi_init_listenfd() {
	int clilen;
	struct sockaddr_un servaddr;

	memset(&servaddr, 0, sizeof(struct sockaddr_un));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, devices[selected_box].cam_socket_path);
	clilen = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

	if ((unlink(devices[selected_box].cam_socket_path) < 0) && (errno != ENOENT))
		return 0;
	if ((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return 0;
	if (bind(listenfd, (struct sockaddr *) &servaddr, clilen) < 0)
		return 0;
	if (listen(listenfd, 5) < 0)
		return 0;

	return 1;
}

void *thread_check_zap(void *arg) {
	unsigned char buffer[BUFSIZE];
	struct sockaddr_un servaddr;
	ssize_t len;
	int connfd,clilen;

	while(1)
	{
		cs_sleepms(500);
		//cs_debug("dvbapi: check zap");

		connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);

		if (connfd <= 0) { //socket not available
			cs_debug("dvbapi: socket not available");
			break;
		}

		len = read(connfd, buffer, sizeof(buffer));

		if (len < 3) {
			cs_debug("dvbapi: camd.socket: too short message received");
			continue;
		}

		// if message begins with an apdu_tag and is longer than three bytes
		if ((buffer[0] == 0x9F) && ((buffer[1] >> 7) == 0x01) && ((buffer[2] >> 7) == 0x00)) {
			dvbapi_handlesockmsg(buffer, len);
		} else {
			cs_debug("dvbapi: invaild capmt");
		}

		close(connfd);

	}

	cs_log("dvbapi: check_zap() aborted");
	return 0;
}

void dvbapi_chk_caidtab(char *caidasc, CAIDTAB *ctab) {

	char *ptr1, *ptr3;
	int i;

	for (i=0, ptr1=strtok(caidasc, ","); (i<CS_MAXCAIDTAB) && (ptr1); ptr1=strtok(NULL, ","))
	{
		unsigned long caid, prov;
		if( (ptr3=strchr(trim(ptr1), ':')) )
			*ptr3++='\0';
		else
			ptr3="";

		if (((caid=a2i(ptr1, 2))|(prov=a2i(ptr3, 3))) < 0x10000)
		{
			ctab->caid[i]=caid;
			ctab->mask[i]=prov;
			i++;
		}
	}
}

int dvbapi_main_local()
{
	struct pollfd pfd2[1];
	int i,rc;
	pthread_t p1;

	if (cfg->dvbapi_usr[0]==0) {
	    //
	}

	if (cfg->dvbapi_boxtype[0]==0) {
		strncpy(cfg->dvbapi_boxtype, "dreambox", sizeof(cfg->dvbapi_boxtype)-1);
		cs_log("dvbapi: boxtype not set. Assume boxtype=%s.", cfg->dvbapi_boxtype);
	} else
		cs_log("dvbapi: boxtype=%s.", cfg->dvbapi_boxtype);

	for (i=0;i<MAX_DEMUX;i++)
	{
		demux[i].program_number=0;
		demux[i].demux_ecm_fd=0;
		demux[i].demux_emm_fd=0;
		demux[i].ca_system_id=0;
		demux[i].ca_pid=0;
		demux[i].emm_pid=0;
		demux[i].cadev_index=-1;
		demux[i].ca_fd=0;
		demux[i].demux_index=-1;
		memset(demux[i].buffer_cache_dmx,0 ,12);
	}

	dvbapi_detect_api();

	if (selected_box == -1 || selected_api==-1) {
		cs_log("dvbapi: could not detect api version");
		return 1;
	}

	if (!dvbapi_init_listenfd())
	{
		cs_log("dvbapi: could not init camd.socket.");
		return 1;
	}

	dvbapi_chk_caidtab(cfg->dvbapi_priority, &prioritytab);
	dvbapi_chk_caidtab(cfg->dvbapi_ignore, &ignoretab);

	pfd2[0].fd = fd_m2c;
	pfd2[0].events = (POLLIN | POLLPRI);

	pthread_create (&p1, NULL, thread_check_zap, NULL);

	struct timeb tp;
	cs_ftime(&tp);
	tp.time+=500;

	while (1) {
		if (master_pid!=getppid())
			cs_exit(0);

		chk_pending(tp);

		rc=poll(pfd2, 1, 1000);

		if (rc<0)
			break;

		if (pfd2[0].revents & (POLLIN | POLLPRI)) {
			chk_dcw(fd_m2c);

		}

	}
	return 0;
}


void dvbapi_send_dcw(ECM_REQUEST *er)
{
	unsigned char cw_0[8], cw_1[8];
	int i;
	unsigned char nullcw[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	cs_debug("dvbapi: ECM rc: %d", er->rc);

	memcpy(cw_0, er->cw, 8);
	memcpy(cw_1, er->cw+8, 8);

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].program_number==er->srvid) {
			if (er->rc<=2 && demux[i].ca_system_id==0 && er->caid!=0) {
				dvbapi_start_descrambling(i, er->caid, er->pid, er->prid);
			}

			if (er->rc==4 && cfg->dvbapi_au==1 && dvbapi_check_array(global_caid_list, MAX_CAID, er->caid)>=0) {
				//local card and not found -> maybe card need emm
				dvbapi_start_descrambling(i, er->caid, er->pid, er->prid);
			}

			if (er->rc>3) {
				cs_debug("dvbapi: cw not found");
				return;
			}

			ca_descr_t ca_descr;
			memset(&ca_descr,0,sizeof(ca_descr));

			if (demux[i].ca_fd<=0) {
				cs_log("dvbapi: could not write cw.");
				return;
			}

			if (memcmp(cw_0,demux[i].lastcw0,8)!=0 && memcmp(cw_0,nullcw,8)!=0) {
				ca_descr.index = i;
				ca_descr.parity = 0;
				memcpy(demux[i].lastcw0,cw_0,8);
				memcpy(ca_descr.cw,cw_0,8);
				cs_debug("dvbapi: write cw1 index: %d", i);
				if (ioctl(demux[i].ca_fd, CA_SET_DESCR, &ca_descr) < 0)
					cs_debug("dvbapi: Error CA_SET_DESCR");
			}

			if (memcmp(cw_1,demux[i].lastcw1,8)!=0 && memcmp(cw_1,nullcw,8)!=0) {
				ca_descr.index = i;
				ca_descr.parity = 1;
				memcpy(demux[i].lastcw1,cw_1,8);
				memcpy(ca_descr.cw,cw_1,8);
				cs_debug("dvbapi: write cw2 index: %d", i);
				if (ioctl(demux[i].ca_fd, CA_SET_DESCR, &ca_descr) < 0)
					cs_debug("dvbapi: Error CA_SET_DESCR");
			}
		}
	}
}

static void dvbapi_handler(int idx)
{
	static struct s_auth *account=0;

	if (cfg->dvbapi_enabled != 1) {
		cs_log("dvbapi disabled");
		return;
	}

	//cs_log("dvbapi loaded fd=%d", idx);

	switch(cs_fork(0, idx))
	{
		case  0: //master
		case -1:
			return;
		default:
			wait4master();
	}

	int ok=0;
	if( !account )
	{
		client[cs_idx].usr[0]=0;
		for (ok=0, account=cfg->account; (account) && (!ok); account=account->next)
			if( (ok=!strcmp(cfg->dvbapi_usr, account->usr)) )
				break;
	}

	cs_auth_client(ok ? account : (struct s_auth *)(-1), "unknown");

	dvbapi_main_local();

	cs_log("Module dvbapi error");
	cs_exit(0);

	return;
}



/*
 *	protocol structure
 */

void module_dvbapi(struct s_module *ph)
{
	strcpy(ph->desc, "dvbapi");
	ph->type=MOD_CONN_SERIAL;
	ph->multi=1;
	ph->watchdog=0;
	ph->s_handler=dvbapi_handler;
	ph->send_dcw=dvbapi_send_dcw;
}
#endif // HAVE_DVBAPI
