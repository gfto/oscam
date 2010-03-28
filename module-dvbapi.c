#include "globals.h"

#ifdef HAVE_DVBAPI

#include <sys/un.h>

#define MAX_DEMUX 5
#define MAX_CAID 50
#define ECM_PIDS 20
#define MAX_FILTER 10

#define TYPE_ECM 0
#define TYPE_EMM 1

typedef struct ECMPIDS
{
	unsigned short CA_PID;
	unsigned short CA_System_ID;
	unsigned short EMM_PID;
	//unsigned int provider_id;
	unsigned short checked;
} ECMPIDSTYPE;

typedef struct filter_s
{
	int fd;
	ushort PID;
	ushort CA_System_ID;
	ushort type;
} FILTERTYPE;

typedef struct demux_s
{
	unsigned short demux_index;
	FILTERTYPE demux_fd[MAX_FILTER];
	unsigned short cadev_index;
	int ca_fd;
	int socket_fd;
	unsigned short ECMpidcount;
	ECMPIDSTYPE ECMpids[ECM_PIDS];
	int pidindex;
	unsigned short program_number;
	unsigned short STREAMpidcount;
	unsigned short STREAMpids[ECM_PIDS];
	unsigned char buffer_cache_dmx[CS_ECMSTORESIZE];
	unsigned char lastcw[2][8];
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

#define BOX_COUNT 3
struct box_devices
{
	char ca_device_path[32];
	char demux_device_path[32];
	char cam_socket_path[32];
};

struct box_devices devices[BOX_COUNT] = {
	/* QboxHD (dvb-api-3)*/	{ "/tmp/virtual_adapter/ca%d", "/tmp/virtual_adapter/demux%d", "/tmp/camd.socket" },
	/* dreambox (dvb-api-3)*/	{ "/dev/dvb/adapter0/ca%d", "/dev/dvb/adapter0/demux%d", "/var/tmp/camd.socket" },
	/* dreambox (dvb-api-1)*/	{ "/dev/dvb/card0/ca%d", "/dev/dvb/card0/demux%d", "/var/tmp/camd.socket" }
};

int selected_box=-1;
int selected_api=-1;

int dvbapi_set_filter(int dmx_fd, int api, unsigned short pid, uchar *filt, uchar *mask, int timeout) {
	int ret=-1;

	cs_debug("dvbapi: set filter pid:%04x", pid);

	switch(api)
	{
		case 0:
			api=api;
			struct dmx_sct_filter_params sFP2;

			memset(&sFP2,0,sizeof(sFP2));

			sFP2.pid			= pid;
			sFP2.timeout			= timeout;
			sFP2.flags			= DMX_IMMEDIATE_START;
			memcpy(sFP2.filter.filter,filt,16);
			memcpy(sFP2.filter.mask,mask,16);
			ret=ioctl(dmx_fd, DMX_SET_FILTER, &sFP2);

			break;
		case 1:
			api=api;
			struct dmxSctFilterParams sFP1;

			memset(&sFP1,0,sizeof(sFP1));

			sFP1.pid			= pid;
			sFP1.timeout			= timeout;
			sFP1.flags			= DMX_IMMEDIATE_START;
			memcpy(sFP1.filter.filter,filt,16);
			memcpy(sFP1.filter.mask,mask,16);
			ret=ioctl(dmx_fd, DMX_SET_FILTER1, &sFP1);

			break;
		default:
			break;
	}

	if (ret < 0)
		cs_debug("dvbapi: could not start demux filter (Errno: %d)", errno);

	return ret;
}

int dvbapi_check_array(unsigned short *array, int len, unsigned short match) {
	int i;
	for (i=0; i<len; i++) {
		if (array[i]==match) {
			return i;
		}
	}
	return -1;
}

int dvbapi_detect_api() {
	int num_apis=2;
	int i,devnum=-1;
	int apinum=-1;
	int dmx_fd=0;
	uchar filter[16], filtermask[16];

	memset(filter,0,16);
	memset(filtermask,0,16);
	filter[0]=0x01;
	filtermask[0]=0xFF;

	char device_path[128];

	for (i=0;i<BOX_COUNT;i++) {
		sprintf(device_path, devices[i].demux_device_path, 0);
		if ((dmx_fd = open(device_path, O_RDWR)) > 0) {
			devnum=i;
			break;
		}
	}

	if (dmx_fd < 0) return 0;

	int ret=-1;

	for (i=0;i<num_apis;i++) {
		ret=dvbapi_set_filter(dmx_fd, i, 0x0001, filter, filtermask, 1);

		if (ret >= 0)
		{
			apinum=i;
			break;
		}
	}
	close(dmx_fd);

	if (ret < 0) return 0;

	selected_box=devnum;
	selected_api=apinum;
	cs_debug("dvbapi: Detected %s Api: %d", device_path, apinum);

	return 1;
}

int dvbapi_read_device(int dmx_fd, unsigned char *buf, int length, int debug) {
	int len, rc;
	struct pollfd pfd[1];

	pfd[0].fd = dmx_fd;
	pfd[0].events = (POLLIN | POLLPRI);

	rc = poll(pfd, 1, 1000);
	if (rc<1)
		return -1;

	len = read(dmx_fd, buf, length);

	if (len==-1)
		cs_log("dvbapi: read error %d on fd %d", errno, dmx_fd);

	if (debug==1)
		cs_debug("dvbapi: Read %d bytes from demux", len);

	return len;
}

int dvbapi_open_device(int index_demux, int type) {
	int dmx_fd,i;
	int ca_offset=0;
	char device_path[128];

	if (type==0)
		sprintf(device_path, devices[selected_box].demux_device_path, demux[index_demux].demux_index);
	else {
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

	cs_debug("dvbapi: DEVICE open (%s) fd %d", device_path, dmx_fd);
	return dmx_fd;
}

int dvbapi_stop_filter(int demux_index, int type) {
	int g;

	for (g=0;g<MAX_FILTER;g++) {
		if (demux[demux_index].demux_fd[g].fd>0 && demux[demux_index].demux_fd[g].type==type) {
			ioctl(demux[demux_index].demux_fd[g].fd,DMX_STOP);
			close(demux[demux_index].demux_fd[g].fd);
			demux[demux_index].demux_fd[g].fd=0;
		}
	}

	return 1;
}

void dvbapi_start_filter(int demux_index, ushort caid, unsigned short pid, uchar table, uchar mask, int type) {
	int dmx_fd,i,n=-1;
	uchar filter[32];

	for (i=0;i<MAX_FILTER;i++) {
		if (demux[demux_index].demux_fd[i].fd<=0) {
			n=i;
			break;
		}
	}

	if (n==-1) {
		cs_log("dvbapi: no free filter");
		return;
	}

	dmx_fd=dvbapi_open_device(demux_index, 0);

	demux[demux_index].demux_fd[n].fd=dmx_fd;
	demux[demux_index].demux_fd[n].CA_System_ID=caid;
	demux[demux_index].demux_fd[n].PID=pid;
	demux[demux_index].demux_fd[n].type=type;

	memset(filter,0,32);

	filter[0]=table;
	filter[16]=mask;

	dvbapi_set_filter(dmx_fd, selected_api, pid, filter, filter+16, 4000);
}

void dvbapi_start_emm_filter(int demux_index, int emmtype, int type) {
	int dmx_fd,i,n=-1;
	uchar filter[32];

	if (demux[demux_index].pidindex==-1) return;

	ushort caid = demux[demux_index].ECMpids[demux[demux_index].pidindex].CA_System_ID;
	ushort pid  = demux[demux_index].ECMpids[demux[demux_index].pidindex].EMM_PID;

	int found=0;
	for (i=0;i<CS_MAXREADER;i++) {
		if (reader[i].caid[0] == demux[demux_index].ECMpids[demux[demux_index].pidindex].CA_System_ID) {
			client[cs_idx].au=i;
			found=1;
			break;
		}
	}

	switch(reader[client[cs_idx].au].card_system) {
		default:
			if (emmtype!=GLOBAL) return;
			memset(filter,0,32);
			filter[0]=0x80;
			filter[0+16]=0xF0;
			break;
	}

	for (i=0;i<MAX_FILTER;i++) {
		if (demux[demux_index].demux_fd[i].fd<=0) {
			n=i;
			break;
		}
	}

	if (n==-1) {
		cs_log("dvbapi: no free filter");
		return;
	}

	dmx_fd=dvbapi_open_device(demux_index, 0);

	demux[demux_index].demux_fd[n].fd=dmx_fd;
	demux[demux_index].demux_fd[n].CA_System_ID=caid;
	demux[demux_index].demux_fd[n].PID=pid;
	demux[demux_index].demux_fd[n].type=type;

	cs_ddump(filter, 32, "demux filter:");
	dvbapi_set_filter(dmx_fd, selected_api, pid, filter, filter+16, 0);
}

void dvbapi_parse_cat(int demux_index, uchar *buf, int len) {
	unsigned short i, j;

	cs_ddump(buf, len, "cat:");

	for (i = 8; i < (((buf[1] & 0x0F) << 8) | buf[2]) - 1; i += buf[i + 1] + 2) {
		if (buf[i] != 0x09) continue;
		unsigned short cat_sys_id=(((buf[i + 2] & 0x1F) << 8) | buf[i + 3]);
		unsigned short emm_pid=(((buf[i + 4] & 0x1F) << 8) | buf[i + 5]);
		cs_debug("cat: ca_system_id: %04x\temm_pid %04x", cat_sys_id, emm_pid);
		for (j=0;j<demux[demux_index].ECMpidcount;j++) {
			if (demux[demux_index].ECMpids[j].CA_System_ID==(((buf[i + 2] & 0x1F) << 8) | buf[i + 3])) {
				demux[demux_index].ECMpids[j].EMM_PID=emm_pid;
			}
		}
	}
	return;
}

void dvbapi_stop_descrambling(int demux_id) {
	int i;

	demux[demux_id].demux_index=-1;
	demux[demux_id].program_number=0;
	demux[demux_id].socket_fd=0;
	demux[demux_id].pidindex=-1;

	dvbapi_stop_filter(demux_id, TYPE_ECM);
	dvbapi_stop_filter(demux_id, TYPE_EMM);

	memset(demux[demux_id].buffer_cache_dmx, 0, CS_ECMSTORESIZE);

	if (demux[demux_id].ca_fd>0) {
		for (i=0;i<demux[demux_id].STREAMpidcount;i++) {
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

	unlink("/tmp/ecm.info");

	return;
}

void dvbapi_start_descrambling(int demux_index, unsigned short caid, unsigned short pid) {
	int i,n;

	cs_log("dvbapi: Start descrambling CAID: %04x", caid);

	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		if (demux[demux_index].ECMpids[n].CA_System_ID==caid && demux[demux_index].ECMpids[n].CA_PID==pid) {
			demux[demux_index].pidindex=n;
			break;
		}
	}

	demux[demux_index].ca_fd = dvbapi_open_device(demux_index,1);
	if (demux[demux_index].ca_fd<=0)
		return;

	for (i=0;i<demux[demux_index].STREAMpidcount;i++) {
		ca_pid_t ca_pid2;
		memset(&ca_pid2,0,sizeof(ca_pid2));
		ca_pid2.pid = demux[demux_index].STREAMpids[i];
		ca_pid2.index = demux_index;
		if (ioctl(demux[demux_index].ca_fd, CA_SET_PID, &ca_pid2)==-1)
			cs_debug("dvbapi: Error Stream SET_PID");
	}

	if (cfg->dvbapi_au==1)
		dvbapi_start_filter(demux_index, caid, 0x001, 0x01, 0xFF, TYPE_EMM); //CAT
}

void dvbapi_process_emm (int demux_index, unsigned char *buffer, unsigned int len) {
	int i;
	EMM_PACKET epg;

	if (demux[demux_index].pidindex==-1) return;
	cs_ddump(buffer, 16, "emm:");

	//force emm output
	reader[ridx].logemm=9999;

	memset(&epg, 0, sizeof(epg));
	epg.caid[0] = (uchar)(demux[demux_index].ECMpids[demux[demux_index].pidindex].CA_System_ID>>8);
	epg.caid[1] = (uchar)(demux[demux_index].ECMpids[demux[demux_index].pidindex].CA_System_ID);

	unsigned long provid = (buffer[10] << 8) | buffer[11];
	int pid = dvbapi_check_array(cfg->dvbapi_prioritytab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[demux[demux_index].pidindex].CA_System_ID);
	if (pid>=0) {
		if (cfg->dvbapi_prioritytab.mask[pid]>0)
			provid = (cfg->dvbapi_prioritytab.cmap[pid] << 8 | cfg->dvbapi_prioritytab.mask[pid]);
	}

	epg.provid[1] = (uchar)(provid>>16);
	epg.provid[2] = (uchar)(provid>>8);
	epg.provid[3] = (uchar)(provid);

	epg.l=len;
	memcpy(epg.emm, buffer, epg.l);
/*
	int found=0;
	for (i=0;i<CS_MAXREADER;i++) {
		if (reader[i].caid[0] == demux[demux_index].ECMpids[demux[demux_index].pidindex].CA_System_ID) {
			client[cs_idx].au=i;
			found=1;
			break;
		}
	}
*/
	//if (found==1 && reader[client[cs_idx].au].card_system>0) {
	do_emm(&epg);
	//}

}

void dvbapi_resort_ecmpids(int demux_index) {
	ECMPIDSTYPE tmppids[ECM_PIDS],tmppids2[ECM_PIDS];
	int tmppidcount=0,tmppid2count=0,n,i,k=0,j;

	for (i=0;i<MAX_CAID;i++)
		global_caid_list[i]=0;

	for (i=0;i<CS_MAXREADER;i++) {
		for (j=0;j<CS_MAXREADER;j++) {
			if (reader[i].caid[j] != 0 && reader[i].card_system > 0) {
				if (k+1>=MAX_CAID) break;
				global_caid_list[k++]=reader[i].caid[j];	
			}
		}
	}
	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		if (dvbapi_check_array(cfg->dvbapi_ignoretab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[n].CA_System_ID)>=0) {
			cs_debug("-> ignore %04x", demux[demux_index].ECMpids[n].CA_System_ID);
		} else if (dvbapi_check_array(global_caid_list, MAX_CAID, demux[demux_index].ECMpids[n].CA_System_ID)>=0) {
			cs_debug("-> caid list %04x", demux[demux_index].ECMpids[n].CA_System_ID);
			tmppids[tmppidcount++]=demux[demux_index].ECMpids[n];
		} else if (dvbapi_check_array(cfg->dvbapi_prioritytab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[n].CA_System_ID)>=0) {
			cs_debug("-> priority %04x", demux[demux_index].ECMpids[n].CA_System_ID);
			tmppids[tmppidcount++]=demux[demux_index].ECMpids[n];
		} else {
			tmppids2[tmppid2count++]=demux[demux_index].ECMpids[n];
		}
	}

	for (n=0;n<tmppid2count;n++)
		tmppids[tmppidcount++]=tmppids2[n];
	
	for (n=0; n<tmppidcount; n++)
		demux[demux_index].ECMpids[n]=tmppids[n];

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
				if (demux[demux_id].ECMpids[n].CA_System_ID==descriptor_ca_system_id && demux[demux_id].ECMpids[n].CA_PID==descriptor_ca_pid)
					added=1;
			}
			if (added==0) {
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CA_PID=descriptor_ca_pid;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CA_System_ID=descriptor_ca_system_id;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].checked=0;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount++].EMM_PID=0;
			}
		}
	}
}

// from tuxbox camd
int dvbapi_parse_capmt(unsigned char *buffer, unsigned int length, int connfd) {
	unsigned short i;
	unsigned short ca_mask=0x01, demux_index2=0x00;

	//int ca_pmt_list_management = buffer[0];
	unsigned int program_number = (buffer[1] << 8) | buffer[2];
	int program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	if (buffer[17]==0x82 && buffer[18]==0x02) {
		//enigma2
		ca_mask = buffer[19];
		demux_index2 = buffer[20];
	}

	//get free id
	int demux_id=-1;
	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].program_number==0) {
			demux_id=i;
			break;
		}
	}

	if (demux_id<0) {
		cs_log("dvbapi: error no free id (MAX_DEMUX)");
		return -1;
	}

	cs_ddump(buffer, length, "capmt:");

	demux[demux_id].program_number=((buffer[1] << 8) | buffer[2]);
	demux[demux_id].demux_index=demux_index2;
	demux[demux_id].ECMpidcount=0;
	demux[demux_id].STREAMpidcount=0;
	demux[demux_id].cadev_index=demux_index2;
	demux[demux_id].socket_fd=connfd;

	for (i=0;i<8;i++) {
		if (ca_mask & (1 << i)) {
			demux[demux_id].cadev_index=i;
			break;
       	}
	}
	cs_debug("dvbapi: id: %d demux index: %d ca index: %d", demux_id, demux[demux_id].demux_index, demux[demux_id].cadev_index);

	if (program_info_length != 0) {
		dvbapi_parse_descriptor(demux_id, 1, program_info_length, buffer);
	}

	unsigned int es_info_length=0;
	for (i = program_info_length + 6; i < length; i += es_info_length + 5) {
		int stream_type = buffer[i];
		unsigned short elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug("stream_type: %02x\telementary_pid: %04x\tes_info_length: %04x", stream_type, elementary_pid, es_info_length);

		demux[demux_id].STREAMpids[demux[demux_id].STREAMpidcount++]=elementary_pid;

		if (es_info_length != 0) {
			dvbapi_parse_descriptor(demux_id, i, es_info_length, buffer);
		}
	}
	cs_debug("dvbapi: Found %d ECMpids and %d STREAMpids in PMT", demux[demux_id].ECMpidcount, demux[demux_id].STREAMpidcount);

	if (demux[demux_id].ECMpidcount>0) {
		char *name = get_servicename(demux[demux_id].program_number, demux[demux_id].ECMpids[0].CA_System_ID);
		cs_log("dvbapi: new program number: %04X (%s)", program_number, name);
		dvbapi_resort_ecmpids(demux_id);
		if (demux[demux_id].ECMpidcount>0) {
			cs_debug("dvbapi: trying CA_System_ID: %04x CA_PID: %04x", demux[demux_id].ECMpids[0].CA_System_ID, demux[demux_id].ECMpids[0].CA_PID);

			dvbapi_start_filter(demux_id, demux[demux_id].ECMpids[0].CA_System_ID, demux[demux_id].ECMpids[0].CA_PID, 0x80, 0xF0, TYPE_ECM);
			
			demux[demux_id].ECMpids[0].checked=1;
		}
	} else
		cs_log("dvbapi: new program number: %04X", program_number);

	return demux_id;
}


void dvbapi_handlesockmsg (unsigned char *buffer, unsigned int len, int connfd) {
	unsigned int val=0, size=0, i, k;

	//cs_dump(buffer, len, "handlesockmsg:");
	for (k = 0; k < len; k += 3 + size + val) {
		if (buffer[0+k] != 0x9F || buffer[1+k] != 0x80) {
			cs_log("dvbapi: unknown socket command: %02x", buffer[0+k]);
			return;
		}

		if (k>0) {
			cs_log("dvbapi: Unsupported capmt. Please report");
			cs_dump(buffer, len, "capmt:");
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
				dvbapi_parse_capmt(buffer + size + 3 + k, val, connfd);
				break;
			case 0x3f:
				//9F 80 3f 04 83 02 00 <demux index>
				cs_ddump(buffer, len, "capmt 3f:");
				//int demux_index=buffer[7+k];
				//dvbapi_stop_descrambling_all(demux_index);
				close(connfd);
				break;
			default:
				cs_log("dvbapi: handlesockmsg() unknown command");
				cs_dump(buffer, len, "unknown command:");
				break;
		}
	
	}
}

int dvbapi_init_listenfd() {
	int clilen,listenfd;
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

	return listenfd;
}

void dvbapi_chk_caidtab(char *caidasc, CAIDTAB *ctab) {
	char *ptr1, *ptr3;
	int i;

	for (i=0, ptr1=strtok(caidasc, ","); (i<CS_MAXCAIDTAB) && (ptr1); ptr1=strtok(NULL, ",")) {
		unsigned long caid, prov;
		if( (ptr3=strchr(trim(ptr1), ':')) )
			*ptr3++='\0';
		else
			ptr3="";

		if (((caid=a2i(ptr1, 2))|(prov=a2i(ptr3, 3))))
		{
			ctab->caid[i]=caid;
			ctab->cmap[i]=prov >> 8;
			ctab->mask[i++]=prov;
		}
	}
}

time_t pmt_timestamp=0;
int pmt_id=-1, dir_fd=-1;

void event_handler(int signal) {
	struct stat pmt_info;
	uchar inhalt[400], dest[200];
	uint len;
	signal=signal;
	int pmt_fd = open("/tmp/pmt.tmp", O_RDONLY);
	if(pmt_fd>0) {
		if (fstat(pmt_fd, &pmt_info) == 0) {
			if (pmt_info.st_mtime == pmt_timestamp) {
				close(pmt_fd);
				return;
			}

			if (pmt_id > -1) {
				dvbapi_stop_descrambling(pmt_id);
				fcntl(dir_fd, F_NOTIFY, 0);
				close(dir_fd);
				close(pmt_fd);
				return;
			}

			pmt_timestamp = pmt_info.st_mtime;

			cs_sleepms(100);

			len = read(pmt_fd,inhalt,sizeof(inhalt));
			if (len<1) return;
#ifdef QBOXHD
			uint j1,j2;
			// QboxHD pmt.tmp is the full capmt written as a string of hex values
			// pmt.tmp must be longer than 3 bytes (6 hex chars) and even length
			if ((len<6) || ((len%2) != 0)) {
				cs_log("dvbapi: error parsing QboxHD pmt.tmp, incorrect length");
				return;
			}

			for(j2=0,j1=0;j2<len;j2+=2,j1++) {
				if (sscanf((char*)inhalt+j2,"%02X",(uint*)dest+j1) != 1) {
					cs_log("dvbapi: error parsing QboxHD pmt.tmp, data not valid in position %d",j2);
					return;
				}
			}

			cs_ddump(dest,len/2,"QboxHD pmt.tmp:");

			pmt_id = dvbapi_parse_capmt(dest+4, (len/2)-4, -1);
#else
			cs_ddump(inhalt,len,"pmt:");
		
			memcpy(dest, "\x00\xFF\xFF\x00\x00\x13\x00", 7);
			
			dest[1] = inhalt[3];
			dest[2] = inhalt[4];
			dest[5] = inhalt[11]+1;
		
			memcpy(dest + 7, inhalt + 12, len - 12 - 4);

			pmt_id = dvbapi_parse_capmt(dest, 7 + len - 12 - 4, -1);
#endif
			close(pmt_fd);
		}
	} else {
		if (pmt_id > -1)
			dvbapi_stop_descrambling(pmt_id);

		fcntl(dir_fd, F_NOTIFY, 0);
		close(dir_fd);
	}
}


void dvbapi_main_local() {
	int maxpfdsize=(MAX_DEMUX*MAX_FILTER)+MAX_DEMUX+2;
	struct pollfd pfd2[maxpfdsize];
	int i,rc,pfdcount,g,listenfd,connfd,clilen,j;
	unsigned char md5buf[CS_ECMSTORESIZE];
	int ids[maxpfdsize], fdn[maxpfdsize], type[maxpfdsize];
	struct timeb tp;
	struct sockaddr_un servaddr;
	ssize_t len=0;

	if (cfg->dvbapi_boxtype[0]==0) {
		strncpy(cfg->dvbapi_boxtype, "dreambox", sizeof(cfg->dvbapi_boxtype)-1);
		cs_log("dvbapi: boxtype not set. Assume boxtype=%s.", cfg->dvbapi_boxtype);
	} else
		cs_log("dvbapi: boxtype=%s.", cfg->dvbapi_boxtype);

	for (i=0;i<MAX_DEMUX;i++) {
		demux[i].program_number=0;
		demux[i].pidindex=-1;
		demux[i].cadev_index=-1;
		demux[i].ca_fd=0;
		demux[i].demux_index=-1;
		demux[i].socket_fd=0;
		memset(demux[i].buffer_cache_dmx, 0, CS_ECMSTORESIZE);
		for (rc=0;rc<MAX_FILTER;rc++) demux[i].demux_fd[rc].fd=0;
	}

	dvbapi_detect_api();

	if (selected_box == -1 || selected_api==-1) {
		cs_log("dvbapi: could not detect api version");
		return;
	}

	listenfd=dvbapi_init_listenfd();
	if (listenfd<1) {
		cs_log("dvbapi: could not init camd.socket.");
		return;
	}

	int pmt_fd = open("/tmp/pmt.tmp", O_RDONLY);
	if(pmt_fd>0) {
		struct sigaction signal_action;
		signal_action.sa_handler = event_handler;
		sigemptyset(&signal_action.sa_mask);
		signal_action.sa_flags = 0;
		sigaction(SIGRTMIN + 1, &signal_action, NULL);
	
		dir_fd = open("/tmp/", O_RDONLY);
		if (dir_fd >= 0) {
			fcntl(dir_fd, F_SETSIG, SIGRTMIN + 1);
			fcntl(dir_fd, F_NOTIFY, DN_MODIFY | DN_CREATE | DN_DELETE | DN_MULTISHOT);
			event_handler(SIGRTMIN + 1);
		}
		close(pmt_fd);
	}

	cs_ftime(&tp);
	tp.time+=500;

	pfd2[0].fd = fd_m2c;
	pfd2[0].events = (POLLIN | POLLPRI);
	type[0]=0;

	pfd2[1].fd = listenfd;
	pfd2[1].events = (POLLIN | POLLPRI);
	type[1]=1;

	while (1) {
		if (master_pid!=getppid())
			cs_exit(0);

		pfdcount=2;

		chk_pending(tp);

		for (i=0;i<MAX_DEMUX;i++) {
			for (g=0;g<MAX_FILTER;g++) {
				if (demux[i].demux_fd[g].fd>0) {
					pfd2[pfdcount].fd = demux[i].demux_fd[g].fd;
					pfd2[pfdcount].events = (POLLIN | POLLPRI);
					ids[pfdcount]=i;
					fdn[pfdcount]=g;
					type[pfdcount++]=0;
				}
			}
		
			if (demux[i].socket_fd>0) {
				pfd2[pfdcount].fd=demux[i].socket_fd;
				pfd2[pfdcount].events = (POLLIN | POLLPRI | POLLHUP);
				type[pfdcount++]=1;
			}
		}

		rc = poll(pfd2, pfdcount, 500);
	
		if (rc<1) continue;

		for (i = 0; i < pfdcount; i++) {
			if (pfd2[i].revents > 3)
				cs_debug("dvbapi: event %d on fd %d", pfd2[i].revents, pfd2[i].fd);
			
			if (pfd2[i].revents & (POLLHUP | POLLNVAL)) {
				if (type[i]==1) {
					for (j=0;j<MAX_DEMUX;j++) {
						if (demux[j].socket_fd==pfd2[i].fd) {
							cs_debug("dvbapi: closing socket (demux_index: %d)", j);
							dvbapi_stop_descrambling(j);
						}					
					}
					close(pfd2[i].fd);
					continue;
				}
			}
			if (pfd2[i].revents & (POLLIN | POLLPRI)) {
				if (pfd2[i].fd==fd_m2c) {
					chk_dcw(fd_m2c);
					continue;
				}

				if (type[i]==1) {
					if (pfd2[i].fd==listenfd) {
						cs_debug("dvbapi: new socket connection");
						connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);

						if (connfd <= 0) {
							cs_log("dvbapi: accept() returns error %d, fd event %d", errno, pfd2[i].revents);
							continue;
						}

						len = read(connfd, mbuf, sizeof(mbuf));

						if (len < 3) {
							cs_debug("dvbapi: camd.socket: too short message received");
							continue;
						}

						// if message begins with an apdu_tag and is longer than three bytes
						if ((mbuf[0] == 0x9F) && ((mbuf[1] >> 7) == 0x01) && ((mbuf[2] >> 7) == 0x00))
							dvbapi_handlesockmsg(mbuf, len, connfd);
						else
							cs_debug("dvbapi: invaild capmt");
					} else {
						cs_log("dvbapi: New capmt on old socket. Please report.");
						len = read(pfd2[i].fd, mbuf, sizeof(mbuf));
						cs_dump(mbuf, len, "message:");
					}
				} else { // type==0
					if ((len=dvbapi_read_device(pfd2[i].fd, mbuf, sizeof(mbuf), 0)) <= 0)
						continue;

					int demux_index=ids[i];
					int n=fdn[i];

					if (pfd2[i].fd==demux[demux_index].demux_fd[n].fd) {
						if (demux[demux_index].demux_fd[n].type==TYPE_ECM) {
							if (len != (((mbuf[1] & 0xf) << 8) | mbuf[2]) + 3) //invaild CAT length
								continue;

							if (mbuf[0] != 0x80 && mbuf[0] != 0x81) 
								continue;

							memcpy(md5buf, MD5(mbuf, len, NULL), CS_ECMSTORESIZE);

							if (memcmp(md5buf, demux[demux_index].buffer_cache_dmx, CS_ECMSTORESIZE) != 0) {
								memcpy(demux[demux_index].buffer_cache_dmx, md5buf, CS_ECMSTORESIZE);
								
								unsigned long provid=0;
								int pid = dvbapi_check_array(cfg->dvbapi_prioritytab.caid, CS_MAXCAIDTAB, demux[demux_index].demux_fd[n].CA_System_ID);
								if (pid>=0) {
									if (cfg->dvbapi_prioritytab.mask[pid]>0)
										provid = (cfg->dvbapi_prioritytab.cmap[pid] << 8 | cfg->dvbapi_prioritytab.mask[pid]);
								}
	
								ECM_REQUEST *er;
								if (!(er=get_ecmtask()))
									continue;

								er->srvid = demux[demux_index].program_number;
								er->caid  = demux[demux_index].demux_fd[n].CA_System_ID;
								er->pid   = demux[demux_index].demux_fd[n].PID;
								er->prid  = provid;

								er->l=len;
								memcpy(er->ecm, mbuf, er->l);
								get_cw(er);
							}
						}
						if (demux[demux_index].demux_fd[n].type==TYPE_EMM) {
							if (mbuf[0]==0x01) { //CAT
								cs_debug("dvbapi: receiving cat");
								dvbapi_parse_cat(demux_index, mbuf, len);

								if (demux[demux_index].pidindex < 0)
									continue;
								
								dvbapi_stop_filter(demux_index, TYPE_EMM);
								if (cfg->dvbapi_au==0)
									continue;
								
								dvbapi_start_emm_filter(demux_index, SHARED, TYPE_EMM);
								dvbapi_start_emm_filter(demux_index, GLOBAL, TYPE_EMM);
								//dvbapi_start_emm_filter(demux_index, UNIQUE, TYPE_EMM);
								continue;
							}
							cs_debug("EMM Filter fd %d", demux[demux_index].demux_fd[n].fd);
							dvbapi_process_emm(demux_index, mbuf, len);
						}
					}
				}
			}
		}
	}
	return;
}

void dvbapi_send_dcw(ECM_REQUEST *er) {
	int i,n;
	unsigned char nullcw[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	ca_descr_t ca_descr;

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].program_number==er->srvid) {
			if (er->rc<=3 && demux[i].pidindex==-1 && er->caid!=0) {
				dvbapi_start_descrambling(i, er->caid, er->pid);
			}

			if (er->rc==4 && cfg->dvbapi_au==1 && dvbapi_check_array(global_caid_list, MAX_CAID, er->caid)>=0) {
				//local card and not found -> maybe card need emm
				dvbapi_start_descrambling(i, er->caid, er->pid);
			}

			if (er->rc>3 && demux[i].pidindex==-1) {
				for (n=0; n<demux[i].ECMpidcount; n++) {
					if (demux[i].ECMpids[n].checked==0) {
						dvbapi_stop_filter(i, TYPE_ECM);
						cs_debug("dvbapi: trying CA_System_ID: %04x CA_PID: %04x", demux[i].ECMpids[n].CA_System_ID, demux[i].ECMpids[n].CA_PID);

						//grep ecm
						dvbapi_start_filter(i, demux[i].ECMpids[n].CA_System_ID, demux[i].ECMpids[n].CA_PID, 0x80,0xF0,TYPE_ECM); //ECM
						demux[i].ECMpids[n].checked=1;
						break;
					}
				}
				return;
			}

			if (er->rc>3) {
				cs_debug("dvbapi: cw not found");
				return;
			}

			memset(&ca_descr,0,sizeof(ca_descr));

			if (demux[i].ca_fd<=0) {
				cs_log("dvbapi: could not write cw.");
				demux[i].ca_fd = dvbapi_open_device(i,1);
				if (demux[i].ca_fd<=0)
					return;
			}

			for (n=0;n<2;n++) {
				if (memcmp(er->cw+(n*8),demux[i].lastcw[n],8)!=0 && memcmp(er->cw+(n*8),nullcw,8)!=0) {
					ca_descr.index = i;
					ca_descr.parity = n;
					memcpy(demux[i].lastcw[n],er->cw+(n*8),8);
					memcpy(ca_descr.cw,er->cw+(n*8),8);
					cs_debug("dvbapi: write cw%d index: %d", n, i);
					if (ioctl(demux[i].ca_fd, CA_SET_DESCR, &ca_descr) < 0)
						cs_debug("dvbapi: Error CA_SET_DESCR");
				}
			}

			FILE *ecmtxt;
			ecmtxt = fopen("/tmp/ecm.info", "w");
			if(ecmtxt != NULL) {
				fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
				fprintf(ecmtxt, "reader: %s\n", reader[er->reader[0]].label);
				if (reader[er->reader[0]].typ & R_IS_CASCADING)
					fprintf(ecmtxt, "from: %s\n", reader[er->reader[0]].device);
				fprintf(ecmtxt, "protocol: %d\n", reader[er->reader[0]].typ);
				//if (reader[er->reader[0]].typ == R_CCCAM)
					fprintf(ecmtxt, "hops: %d\n", reader[er->reader[0]].cc_currenthops);
				fprintf(ecmtxt, "ecm time: %.3f\n", (float) client[cs_idx].cwlastresptime/1000);
				fprintf(ecmtxt, "cw0: %s\n", cs_hexdump(1,demux[i].lastcw[0],8));
				fprintf(ecmtxt, "cw1: %s\n", cs_hexdump(1,demux[i].lastcw[1],8));
				fclose(ecmtxt);
				ecmtxt = NULL;
			}
		}
	}
}

static void dvbapi_handler(int idx) {
	static struct s_auth *account=0;

	if (cfg->dvbapi_enabled != 1) {
		cs_log("dvbapi disabled");
		return;
	}

	//cs_log("dvbapi loaded fd=%d", idx);

	switch(cs_fork(0, idx)) {
		case  0: //master
		case -1:
			return;
		default:
			wait4master();
	}

	int ok=0;
	if (!account) {
		client[cs_idx].usr[0]=0;
		for (ok=0, account=cfg->account; (account) && (!ok); account=account->next)
			if( (ok=!strcmp(cfg->dvbapi_usr, account->usr)) )
				break;
	}

	cs_auth_client(ok ? account : (struct s_auth *)(-1), "dvbapi");

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
