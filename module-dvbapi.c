#include "globals.h"

//#define WITH_STAPI

#ifdef WITH_STAPI
#include "stapi.c"
#endif

#ifdef HAVE_DVBAPI

#include <sys/un.h>
#include <dirent.h>

#define MAX_DEMUX 5
#define MAX_CAID 50
#define ECM_PIDS 20
#define MAX_FILTER 10

extern struct s_reader * reader;

typedef struct ECMPIDS
{
	unsigned short CAID;
	unsigned short ECM_PID;
	unsigned short EMM_PID;
	int checked;
	int notfound;
	unsigned char table;
} ECMPIDSTYPE;

typedef struct filter_s
{
	uint fd; //FilterHandle
	int pidindex;
	int pid;
	ushort type;
	int count;
#ifdef WITH_STAPI
	uint	SlotHandle;
	uint  	BufferHandle;
#endif
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
	unsigned char lastcw[2][8];
	int emm_filter;
	uchar hexserial[8];
	struct s_reader *rdr;
	uchar pmt_file[50];
	int pmt_time;
#ifdef WITH_STAPI
	uint STREAMhandle[ECM_PIDS];
#endif
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

char *boxdesc[] = { "none", "dreambox", "duckbox", "ufs910", "dbox2", "ipbox" };

#define BOX_COUNT 4
struct box_devices
{
	char ca_device_path[32];
	char demux_device_path[32];
	char cam_socket_path[32];
};

struct box_devices devices[BOX_COUNT] = {
	/* QboxHD (dvb-api-3)*/	{ "/tmp/virtual_adapter/ca%d",	"/tmp/virtual_adapter/demux%d",	"/tmp/camd.socket" },
	/* dreambox (dvb-api-3)*/	{ "/dev/dvb/adapter0/ca%d", 	"/dev/dvb/adapter0/demux%d",	"/tmp/camd.socket" },
	/* dreambox (dvb-api-1)*/	{ "/dev/dvb/card0/ca%d", 		"/dev/dvb/card0/demux%d",		"/tmp/camd.socket" },
	/* sh4      (stapi)*/	{ "/dev/stapi/stpti4_ioctl", 	"/dev/stapi/stpti4_ioctl",		"/tmp/camd.socket" }
};

#define TYPE_ECM 1
#define TYPE_EMM 2

#define DVBAPI_3	0
#define DVBAPI_1	1
#define STAPI		2

#define TMPDIR	"/tmp/"
#define STANDBY_FILE	"/tmp/.pauseoscam"
#define ECMINFO_FILE	"/tmp/ecm.info"

int selected_box=-1;
int selected_api=-1;
int disable_pmt_files=0;
int dir_fd=-1, pausecam=0;
unsigned short global_caid_list[MAX_CAID];
DEMUXTYPE demux[MAX_DEMUX];

void dvbapi_stop_descrambling(int);

int dvbapi_set_filter(int demux_id, int api, unsigned short pid, uchar *filt, uchar *mask, int timeout, int pidindex, int count, int type) {
	int ret=-1,n=-1,i,dmx_fd;

	for (i=0;i<MAX_FILTER;i++) {
		if (demux[demux_id].demux_fd[i].fd<=0) {
			n=i;
			break;
		}
	}

	if (n==-1) {
		cs_log("dvbapi: no free filter");
		return;
	}

	dmx_fd = dvbapi_open_device(demux_id, 0);

	demux[demux_id].demux_fd[n].fd       = dmx_fd;
	demux[demux_id].demux_fd[n].pidindex = pidindex;
	demux[demux_id].demux_fd[n].pid      = pid;
	demux[demux_id].demux_fd[n].type     = type;
	demux[demux_id].demux_fd[n].count    = count;
	
	switch(api) {
		case DVBAPI_3:
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
		case DVBAPI_1:
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
#ifdef WITH_STAPI
		case STAPI:
			ret=stapi_set_filter(demux_id, pid, filt, mask, n);

			break;
#endif
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
	int num_apis=2, i,devnum=-1, apinum=-1, dmx_fd=0, ret=-1;
	uchar filter[32];
	char device_path[128];

	for (i=0;i<BOX_COUNT;i++) {
		sprintf(device_path, devices[i].demux_device_path, 0);
		if ((dmx_fd = open(device_path, O_RDWR)) > 0) {
			devnum=i;
			break;
		}
	}

	if (dmx_fd < 0) return 0;
	close(dmx_fd);
	selected_box = devnum;

#ifdef WITH_STAPI
	if (devnum==3) {
		if (stapi_open()==FALSE) {
			cs_log("stapi: setting up stapi failed.");
			return 0;
		}

		selected_api=STAPI;
		selected_box=3;
		close(dmx_fd);
		return 1;
	}
#endif
	memset(filter,0,32);

	filter[0]=0x01;
	filter[16]=0xFF;

	for (i=0;i<num_apis;i++) {
		ret = dvbapi_set_filter(0, i, 0x0001, filter, filter+16, 1, 0, 0, TYPE_ECM);

		if (ret >= 0) {
			apinum=i;
			dvbapi_stop_descrambling(0);
			break;
		}
	}

	if (ret < 0) return 0;
	selected_api=apinum;

	cs_debug("dvbapi: Detected %s Api: %d", device_path, apinum);

	return 1;
}

int dvbapi_read_device(int dmx_fd, unsigned char *buf, int length) {
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

	return len;
}

int dvbapi_open_device(int index_demux, int type) {
	int dmx_fd,i;
	int ca_offset=0;
	char device_path[128];

#ifdef WITH_STAPI
	return 1;
#endif

	if (type==0)
		sprintf(device_path, devices[selected_box].demux_device_path, demux[index_demux].demux_index);
	else {
		if (cfg->dvbapi_boxtype==BOXTYPE_DUCKBOX || cfg->dvbapi_boxtype==BOXTYPE_DBOX2 || cfg->dvbapi_boxtype==BOXTYPE_UFS910)
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
		if (demux[demux_index].demux_fd[g].type==type) {		
			dvbapi_stop_filternum(demux_index, g);
		}
	}

	return 1;
}

int dvbapi_stop_filternum(int demux_index, int num) {
#ifdef WITH_STAPI
	if (demux[demux_index].demux_fd[num].fd>0) {
		stapi_remove_filter(demux_index, num);
		demux[demux_index].demux_fd[num].fd=0;
	}
#else	
	if (demux[demux_index].demux_fd[num].fd>0) {
		ioctl(demux[demux_index].demux_fd[num].fd,DMX_STOP);
		close(demux[demux_index].demux_fd[num].fd);
		demux[demux_index].demux_fd[num].fd=0;
	}
#endif
	return 1;
}

void dvbapi_start_filter(int demux_id, int pidindex, unsigned short pid, uchar table, uchar mask, int type) {
	int dmx_fd,i,n=-1;
	uchar filter[32];

	cs_debug("dvbapi: set filter pid: %04x", pid);

	memset(filter,0,32);

	filter[0]=table;
	filter[16]=mask;

	dvbapi_set_filter(demux_id, selected_api, pid, filter, filter+16, 4000, pidindex, 0, type);
}

void dvbapi_start_emm_filter(int demux_index) {
	int dmx_fd, i, j, n;
	uchar nullserial[8];
	char *typtext[]={"UNKNOWN", "UNIQUE", "SHARED", "GLOBAL"};

	if (demux[demux_index].pidindex==-1) return;

	if (demux[demux_index].ECMpids[demux[demux_index].pidindex].EMM_PID==0 || !demux[demux_index].rdr)
		return;

	memset(nullserial,0,8);

	if (!memcmp(demux[demux_index].rdr->hexserial, nullserial, 8)) {
		//cs_debug("dvbapi: hexserial not set %s", cs_hexdump(1, demux[demux_index].rdr->hexserial, 8));
		return;
	}

	if (demux[demux_index].emm_filter==1 && !memcmp(demux[demux_index].rdr->hexserial, demux[demux_index].hexserial, 8)) {
		return;
	}

	if (memcmp(demux[demux_index].rdr->hexserial, demux[demux_index].hexserial, 8)) {
		dvbapi_stop_filter(demux_index, TYPE_EMM);
	}

	if (demux[demux_index].rdr->card_system==0)
		demux[demux_index].rdr->card_system=get_cardsystem(demux[demux_index].ECMpids[demux[demux_index].pidindex].CAID);

	uchar dmx_filter[256];
	memset(dmx_filter, 0, sizeof(dmx_filter));

	get_emm_filter(demux[demux_index].rdr, dmx_filter);

	int filter_count=dmx_filter[1];

	for (j=1;j<=filter_count && j < 8;j++) {
		int startpos=2+(34*(j-1));

		if (dmx_filter[startpos+1] != 0x00)
			continue;

		uchar filter[32];
		memcpy(filter, dmx_filter+startpos+2, 32);
		int emmtype=dmx_filter[startpos];
		int count=dmx_filter[startpos+1];

		cs_log("dvbapi: starting emm filter %s",typtext[emmtype]);
		cs_dump(filter, 32, "demux filter:");
		dvbapi_set_filter(demux_index, selected_api, demux[demux_index].ECMpids[demux[demux_index].pidindex].EMM_PID, filter, filter+16, 0, demux[demux_index].pidindex, count, TYPE_EMM);
	}

	memcpy(demux[demux_index].hexserial, demux[demux_index].rdr->hexserial, 8);
	demux[demux_index].emm_filter=1;
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
			if (demux[demux_index].ECMpids[j].CAID==(((buf[i + 2] & 0x1F) << 8) | buf[i + 3])) {
				demux[demux_index].ECMpids[j].EMM_PID=emm_pid;
			}
		}
	}
	return;
}

void dvbapi_set_pid(int demux_id, int num, int index) {
	switch(selected_api) {
#ifdef WITH_STAPI	
		case STAPI:
			stapi_set_pid(demux_id,num,index);
			break;
#endif
		default:
			if (demux[demux_id].ca_fd>0) {
				ca_pid_t ca_pid2;
				memset(&ca_pid2,0,sizeof(ca_pid2));
				ca_pid2.pid = demux[demux_id].STREAMpids[num];
				ca_pid2.index = index;
				if (ioctl(demux[demux_id].ca_fd, CA_SET_PID, &ca_pid2)==-1)
					cs_debug("dvbapi: Error Stream SET_PID");
			}
			break;
	}
	return;
}

void dvbapi_stop_descrambling(int demux_id) {
	int i;

	cs_debug("dvbapi: stop descrambling (demux_id: %d)", demux_id);
	
	dvbapi_stop_filter(demux_id, TYPE_ECM);
	dvbapi_stop_filter(demux_id, TYPE_EMM);

	for (i=0;i<demux[demux_id].STREAMpidcount;i++) {
		dvbapi_set_pid(demux_id, i, -1);
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

	memset(&demux[demux_id], 0 ,sizeof(DEMUXTYPE));
	demux[demux_id].socket_fd=0;
	demux[demux_id].pidindex=-1;

	unlink(ECMINFO_FILE);

	return;
}

void dvbapi_start_descrambling(int demux_index, unsigned short caid, unsigned short pid) {
	int i,n;

	cs_log("dvbapi: Start descrambling CAID: %04x", caid);

	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		if (demux[demux_index].ECMpids[n].CAID==caid && demux[demux_index].ECMpids[n].ECM_PID==pid) {
			demux[demux_index].pidindex=n;
			break;
		}
	}

	demux[demux_index].ca_fd = dvbapi_open_device(demux_index,1);
	if (demux[demux_index].ca_fd<=0)
		return;

	for (i=0;i<demux[demux_index].STREAMpidcount;i++) {
		dvbapi_set_pid(demux_index, i, demux_index);
	}

	if (cfg->dvbapi_au==1)
		dvbapi_start_filter(demux_index, demux[demux_index].pidindex, 0x001, 0x01, 0xFF, TYPE_EMM); //CAT
}

void dvbapi_process_emm (int demux_index, unsigned char *buffer, unsigned int len) {
	EMM_PACKET epg;

	if (demux[demux_index].pidindex==-1) return;

	cs_ddump(buffer, 16, "emm:");

	memset(&epg, 0, sizeof(epg));
	epg.caid[0] = (uchar)(demux[demux_index].ECMpids[demux[demux_index].pidindex].CAID>>8);
	epg.caid[1] = (uchar)(demux[demux_index].ECMpids[demux[demux_index].pidindex].CAID);

	unsigned long provid = (buffer[10] << 8) | buffer[11];
	int pid = dvbapi_check_array(cfg->dvbapi_prioritytab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[demux[demux_index].pidindex].CAID);
	if (pid>=0) {
		if (cfg->dvbapi_prioritytab.mask[pid]>0)
			provid = (cfg->dvbapi_prioritytab.cmap[pid] << 8 | cfg->dvbapi_prioritytab.mask[pid]);
	}

	epg.provid[1] = (uchar)(provid>>16);
	epg.provid[2] = (uchar)(provid>>8);
	epg.provid[3] = (uchar)(provid);

	epg.l=len;
	memcpy(epg.emm, buffer, epg.l);

	do_emm(&epg);
}

void dvbapi_resort_ecmpids(int demux_index) {
	ECMPIDSTYPE tmppids[ECM_PIDS],tmppids2[ECM_PIDS];
	int tmppidcount=0,tmppid2count=0,n,i,k=0,j;

	for (i=0;i<MAX_CAID;i++)
		global_caid_list[i]=0;

	for (i=0;i<CS_MAXREADER;i++) {
		for (j=0;j<CS_MAXREADER;j++) {
			if (reader[i].caid[j] != 0 && reader[i].card_status > NO_CARD) {
				if (k+1>=MAX_CAID) break;
				global_caid_list[k++]=reader[i].caid[j];	
			}
		}
	}
	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		if (dvbapi_check_array(cfg->dvbapi_ignoretab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[n].CAID)>=0) {
			cs_debug("-> ignore %04x", demux[demux_index].ECMpids[n].CAID);
		} else if (dvbapi_check_array(global_caid_list, MAX_CAID, demux[demux_index].ECMpids[n].CAID)>=0) {
			cs_debug("-> caid list %04x", demux[demux_index].ECMpids[n].CAID);
			tmppids[tmppidcount++]=demux[demux_index].ECMpids[n];
		} else if (dvbapi_check_array(cfg->dvbapi_prioritytab.caid, CS_MAXCAIDTAB, demux[demux_index].ECMpids[n].CAID)>=0) {
			cs_debug("-> priority %04x", demux[demux_index].ECMpids[n].CAID);
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

		cs_debug("typ: %02x\tcaid: %04x\t ca_pid: %04x", buffer[i + j + 6], descriptor_ca_system_id, descriptor_ca_pid);

		if (buffer[i + j + 6] == 0x09) {
			added=0;
			for (n=0;n<demux[demux_id].ECMpidcount;n++) {
				if (demux[demux_id].ECMpids[n].CAID==descriptor_ca_system_id && demux[demux_id].ECMpids[n].ECM_PID==descriptor_ca_pid)
					added=1;
			}
			if (added==0) {
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].ECM_PID=descriptor_ca_pid;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CAID=descriptor_ca_system_id;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].checked=0;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].notfound=0;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].table=0;
				demux[demux_id].ECMpids[demux[demux_id].ECMpidcount++].EMM_PID=0;
			}
		}
	}
}


void dvbapi_try_caid(int demux_index, int num) {
	//stop all ecm filter on demux
	dvbapi_stop_filter(demux_index, TYPE_ECM);

	if (demux[demux_index].ECMpids[num].notfound>2) {
		cs_log("dvbapi: can't decode channel");
		return;
	}

	cs_debug("dvbapi: trying CAID: %04x CA_PID: %04x", demux[demux_index].ECMpids[num].CAID, demux[demux_index].ECMpids[num].ECM_PID);

	//grep ecm
	dvbapi_start_filter(demux_index, num, demux[demux_index].ECMpids[num].ECM_PID, 0x80, 0xF0, TYPE_ECM); //ECM
	demux[demux_index].ECMpids[num].checked=1;
}

int dvbapi_parse_capmt(unsigned char *buffer, unsigned int length, int connfd) {
	int i;
	unsigned short ca_mask=0x01, demux_index=0x00;

	//int ca_pmt_list_management = buffer[0];
	unsigned int program_number = (buffer[1] << 8) | buffer[2];
	int program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	if (buffer[17]==0x82 && buffer[18]==0x02) {
		//enigma2
		ca_mask = buffer[19];
		demux_index = buffer[20];
	}
	
	for (i = 0; i < MAX_DEMUX; i++) {
		if (demux[i].demux_index == demux_index) {
			if (demux[i].program_number == program_number) {
				return -1; //same pmt on same demux, exit
			}
		}
	}

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

	memset(&demux[demux_id], 0, sizeof(DEMUXTYPE));
	demux[demux_id].program_number=((buffer[1] << 8) | buffer[2]);
	demux[demux_id].demux_index=demux_index;
	demux[demux_id].cadev_index=demux_index;
	demux[demux_id].socket_fd=connfd;
	demux[demux_id].rdr=NULL;
	demux[demux_id].pidindex=-1;

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

		if (es_info_length != 0 && es_info_length < length) {
			dvbapi_parse_descriptor(demux_id, i, es_info_length, buffer);
		}
	}
	cs_debug("dvbapi: Found %d ECMpids and %d STREAMpids in PMT", demux[demux_id].ECMpidcount, demux[demux_id].STREAMpidcount);

	char *name = get_servicename(demux[demux_id].program_number, demux[demux_id].ECMpidcount>0 ? demux[demux_id].ECMpids[0].CAID : 0);
		cs_log("dvbapi: new program number: %04X (%s)", program_number, name);

	if (demux[demux_id].ECMpidcount>0) {
		dvbapi_resort_ecmpids(demux_id);

#ifdef WITH_STAPI
		demux[demux_id].demux_index=stapi_get_device(demux_id, demux[demux_id].STREAMpids[0]);
#endif
		if (demux[demux_id].ECMpidcount>0)
			dvbapi_try_caid(demux_id, 0);
	} else {
		// set channel srvid+caid
		client[cs_idx].last_srvid = demux[demux_id].program_number;
		client[cs_idx].last_caid = 0;
		// reset idle-Time
		client[cs_idx].last=time((time_t)0);
	}

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
				// ipbox fix
				if (cfg->dvbapi_boxtype==BOXTYPE_IPBOX) {
					int demux_index=buffer[7+k];
					for (i = 0; i < MAX_DEMUX; i++) {
						if (demux[i].demux_index == demux_index) {
							dvbapi_stop_descrambling(i);
							break;
						}				
					}			
				} else {
					close(connfd);
				}
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

void event_handler(int signal) {
	struct stat pmt_info;
	uchar dest[1024];
	uint len;
	DIR *dirp;
	struct dirent *dp;
	struct stat buf;
	int i,pmt_fd,found;

	signal=signal;
	
	int standby_fd = open(STANDBY_FILE, O_RDONLY);
	pausecam = (standby_fd > 0) ? 1 : 0;

	if (cfg->dvbapi_boxtype==BOXTYPE_IPBOX)
		return;

	if (disable_pmt_files)
  		return; 

	dirp = opendir(TMPDIR);
	if (!dirp)
		cs_log("dvbapi: opendir errno %d", errno);
  
	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].pmt_file[0] != 0) {
			sprintf(dest, "%s%s", TMPDIR, demux[i].pmt_file);
			pmt_fd = open(dest, O_RDONLY);
			if(pmt_fd>0) {
				close(pmt_fd);
				continue;
			} else {
				dvbapi_stop_descrambling(i);
			}
		}
	}

	while (dp = readdir(dirp)) {
		if (strncmp(dp->d_name, "pmt", 3)==0 && strncmp(dp->d_name+strlen(dp->d_name)-4, ".tmp", 4)==0) {
			sprintf(dest, "%s%s", TMPDIR, dp->d_name);
		
			pmt_fd = open(dest, O_RDONLY);
			if(pmt_fd>0) {
				if (fstat(pmt_fd, &pmt_info) == 0) {
					found=0;
					for (i=0;i<MAX_DEMUX;i++) {
						if (strcmp(demux[i].pmt_file, dp->d_name)==0) {
							if (pmt_info.st_mtime == demux[i].pmt_time) {
								found=1;
								continue;
							}
							dvbapi_stop_descrambling(i);
						}
					}
					if (found) continue;
					cs_log("dvbapi: found pmt file %s", dest);

					cs_sleepms(100);

					len = read(pmt_fd,mbuf,sizeof(mbuf));
					if (len<1) continue;

					int pmt_id;
#ifdef QBOXHD
					uint j1,j2;
					// QboxHD pmt.tmp is the full capmt written as a string of hex values
					// pmt.tmp must be longer than 3 bytes (6 hex chars) and even length
					if ((len<6) || ((len%2) != 0) || ((len/2)>sizeof(dest))) {
						cs_log("dvbapi: error parsing QboxHD pmt.tmp, incorrect length");
						continue;
					}

					for(j2=0,j1=0;j2<len;j2+=2,j1++) {
						if (sscanf((char*)mbuf+j2, "%02X", dest+j1) != 1) {
							cs_log("dvbapi: error parsing QboxHD pmt.tmp, data not valid in position %d",j2);
							return;
						}
					}

					cs_ddump(dest,len/2,"QboxHD pmt.tmp:");
				
					pmt_id = dvbapi_parse_capmt(dest+4, (len/2)-4, -1);
#else
					if (len>sizeof(dest)) continue;
					cs_ddump(mbuf,len,"pmt:");
		
					memcpy(dest, "\x00\xFF\xFF\x00\x00\x13\x00", 7);
			
					dest[1] = mbuf[3];
					dest[2] = mbuf[4];
					dest[5] = mbuf[11]+1;
		
					memcpy(dest + 7, mbuf + 12, len - 12 - 4);

					pmt_id = dvbapi_parse_capmt(dest, 7 + len - 12 - 4, -1);
#endif
					strcpy(demux[pmt_id].pmt_file, dp->d_name);
					demux[pmt_id].pmt_time = pmt_info.st_mtime;
				}
				close(pmt_fd);
			}
		}
	}
	
	closedir(dirp);
}

void dvbapi_process_input(int demux_id, int filter_num, uchar *buffer, int len) {

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_ECM) {
		if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
			return;

		if (buffer[0] != 0x80 && buffer[0] != 0x81) 
			return;

		if (demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].table == buffer[0])
			return;					
							
		demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].table = buffer[0];

		if (cfg->dvbapi_au==1)
			dvbapi_start_emm_filter(demux_id);

		unsigned long provid=0;
		int pid = dvbapi_check_array(cfg->dvbapi_prioritytab.caid, CS_MAXCAIDTAB, demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].CAID);
		if (pid>=0) {
			if (cfg->dvbapi_prioritytab.mask[pid]>0)
				provid = (cfg->dvbapi_prioritytab.cmap[pid] << 8 | cfg->dvbapi_prioritytab.mask[pid]);
		}

		ECM_REQUEST *er;
		if (!(er=get_ecmtask()))
			return;

		er->srvid = demux[demux_id].program_number;
		er->caid  = demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].CAID;
		er->pid   = demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].ECM_PID;
		er->prid  = provid;

		er->l=len;
		memcpy(er->ecm, buffer, er->l);
		get_cw(er);
	}

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_EMM) {
		if (buffer[0]==0x01) { //CAT
			cs_debug("dvbapi: receiving cat");
			dvbapi_parse_cat(demux_id, buffer, len);
			if (demux[demux_id].pidindex < 0)
				return;
								
			dvbapi_stop_filternum(demux_id, filter_num);
			return;
		}
		cs_debug("EMM Filter fd %d", demux[demux_id].demux_fd[filter_num].fd);
		dvbapi_process_emm(demux_id, buffer, len);
	}

	if (demux[demux_id].demux_fd[filter_num].count==1) {
		//stop filter
		dvbapi_stop_filternum(demux_id, filter_num);
	}
	if (demux[demux_id].demux_fd[filter_num].count>1) {
		demux[demux_id].demux_fd[filter_num].count--;
	}
}

void dvbapi_main_local() {
	int maxpfdsize=(MAX_DEMUX*MAX_FILTER)+MAX_DEMUX+2;
	struct pollfd pfd2[maxpfdsize];
	int i,rc,pfdcount,g,listenfd,connfd,clilen,j;
	int ids[maxpfdsize], fdn[maxpfdsize], type[maxpfdsize];
	struct timeb tp;
	struct sockaddr_un servaddr;
	ssize_t len=0;

	for (i=0;i<MAX_DEMUX;i++) {
		memset(&demux[i], 0, sizeof(DEMUXTYPE));
		demux[i].pidindex=-1;
		demux[i].rdr=NULL;
	}

	dvbapi_detect_api();

	if (selected_box == -1 || selected_api==-1) {
		cs_log("dvbapi: could not detect api version");
		return;
	}

	listenfd = dvbapi_init_listenfd();
	if (listenfd < 1) {
		cs_log("dvbapi: could not init camd.socket.");
		return;
	}

	struct sigaction signal_action;
	signal_action.sa_handler = event_handler;
	sigemptyset(&signal_action.sa_mask);
	signal_action.sa_flags = SA_RESTART;
	sigaction(SIGRTMIN + 1, &signal_action, NULL);
	
	dir_fd = open(TMPDIR, O_RDONLY);
	if (dir_fd >= 0) {
		fcntl(dir_fd, F_SETSIG, SIGRTMIN + 1);
		fcntl(dir_fd, F_NOTIFY, DN_MODIFY | DN_CREATE | DN_DELETE | DN_MULTISHOT);
		event_handler(SIGRTMIN + 1);
	}

	cs_ftime(&tp);
	tp.time+=500;

	pfd2[0].fd = client[cs_idx].fd_m2c_c;
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

		if (pausecam==1) {
			cs_sleepms(500);
			continue;
		}

		for (i=0;i<MAX_DEMUX;i++) {
			for (g=0;g<MAX_FILTER;g++) {
				if (demux[i].demux_fd[g].fd>1) {
					pfd2[pfdcount].fd = demux[i].demux_fd[g].fd;
					pfd2[pfdcount].events = (POLLIN | POLLPRI);
					ids[pfdcount]=i;
					fdn[pfdcount]=g;
					type[pfdcount++]=0;
				}
			}
		
			if (demux[i].socket_fd>0) {
				rc=0;
				if (cfg->dvbapi_boxtype==BOXTYPE_IPBOX) {
					for (j = 0; j < pfdcount; j++)
						if (pfd2[j].fd == demux[i].socket_fd) {
							rc=1;
							break;
						}
				}

				if (rc==1) continue;

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
							dvbapi_stop_descrambling(j);
						}
					}
					close(pfd2[i].fd);
					continue;
				}
				if (pfd2[i].fd==client[cs_idx].fd_m2c_c) {
					cs_exit(0);
				}
			}
			if (pfd2[i].revents & (POLLIN | POLLPRI)) {
				if (pfd2[i].fd==client[cs_idx].fd_m2c_c) {
					chk_dcw(client[cs_idx].fd_m2c_c);
					continue;
				}

				if (type[i]==1) {
					if (pfd2[i].fd==listenfd) {
						connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);
						cs_debug("dvbapi: new socket connection fd: %d", connfd);

						disable_pmt_files=1;

						if (connfd <= 0) {
							cs_log("dvbapi: accept() returns error %d, fd event %d", errno, pfd2[i].revents);
							continue;
						}
					} else {
						cs_debug("dvbapi: New capmt on old socket. Please report.");
						connfd = pfd2[i].fd;
					}

					len = read(connfd, mbuf, sizeof(mbuf));

					if (len < 3) {
						cs_debug("dvbapi: camd.socket: too short message received");
						continue;
					}

					dvbapi_handlesockmsg(mbuf, len, connfd);

					if (cfg->dvbapi_boxtype==BOXTYPE_IPBOX) {
						// check do we have any demux running on this fd
						short execlose = 1;
						for (j = 0; j < MAX_DEMUX; j++) {
							if (demux[j].socket_fd == connfd) {
								execlose = 0;
								break;
							}
						}
						if (execlose) close(connfd);
					}
				} else { // type==0
					if ((len=dvbapi_read_device(pfd2[i].fd, mbuf, sizeof(mbuf))) <= 0)
						continue;

					int demux_index=ids[i];
					int n=fdn[i];

					if (pfd2[i].fd==demux[demux_index].demux_fd[n].fd) {
						dvbapi_process_input(demux_index,n,mbuf,len);
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
			demux[i].rdr=&reader[er->reader[0]];

			if (er->rc<=3 && demux[i].pidindex==-1 && er->caid!=0) {
				dvbapi_start_descrambling(i, er->caid, er->pid);
			}

			if (er->rc==4 && cfg->dvbapi_au==1 && dvbapi_check_array(global_caid_list, MAX_CAID, er->caid)>=0) {
				//local card and not found -> maybe card need emm
				dvbapi_start_descrambling(i, er->caid, er->pid);
			}

			if (er->rc>3 && demux[i].pidindex==-1) {
				for (n=1; n<demux[i].ECMpidcount; n++) {
					if (demux[i].ECMpids[n].checked==0) {
						demux[i].ECMpids[n-1].notfound++;
						dvbapi_try_caid(i, n);
						return;
					}
				}

				for (n=0; n<demux[i].ECMpidcount; n++)
					demux[i].ECMpids[n].checked=0;

				dvbapi_try_caid(i, 0);
				return;
			}

			if (er->rc>3) {
				cs_debug("dvbapi: cw not found");
				return;
			}

			if (demux[i].ca_fd<=0) {
				cs_log("dvbapi: could not write cw.");
				demux[i].ca_fd = dvbapi_open_device(i,1);
				if (demux[i].ca_fd<=0)
					return;
			}

			int dindex = dvbapi_check_array(cfg->dvbapi_delaytab.caid, CS_MAXCAIDTAB, er->caid);
			if (dindex>=0) {
				char tmp1[5];
				sprintf(tmp1, "%04X", cfg->dvbapi_delaytab.mask[dindex]);
				int cw_delay = strtol(tmp1, '\0', 10);
				if (cw_delay<1000) {
					cs_debug("dvbapi: wait %d ms", cw_delay);
					cs_sleepms(cw_delay);
				}
			}
#ifdef WITH_STAPI
			stapi_write_cw(i, er->cw);
#else
			memset(&ca_descr,0,sizeof(ca_descr));
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
#endif
			// reset idle-Time
			client[cs_idx].last=time((time_t)0);

			FILE *ecmtxt;
			ecmtxt = fopen(ECMINFO_FILE, "w");
			if(ecmtxt != NULL) {
				fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
				fprintf(ecmtxt, "reader: %s\n", reader[er->reader[0]].label);
				if (reader[er->reader[0]].typ & R_IS_CASCADING)
					fprintf(ecmtxt, "from: %s\n", reader[er->reader[0]].device);
				else
					fprintf(ecmtxt, "from: local\n");
				fprintf(ecmtxt, "protocol: %d\n", reader[er->reader[0]].typ);
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
	struct s_auth *account=0;

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
