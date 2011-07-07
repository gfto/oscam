#include "globals.h"

#ifdef HAVE_DVBAPI

#include "module-dvbapi.h"

const char *boxdesc[] = { "none", "dreambox", "duckbox", "ufs910", "dbox2", "ipbox", "ipbox-pmt", "dm7000", "qboxhd", "coolstream", "neumo" };

const struct box_devices devices[BOX_COUNT] = {
	/* QboxHD (dvb-api-3)*/	{ "/tmp/virtual_adapter/", 	"ca%d",		"demux%d",			"/tmp/camd.socket" },
	/* dreambox (dvb-api-3)*/	{ "/dev/dvb/adapter%d/",	"ca%d", 		"demux%d",			"/tmp/camd.socket" },
	/* dreambox (dvb-api-1)*/	{ "/dev/dvb/card%d/",	"ca%d",		"demux%d",			"/tmp/camd.socket" },
	/* neumo (dvb-api-1)*/	{ "/dev/",			"demuxapi",		"demuxapi",			"/tmp/camd.socket" },
	/* sh4      (stapi)*/	{ "/dev/stapi/", 		"stpti4_ioctl",	"stpti4_ioctl",		"/tmp/camd.socket" },
	/* coolstream*/		{ "/dev/cnxt/", 		"null",		"null",			"/tmp/camd.socket" }
};

int32_t selected_box=-1;
int32_t selected_api=-1;
int32_t disable_pmt_files=0;
int32_t dir_fd=-1, pausecam=0;
DEMUXTYPE demux[MAX_DEMUX];
int32_t ca_fd[8];

struct s_dvbapi_priority *dvbapi_priority=NULL;
struct s_client *dvbapi_client=NULL;

#ifdef WITH_STAPI
int32_t stapi_on	= 0;
pthread_mutex_t filter_lock;
struct STDEVICE dev_list[PTINUM];
#endif

int32_t dvbapi_set_filter(int32_t demux_id, int32_t api, uint16_t pid, uchar *filt, uchar *mask, int32_t timeout, int32_t pidindex, int32_t count, int32_t type) {
#ifdef AZBOX
	openxcas_caid = demux[demux_id].ECMpids[pidindex].CAID;
	openxcas_ecm_pid = pid;

 	return 1;
#endif
	int32_t ret=-1,n=-1,i;

	for (i=0; i<MAX_FILTER && demux[demux_id].demux_fd[i].fd>0; i++);

	if (i>=MAX_FILTER) {
		cs_log("no free filter");
		return -1;
	}
	n=i;

	demux[demux_id].demux_fd[n].pidindex = pidindex;
	demux[demux_id].demux_fd[n].pid      = pid;
	demux[demux_id].demux_fd[n].type     = type;
	demux[demux_id].demux_fd[n].count    = count;

	switch(api) {
		case DVBAPI_3:
			demux[demux_id].demux_fd[n].fd = dvbapi_open_device(0, demux[demux_id].demux_index, demux[demux_id].adapter_index);
			struct dmx_sct_filter_params sFP2;

			memset(&sFP2,0,sizeof(sFP2));

			sFP2.pid			= pid;
			sFP2.timeout			= timeout;
			sFP2.flags			= DMX_IMMEDIATE_START;
			memcpy(sFP2.filter.filter,filt,16);
			memcpy(sFP2.filter.mask,mask,16);
			ret=ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER, &sFP2);

			break;
		case DVBAPI_1:
			demux[demux_id].demux_fd[n].fd = dvbapi_open_device(0, demux[demux_id].demux_index, demux[demux_id].adapter_index);
			struct dmxSctFilterParams sFP1;

			memset(&sFP1,0,sizeof(sFP1));

			sFP1.pid			= pid;
			sFP1.timeout			= timeout;
			sFP1.flags			= DMX_IMMEDIATE_START;
			memcpy(sFP1.filter.filter,filt,16);
			memcpy(sFP1.filter.mask,mask,16);
			ret=ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER1, &sFP1);

			break;
#ifdef WITH_STAPI
		case STAPI:
			demux[demux_id].demux_fd[n].fd = 1;
			ret=stapi_set_filter(demux_id, pid, filt, mask, n, demux[demux_id].pmt_file);

			break;
#endif
#ifdef COOL
		case COOLAPI:
			demux[demux_id].demux_fd[n].fd = coolapi_open_device(demux[demux_id].demux_index, demux_id);
			if(demux[demux_id].demux_fd[n].fd > 0)
				ret = coolapi_set_filter(demux[demux_id].demux_fd[n].fd, n, pid, filt, mask);
			break;
#endif
		default:
			break;
	}

	if (ret < 0)
		cs_debug_mask(D_DVBAPI, "could not start demux filter (errno=%d %s)", errno, strerror(errno));

	return ret;
}

static int32_t dvbapi_detect_api() {
#ifdef COOL
	selected_api=COOLAPI;
	selected_box = 5;
	disable_pmt_files = 1;
	cs_debug_mask(D_DVBAPI, "Detected coolstream Api");
	return 1;
#else
	int32_t num_apis=2, i,devnum=-1, dmx_fd=0, ret=-1;
	uchar filter[32];
	char device_path[128], device_path2[128];

	for (i=0;i<BOX_COUNT;i++) {
		snprintf(device_path2, sizeof(device_path2), devices[i].demux_device, 0);
		snprintf(device_path, sizeof(device_path), devices[i].path, 0);

		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);

		if ((dmx_fd = open(device_path, O_RDWR)) > 0) {
			devnum=i;
			break;
		}
	}

	if (dmx_fd < 0) return 0;
	close(dmx_fd);
	selected_box = devnum;

#ifdef WITH_STAPI
	if (devnum==4) {
		if (stapi_open()==FALSE) {
			cs_log("stapi: setting up stapi failed.");
			return 0;
		}

		selected_api=STAPI;
		selected_box=4;
		close(dmx_fd);
		return 1;
	}
#endif
	if (cfg.dvbapi_boxtype == BOXTYPE_NEUMO) {
		selected_api=DVBAPI_1;
		return 1;
	}

	memset(filter,0,32);

	filter[0]=0x01;
	filter[16]=0xFF;

	for (i=0;i<num_apis;i++) {
		ret = dvbapi_set_filter(0, i, 0x0001, filter, filter+16, 1, 0, 0, TYPE_ECM);

		if (ret >= 0) {
			selected_api=i;
			dvbapi_stop_filter(0, TYPE_ECM);
			break;
		}
	}

	if (ret < 0) return 0;

	cs_debug_mask(D_DVBAPI, "Detected %s Api: %d", device_path, selected_api);
#endif

	return 1;
}

static int32_t dvbapi_read_device(int32_t dmx_fd, unsigned char *buf, int32_t length) 
{
	int32_t len, rc;
	struct pollfd pfd[1];

	pfd[0].fd = dmx_fd;
	pfd[0].events = (POLLIN | POLLPRI);

	rc = poll(pfd, 1, 7000);
	if (rc<1) {
		cs_log("read on %d timed out", dmx_fd);
		return -1;
	}

	len = read(dmx_fd, buf, length);

	if (len==-1)
		cs_log("read error on fd %d (errno=%d %s)", dmx_fd, errno, strerror(errno));

	return len;
}

int32_t dvbapi_open_device(int32_t type, int32_t num, int32_t adapter) {
	int32_t dmx_fd;
	int32_t ca_offset=0;
	char device_path[128], device_path2[128];

	if (type==0) {
		snprintf(device_path2, sizeof(device_path2), devices[selected_box].demux_device, num);
		snprintf(device_path, sizeof(device_path), devices[selected_box].path, adapter);

		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);
	} else {
		if (cfg.dvbapi_boxtype==BOXTYPE_DUCKBOX || cfg.dvbapi_boxtype==BOXTYPE_DBOX2 || cfg.dvbapi_boxtype==BOXTYPE_UFS910)
			ca_offset=1;

		if (cfg.dvbapi_boxtype==BOXTYPE_QBOXHD)
			num=0;

		snprintf(device_path2, sizeof(device_path2), devices[selected_box].ca_device, num+ca_offset);
		snprintf(device_path, sizeof(device_path), devices[selected_box].path, adapter);

		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);
	}

	if ((dmx_fd = open(device_path, O_RDWR)) < 0) {
		cs_debug_mask(D_DVBAPI, "error opening device %s (errno=%d %s)", device_path, errno, strerror(errno));
		return -1;
	}

	cs_debug_mask(D_DVBAPI, "DEVICE open (%s) fd %d", device_path, dmx_fd);
	return dmx_fd;
}

int32_t dvbapi_stop_filter(int32_t demux_index, int32_t type) {
	int32_t g;

	for (g=0;g<MAX_FILTER;g++) {
		if (demux[demux_index].demux_fd[g].type==type) {
			dvbapi_stop_filternum(demux_index, g);
		}
	}

	return 1;
}

int32_t dvbapi_stop_filternum(int32_t demux_index, int32_t num) 
{
	int32_t ret=-1;
	if (demux[demux_index].demux_fd[num].fd>0) {
#ifdef COOL
		ret=coolapi_remove_filter(demux[demux_index].demux_fd[num].fd, num);
		coolapi_close_device(demux[demux_index].demux_fd[num].fd);
#else
#ifdef WITH_STAPI
		ret=stapi_remove_filter(demux_index, num, demux[demux_index].pmt_file);
#else
		ret=ioctl(demux[demux_index].demux_fd[num].fd,DMX_STOP);
		close(demux[demux_index].demux_fd[num].fd);
#endif
#endif
		demux[demux_index].demux_fd[num].fd=0;
	}
	return ret;
}

void dvbapi_start_filter(int32_t demux_id, int32_t pidindex, uint16_t pid, uchar table, uchar mask, int32_t timeout, int32_t type, int32_t count) 
{
	uchar filter[32];

	cs_debug_mask(D_DVBAPI, "set filter pid: %04x", pid);

	memset(filter,0,32);

	filter[0]=table;
	filter[16]=mask;

	dvbapi_set_filter(demux_id, selected_api, pid, filter, filter+16, timeout, pidindex, count, type);
}

void dvbapi_sort_nanos(unsigned char *dest, const unsigned char *src, int32_t len)
{
	int32_t w=0, c=-1, j=0;
	while(1) {
		int32_t n=0x100;
		for(j=0; j<len;) {
			int32_t l=src[j+1]+2;
				if(src[j]==c) {
					if(w+l>len) {
						cs_debug_mask(D_DVBAPI, "sortnanos: sanity check failed. Exceeding memory area. Probably corrupted nanos!");
						memset(dest,0,len); // zero out everything
						return;
					}
					memcpy(&dest[w],&src[j],l);
				w+=l;
			} else if(src[j]>c && src[j]<n)
				n=src[j];
			j+=l;
		}
		if(n==0x100) break;
		c=n;
	}
}


int32_t dvbapi_find_emmpid(int32_t demux_id, uint8_t type) {
	int32_t k;
	int32_t bck = -1;
	for (k=0; k<demux[demux_id].EMMpidcount; k++) {
		if (demux[demux_id].EMMpids[k].CAID == demux[demux_id].ECMpids[demux[demux_id].pidindex].CAID
		 && demux[demux_id].EMMpids[k].PROVID == demux[demux_id].ECMpids[demux[demux_id].pidindex].PROVID
		 && demux[demux_id].EMMpids[k].type & type)
			return k;
		else if (demux[demux_id].EMMpids[k].CAID == demux[demux_id].ECMpids[demux[demux_id].pidindex].CAID
		 && (!demux[demux_id].EMMpids[k].PROVID || !demux[demux_id].ECMpids[demux[demux_id].pidindex].PROVID)
		 && (demux[demux_id].EMMpids[k].type & type) && bck == -1)
			bck = k;
	}
	return bck;
}

void dvbapi_start_emm_filter(int32_t demux_index) {
	int32_t j;
	const char *typtext[] = { "UNIQUE", "SHARED", "GLOBAL", "UNKNOWN" };

	if (demux[demux_index].pidindex==-1) return;

	if (demux[demux_index].EMMpidcount == 0 || !demux[demux_index].rdr || !hexserialset(demux[demux_index].rdr))
		return;

	if (demux[demux_index].emm_filter==1 && !memcmp(demux[demux_index].rdr->hexserial, demux[demux_index].hexserial, 8))
		return;

	if (memcmp(demux[demux_index].rdr->hexserial, demux[demux_index].hexserial, 8))
		dvbapi_stop_filter(demux_index, TYPE_EMM);

	uchar dmx_filter[342]; // 10 filter + 2 byte header
	memset(dmx_filter, 0, sizeof(dmx_filter));
	dmx_filter[0]=0xFF;
	dmx_filter[1]=0;

	struct s_cardsystem *cs = get_cardsystem_by_caid(demux[demux_index].ECMpids[demux[demux_index].pidindex].CAID);

	if (cs)
		cs->get_emm_filter(demux[demux_index].rdr, dmx_filter);
	else {
		cs_debug_mask(D_DVBAPI, "cardsystem for emm filter not found");
		return;	
	}

	int32_t filter_count=dmx_filter[1];

	cs_debug_mask(D_DVBAPI, "start %d emm filter for %s", filter_count, demux[demux_index].rdr->label);

	for (j=1;j<=filter_count && j <= 10;j++) {
		int32_t startpos=2+(34*(j-1));

		if (dmx_filter[startpos+1] != 0x00)
			continue;

		uchar filter[32];
		memcpy(filter, dmx_filter+startpos+2, 32);
		int32_t emmtype=dmx_filter[startpos];
		int32_t count=dmx_filter[startpos+1];
		int32_t l=-1;

		if ( (filter[0] && (((1<<(filter[0] % 0x80)) & demux[demux_index].rdr->b_nano) && !((1<<(filter[0] % 0x80)) & demux[demux_index].rdr->s_nano))) )
			continue;

		if ((demux[demux_index].rdr->blockemm & emmtype) && !((1<<(filter[0] % 0x80)) & demux[demux_index].rdr->s_nano))
			continue;

		l = dvbapi_find_emmpid(demux_index, emmtype);

		if (l>-1) {
			uint32_t typtext_idx = 0;
			while (((emmtype >> typtext_idx) & 0x01) == 0 && typtext_idx < sizeof(typtext) / sizeof(const char *))
                           ++typtext_idx;
			cs_ddump_mask(D_DVBAPI, filter, 32, "starting emm filter type %s, pid: 0x%04X", typtext[typtext_idx], demux[demux_index].EMMpids[l].PID);
			dvbapi_set_filter(demux_index, selected_api, demux[demux_index].EMMpids[l].PID, filter, filter+16, 0, demux[demux_index].pidindex, count, TYPE_EMM);
		} else {
			cs_debug_mask(D_DVBAPI, "no emm pid found");
		}
	}

	memcpy(demux[demux_index].hexserial, demux[demux_index].rdr->hexserial, 8);
	demux[demux_index].emm_filter=1;
}

void dvbapi_add_ecmpid(int32_t demux_id, uint16_t caid, uint16_t ecmpid, uint32_t provid) {
	int32_t n,added=0;

	if (demux[demux_id].ECMpidcount>=ECM_PIDS)
		return;

	int32_t stream = demux[demux_id].STREAMpidcount-1;
	for (n=0;n<demux[demux_id].ECMpidcount;n++) {
		if (stream>-1 && demux[demux_id].ECMpids[n].CAID == caid && demux[demux_id].ECMpids[n].ECM_PID == ecmpid) {
			if (!demux[demux_id].ECMpids[n].streams) {
				//we already got this caid/ecmpid as global, no need to add the single stream
				cs_debug_mask(D_DVBAPI, "[SKIP STREAM %d] CAID: %04X\tECM_PID: %04X\tPROVID: %06X", n, caid, ecmpid, provid);
				continue;
			}
			added=1;
			demux[demux_id].ECMpids[n].streams |= (1 << stream);
			cs_debug_mask(D_DVBAPI, "[ADD STREAM %d] CAID: %04X\tECM_PID: %04X\tPROVID: %06X", n, caid, ecmpid, provid);
		}
	}

	if (added==1)
		return;

	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].ECM_PID = ecmpid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CAID = caid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].PROVID = provid;
	if (stream>-1)
		demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].streams |= (1 << stream);

	cs_log("[ADD PID %d] CAID: %04X\tECM_PID: %04X\tPROVID: %06X", demux[demux_id].ECMpidcount, caid, ecmpid, provid);
	demux[demux_id].ECMpidcount++;
}

void dvbapi_add_emmpid(int32_t demux_id, uint16_t caid, uint16_t emmpid, uint32_t provid, uint8_t type) {
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PID = emmpid;
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].CAID = caid;
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PROVID = provid;
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount++].type = type;
	cs_debug_mask(D_DVBAPI, "[ADD EMMPID] CAID: %04X\tEMM_PID: %04X\tPROVID: %06X - (type %d)", caid, emmpid, provid, type);
}

void dvbapi_parse_cat(int32_t demux_id, uchar *buf, int32_t len) {
	uint16_t i, k;

	cs_ddump_mask(D_DVBAPI, buf, len, "cat:");

	for (i = 8; i < (((buf[1] & 0x0F) << 8) | buf[2]) - 1; i += buf[i + 1] + 2) {
		if (buf[i] != 0x09) continue;

		if (demux[demux_id].EMMpidcount >= ECM_PIDS) break;

		uint16_t caid=(((buf[i + 2] & 0x1F) << 8) | buf[i + 3]);
		uint16_t emm_pid=(((buf[i + 4] & 0x1F) << 8) | buf[i + 5]);
		uint32_t emm_provider = 0;

		switch (caid >> 8) {
			case 0x01:
				dvbapi_add_emmpid(demux_id, caid, emm_pid, 0, EMM_UNIQUE);
				cs_debug_mask(D_DVBAPI, "[cat] CAID: %04x\tEMM_PID: %04x", caid, emm_pid);
				for (k = i+7; k < i+buf[i+1]+2; k += 4) {
					emm_provider = (buf[k+2] << 8| buf[k+3]);
					emm_pid = (buf[k] & 0x0F) << 8 | buf[k+1];
					cs_debug_mask(D_DVBAPI, "[cat] CAID: %04X\tEMM_PID: %04X\tPROVID: %06X", caid, emm_pid, emm_provider);
					dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider, EMM_SHARED);
				}
				break;
			case 0x05:
				for (k = i+6; k < i+buf[i+1]+2; k += buf[k+1]+2) {
					if (buf[k]==0x14) {
						emm_provider = buf[k+2] << 16 | (buf[k+3] << 8| (buf[k+4] & 0xF0));
						cs_debug_mask(D_DVBAPI, "[cat] CAID: %04x\tEMM_PID: %04x\tPROVID: %06X", caid, emm_pid, emm_provider);
						dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
					}
				}
				break;
			case 0x18:
				emm_provider = (buf[i+1] == 0x07) ? (buf[i+6] << 16 | (buf[i+7] << 8| (buf[i+8]))) : 0;
				cs_debug_mask(D_DVBAPI, "[cat] CAID: %04x\tEMM_PID: %04x\tPROVID: %06X", caid, emm_pid, emm_provider);
				dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
				break;
			default:
				cs_debug_mask(D_DVBAPI, "[cat] CAID: %04x\tEMM_PID: %04x", caid, emm_pid);
				dvbapi_add_emmpid(demux_id, caid, emm_pid, 0, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
				break;
		}
	}
	return;
}

int32_t dvbapi_get_descindex() {
	int32_t i,j,idx=1,fail=1;
	while (fail) {
		fail=0;
		for (i=0;i<MAX_DEMUX;i++) {
			for (j=0;j<demux[i].ECMpidcount;j++) {
				if (demux[i].ECMpids[j].index==idx) {
					idx++;
					fail=1;
					break;
				}
			}
		}
	}
	return idx;
}

void dvbapi_set_pid(int32_t demux_id, int32_t num, int32_t index) {
	int32_t i;

	if (demux[demux_id].pidindex == -1) return;

	switch(selected_api) {
#ifdef WITH_STAPI
		case STAPI:
			stapi_set_pid(demux_id, num, index, demux[demux_id].STREAMpids[num], demux[demux_id].pmt_file);
			break;
#endif
		default:
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {
					if (ca_fd[i]<=0)
						ca_fd[i]=dvbapi_open_device(1, i, demux[demux_id].adapter_index);
					if (ca_fd[i]>0) {
						ca_pid_t ca_pid2;
						memset(&ca_pid2,0,sizeof(ca_pid2));
						ca_pid2.pid = demux[demux_id].STREAMpids[num];
						ca_pid2.index = index;
						if (ioctl(ca_fd[i], CA_SET_PID, &ca_pid2)==-1)
							cs_debug_mask(D_DVBAPI, "Error CA_SET_PID pid=0x%04x index=%d (errno=%d %s)", ca_pid2.pid, ca_pid2.index, errno, strerror(errno));
						else
							cs_debug_mask(D_DVBAPI, "CA_SET_PID pid=0x%04x index=%d", ca_pid2.pid, ca_pid2.index);
					}
				}
			}
			break;
	}
	return;
}

void dvbapi_stop_descrambling(int32_t demux_id) {
	int32_t i;

	if (demux[demux_id].program_number==0) return;

	cs_debug_mask(D_DVBAPI, "stop descrambling (demux_id: %d)", demux_id);

	dvbapi_stop_filter(demux_id, TYPE_ECM);
	dvbapi_stop_filter(demux_id, TYPE_EMM);

	for (i=0;i<demux[demux_id].STREAMpidcount;i++) {
		dvbapi_set_pid(demux_id, i, -1);
	}

	memset(&demux[demux_id], 0 ,sizeof(DEMUXTYPE));
	demux[demux_id].pidindex=-1;

	unlink(ECMINFO_FILE);

	return;
}

void dvbapi_start_descrambling(int32_t demux_id) {
	int32_t j,k;
	int32_t streamcount=0;

	demux[demux_id].pidindex = demux[demux_id].curindex;

	for (j=0; j<demux[demux_id].ECMpidcount; j++) {
		if (demux[demux_id].curindex == j || (demux[demux_id].ECMpids[demux[demux_id].curindex].CAID == demux[demux_id].ECMpids[j].CAID
				&& demux[demux_id].ECMpids[demux[demux_id].curindex].PROVID == demux[demux_id].ECMpids[j].PROVID
				&& demux[demux_id].ECMpids[j].PROVID > 0)) {

			if (demux[demux_id].curindex != j) {
				if (demux[demux_id].ECMpids[j].status < 0 || !demux[demux_id].ECMpids[demux[demux_id].curindex].streams)
					continue;

				dvbapi_start_filter(demux_id, j, demux[demux_id].ECMpids[j].ECM_PID, 0x80, 0xF0, 3000, TYPE_ECM, 0);
			}

			if (!demux[demux_id].ECMpids[j].index)
				demux[demux_id].ECMpids[j].index=dvbapi_get_descindex();

			demux[demux_id].ECMpids[j].checked=1;
			demux[demux_id].ECMpids[j].irdeto_curchid=demux[demux_id].ECMpids[demux[demux_id].curindex].irdeto_curchid;

			for (k=0;k<demux[demux_id].STREAMpidcount;k++) {
				if (!demux[demux_id].ECMpids[j].streams || (demux[demux_id].ECMpids[j].streams & (1 << k))) {
					dvbapi_set_pid(demux_id, k, demux[demux_id].ECMpids[j].index-1);
				}
			}

			streamcount++;
		}
	}

	cs_log("Start descrambling PID #%d (CAID: %04X) %d", demux[demux_id].curindex, demux[demux_id].ECMpids[demux[demux_id].curindex].CAID, streamcount);

	if (cfg.dvbapi_au>0)
		dvbapi_start_filter(demux_id, demux[demux_id].pidindex, 0x001, 0x01, 0xFF, 0, TYPE_EMM, 0); //CAT
}

#ifdef READER_VIACCESS
extern int32_t viaccess_reassemble_emm(uchar *buffer, uint32_t *len);
#endif
#ifdef READER_CRYPTOWORKS
extern int32_t cryptoworks_reassemble_emm(uchar *buffer, uint32_t *len);
#endif

void dvbapi_process_emm (int32_t demux_index, int32_t filter_num, unsigned char *buffer, uint32_t len) {
	EMM_PACKET epg;

	if (demux[demux_index].pidindex==-1) return;

	uint32_t provider = demux[demux_index].ECMpids[demux[demux_index].pidindex].PROVID;
	uint16_t caid = demux[demux_index].ECMpids[demux[demux_index].pidindex].CAID;

	switch (caid >> 8) {
		case 0x05:
#ifdef READER_VIACCESS
			if (!viaccess_reassemble_emm(buffer, &len))
#endif
				return;
			break;
      		case 0x0d:
#ifdef READER_CRYPTOWORKS
			if (!cryptoworks_reassemble_emm(buffer, &len))
#endif
				return;
			break;
	}


	cs_ddump_mask(D_DVBAPI, buffer, len, "emm from fd %d:", demux[demux_index].demux_fd[filter_num].fd);

	struct s_dvbapi_priority *mapentry = dvbapi_check_prio_match(demux_index, demux[demux_index].pidindex, 'm');
	if (mapentry) {
		cs_debug_mask(D_DVBAPI, "Mapping EMM from %04X:%06X to %04X:%06X", caid, provider, mapentry->mapcaid, mapentry->mapprovid);
		caid = mapentry->mapcaid;
		provider = mapentry->mapprovid;
	}

	memset(&epg, 0, sizeof(epg));

	i2b_buf(2, caid, epg.caid);
	i2b_buf(4, provider, epg.provid);

	epg.l=len;
	memcpy(epg.emm, buffer, epg.l);

	do_emm(dvbapi_client, &epg);
}

void dvbapi_read_priority() {
	FILE *fp;
	char token[128], str1[128];
	char type;
	int32_t i, ret, count=0;

	const char *cs_prio="oscam.dvbapi";

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_prio);
	fp=fopen(token, "r");

	if (!fp) {
		cs_log("can't open priority file %s", token);
		return;
	}

	if (dvbapi_priority) {
		cs_log("reread priority file %s", cs_prio);
		struct s_dvbapi_priority *o, *p;
		for (p = dvbapi_priority; p != NULL; p = o) {
			o = p->next;
			free(p);
		}
		dvbapi_priority = NULL;
	}

	while (fgets(token, sizeof(token), fp)) {
		if (token[0]=='#' || token[0]=='/') continue;
		if (strlen(token)>100) continue;

		memset(str1, 0, 128);

		for (i=0;i<(int)strlen(token);i++) {
			if ((token[i]==':' || token[i]==' ') && token[i+1]==':') {
				memmove(token+i+2, token+i+1, strlen(token)-i+1);
				token[i+1]='0';
			}
			if (token[i]=='#' || token[i]=='/') {
				token[i]='\0';
				break;
			}
		}

		type = 0;
#ifdef WITH_STAPI
		uint32_t disablefilter=0;
		ret = sscanf(trim(token), "%c: %63s %63s %d", &type, str1, str1+64, &disablefilter);
#else
		ret = sscanf(trim(token), "%c: %63s %63s", &type, str1, str1+64);
#endif
		type = tolower(type);

		if (ret<1 || (type != 'p' && type != 'i' && type != 'm' && type != 'd' && type != 's' && type != 'l'))
			continue;

		struct s_dvbapi_priority *entry;
		if(!cs_malloc(&entry,sizeof(struct s_dvbapi_priority), -1)){
			fclose(fp);
			return;
		}

		entry->type=type;
		entry->next=NULL;

		count++;

#ifdef WITH_STAPI
		if (type=='s') {
			strncpy(entry->devname, str1, 29);
			strncpy(entry->pmtfile, str1+64, 29);

			entry->disablefilter=disablefilter;

			cs_debug_mask(D_DVBAPI, "stapi prio: ret=%d | %c: %s %s | disable %d", ret, type, entry->devname, entry->pmtfile, disablefilter);

			if (!dvbapi_priority) {
				dvbapi_priority=entry;
			} else {
 				struct s_dvbapi_priority *p;
				for (p = dvbapi_priority; p->next != NULL; p = p->next);
				p->next = entry;
			}
			continue;
		}
#endif

		char c_srvid[34];
		c_srvid[0]='\0';
		uint32_t caid=0, provid=0, srvid=0, ecmpid=0, chid=0;
		sscanf(str1, "%4x:%6x:%33[^:s]:%4x:%4x", &caid, &provid, c_srvid, &ecmpid, &chid);

		entry->caid=caid;
		entry->provid=provid;
		entry->ecmpid=ecmpid;
		entry->chid=chid;

		uint32_t delay=0, force=0, mapcaid=0, mapprovid=0;
		switch (type) {
			case 'd':
				sscanf(str1+64, "%4d", &delay);
				entry->delay=delay;
				break;
			case 'l':
				entry->delay = dyn_word_atob(str1+64);
				if (entry->delay == -1) entry->delay = 0;
				break;
			case 'p':
				sscanf(str1+64, "%1d", &force);
				entry->force=force;
				break;
			case 'm':
				sscanf(str1+64, "%4x:%6x", &mapcaid, &mapprovid);
				entry->mapcaid=mapcaid;
				entry->mapprovid=mapprovid;
				break;
		}

		if (c_srvid[0]=='=') {
			struct s_srvid *this;

			for (i=0;i<16;i++)
			for (this = cfg.srvid[i]; this; this = this->next) {
				if (strcmp(this->prov, c_srvid+1)==0) {
					struct s_dvbapi_priority *entry2;
					if(!cs_malloc(&entry2,sizeof(struct s_dvbapi_priority), -1)) continue;
					memcpy(entry2, entry, sizeof(struct s_dvbapi_priority));

					entry2->srvid=this->srvid;

					cs_debug_mask(D_DVBAPI, "prio srvid: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X | prio %d | delay %d",
						ret, entry2->type, entry2->caid, entry2->provid, entry2->srvid, entry2->ecmpid, entry2->chid, entry2->mapcaid, entry2->mapprovid, entry2->force, entry2->delay);

					if (!dvbapi_priority) {
						dvbapi_priority=entry2;
					} else {
 						struct s_dvbapi_priority *p;
						for (p = dvbapi_priority; p->next != NULL; p = p->next);
						p->next = entry2;
					}
				}
			}
			free(entry);
			continue;
		} else {
			sscanf(c_srvid, "%4x", &srvid);
			entry->srvid=srvid;
		}

		cs_debug_mask(D_DVBAPI, "prio: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X | prio %d | delay %d",
			ret, entry->type, entry->caid, entry->provid, entry->srvid, entry->ecmpid, entry->chid, entry->mapcaid, entry->mapprovid, entry->force, entry->delay);

		if (!dvbapi_priority) {
			dvbapi_priority=entry;
		} else {
 			struct s_dvbapi_priority *p;
			for (p = dvbapi_priority; p->next != NULL; p = p->next);
			p->next = entry;
		}
	}

	cs_log("%d entries read from %s", count, cs_prio);

	fclose(fp);
	return;
}

struct s_dvbapi_priority *dvbapi_check_prio_match(int32_t demux_id, int32_t pidindex, char type) {
	struct s_dvbapi_priority *p;
	struct s_ecmpids *ecmpid = &demux[demux_id].ECMpids[pidindex];
	int32_t i;

	for (p=dvbapi_priority, i=0; p != NULL; p=p->next, i++) {
		if (p->type != type) continue;

		if (p->caid 	&& p->caid 	!= ecmpid->CAID)	continue;
		if (p->provid && p->provid 	!= ecmpid->PROVID)	continue;
		if (p->ecmpid	&& p->ecmpid 	!= ecmpid->ECM_PID)	continue;
		if (p->srvid	&& p->srvid 	!= demux[demux_id].program_number)			continue;

		if (p->type == 'i' && p->chid) continue;

		return p;
	}
	return NULL;

}

void dvbapi_resort_ecmpids(int32_t demux_index) {
	int32_t n,i;

	for (n=0; n<demux[demux_index].ECMpidcount; n++)
		demux[demux_index].ECMpids[n].status=0;

	demux[demux_index].max_status=0;
	int32_t new_status=1;

	if (dvbapi_priority) {
		struct s_dvbapi_priority *p;
		for (p=dvbapi_priority, i=0; p != NULL; p=p->next, i++) {
			if (p->type != 'p' && p->type != 'i') continue;
			for (n=0; n<demux[demux_index].ECMpidcount; n++) {
				if (demux[demux_index].ECMpids[n].status != 0) continue;

				if (p->caid 	&& p->caid 	!= demux[demux_index].ECMpids[n].CAID)	continue;
				if (p->provid && p->provid 	!= demux[demux_index].ECMpids[n].PROVID)	continue;
				if (p->ecmpid	&& p->ecmpid 	!= demux[demux_index].ECMpids[n].ECM_PID)	continue;
				if (p->srvid	&& p->srvid	!= demux[demux_index].program_number)	continue;

				if (p->type=='p') {
					demux[demux_index].ECMpids[n].status = new_status++;
					cs_debug_mask(D_DVBAPI, "[PRIORITIZE PID %d] %04X:%06X (position: %d)", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].status);
				} else if (p->type=='i') {
					if (p->chid) continue;
					demux[demux_index].ECMpids[n].status = -1;
					cs_debug_mask(D_DVBAPI, "[IGNORE PID %d] %04X:%06X (file)", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID);
				}
			}
		}
	}

	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		int32_t nr;
		SIDTAB *sidtab;
		ECM_REQUEST er;
		er.caid  = demux[demux_index].ECMpids[n].CAID;
		er.prid  = demux[demux_index].ECMpids[n].PROVID;
		er.srvid = demux[demux_index].program_number;

		for (nr=0, sidtab=cfg.sidtab; sidtab; sidtab=sidtab->next, nr++) {
			if (sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid) {
				if ((cfg.dvbapi_sidtabno&((SIDTABBITS)1<<nr)) && (chk_srvid_match(&er, sidtab))) {
					demux[demux_index].ECMpids[n].status = -1; //ignore
					cs_debug_mask(D_DVBAPI, "[IGNORE PID %d] %04X:%06X (service %s) pos %d", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, sidtab->label, nr);
				}
				if ((cfg.dvbapi_sidtabok&((SIDTABBITS)1<<nr)) && (chk_srvid_match(&er, sidtab))) {
					demux[demux_index].ECMpids[n].status = new_status++; //priority
					cs_debug_mask(D_DVBAPI, "[PRIORITIZE PID %d] %04X:%06X (service: %s position: %d)", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, sidtab->label, demux[demux_index].ECMpids[n].status);
				}
			}
		}
	}

	demux[demux_index].max_status = new_status;
	return;
}


void dvbapi_parse_descriptor(int32_t demux_id, uint32_t info_length, unsigned char *buffer) {
	//int32_t ca_pmt_cmd_id = buffer[i + 5];
	uint32_t descriptor_length=0;
	uint32_t j,u;

	if (info_length<1)
		return;

	if (buffer[0]==0x01) {
		buffer=buffer+1;
		info_length--;
	}

	for (j = 0; j < info_length; j += descriptor_length + 2) {
		descriptor_length = buffer[j+1];
		int32_t descriptor_ca_system_id = (buffer[j+2] << 8) | buffer[j+3];
		int32_t descriptor_ca_pid = ((buffer[j+4] & 0x1F) << 8) | buffer[j+5];
		int32_t descriptor_ca_provider = 0;

		if (demux[demux_id].ECMpidcount>=ECM_PIDS)
			break;

		cs_debug_mask(D_DVBAPI, "[pmt] type: %02x\tlength: %d", buffer[j], descriptor_length);

		if (buffer[j] != 0x09) continue;

		if (descriptor_ca_system_id >> 8 == 0x01) {
			for (u=2; u<descriptor_length; u+=15) {
				descriptor_ca_pid = ((buffer[j+2+u] & 0x1F) << 8) | buffer[j+2+u+1];
				descriptor_ca_provider = (buffer[j+2+u+2] << 8) | buffer[j+2+u+3];
				dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider);
			}
		} else {
			if (descriptor_ca_system_id >> 8 == 0x05 && descriptor_length == 0x0F && buffer[j+12] == 0x14)
				descriptor_ca_provider = buffer[j+14] << 16 | (buffer[j+15] << 8| (buffer[j+16] & 0xF0));

			if (descriptor_ca_system_id >> 8 == 0x18 && descriptor_length == 0x07)
				descriptor_ca_provider = buffer[j+6] << 16 | (buffer[j+7] << 8| (buffer[j+8])); 

			if (descriptor_ca_system_id >> 8 == 0x4A && descriptor_length == 0x05)
				descriptor_ca_provider = buffer[j+6];

			dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider);
		}
	}
}

void dvbapi_try_next_caid(int32_t demux_id) {
	int32_t num=-1, n, j;

	if (demux[demux_id].tries > 2) {
		cs_log("can't decode channel");
		dvbapi_stop_filter(demux_id, TYPE_ECM);
		return;
	}

	//values for first run (status > 0)
	int32_t start=1;
	int32_t end=demux[demux_id].max_status;

	while (num==-1) {
		for (j = start; j <= end && num == -1; j++) {
			for (n=0; n<demux[demux_id].ECMpidcount; n++) {
				if (demux[demux_id].ECMpids[n].checked == 0 && demux[demux_id].ECMpids[n].status == j) {
					num=n;
					break;
				}
			}
		}
		if (start==0 || num>-1) break;
		//values for second run (status==0)
		start=0;
		end=0;
	}

	if (num == -1) {
		if (cfg.dvbapi_requestmode == 1)
			return;

		demux[demux_id].tries++;
		cs_log("try pids again #%d", demux[demux_id].tries);
		for (n=0; n<demux[demux_id].ECMpidcount; n++) {
			demux[demux_id].ECMpids[n].checked=0;
			demux[demux_id].ECMpids[n].irdeto_curchid=0;
			demux[demux_id].ECMpids[n].irdeto_chids=0;
			demux[demux_id].ECMpids[n].irdeto_cycle=0;
			demux[demux_id].ECMpids[n].table=0;
		}
		dvbapi_try_next_caid(demux_id);
		return;
	}

	if (cfg.dvbapi_requestmode != 1)
		dvbapi_stop_filter(demux_id, TYPE_ECM);

	cs_debug_mask(D_DVBAPI, "[TRY PID %d] CAID: %04X PROVID: %06X CA_PID: %04X", num, demux[demux_id].ECMpids[num].CAID, demux[demux_id].ECMpids[num].PROVID, demux[demux_id].ECMpids[num].ECM_PID);
#ifdef AZBOX
	openxcas_provid = demux[demux_id].ECMpids[num].PROVID;
	openxcas_caid = demux[demux_id].ECMpids[num].CAID;
	openxcas_ecm_pid = demux[demux_id].ECMpids[num].ECM_PID;
#endif
	demux[demux_id].curindex=num;

	demux[demux_id].ECMpids[num].checked=1;

	//BISS
	//ecm stream pid is fake, so send out one fake ecm request
	if ((demux[demux_id].ECMpids[num].CAID >> 8) == 0x26) {
		ECM_REQUEST *er;
		if (!(er=get_ecmtask()))
			return;

		er->srvid = demux[demux_id].program_number;
		er->caid  = demux[demux_id].ECMpids[num].CAID;
		er->pid   = demux[demux_id].ECMpids[num].ECM_PID;
		er->prid  = demux[demux_id].ECMpids[num].PROVID;

		er->l=3;
		memset(er->ecm, 0, 3);

		cs_debug_mask(D_DVBAPI, "request cw for caid %04X provid %06X srvid %04X pid %04X", er->caid, er->prid, er->srvid, er->pid);
		get_cw(dvbapi_client, er);

		if (cfg.dvbapi_requestmode == 1)
			dvbapi_try_next_caid(demux_id);

		return;
	}

	if (cfg.dvbapi_requestmode == 1) {
		dvbapi_start_filter(demux_id, num, demux[demux_id].ECMpids[num].ECM_PID, 0x80, 0xF0, 3000, TYPE_ECM, 3); 
		dvbapi_try_next_caid(demux_id);
	} else {
		dvbapi_start_filter(demux_id, num, demux[demux_id].ECMpids[num].ECM_PID, 0x80, 0xF0, 3000, TYPE_ECM, 0);
	}
}

int32_t dvbapi_parse_capmt(unsigned char *buffer, uint32_t length, int32_t connfd, char *pmtfile) {
	uint32_t i;
	int32_t demux_id=-1;
	uint16_t ca_mask=0x01, demux_index=0x00, adapter_index=0x00;

	int32_t ca_pmt_list_management = buffer[0];
	uint32_t program_number = (buffer[1] << 8) | buffer[2];
	uint32_t program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	if (buffer[17]==0x82 && buffer[18]==0x02) {
		//enigma2
		ca_mask = buffer[19];
		demux_index = buffer[20];
	}

	cs_ddump_mask(D_DVBAPI, buffer, length, "capmt:");

	for (i = 0; i < MAX_DEMUX; i++) {
		if (connfd>0 && demux[i].socket_fd == connfd) {
			//PMT Update
#ifdef COOL
			demux_id = i;
			unsigned char lastcw[16];
			int32_t n;
			for(n = 0; n < 2; n++) {
				memcpy(&lastcw[n*8], demux[demux_id].lastcw[n], 8);
				memset(demux[demux_id].lastcw[n], 0, 8);
			}
			demux[demux_id].ca_mask=ca_mask;
			dvbapi_write_cw(demux_id, lastcw, 0);//FIXME
			demux[demux_id].curindex = demux[demux_id].pidindex;
			demux[demux_id].STREAMpidcount=0;
			demux[demux_id].ECMpidcount=0;
			demux[demux_id].EMMpidcount=0;
			ca_pmt_list_management = 0x03;
#else
			if (ca_pmt_list_management == 0x05) {
				demux_id = i;
				demux[demux_id].curindex = demux[demux_id].pidindex;
				demux[demux_id].STREAMpidcount=0;
				demux[demux_id].ECMpidcount=0;
				demux[demux_id].EMMpidcount=0;
			}
			if (ca_pmt_list_management == 0x03 || ca_pmt_list_management == 0x01)
				dvbapi_stop_descrambling(i);
			if (ca_pmt_list_management == 0x02)
				demux_id=i;
#endif
		}
	}

	if (demux_id==-1)
		for (demux_id=0; demux_id<MAX_DEMUX && demux[demux_id].program_number>0; demux_id++);

	if (demux_id>=MAX_DEMUX) {
		cs_log("error no free id (MAX_DEMUX)");
		return -1;
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_IPBOX_PMT) {
		ca_mask = demux_id + 1;
		demux_index = demux_id;
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_QBOXHD && buffer[17]==0x82 && buffer[18]==0x03) {
		//ca_mask = buffer[19];     // with STONE 1.0.4 always 0x01
		demux_index = buffer[20];   // with STONE 1.0.4 always 0x00
		adapter_index = buffer[21]; // with STONE 1.0.4 adapter index can be 0,1,2
		ca_mask = (1 << adapter_index); // use adapter_index as ca_mask (used as index for ca_fd[] array)
	}

	demux[demux_id].program_number=((buffer[1] << 8) | buffer[2]);
	demux[demux_id].demux_index=demux_index;
	demux[demux_id].adapter_index=adapter_index;
	demux[demux_id].ca_mask=ca_mask;
	demux[demux_id].socket_fd=connfd;
	demux[demux_id].rdr=NULL;
	demux[demux_id].pidindex=-1;

	cs_debug_mask(D_DVBAPI, "id: %d\tdemux_index: %d\tca_mask: %02x\tprogram_info_length: %d\tca_pmt_list_management %02x", 
			demux_id, demux[demux_id].demux_index, demux[demux_id].ca_mask, program_info_length, ca_pmt_list_management);

	if (pmtfile)
		cs_strncpy(demux[demux_id].pmt_file, pmtfile, sizeof(demux[demux_id].pmt_file));

	if (program_info_length > 1 && program_info_length < length)
		dvbapi_parse_descriptor(demux_id, program_info_length-1, buffer+7);

	uint32_t es_info_length=0;
	for (i = program_info_length + 6; i < length; i += es_info_length + 5) {
		int32_t stream_type = buffer[i];
		uint16_t elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug_mask(D_DVBAPI, "[pmt] stream_type: %02x\tpid: %04x\tlength: %d", stream_type, elementary_pid, es_info_length);

		if (demux[demux_id].STREAMpidcount >= ECM_PIDS)
			break;

		demux[demux_id].STREAMpids[demux[demux_id].STREAMpidcount++]=elementary_pid;

		if (es_info_length != 0 && es_info_length < length) {
			dvbapi_parse_descriptor(demux_id, es_info_length, buffer+i+5);
		}
	}
	cs_debug_mask(D_DVBAPI, "Found %d ECMpids and %d STREAMpids in PMT", demux[demux_id].ECMpidcount, demux[demux_id].STREAMpidcount);

	char channame[32];
	get_servicename(dvbapi_client, demux[demux_id].program_number, demux[demux_id].ECMpidcount>0 ? demux[demux_id].ECMpids[0].CAID : 0, channame);
	cs_log("new program number: %04X (%s)", program_number, channame);

#ifdef AZBOX
	openxcas_sid = program_number;
#endif

	if (ca_pmt_list_management == 0x05) {
		if (demux[demux_id].curindex==-1) {
			dvbapi_resort_ecmpids(demux_id);
			dvbapi_try_next_caid(demux_id);
		} else
			dvbapi_start_descrambling(demux_id);
	} else if (demux[demux_id].ECMpidcount>0 && ca_pmt_list_management != 0x01) {
		dvbapi_resort_ecmpids(demux_id);
		dvbapi_try_next_caid(demux_id);
	} else {
		// set channel srvid+caid
		dvbapi_client->last_srvid = demux[demux_id].program_number;
		dvbapi_client->last_caid = 0;
		// reset idle-Time
		dvbapi_client->last=time((time_t)0);
	}

	return demux_id;
}


void dvbapi_handlesockmsg (unsigned char *buffer, uint32_t len, int32_t connfd) {
	uint32_t val=0, size=0, i, k;

	//cs_dump(buffer, len, "handlesockmsg:");
	for (k = 0; k < len; k += 3 + size + val) {
		if (buffer[0+k] != 0x9F || buffer[1+k] != 0x80) {
			cs_log("unknown socket command: %02x", buffer[0+k]);
			return;
		}

		if (k>0) {
			cs_log("Unsupported capmt. Please report");
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
				dvbapi_parse_capmt(buffer + size + 3 + k, val, connfd, NULL);
				break;
			case 0x3f:
				//9F 80 3f 04 83 02 00 <demux index>
				cs_ddump_mask(D_DVBAPI, buffer, len, "capmt 3f:");
				// ipbox fix
				if (cfg.dvbapi_boxtype==BOXTYPE_IPBOX) {
					int32_t demux_index=buffer[7+k];
					for (i = 0; i < MAX_DEMUX; i++) {
						if (demux[i].demux_index == demux_index) {
							dvbapi_stop_descrambling(i);
							break;
						}
					}
					// check do we have any demux running on this fd
					int16_t execlose = 1;
					for (i = 0; i < MAX_DEMUX; i++) {
						if (demux[i].socket_fd == connfd) {
							 execlose = 0;
							 break;
						}
					}
					if (execlose) close(connfd);
				} else {
					close(connfd);
				}
				break;
			default:
				cs_log("handlesockmsg() unknown command");
				cs_dump(buffer, len, "unknown command:");
				break;
		}
	}
}

int32_t dvbapi_init_listenfd() {
	int32_t clilen,listenfd;
	struct sockaddr_un servaddr;

	memset(&servaddr, 0, sizeof(struct sockaddr_un));
	servaddr.sun_family = AF_UNIX;
	cs_strncpy(servaddr.sun_path, devices[selected_box].cam_socket_path, sizeof(servaddr.sun_path));
	clilen = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

	if ((unlink(devices[selected_box].cam_socket_path) < 0) && (errno != ENOENT))
		return 0;
	if ((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return 0;
	if (bind(listenfd, (struct sockaddr *) &servaddr, clilen) < 0)
		return 0;
	if (listen(listenfd, 5) < 0)
		return 0;
    // change the access right on the camd.socket
    // this will allow oscam to run as root if needed
    // and still allow non root client to connect to the socket

    chmod(devices[selected_box].cam_socket_path, S_IRWXU | S_IRWXG | S_IRWXO);

	return listenfd;
}

void dvbapi_chk_caidtab(char *caidasc, char type) {
	char *ptr1, *ptr3, *saveptr1 = NULL;
	int32_t i;

	for (i=0, ptr1=strtok_r(caidasc, ",", &saveptr1); (ptr1); ptr1=strtok_r(NULL, ",", &saveptr1)) {
		uint32_t caid, prov;
		if( (ptr3=strchr(trim(ptr1), ':')) )
			*ptr3++='\0';
		else
			ptr3="";

		if (((caid=a2i(ptr1, 2))|(prov=a2i(ptr3, 3)))) {
			struct s_dvbapi_priority *entry;
			if(!cs_malloc(&entry,sizeof(struct s_dvbapi_priority), -1)) return;
			entry->caid=caid;

			if (type=='d') {
				char tmp1[5];
				snprintf(tmp1, sizeof(tmp1), "%04X", (uint)prov);
				int32_t cw_delay = strtol(tmp1, '\0', 10);
				entry->delay=cw_delay;
			} else
				entry->provid=prov;

			entry->type=type;

			entry->next=NULL;

			if (!dvbapi_priority) {
				dvbapi_priority=entry;
			} else {
	 			struct s_dvbapi_priority *p;
				for (p = dvbapi_priority; p->next != NULL; p = p->next);
				p->next = entry;
			}

		}
	}
}

pthread_mutex_t event_handler_lock;

void event_handler(int32_t signal) {
	struct stat pmt_info;
	char dest[1024];
	DIR *dirp;
	struct dirent *dp;
	int32_t i, pmt_fd;
	uchar mbuf[1024];

	if (dvbapi_client != cur_client()) return;

	signal=signal; //avoid compiler warnings

	if (pthread_mutex_trylock(&event_handler_lock) == EBUSY)
		return;

	int32_t standby_fd = open(STANDBY_FILE, O_RDONLY);
	pausecam = (standby_fd > 0) ? 1 : 0;
	if (standby_fd) close(standby_fd);

	if (cfg.dvbapi_boxtype==BOXTYPE_IPBOX || cfg.dvbapi_pmtmode == 1) {
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].pmt_file[0] != 0) {
			snprintf(dest, sizeof(dest), "%s%s", TMPDIR, demux[i].pmt_file);
			pmt_fd = open(dest, O_RDONLY);
			if(pmt_fd>0) {
				if (fstat(pmt_fd, &pmt_info) != 0) {
					close(pmt_fd);
					continue;
				}

				if (pmt_info.st_mtime != demux[i].pmt_time) {
					cs_log("stoping demux for pmt file %s", dest);
				 	dvbapi_stop_descrambling(i);
				}

				close(pmt_fd);
				continue;
			} else {
				cs_log("stoping demux for pmt file %s", dest);
				dvbapi_stop_descrambling(i);
			}
		}
	}

	if (disable_pmt_files) {
	   	pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	dirp = opendir(TMPDIR);
	if (!dirp) {
		cs_log("opendir failed (errno=%d %s)", errno, strerror(errno));
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	while ((dp = readdir(dirp))) {
		if (strlen(dp->d_name) < 7)
  			continue;
		if (strncmp(dp->d_name, "pmt", 3)!=0 || strncmp(dp->d_name+strlen(dp->d_name)-4, ".tmp", 4)!=0)
			continue;

		snprintf(dest, sizeof(dest), "%s%s", TMPDIR, dp->d_name);
		pmt_fd = open(dest, O_RDONLY);
		if (pmt_fd < 0)
			continue;

		if (fstat(pmt_fd, &pmt_info) != 0)
			{ close(pmt_fd); continue; }

		int32_t found=0;
		for (i=0;i<MAX_DEMUX;i++) {
			if (strcmp(demux[i].pmt_file, dp->d_name)==0) {
				if (pmt_info.st_mtime == demux[i].pmt_time) {
				 	found=1;
					continue;
				}
				dvbapi_stop_descrambling(i);
			}
		}
		if (found)
			{ close(pmt_fd); continue; }

		cs_log("found pmt file %s", dest);
		cs_sleepms(100);

		uint32_t len = read(pmt_fd,mbuf,sizeof(mbuf));
		close(pmt_fd);

		if (len < 1) {
			cs_log("pmt file %s have invalid len!", dest);
			continue;
		}

		int32_t pmt_id;
#ifdef QBOXHD
		uint32_t j1,j2;
		// QboxHD pmt.tmp is the full capmt written as a string of hex values
		// pmt.tmp must be longer than 3 bytes (6 hex chars) and even length
		if ((len<6) || ((len%2) != 0) || ((len/2)>sizeof(dest))) {
			cs_log("error parsing QboxHD pmt.tmp, incorrect length");
			continue;
		}

		for(j2=0,j1=0;j2<len;j2+=2,j1++) {
			if (sscanf((char*)mbuf+j2, "%02X", dest+j1) != 1) {
				cs_log("error parsing QboxHD pmt.tmp, data not valid in position %d",j2);
				pthread_mutex_unlock(&event_handler_lock);
				return;
			}
		}

		cs_ddump_mask(D_DVBAPI, dest,len/2,"QboxHD pmt.tmp:");

		pmt_id = dvbapi_parse_capmt(dest+4, (len/2)-4, -1, dp->d_name);
#else
		if (len>sizeof(dest)) {
			cs_log("event_handler() dest buffer is to small for pmt data!");
			continue;
		}
		cs_ddump_mask(D_DVBAPI, mbuf,len,"pmt:");

		memcpy(dest, "\x03\xFF\xFF\x00\x00\x13\x00", 7);

		dest[1] = mbuf[3];
		dest[2] = mbuf[4];
		dest[5] = mbuf[11]+1;

		memcpy(dest + 7, mbuf + 12, len - 12 - 4);

		pmt_id = dvbapi_parse_capmt((uchar*)dest, 7 + len - 12 - 4, -1, dp->d_name);
#endif
		if (pmt_id>=0) {
			cs_strncpy(demux[pmt_id].pmt_file, dp->d_name, sizeof(demux[pmt_id].pmt_file));
			demux[pmt_id].pmt_time = pmt_info.st_mtime;
		}

		if (cfg.dvbapi_pmtmode == 3) {
			disable_pmt_files=1;
			break;
		}
	}
	closedir(dirp);
	pthread_mutex_unlock(&event_handler_lock);
}

void *dvbapi_event_thread(void *cli) {
	struct s_client * client = (struct s_client *) cli;
	pthread_setspecific(getclient, client);

	while(1) {
		cs_sleepms(750);
		event_handler(0);
	}
	
	return NULL;
}

void dvbapi_process_input(int32_t demux_id, int32_t filter_num, uchar *buffer, int32_t len) {
	struct s_ecmpids *curpid = &demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex];
	uint16_t chid = 0;

#ifdef COOL
	cs_debug_mask(D_DVBAPI, "dvbapi_process_input: demux %d filter %d len %d buffer %x curtable %x curindex %d\n", demux_id, filter_num, len, buffer[0], curpid->table, demux[demux_id].curindex);
#endif

	if (pausecam)
		return;

	struct s_dvbapi_priority *p;
	for (p = dvbapi_priority; p != NULL; p = p->next) {
		if (p->type != 'l')		continue;

		if (p->caid 	&& p->caid 	!= curpid->CAID)	continue;
		if (p->provid && p->provid 	!= curpid->PROVID)	continue;
		if (p->ecmpid	&& p->ecmpid 	!= curpid->ECM_PID)	continue;
		if (p->srvid	&& p->srvid 	!= demux[demux_id].program_number)	continue;

		if (p->delay == len && p->force < 6) {
			p->force++;
			return;
		}
		if (p->force >= 6)
			p->force=0;
	}

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_ECM) {
		if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
			return;

		if (buffer[0] != 0x80 && buffer[0] != 0x81)
			return;

		uint16_t caid = curpid->CAID;
		uint32_t provid = curpid->PROVID;

		if ((caid >> 8) == 0x06) {
			//80 70 39 53 04 05 00 88
			if (buffer[5]>20) return;
			if (curpid->irdeto_numchids != buffer[5]+1) {
				cs_log("Found %d IRDETO ECM CHIDs", buffer[5]+1);
				curpid->irdeto_numchids = buffer[5]+1;
				curpid->irdeto_curchid = 0;
				curpid->irdeto_cycle = 0;
				curpid->irdeto_chids = 0;
				if (demux[demux_id].demux_fd[filter_num].count && (demux[demux_id].demux_fd[filter_num].count < (curpid->irdeto_numchids * 3)))
					demux[demux_id].demux_fd[filter_num].count = curpid->irdeto_numchids * 3;
			}

			if (curpid->irdeto_curchid+1 > curpid->irdeto_numchids) {
				curpid->irdeto_cycle++;
				curpid->irdeto_curchid = 0;
			}

			if (buffer[4] != curpid->irdeto_curchid) {
				//wait for the correct chid
				return;
			}

			chid = (buffer[6] << 8) | buffer[7];
			if (demux[demux_id].pidindex==-1) {
				int8_t i = 0, found = 0;

				if (curpid->irdeto_chids & (1<<curpid->irdeto_curchid)) {
					curpid->irdeto_curchid++;
					return;
				}

				for (p=dvbapi_priority, i=0; p != NULL && curpid->irdeto_cycle > -1; p = p->next) {
					if (p->type != 'p' && p->type != 'i') continue;

					if (!p->chid) continue;

					if (p->caid 	&& p->caid 	!= curpid->CAID)	continue;
					if (p->provid && p->provid 	!= curpid->PROVID)	continue;
					if (p->ecmpid	&& p->ecmpid 	!= curpid->ECM_PID)	continue;
					if (p->srvid	&& p->srvid 	!= demux[demux_id].program_number)	continue;

					if (p->type == 'i' && p->chid == chid) {
						curpid->irdeto_chids |= (1<<curpid->irdeto_curchid);
						curpid->irdeto_curchid++;
						return;
					} else if (p->type == 'i')
						continue;
	
					if (i++ != curpid->irdeto_cycle)
						continue;

					if (p->chid == chid) {
						found=1;
						break;
					} else {
						curpid->irdeto_curchid++;
						return;
					}
				}

				if (!found && curpid->irdeto_cycle > -1) {
					curpid->irdeto_cycle = -1;
					curpid->irdeto_curchid = 0;
					return;
				}

				if (curpid->irdeto_curchid+1 > curpid->irdeto_numchids)
					return;
			}
			curpid->irdeto_chids |= (1<<curpid->irdeto_curchid);
		}

		if (curpid->table == buffer[0])
			return;

		curpid->table = buffer[0];
#ifdef COOL
		int32_t num = demux[demux_id].curindex;//FIXME or pidindex ?
		dvbapi_stop_filternum(demux_id, filter_num);
		dvbapi_start_filter(demux_id, num, demux[demux_id].ECMpids[num].ECM_PID, buffer[0] ^ 1, 0xFF, 3000, TYPE_ECM, 0);
#endif

		struct s_dvbapi_priority *mapentry = dvbapi_check_prio_match(demux_id, demux[demux_id].demux_fd[filter_num].pidindex, 'm');

		if (!provid)
			provid = chk_provid(buffer, caid);

		if (provid != curpid->PROVID)
			curpid->PROVID = provid;

		if (cfg.dvbapi_au>0)
			dvbapi_start_emm_filter(demux_id);

		ECM_REQUEST *er;
		if (!(er=get_ecmtask()))
			return;

		er->srvid = demux[demux_id].program_number;
		er->caid  = caid;
		er->pid   = curpid->ECM_PID;
		er->prid  = provid;

		if (mapentry) {
			cs_debug_mask(D_DVBAPI, "mapping ECM from %04X:%06X to %04X:%06X", er->caid, er->prid, mapentry->mapcaid, mapentry->mapprovid);
			er->caid = mapentry->mapcaid;
			er->prid = mapentry->mapprovid;
		}

		er->l=len;
		memcpy(er->ecm, buffer, er->l);

		cs_debug_mask(D_DVBAPI, "request cw for caid %04X provid %06X srvid %04X pid %04X chid %04X", er->caid, er->prid, er->srvid, er->pid, chid);
		get_cw(dvbapi_client, er);
	}

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_EMM) {
		if (buffer[0]==0x01) { //CAT
			cs_debug_mask(D_DVBAPI, "receiving cat");
			dvbapi_parse_cat(demux_id, buffer, len);

			dvbapi_stop_filternum(demux_id, filter_num);
			return;
		}
		dvbapi_process_emm(demux_id, filter_num, buffer, len);
	}

	if (demux[demux_id].demux_fd[filter_num].count==1) {
		cs_debug_mask(D_DVBAPI, "auto disable filter #%d", filter_num);
		dvbapi_stop_filternum(demux_id, filter_num);
	}
	if (demux[demux_id].demux_fd[filter_num].count>1) {
		demux[demux_id].demux_fd[filter_num].count--;
	}
}

#pragma GCC diagnostic ignored "-Wempty-body"
static void * dvbapi_main_local(void *cli) {
	struct s_client * client = (struct s_client *) cli;
	client->thread=pthread_self();
	pthread_setspecific(getclient, cli);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_cleanup_push(cleanup_thread, (void *) client);

	dvbapi_client=cli;

	int32_t maxpfdsize=(MAX_DEMUX*MAX_FILTER)+MAX_DEMUX+2;
	struct pollfd pfd2[maxpfdsize];
	int32_t i,rc,pfdcount,g,connfd,clilen,j;
	int32_t ids[maxpfdsize], fdn[maxpfdsize], type[maxpfdsize];
	struct sockaddr_un servaddr;
	ssize_t len=0;
	uchar mbuf[1024];

	struct s_auth *account;
	int32_t ok=0;
	for (ok=0, account=cfg.account; (account) && (!ok); account=account->next)
		if( (ok=!strcmp(cfg.dvbapi_usr, account->usr)) )
			break;
	cs_auth_client(client, ok ? account : (struct s_auth *)(-1), "dvbapi");

	memset(demux, 0, sizeof(struct demux_s) * MAX_DEMUX);
	memset(ca_fd, 0, sizeof(ca_fd));

	dvbapi_read_priority();
	dvbapi_detect_api();

	if (selected_box == -1 || selected_api==-1) {
		cs_log("could not detect api version");
		return NULL;
	}

	if (cfg.dvbapi_pmtmode == 1)
		disable_pmt_files=1;

	int32_t listenfd = -1;
	if (cfg.dvbapi_boxtype != BOXTYPE_IPBOX_PMT && cfg.dvbapi_pmtmode != 2 && cfg.dvbapi_pmtmode != 5) {
		listenfd = dvbapi_init_listenfd();
		if (listenfd < 1) {
			cs_log("could not init camd.socket.");
			return NULL;
		}
	}

	pthread_mutex_init(&event_handler_lock, NULL);

	if (cfg.dvbapi_pmtmode != 4 && cfg.dvbapi_pmtmode != 5) {
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
	} else {
		pthread_t event_thread;
		pthread_create(&event_thread, NULL, dvbapi_event_thread, (void*) dvbapi_client);
		pthread_detach(event_thread);
	}

	pfd2[0].fd = client->fd_m2c_c;
	pfd2[0].events = (POLLIN | POLLPRI);
	type[0]=0;

	pfd2[1].fd = listenfd;
	pfd2[1].events = (POLLIN | POLLPRI);
	type[1]=1;

	while (1) {
		pfdcount = (listenfd > -1) ? 2 : 1;

		chk_pending(500);

		for (i=0;i<MAX_DEMUX;i++) {
			for (g=0;g<MAX_FILTER;g++) {
				if (demux[i].demux_fd[g].fd>0 && selected_api != STAPI && selected_api != COOLAPI) {
					pfd2[pfdcount].fd = demux[i].demux_fd[g].fd;
					pfd2[pfdcount].events = (POLLIN | POLLPRI);
					ids[pfdcount]=i;
					fdn[pfdcount]=g;
					type[pfdcount++]=0;
				}
			}

			if (demux[i].socket_fd>0) {
				rc=0;
				if (cfg.dvbapi_boxtype==BOXTYPE_IPBOX) {
					for (j = 0; j < pfdcount; j++) {
						if (pfd2[j].fd == demux[i].socket_fd) {
							rc=1;
							break;
						}
					}
					if (rc==1) continue;
				}

				pfd2[pfdcount].fd=demux[i].socket_fd;
				pfd2[pfdcount].events = (POLLIN | POLLPRI | POLLHUP);
				ids[pfdcount]=i;
				type[pfdcount++]=1;
			}
		}

		rc = poll(pfd2, pfdcount, 500);
		if (rc<1) continue;

		for (i = 0; i < pfdcount; i++) {
			if (pfd2[i].revents > 3)
				cs_debug_mask(D_DVBAPI, "event %d on fd %d", pfd2[i].revents, pfd2[i].fd);

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
				if (pfd2[i].fd==client->fd_m2c_c) {
					cs_exit(0);
				}
			}
			if (pfd2[i].revents & (POLLIN | POLLPRI)) {
				if (pfd2[i].fd==client->fd_m2c_c) {
					process_client_pipe(client, NULL, 0);
					continue;
				}

				if (type[i]==1) {
					if (pfd2[i].fd==listenfd) {
						connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);
						cs_debug_mask(D_DVBAPI, "new socket connection fd: %d", connfd);

						disable_pmt_files=1;

						if (connfd <= 0) {
							cs_log("accept() returns error on fd event %d (errno=%d %s)", pfd2[i].revents, errno, strerror(errno));
							continue;
						}
					} else {
						cs_debug_mask(D_DVBAPI, "PMT Update on socket %d.", pfd2[i].fd);
						connfd = pfd2[i].fd;
					}

					len = read(connfd, mbuf, sizeof(mbuf));

					if (len < 3) {
						cs_debug_mask(D_DVBAPI, "camd.socket: too small message received");
						continue;
					}

					dvbapi_handlesockmsg(mbuf, len, connfd);
				} else { // type==0
					int32_t demux_index=ids[i];
					int32_t n=fdn[i];

					if ((len=dvbapi_read_device(pfd2[i].fd, mbuf, sizeof(mbuf))) <= 0) {
						if (demux[demux_index].pidindex==-1) {
							dvbapi_try_next_caid(demux_index);
						}
						continue;
					}

					if (pfd2[i].fd==(int)demux[demux_index].demux_fd[n].fd) {
						dvbapi_process_input(demux_index,n,mbuf,len);
					}
				}
			}
		}
	}
	pthread_cleanup_pop(1);
	return NULL;
}

static void dvbapi_write_cw(int32_t demux_id, uchar *cw, int32_t index) {
	int32_t n;
	unsigned char nullcw[8];
	memset(nullcw, 0, 8);
	ca_descr_t ca_descr;
	memset(&ca_descr,0,sizeof(ca_descr));

	for (n=0;n<2;n++) {
		if (memcmp(cw+(n*8),demux[demux_id].lastcw[n],8)!=0 && memcmp(cw+(n*8),nullcw,8)!=0) {
			ca_descr.index = index;
			ca_descr.parity = n;
			memcpy(demux[demux_id].lastcw[n],cw+(n*8),8);
			memcpy(ca_descr.cw,cw+(n*8),8);
#ifdef COOL
			cs_debug_mask(D_DVBAPI, "write cw%d index: %d (ca_mask %d)", n, ca_descr.index, demux[demux_id].ca_mask);
			coolapi_write_cw(demux[demux_id].ca_mask, demux[demux_id].STREAMpids, demux[demux_id].STREAMpidcount, &ca_descr);
#else
			int32_t i;
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {
					cs_debug_mask(D_DVBAPI, "write cw%d index: %d (ca%d)", n, ca_descr.index, i);
					if (ca_fd[i]<=0) {
						ca_fd[i]=dvbapi_open_device(1, i, demux[demux_id].adapter_index);
						if (ca_fd[i]<=0)
							return;
					}

					if (ioctl(ca_fd[i], CA_SET_DESCR, &ca_descr) < 0)
						cs_debug_mask(D_DVBAPI, "Error CA_SET_DESCR");
				}
			}
#endif
		}
	}
}

static void dvbapi_send_dcw(struct s_client *client, ECM_REQUEST *er) 
{
#ifdef AZBOX
	azbox_send_dcw(client, er);
	return;
#endif
	int32_t i,j;

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].program_number==er->srvid) {
			demux[i].rdr=er->selected_reader;

			for (j=0; j<demux[i].ECMpidcount; j++)
				if (demux[i].ECMpids[j].CAID == er->caid && demux[i].ECMpids[j].ECM_PID == er->pid)
						break;
			if (j==demux[i].ECMpidcount) continue;

			if (er->rc < E_NOTFOUND && demux[i].pidindex==-1 && er->caid!=0) {
				if (cfg.dvbapi_requestmode == 1) {
					int32_t o=0;
					for (o=0; o<MAX_FILTER; o++) {
						if (demux[i].demux_fd[o].fd > 0) {
							if (demux[i].demux_fd[o].pid == er->pid)
								demux[i].demux_fd[o].count=0;
							else
								dvbapi_stop_filternum(i, o);
						}
					}
					demux[i].curindex=j;	
				}
				dvbapi_start_descrambling(i);
			}

			if (er->rc >= E_NOTFOUND) {
				if ((er->caid >> 8) == 0x06 && demux[i].ECMpids[j].irdeto_chids < (((0xFFFF<<(demux[i].ECMpids[j].irdeto_numchids)) ^ 0xFFFF) & 0xFFFF)) {
					demux[i].ECMpids[j].irdeto_curchid++;
					demux[i].ECMpids[j].table=0;
					cs_log("trying irdeto chid index: %d", demux[i].ECMpids[j].irdeto_curchid);
					return;
				}
				demux[i].ECMpids[j].irdeto_chids = 0;
				demux[i].ECMpids[j].irdeto_curchid = 0;
				demux[i].ECMpids[j].irdeto_cycle = 0;

				if (demux[i].pidindex==-1) {
					if (cfg.dvbapi_requestmode == 1)
						return;

					struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(i, demux[i].curindex, 'p');
					if (forceentry) {
						if (forceentry->force>0)
							dvbapi_start_descrambling(i);
						else
							dvbapi_try_next_caid(i);
					} else {
						dvbapi_try_next_caid(i);
					}
				} else {
					demux[i].tries++;
					struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(i, demux[i].curindex, 'p');
					if (!forceentry && demux[i].tries>3) {
						demux[i].tries = 0;
						demux[i].curindex = 0;
						demux[i].pidindex = -1;
						dvbapi_try_next_caid(i);
					}
				}
				return;
			}

			struct s_dvbapi_priority *delayentry=dvbapi_check_prio_match(i, demux[i].pidindex, 'd');
			if (delayentry) {
				if (delayentry->delay<1000) {
					cs_debug_mask(D_DVBAPI, "wait %d ms", delayentry->delay);
					cs_sleepms(delayentry->delay);
				}
			}

			switch (selected_api) {
#ifdef WITH_STAPI
				case STAPI:
					stapi_write_cw(i, er->cw, demux[i].STREAMpids, demux[i].STREAMpidcount, demux[i].pmt_file);
					break;
#endif
				default:
					if (cfg.dvbapi_boxtype == BOXTYPE_NEUMO) {
						int32_t idx=0;
						sscanf(demux[i].pmt_file, "pmt%d.tmp", &idx);
						dvbapi_write_cw(i, er->cw, idx);
						break;
					}
					dvbapi_write_cw(i, er->cw, demux[i].ECMpids[j].index-1);
					break;
			}

			// reset idle-Time
			client->last=time((time_t)0);

			FILE *ecmtxt;
			ecmtxt = fopen(ECMINFO_FILE, "w"); 
			if(ecmtxt != NULL && er->selected_reader) { 
				char tmp[25];
				fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
				fprintf(ecmtxt, "reader: %s\n", er->selected_reader->label);
				if (er->selected_reader->typ & R_IS_CASCADING)
					fprintf(ecmtxt, "from: %s\n", er->selected_reader->device);
				else
					fprintf(ecmtxt, "from: local\n");
				fprintf(ecmtxt, "protocol: %s\n", er->selected_reader->ph.desc);
#ifdef MODULE_CCCAM
				fprintf(ecmtxt, "hops: %d\n", er->selected_reader->cc_currenthops);
#endif
				fprintf(ecmtxt, "ecm time: %.3f\n", (float) client->cwlastresptime/1000);
				fprintf(ecmtxt, "cw0: %s\n", cs_hexdump(1,demux[i].lastcw[0],8, tmp, sizeof(tmp)));
				fprintf(ecmtxt, "cw1: %s\n", cs_hexdump(1,demux[i].lastcw[1],8, tmp, sizeof(tmp)));
				fclose(ecmtxt);
				ecmtxt = NULL;
			}
		}
	}
}

static void * dvbapi_handler(int32_t ctyp) {
	//cs_log("dvbapi loaded fd=%d", idx);
	if (cfg.dvbapi_enabled == 1) {
		struct s_client * cl = create_client(0);
		cl->typ='c';
		cl->ctyp=ctyp;
#ifdef AZBOX
		pthread_create(&cl->thread, NULL, azbox_main, (void*) cl);
#else
		pthread_create(&cl->thread, NULL, dvbapi_main_local, (void*) cl);
#endif
		pthread_detach(cl->thread);
	}

	return NULL;
}


#ifdef WITH_STAPI
static void stapi_off() {
	int32_t i;

	pthread_mutex_lock(&filter_lock);

	cs_log("stapi shutdown");

	disable_pmt_files=1;
	stapi_on=0;

	for (i=0;i<MAX_DEMUX;i++)
		dvbapi_stop_descrambling(i);

	for (i=0;i<PTINUM;i++) {
		if (dev_list[i].SessionHandle>0) {
			if (dev_list[i].SignalHandle > 0) {
				oscam_stapi_SignalAbort(dev_list[i].SignalHandle);
			}
			pthread_cancel(dev_list[i].thread);
		}
	}

	pthread_mutex_unlock(&filter_lock);
	sleep(2);
	return;
}

static int32_t stapi_open() {
	uint32_t ErrorCode;

	DIR *dirp;
	struct dirent *dp;
	struct stat buf;
	int32_t i;
	char pfad[80];
	stapi_on=1;
	int32_t stapi_priority=0;

	dirp = opendir(PROCDIR);
	if (!dirp) {
		cs_log("opendir failed (errno=%d %s)", errno, strerror(errno));
		return FALSE;
	}

	memset(dev_list, 0, sizeof(struct STDEVICE)*PTINUM);

	if (dvbapi_priority) {
		struct s_dvbapi_priority *p;
		for (p=dvbapi_priority; p != NULL; p=p->next) {
			if (p->type=='s') {
				stapi_priority=1;
				break;
			}
		}
	}

	if (!stapi_priority) {
		cs_log("WARNING: no PTI devices defined, stapi disabled");	
		return FALSE;
	}

	oscam_stapi_CheckVersion();

	i=0;
	while ((dp = readdir(dirp))) {
		snprintf(pfad, sizeof(pfad), "%s%s", PROCDIR, dp->d_name);
		if (stat(pfad,&buf) != 0)
			continue;

		if (!(buf.st_mode & S_IFDIR && strncmp(dp->d_name, ".", 1)!=0)) 
			continue;

		int32_t do_open=0;
		struct s_dvbapi_priority *p;

		for (p=dvbapi_priority; p != NULL; p=p->next) {
			if (p->type!='s') continue;
			if(strcmp(dp->d_name, p->devname)==0) {
				do_open=1;
				break;
			}
		} 

		if (!do_open) {
			cs_log("PTI: %s skipped", dp->d_name);
			continue;
		}

		ErrorCode= oscam_stapi_Open(dp->d_name, &dev_list[i].SessionHandle);
		if (ErrorCode != 0) {
			cs_log("STPTI_Open ErrorCode: %d", ErrorCode);
			continue;
		}

		//debug
		//oscam_stapi_Capability(dp->d_name);

		cs_strncpy(dev_list[i].name,dp->d_name, sizeof(dev_list[i].name));
		cs_log("PTI: %s open %d", dp->d_name, i);

		ErrorCode = oscam_stapi_SignalAllocate(dev_list[i].SessionHandle, &dev_list[i].SignalHandle);
		if (ErrorCode != 0)
			cs_log("SignalAllocate: ErrorCode: %d SignalHandle: %x", ErrorCode, dev_list[i].SignalHandle);

		i++;
		if (i>=PTINUM) break;	
	}
	closedir(dirp);

	if (i==0) return FALSE;

	pthread_mutex_init(&filter_lock, NULL);

	for (i=0;i<PTINUM;i++) {
		if (dev_list[i].SessionHandle==0)
			continue;

		struct read_thread_param *para;
		if(!cs_malloc(&para,sizeof(struct read_thread_param), -1)) return FALSE;
		para->id=i;
		para->cli=cur_client();

		pthread_create(&dev_list[i].thread, NULL, stapi_read_thread, (void *)para);
		pthread_detach(dev_list[i].thread);
	}

	atexit(stapi_off);

	cs_log("liboscam_stapi v.%s initialized", oscam_stapi_LibVersion());
	return TRUE;
}

static int32_t stapi_set_filter(int32_t demux_id, uint16_t pid, uchar *filter, uchar *mask, int32_t num, char *pmtfile) {
	int32_t i;
	uint16_t pids[1] = { pid };
	struct s_dvbapi_priority *p;

	if (!pmtfile) return FALSE;

	cs_debug_mask(D_DVBAPI, "pmt file %s demux_id %d", pmtfile, demux_id);

	for (p=dvbapi_priority; p != NULL; p=p->next) {
		if (p->type!='s') continue;
		if (strcmp(pmtfile, p->pmtfile)!=0)
			continue;

		for (i=0;i<PTINUM;i++) {
			if(strcmp(dev_list[i].name, p->devname)==0 && p->disablefilter==0) {
				cs_debug_mask(D_DVBAPI, "set stapi filter on %s for pid %04X", dev_list[i].name, pids[0]);
				stapi_do_set_filter(demux_id, &dev_list[i].demux_fd[demux_id][num], pids, 1, filter, mask, i);
			}
		}
	}

	cs_debug_mask(D_DVBAPI, "filter #%d set (pid %04X)", num, pid);
	return TRUE;
}

static int32_t stapi_remove_filter(int32_t demux_id, int32_t num, char *pmtfile) {
	int32_t i;
	struct s_dvbapi_priority *p;

	if (!pmtfile) return FALSE;
	
	for (p=dvbapi_priority; p != NULL; p=p->next) {
		if (p->type!='s') continue;
		if (strcmp(pmtfile, p->pmtfile)!=0) 
			continue;

		for (i=0;i<PTINUM;i++) {
			if(strcmp(dev_list[i].name, p->devname)==0 && p->disablefilter==0) {
				stapi_do_remove_filter(demux_id, &dev_list[i].demux_fd[demux_id][num], i);
			}
		}
	}

	cs_debug_mask(D_DVBAPI, "filter #%d removed", num);
	return TRUE;
}

static uint32_t check_slot(int32_t dev_id, uint32_t checkslot, FILTERTYPE *skipfilter) {
	int32_t d,f,l;
	for (d=0; d<MAX_DEMUX; d++) {
		for (f=0; f<MAX_FILTER; f++) {
			if (skipfilter && &dev_list[dev_id].demux_fd[d][f] == skipfilter)
				continue;
			for (l=0; l<dev_list[dev_id].demux_fd[d][f].NumSlots; l++) {
				if (checkslot == dev_list[dev_id].demux_fd[d][f].SlotHandle[l]) {
					return dev_list[dev_id].demux_fd[d][f].BufferHandle[l];
				}
			}
		}
	}
	return 0;
}


static int32_t stapi_do_set_filter(int32_t demux_id, FILTERTYPE *filter, uint16_t *pids, int32_t pidcount, uchar *filt, uchar *mask, int32_t dev_id) {
	uint32_t FilterAssociateError=0;
	int32_t k, ErrorCode=0, ret=0;

	filter->fd			= 0;
	filter->BufferHandle[0] 	= 0;
	filter->SlotHandle[0]	= 0;

	if (dev_list[dev_id].SessionHandle==0) return FALSE;

	uint32_t FilterAllocateError = oscam_stapi_FilterAllocate(dev_list[dev_id].SessionHandle, &filter->fd);

	if (FilterAllocateError != 0) {
		cs_log("FilterAllocate problem");
		filter->fd=0;
		return FALSE;
	}

	for (k=0;k<pidcount;k++) {
		uint16_t pid = pids[k];

		uint32_t QuerySlot = oscam_stapi_PidQuery(dev_list[dev_id].name, pid);
		int32_t SlotInit=1;

		if (QuerySlot != 0) {
			uint32_t checkslot = check_slot(dev_id, QuerySlot, NULL);
			if (checkslot>0) {
				filter->SlotHandle[k] = QuerySlot;
				filter->BufferHandle[k] = checkslot;
				SlotInit=0;
			} else {
				cs_log("overtake: clear pid: %d", oscam_stapi_SlotClearPid(QuerySlot));
				SlotInit=1;
			} 
		}

		if (SlotInit==1) {
			ret = oscam_stapi_SlotInit(dev_list[dev_id].SessionHandle, dev_list[dev_id].SignalHandle, &filter->BufferHandle[k], &filter->SlotHandle[k], pid);
		}

		FilterAssociateError		= oscam_stapi_FilterAssociate(filter->fd, filter->SlotHandle[k]);
		filter->NumSlots++;
	}

	uint32_t FilterSetError			= oscam_stapi_FilterSet(filter->fd, filt, mask);

	if (ret || FilterAllocateError || FilterAssociateError || FilterSetError) {
		cs_log("set_filter: dev: %d FAl: %d FAs: %d FS: %d",
			dev_id, FilterAllocateError, FilterAssociateError, FilterSetError);
		stapi_do_remove_filter(demux_id, filter, dev_id);
		return FALSE;
	} else {
		return TRUE;
	}
}

static int32_t stapi_do_remove_filter(int32_t demux_id, FILTERTYPE *filter, int32_t dev_id) {
	if (filter->fd==0) return FALSE;

	uint32_t BufferDeallocateError=0, SlotDeallocateError=0;

	if (dev_list[dev_id].SessionHandle==0) return FALSE;

	int32_t k;
	for (k=0;k<filter->NumSlots;k++) {
		uint32_t checkslot = check_slot(dev_id, filter->SlotHandle[k], filter);

		if (checkslot==0) {
			BufferDeallocateError	= oscam_stapi_BufferDeallocate(filter->BufferHandle[k]);
			SlotDeallocateError		= oscam_stapi_SlotDeallocate(filter->SlotHandle[k]);
		}
	}
	uint32_t FilterDeallocateError		= oscam_stapi_FilterDeallocate(filter->fd);

	memset(filter, 0, sizeof(FILTERTYPE));

	if (BufferDeallocateError||SlotDeallocateError||FilterDeallocateError) {
		cs_log("remove_filter: dev: %d BD: %d SD: %d FDe: %d",
			dev_id, BufferDeallocateError, SlotDeallocateError, FilterDeallocateError);
		return FALSE;
	} else {
		return TRUE;
	}
}

static void stapi_cleanup_thread(void *dev){
	int32_t	dev_index=(int)dev;
	
	int32_t ErrorCode;
	ErrorCode = oscam_stapi_Close(dev_list[dev_index].SessionHandle);

	printf("liboscam_stapi: PTI %s closed - %d\n", dev_list[dev_index].name, ErrorCode);
	dev_list[dev_index].SessionHandle=0;
}

static void *stapi_read_thread(void *sparam) {
	int32_t 	dev_index, ErrorCode, i, j, CRCValid;
	uint32_t  	QueryBufferHandle = 0, DataSize = 0;
	uchar buf[BUFFLEN];

	struct read_thread_param *para=sparam;
	dev_index=para->id;

	pthread_setspecific(getclient, para->cli);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_cleanup_push(stapi_cleanup_thread, (void*) dev_index);

	int32_t error_count=0;

	while (1) {
		QueryBufferHandle = 0;
		ErrorCode = oscam_stapi_SignalWaitBuffer(dev_list[dev_index].SignalHandle, &QueryBufferHandle, 1000);

		switch (ErrorCode) {
			case 0: // NO_ERROR:
				break;
			case 852042: // ERROR_SIGNAL_ABORTED
				cs_log("Caught abort signal");
				pthread_exit(NULL);
				break;
			case 11: // ERROR_TIMEOUT:
				//cs_log("timeout %d", dev_index);
				//TODO: if pidindex == -1 try next
				continue;
				break;		
			default:
				if (QueryBufferHandle != 0) { 
					cs_log("SignalWaitBuffer error: %d", ErrorCode);
					oscam_stapi_BufferFlush(QueryBufferHandle); 
					continue; 
				}
				cs_log("SignalWaitBuffer: index %d ErrorCode: %d - QueryBuffer: %x", dev_index, ErrorCode, QueryBufferHandle);
				error_count++;
				if (error_count>10) {
					cs_log("Too many errors in reader thread %d, quitting.", dev_index);
					pthread_exit(NULL);
				}
				continue;	
				break;
		}

		uint32_t NumFilterMatches = 0;
		int32_t demux_id=0, filter_num=0;
		DataSize = 0;
		int32_t found=0, k;

		uint32_t MatchedFilterList[10];
		ErrorCode = oscam_stapi_BufferReadSection(QueryBufferHandle, MatchedFilterList, 10, &NumFilterMatches, &CRCValid, buf, BUFFLEN, &DataSize);	

		if (ErrorCode != 0) {
			cs_log("BufferRead: index: %d ErrorCode: %d", dev_index, ErrorCode);
			cs_sleepms(1000);
			continue;
		}

		if (DataSize<=0)
			continue;

		pthread_mutex_lock(&filter_lock); // don't use cs_lock() here; multiple threads using same s_client struct
		for(k=0;k<NumFilterMatches;k++) {
			for (i=0;i<MAX_DEMUX;i++) {
				for (j=0;j<MAX_FILTER;j++) {
					if (dev_list[dev_index].demux_fd[i][j].fd == MatchedFilterList[k]) {
						demux_id=i;
						filter_num=j;

						dvbapi_process_input(demux_id, filter_num, buf, DataSize);
					}
				}	
			}
		}
		pthread_mutex_unlock(&filter_lock);
	}
	pthread_cleanup_pop(0);
}

#define ASSOCIATE 1
#define DISASSOCIATE 0

#define DE_START 0
#define DE_STOP 1

static void stapi_DescramblerAssociate(int32_t demux_id, uint16_t pid, int32_t mode, int32_t n) {
	uint32_t Slot=0;
	int32_t ErrorCode=0;

	if (dev_list[n].SessionHandle==0) return;

	Slot = oscam_stapi_PidQuery(dev_list[n].name, pid);
	if (!Slot) return;

	if (demux[demux_id].DescramblerHandle[n]==0) return;

	if (mode == ASSOCIATE) {
		int32_t k;
		for (k=0;k<SLOTNUM;k++) {
			if (demux[demux_id].slot_assc[n][k]==Slot) {
				return;
			}
		}

		ErrorCode = oscam_stapi_DescramblerAssociate(demux[demux_id].DescramblerHandle[n], Slot);
		cs_debug_mask(D_DVBAPI, "set pid %04x on %s", pid, dev_list[n].name);

		if (ErrorCode != 0)
			cs_log("DescramblerAssociate %d",ErrorCode);

		for (k=0;k<SLOTNUM;k++) {
			if (demux[demux_id].slot_assc[n][k]==0) {
				demux[demux_id].slot_assc[n][k]=Slot;
				break;
			}
		}
	} else {
		ErrorCode = oscam_stapi_DescramblerDisassociate(demux[demux_id].DescramblerHandle[n], Slot);
		if (ErrorCode != 0)
			cs_debug_mask(D_DVBAPI, "DescramblerDisassociate %d", ErrorCode);

		cs_debug_mask(D_DVBAPI, "unset pid %04x on %s", pid, dev_list[n].name);

		int32_t k;
		for (k=0;k<SLOTNUM;k++) {
			if (demux[demux_id].slot_assc[n][k]==Slot) {
				demux[demux_id].slot_assc[n][k]=0;
				return;
			}
		}
	}

	return;
}

static void stapi_startdescrambler(int32_t demux_id, int32_t dev_index, int32_t mode) {
	int32_t ErrorCode;

	if (mode == DE_START && demux[demux_id].DescramblerHandle[dev_index] == 0) {
		uint32_t DescramblerHandle=0;
		ErrorCode = oscam_stapi_DescramblerAllocate(dev_list[dev_index].SessionHandle, &DescramblerHandle);
		if (ErrorCode != 0) {
			cs_log("DescramblerAllocate: ErrorCode: %d SignalHandle: %x", ErrorCode, dev_list[dev_index].SignalHandle);
			return;
		}

		demux[demux_id].DescramblerHandle[dev_index]=DescramblerHandle;
	}

	if (mode == DE_STOP && demux[demux_id].DescramblerHandle[dev_index] > 0) {
		ErrorCode = oscam_stapi_DescramblerDeallocate(demux[demux_id].DescramblerHandle[dev_index]);

		if (ErrorCode != 0)
			cs_log("DescramblerDeallocate: ErrorCode: %d", ErrorCode);
				
		demux[demux_id].DescramblerHandle[dev_index]=0;
	}

	return;
}

static int32_t stapi_set_pid(int32_t demux_id, int32_t num, int32_t index, uint16_t pid, char *pmtfile) {
	int32_t n;

	if (index==-1) {
		for (n=0;n<PTINUM;n++) {
			if (demux[demux_id].DescramblerHandle[n]==0) continue;

			cs_debug_mask(D_DVBAPI, "stop descrambling PTI: %s", dev_list[n].name);
			stapi_startdescrambler(demux_id, n, DE_STOP);
			memset(demux[demux_id].slot_assc[n], 0, sizeof(demux[demux_id].slot_assc[n]));
		}
	}
	
	return TRUE;
}

static int32_t stapi_write_cw(int32_t demux_id, uchar *cw, uint16_t *STREAMpids, int32_t STREAMpidcount, char *pmtfile) {
	int32_t ErrorCode, l, n, k;
	unsigned char nullcw[8];
	memset(nullcw, 0, 8);
	char *text[] = { "even", "odd" };

	if (!pmtfile) return FALSE;

	for (n=0;n<PTINUM;n++) {
		if (dev_list[n].SessionHandle==0) continue;
		if (demux[demux_id].DescramblerHandle[n]==0) {
			struct s_dvbapi_priority *p;

			for (p=dvbapi_priority; p != NULL; p=p->next) {
				if (p->type!='s') continue;
				if (strcmp(pmtfile, p->pmtfile)!=0)
					continue;

				if(strcmp(dev_list[n].name, p->devname)==0) {
					cs_debug_mask(D_DVBAPI, "start descrambling PTI: %s", dev_list[n].name);
					stapi_startdescrambler(demux_id, n, DE_START);
				}
			}
		}

		if (demux[demux_id].DescramblerHandle[n] == 0) continue;
		for (k=0;k<STREAMpidcount;k++) {
			stapi_DescramblerAssociate(demux_id, STREAMpids[k], ASSOCIATE, n);
		}
	}

	for (l=0;l<2;l++) {
		if (memcmp(cw+(l*8), demux[demux_id].lastcw[l], 8)!=0 && memcmp(cw+(l*8),nullcw,8)!=0) {
			for (n=0;n<PTINUM;n++) {
				if (demux[demux_id].DescramblerHandle[n]==0) continue;

				ErrorCode = oscam_stapi_DescramblerSet(demux[demux_id].DescramblerHandle[n], l, cw+(l*8));
				if (ErrorCode != 0)
					cs_log("DescramblerSet: ErrorCode: %d", ErrorCode);

				memcpy(demux[demux_id].lastcw[l],cw+(l*8),8);
				cs_debug_mask(D_DVBAPI, "write cw %s index: %d %s", text[l], demux_id, dev_list[n].name);
			}
		}
	}

	return TRUE;
}
#endif //WITH_STAPI


#ifdef AZBOX
void azbox_openxcas_ecm_callback(int32_t stream_id, uint32_t seq, int32_t cipher_index, uint32_t caid, unsigned char *ecm_data, int32_t l, uint16_t pid) {
	cs_debug_mask(D_DVBAPI, "openxcas: ecm callback received");

  openxcas_stream_id = stream_id;
  //openxcas_seq = seq;
	//openxcas_caid = caid;
	openxcas_ecm_pid = pid;
	openxcas_busy = 1;

	ECM_REQUEST *er;
	if (!(er=get_ecmtask()))
		return;

	er->srvid = openxcas_sid;
	er->caid  = openxcas_caid;
	er->pid   = openxcas_ecm_pid;
	er->prid  = openxcas_provid;

	er->l=l;
	memcpy(er->ecm, ecm_data, er->l);

	cs_debug_mask(D_DVBAPI, "request cw for caid %04X provid %06X srvid %04X pid %04X", er->caid, er->prid, er->srvid, er->pid);
	get_cw(dvbapi_client, er);

	//openxcas_stop_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);
	//openxcas_remove_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);

	openxcas_cipher_idx = cipher_index;

	struct timeb tp;
	cs_ftime(&tp);
	tp.time+=500;

	struct pollfd pfd;
	pfd.fd = dvbapi_client->fd_m2c_c;
	pfd.events = POLLIN | POLLPRI;
/*
	while(1) {
		chk_pending(tp);

		if (poll(&pfd, 1, 10) < 0)
			continue;

		if (pfd.revents & (POLLHUP | POLLNVAL)) {
			cs_debug_mask(D_DVBAPI, "openxcas: ecm/cw error");
			break;
		}

		if (pfd.revents & (POLLIN | POLLPRI)) {
			chk_dcw(cur_client()->fd_m2c_c);
			break;
		}
	}*/
}


void azbox_openxcas_ex_callback(int32_t stream_id, uint32_t seq, int32_t idx, uint32_t pid, unsigned char *ecm_data, int32_t l) {
	cs_debug_mask(D_DVBAPI, "openxcas: ex callback received");

	openxcas_stream_id = stream_id;
	openxcas_ecm_pid = pid;
	openxcas_cipher_idx = idx; // is this really cipher_idx?

	ECM_REQUEST *er;
	if (!(er=get_ecmtask()))
		return;

	er->srvid = openxcas_sid;
	er->caid  = openxcas_caid;
	er->pid   = openxcas_ecm_pid;
	er->prid  = openxcas_provid;

	er->l=l;
	memcpy(er->ecm, ecm_data, er->l);

	cs_debug_mask(D_DVBAPI, "request cw for caid %04X provid %06X srvid %04X pid %04X", er->caid, er->prid, er->srvid, er->pid);
	get_cw(dvbapi_client, er);

	if (openxcas_stop_filter_ex(stream_id, seq, openxcas_filter_idx) < 0)
		cs_log("openxcas: unable to stop ex filter");
	else
		cs_debug_mask(D_DVBAPI, "openxcas: ex filter stopped");

	chk_pending(500);
	process_client_pipe(dvbapi_client, NULL, 0);

	unsigned char mask[12];
	unsigned char comp[12];
	memset(&mask, 0x00, sizeof(mask));
	memset(&comp, 0x00, sizeof(comp));

	mask[0] = 0xff;
	comp[0] = ecm_data[0] ^ 1;

	if ((openxcas_filter_idx = openxcas_start_filter_ex(stream_id, seq, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ex_callback)) < 0)
		cs_log("openxcas: unable to start ex filter");
	else
		cs_debug_mask(D_DVBAPI, "openxcas: ex filter started, pid = %x", openxcas_ecm_pid);
}

#pragma GCC diagnostic ignored "-Wempty-body"
void * azbox_main(void *cli) {
	struct s_client * client = (struct s_client *) cli;
	client->thread=pthread_self();
	pthread_setspecific(getclient, cli);
	dvbapi_client=cli;
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_cleanup_push(cleanup_thread, (void *) client);

	struct s_auth *account;
	int32_t ok=0;
	for (ok=0, account=cfg.account; (account) && (!ok); account=account->next)
		if( (ok=!strcmp(cfg.dvbapi_usr, account->usr)) )
			break;
	cs_auth_client(client, ok ? account : (struct s_auth *)(-1), "dvbapi");

	dvbapi_read_priority();

	openxcas_msg_t msg;
	int32_t ret;
	while ((ret = openxcas_get_message(&msg, 0)) >= 0) {
		cs_sleepms(10);

		chk_pending(500);

		if (ret) {
			openxcas_stream_id = msg.stream_id;
			openxcas_seq = msg.sequence;

			switch(msg.cmd) {
				case OPENXCAS_SELECT_CHANNEL:
					cs_debug_mask(D_DVBAPI, "openxcas: msg: OPENXCAS_SELECT_CHANNEL");

					// parse channel info
					struct stOpenXCASChannel chan;
					memcpy(&chan, msg.buf, msg.buf_len);

					cs_log("openxcas: channel change: sid = %x, vpid = %x. apid = %x", chan.service_id, chan.v_pid, chan.a_pid);

					openxcas_video_pid = chan.v_pid;
					openxcas_audio_pid = chan.a_pid;
					openxcas_data_pid = chan.d_pid;
					break;
				case OPENXCAS_START_PMT_ECM:
					cs_debug_mask(D_DVBAPI, "openxcas: msg: OPENXCAS_START_PMT_ECM");

					 // parse pmt
					uchar *dest;
					if(!cs_malloc(&dest, msg.buf_len + 7 - 12 - 4, -1)) break;

					memcpy(dest, "\x00\xFF\xFF\x00\x00\x13\x00", 7);

					dest[1] = msg.buf[3];
					dest[2] = msg.buf[4];
					dest[5] = msg.buf[11]+1;

					memcpy(dest + 7, msg.buf + 12, msg.buf_len - 12 - 4);

					dvbapi_parse_capmt(dest, 7 + msg.buf_len - 12 - 4, -1, NULL);
					free(dest);

					unsigned char mask[12];
					unsigned char comp[12];
					memset(&mask, 0x00, sizeof(mask));
					memset(&comp, 0x00, sizeof(comp));

					mask[0] = 0xfe;
					comp[0] = 0x80;

					if ((ret = openxcas_add_filter(msg.stream_id, OPENXCAS_FILTER_ECM, 0, 0xffff, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ecm_callback)) < 0)
						cs_log("openxcas: unable to add ecm filter");
					else
						cs_debug_mask(D_DVBAPI, "openxcas: ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);

					if (openxcas_start_filter(msg.stream_id, msg.sequence, OPENXCAS_FILTER_ECM) < 0)
						cs_log("openxcas: unable to start ecm filter");
					else
						cs_debug_mask(D_DVBAPI, "openxcas: ecm filter started");

					if (!openxcas_create_cipher_ex(msg.stream_id, openxcas_seq, 0, openxcas_ecm_pid, openxcas_video_pid, 0xffff, openxcas_audio_pid, 0xffff, 0xffff, 0xffff))
						cs_log("openxcas: failed to create cipher ex");
					else
						cs_debug_mask(D_DVBAPI, "openxcas: cipher created");
					break;
				case OPENXCAS_STOP_PMT_ECM:
					cs_debug_mask(D_DVBAPI, "openxcas: msg: OPENXCAS_STOP_PMT_ECM");
					openxcas_stop_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
					openxcas_remove_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
					openxcas_stop_filter_ex(msg.stream_id, msg.sequence, openxcas_filter_idx);
					openxcas_destory_cipher_ex(msg.stream_id, msg.sequence);
					memset(&demux, 0, sizeof(demux));
					break;
				case OPENXCAS_ECM_CALLBACK:
					cs_debug_mask(D_DVBAPI, "openxcas: msg: OPENXCAS_ECM_CALLBACK");
					struct stOpenXCAS_Data data;
					memcpy(&data, msg.buf, msg.buf_len);
					if (!openxcas_busy)
					  openxcas_filter_callback(msg.stream_id, msg.sequence, OPENXCAS_FILTER_ECM, &data);
					break;
				case OPENXCAS_PID_FILTER_CALLBACK:
					cs_debug_mask(D_DVBAPI, "openxcas: msg: OPENXCAS_PID_FILTER_CALLBACK");
					openxcas_filter_callback_ex(msg.stream_id, msg.sequence, (struct stOpenXCAS_Data *)msg.buf);
					break;
				case OPENXCAS_QUIT:
					cs_debug_mask(D_DVBAPI, "openxcas: msg: OPENXCAS_QUIT");
					openxcas_close();
					cs_log("openxcas: exited");
					return NULL;
					break;
				case OPENXCAS_UKNOWN_MSG:
				default:
					cs_debug_mask(D_DVBAPI, "openxcas: msg: OPENXCAS_UKNOWN_MSG (%d)", msg.cmd);
					//cs_ddump_mask(D_DVBAPI, &msg, sizeof(msg), "msg dump:");
					break;
			}
		}
	}
	cs_log("openxcas: invalid message");
	pthread_cleanup_pop(1);
	return NULL;
}

void azbox_send_dcw(struct s_client *client, ECM_REQUEST *er) {
	cs_debug_mask(D_DVBAPI, "openxcas: send_dcw");

    FILE *ecmtxt;
    if (ecmtxt = fopen(ECMINFO_FILE, "w")) {
    	char tmp[25];
    	if(er->rc <= E_EMU) {
			fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
			fprintf(ecmtxt, "reader: %s\n", er->selected_reader->label);
			if (er->selected_reader->typ & R_IS_CASCADING)
				fprintf(ecmtxt, "from: %s\n", er->selected_reader->device);
			else
				fprintf(ecmtxt, "from: local\n");
			fprintf(ecmtxt, "protocol: %s\n", er->selected_reader->ph.desc);
			fprintf(ecmtxt, "hops: %d\n", er->selected_reader->cc_currenthops);
			fprintf(ecmtxt, "ecm time: %.3f\n", (float) client->cwlastresptime/1000);
			fprintf(ecmtxt, "cw0: %s\n", cs_hexdump(1,demux[0].lastcw[0],8, tmp, sizeof(tmp)));
			fprintf(ecmtxt, "cw1: %s\n", cs_hexdump(1,demux[0].lastcw[1],8, tmp, sizeof(tmp)));
			fclose(ecmtxt);
			ecmtxt = NULL;
		} else {
			fprintf(ecmtxt, "ECM information not found\n");
			fclose(ecmtxt);
		}
    }

	openxcas_busy = 0;

	int32_t i;
	for (i=0; i < MAX_DEMUX; i++) {
		if (er->rc >= E_NOTFOUND) {
			cs_debug_mask(D_DVBAPI, "cw not found");

			if (demux[i].pidindex==-1)
			  dvbapi_try_next_caid(i);

			openxcas_stop_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);
			openxcas_remove_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);

			unsigned char mask[12];
			unsigned char comp[12];
			memset(&mask, 0x00, sizeof(mask));
			memset(&comp, 0x00, sizeof(comp));

			mask[0] = 0xfe;
			comp[0] = 0x80;

			if (openxcas_add_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM, 0, 0xffff, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ecm_callback) < 0) {
				cs_log("openxcas: unable to add ecm filter (0)");
				if (openxcas_add_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM, openxcas_caid, 0xffff, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ecm_callback) < 0)
					cs_log("openxcas: unable to add ecm filter (%04x)", openxcas_caid);
				else
					cs_debug_mask(D_DVBAPI, "openxcas: ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, openxcas_caid);
			} else
				cs_debug_mask(D_DVBAPI, "openxcas: ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);

			if (openxcas_start_filter(openxcas_stream_id, openxcas_seq, OPENXCAS_FILTER_ECM) < 0)
				cs_log("openxcas: unable to start ecm filter");
			else
				cs_debug_mask(D_DVBAPI, "openxcas: ecm filter started");

			return;
		}
	}

  unsigned char nullcw[8];
  memset(nullcw, 0, 8);

  int32_t n;
  for (n=0;n<2;n++) {
    if (memcmp(er->cw + (n * 8), demux[0].lastcw[n], 8) && memcmp(er->cw + (n * 8), nullcw, 8)) {
      memcpy(demux[0].lastcw[n], er->cw + (n * 8), 8);
      memcpy(openxcas_cw + (n * 8), er->cw + (n * 8), 8);
    }
  }

	if (openxcas_set_key(openxcas_stream_id, openxcas_seq, 0, openxcas_cipher_idx, openxcas_cw, openxcas_cw + 8) != 1)
		cs_log("openxcas: set cw failed");
	else
		cs_ddump_mask(D_DVBAPI, openxcas_cw, 16, "openxcas: write cws to descrambler");
}
#endif
/*
 *	protocol structure
 */

void module_dvbapi(struct s_module *ph)
{
	cs_strncpy(ph->desc, "dvbapi", sizeof(ph->desc));
	ph->type=MOD_CONN_SERIAL;
	ph->listenertype = LIS_DVBAPI;
	ph->multi=1;
	ph->watchdog=0;
	ph->s_handler=dvbapi_handler;
	ph->send_dcw=dvbapi_send_dcw;
}
#endif // HAVE_DVBAPI
