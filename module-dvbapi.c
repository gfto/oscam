#include "globals.h"

#ifdef HAVE_DVBAPI

#include "module-dvbapi.h"

#ifdef AZBOX 
#include "openxcas/openxcas_api.h" 
#include "openxcas/openxcas_message.h"

int openxcas_provid, openxcas_seq, openxcas_filter_idx, openxcas_stream_id, openxcas_cipher_idx, openxcas_busy;
unsigned char openxcas_cw[16];
unsigned short openxcas_sid, openxcas_caid, openxcas_ecm_pid, openxcas_video_pid, openxcas_audio_pid, openxcas_data_pid;

void azbox_openxcas_ecm_callback(int stream_id, unsigned int sequence, int cipher_index, unsigned int caid, unsigned char *ecm_data, int l, unsigned short pid);
void azbox_openxcas_ex_callback(int stream_id, unsigned int seq, int idx, unsigned int pid, unsigned char *ecm_data, int l);
void azbox_send_dcw(ECM_REQUEST *er);
void azbox_main();
#endif

extern struct s_reader * reader;

char *boxdesc[] = { "none", "dreambox", "duckbox", "ufs910", "dbox2", "ipbox", "ipbox-pmt", "dm7000" };

struct box_devices devices[BOX_COUNT] = {
	/* QboxHD (dvb-api-3)*/	{ "/tmp/virtual_adapter/ca%d",	"/tmp/virtual_adapter/demux%d",	"/tmp/camd.socket" },
	/* dreambox (dvb-api-3)*/	{ "/dev/dvb/adapter0/ca%d", 	"/dev/dvb/adapter0/demux%d",	"/tmp/camd.socket" },
	/* dreambox (dvb-api-1)*/	{ "/dev/dvb/card0/ca%d", 		"/dev/dvb/card0/demux%d",		"/tmp/camd.socket" },
	/* sh4      (stapi)*/	{ "/dev/stapi/stpti4_ioctl", 	"/dev/stapi/stpti4_ioctl",		"/tmp/camd.socket" }
};

int selected_box=-1;
int selected_api=-1;
int disable_pmt_files=0;
int dir_fd=-1, pausecam=0;
unsigned short global_caid_list[MAX_CAID];
DEMUXTYPE demux[MAX_DEMUX];
int ca_fd[8];

int dvbapi_set_filter(int demux_id, int api, unsigned short pid, uchar *filt, uchar *mask, int timeout, int pidindex, int count, int type) {
#ifdef AZBOX
	openxcas_caid = demux[demux_id].ECMpids[pidindex].CAID;
	openxcas_ecm_pid = pid; 

 	return 1; 
#endif
	int ret=-1,n=-1,i;

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
			demux[demux_id].demux_fd[n].fd = dvbapi_open_device(demux_id, 0, demux[demux_id].demux_index);
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
			demux[demux_id].demux_fd[n].fd = dvbapi_open_device(demux_id, 0, demux[demux_id].demux_index);
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
			ret=stapi_set_filter(demux_id, pid, filt, mask, n);

			break;
#endif
		default:
			break;
	}

	if (ret < 0)
		cs_debug("could not start demux filter (Errno: %d)", errno);

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
	int num_apis=2, i,devnum=-1, dmx_fd=0, ret=-1;
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
			selected_api=i;
			dvbapi_stop_filter(0, TYPE_ECM);
			break;
		}
	}

	if (ret < 0) return 0;

	cs_debug("Detected %s Api: %d", device_path, selected_api);

	return 1;
}

int dvbapi_read_device(int dmx_fd, unsigned char *buf, int length) {
	int len, rc;
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
		cs_log("read error %d on fd %d", errno, dmx_fd);

	return len;
}

int dvbapi_open_device(int index_demux, int type, int num) {
	int dmx_fd;
	int ca_offset=0;
	char device_path[128];

	if (type==0)
		sprintf(device_path, devices[selected_box].demux_device_path, num);
	else {
		if (cfg->dvbapi_boxtype==BOXTYPE_DUCKBOX || cfg->dvbapi_boxtype==BOXTYPE_DBOX2 || cfg->dvbapi_boxtype==BOXTYPE_UFS910)
			ca_offset=1;
		
		sprintf(device_path, devices[selected_box].ca_device_path, num+ca_offset);
	}

	if ((dmx_fd = open(device_path, O_RDWR)) < 0) {
		cs_debug("error opening device %s (Errno: %d)", device_path, errno);
		return -1;
	}

	cs_debug("DEVICE open (%s) fd %d", device_path, dmx_fd);
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
	int ret=-1;
	if (demux[demux_index].demux_fd[num].fd>0) {
#ifdef WITH_STAPI
		ret=stapi_remove_filter(demux_index, num);
#else	
		ret=ioctl(demux[demux_index].demux_fd[num].fd,DMX_STOP);
		close(demux[demux_index].demux_fd[num].fd);
#endif
		demux[demux_index].demux_fd[num].fd=0;
	}
	return ret;
}

void dvbapi_start_filter(int demux_id, int pidindex, unsigned short pid, uchar table, uchar mask, int timeout, int type) {
	uchar filter[32];

	cs_debug("set filter pid: %04x", pid);

	memset(filter,0,32);

	filter[0]=table;
	filter[16]=mask;

	dvbapi_set_filter(demux_id, selected_api, pid, filter, filter+16, timeout, pidindex, 0, type);
}

void dvbapi_start_emm_filter(int demux_index) {
	int j;
	uchar nullserial[8];
	char *typtext[]={"UNKNOWN", "UNIQUE", "SHARED", "GLOBAL"};

	if (demux[demux_index].pidindex==-1) return;

	if (demux[demux_index].ECMpids[demux[demux_index].pidindex].EMM_PID==0 || !demux[demux_index].rdr)
		return;

	memset(nullserial,0,8);

	if (!memcmp(demux[demux_index].rdr->hexserial, nullserial, 8)) {
		//cs_debug("hexserial not set %s", cs_hexdump(1, demux[demux_index].rdr->hexserial, 8));
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

		cs_debug_mask(D_EMM, "dvbapi: starting emm filter %s, pid: 0x%04X", typtext[emmtype], demux[demux_index].ECMpids[demux[demux_index].pidindex].EMM_PID);
		cs_ddump_mask(D_EMM, filter, 32, "demux filter:");
		dvbapi_set_filter(demux_index, selected_api, demux[demux_index].ECMpids[demux[demux_index].pidindex].EMM_PID, filter, filter+16, 0, demux[demux_index].pidindex, count, TYPE_EMM);
	}

	memcpy(demux[demux_index].hexserial, demux[demux_index].rdr->hexserial, 8);
	demux[demux_index].emm_filter=1;
}

void dvbapi_add_ecmpid(int demux_id, ushort caid, ushort ecmpid, ulong provid, int chid) {
	int n,added=0;

	if (demux[demux_id].ECMpidcount>=ECM_PIDS)
		return;

	for (n=0;n<demux[demux_id].ECMpidcount;n++) {
		if (demux[demux_id].ECMpids[n].CAID == caid && demux[demux_id].ECMpids[n].ECM_PID == ecmpid && demux[demux_id].ECMpids[n].irdeto_chid == chid)
			added=1;
	}

	if (added==0) {
		demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].ECM_PID = ecmpid;
		demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CAID = caid;
		demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].PROVID = provid;
		demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_chid = chid;
		cs_log("[ADD PID %d] CAID: %04X\tECM_PID: %04X\tPROVID: %06X", demux[demux_id].ECMpidcount, caid, ecmpid, provid);
		demux[demux_id].ECMpidcount++;
	}
}

void dvbapi_add_emmpid(int demux_id, ushort caid, ushort emmpid, ulong provid) {
	int j;
	for (j=0;j<demux[demux_id].ECMpidcount;j++) {
		if (demux[demux_id].ECMpids[j].CAID==caid && (demux[demux_id].ECMpids[j].PROVID == provid || provid == 0)) {
			demux[demux_id].ECMpids[j].EMM_PID=emmpid;
			cs_debug("[ADD EMMPID %d] CAID: %04X\tEMM_PID: %04X\tPROVID: %06X", j, caid, emmpid, provid);
		}
	}	
}

void dvbapi_parse_cat(int demux_id, uchar *buf, int len) {
	unsigned short i, k;

	cs_ddump(buf, len, "cat:");

	for (i = 8; i < (((buf[1] & 0x0F) << 8) | buf[2]) - 1; i += buf[i + 1] + 2) {
		if (buf[i] != 0x09) continue;
		unsigned short caid=(((buf[i + 2] & 0x1F) << 8) | buf[i + 3]);
		unsigned short emm_pid=(((buf[i + 4] & 0x1F) << 8) | buf[i + 5]);
		ulong emm_provider = 0;

		switch (caid >> 8) {
			case 0x01:
				dvbapi_add_emmpid(demux_id, caid, emm_pid, 0);
				cs_debug("[cat] CAID: %04x\tEMM_PID: %04x", caid, emm_pid);
				for (k = i+7; k < i+buf[i+1]+2; k += 4) {
					emm_provider = (buf[k+2] << 8| buf[k+3]);
					emm_pid = (buf[k] & 0x0F) << 8 | buf[k+1];
					cs_debug("[cat] CAID: %04X\tEMM_PID: %04X\tPROVID: %06X", caid, emm_pid, emm_provider);
					dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider);
				}
				break;
			case 0x05:
				for (k = i+6; k < i+buf[i+1]+2; k += buf[k+1]+2) {
					if (buf[k]==0x14) {
						emm_provider = buf[k+2] << 16 | (buf[k+3] << 8| (buf[k+4] & 0xF0));
						cs_debug("[cat] CAID: %04x\tEMM_PID: %04x\tPROVID: %06X", caid, emm_pid, emm_provider);
						dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider);
					}
				}
				break;
			case 0x18:
				emm_provider = (buf[i+1] == 0x07) ? (buf[i+6] << 16 | (buf[i+7] << 8| (buf[i+8]))) : 0;
				cs_debug("[cat] CAID: %04x\tEMM_PID: %04x\tPROVID: %06X", caid, emm_pid, emm_provider);
				dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider);
				break;
			default:
				cs_debug("[cat] CAID: %04x\tEMM_PID: %04x", caid, emm_pid);
				dvbapi_add_emmpid(demux_id, caid, emm_pid, 0);
				break;
		}
	}
	return;
}

void dvbapi_set_pid(int demux_id, int num, int index) {
	int i;
	switch(selected_api) {
#ifdef WITH_STAPI	
		case STAPI:
			stapi_set_pid(demux_id,num,index);
			break;
#endif
		default:
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {
					if (ca_fd[i]>0) {
						ca_pid_t ca_pid2;
						memset(&ca_pid2,0,sizeof(ca_pid2));
						ca_pid2.pid = demux[demux_id].STREAMpids[num];
						ca_pid2.index = index;
						if (ioctl(ca_fd[i], CA_SET_PID, &ca_pid2)==-1)
							cs_debug("Error Stream SET_PID");
					}
				}
			}
			break;
	}
	return;
}

void dvbapi_stop_descrambling(int demux_id) {
	int i;

	cs_debug("stop descrambling (demux_id: %d)", demux_id);
	
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

void dvbapi_start_descrambling(int demux_id) {
	int i;
	cs_log("Start descrambling PID #%d (CAID: %04X)", demux[demux_id].curindex, demux[demux_id].ECMpids[demux[demux_id].curindex].CAID);

	demux[demux_id].pidindex=demux[demux_id].curindex;

	for (i=0;i<demux[demux_id].STREAMpidcount;i++)
		dvbapi_set_pid(demux_id, i, demux_id);

	if (cfg->dvbapi_au==1)
		dvbapi_start_filter(demux_id, demux[demux_id].pidindex, 0x001, 0x01, 0xFF, 0, TYPE_EMM); //CAT
}

void dvbapi_process_emm (int demux_index, int filter_num, unsigned char *buffer, unsigned int len) {
	EMM_PACKET epg;
	static uchar emm_global[512];
	static int emm_global_len = 0;
	int pos, emm_len = 0, k;
	uchar emmbuf[512];

	if (demux[demux_index].pidindex==-1) return;

	ulong provider = demux[demux_index].ECMpids[demux[demux_index].pidindex].PROVID;
	ulong emm_provid;		
	switch (demux[demux_index].ECMpids[demux[demux_index].pidindex].CAID >> 8) {
		case 0x05:
			if (len>500) return;
			switch(buffer[0]) {
				case 0x88:
					// emm-u
					break;

				case 0x8a:
				case 0x8b:
					// emm-g
					return;
					break;
                    
				case 0x8c:
				case 0x8d:
					// emm-s part 1
					if (!memcmp(emm_global, buffer, len))
						return;

					if (buffer[3] == 0x90 && buffer[4] == 0x03) {
						emm_provid = buffer[5] << 16 | buffer[6] << 8 | (buffer[7] & 0xFE);
					} else {
						return;
					}

					if (emm_provid!=provider)
						return;

					//cs_log("viaccess global emm_provid: %06X provid: %06X", emm_provid, provider);

					// copy first part of the emm-s
					memcpy(emm_global, buffer, len);
					emm_global_len=len;
					//cs_ddump(buffer, len, "viaccess global emm:");
					return;
					
				case 0x8e:
					// emm-s part 2
					if (!emm_global_len) return;

					if (buffer[6]!=0x00) return;

					memcpy(emmbuf, buffer, 7);
					pos=7;

					for (k=3; k<emm_global[2]+2 && k<emm_global_len; k += emm_global[k+1]+2) {
						if (emm_global[k]!=0x90) continue;
						memcpy(emmbuf+pos, emm_global+k, emm_global[k+1]+2);
						pos += emm_global[k+1]+2;
					}

					memcpy(emmbuf+pos, "\x9E\x20", 2);
					memcpy(emmbuf+pos+2, buffer+7, 32);
					pos+=34;

					int found=0;
					for (k=8; k<emm_global[2]+2 && k<emm_global_len; k += emm_global[k+1]+2) {
						if (emm_global[k] == 0xA1 || emm_global[k] == 0xA8 || emm_global[k] == 0xA9 || emm_global[k] == 0xB6) {
							memcpy(emmbuf+pos, emm_global+k, emm_global[k+1]+2);
							pos += emm_global[k+1]+2;
							found=1;
						}
					}
					if (found==0) return;

					memcpy(emmbuf+pos, "\xF0\x08", 2);
					memcpy(emmbuf+pos+2, buffer+39, 8);
					pos+=10;

					emm_len=pos;
					emmbuf[2]=emm_len-3;
					cs_ddump(buffer, len, "original emm:");
					memcpy(buffer, emmbuf, emm_len);
					len=emm_len;
					break;
			}
			break;
      		case 0x0d:
			if (len>500) return;
			switch (buffer[0]) {
				case 0x86:
					if (!memcmp(emm_global, buffer, len)) return;
					//cs_log("provider %06X - %02X", provider , buffer[7]);
					memcpy(emm_global, buffer, len);
					emm_global_len=len;
					cs_ddump(buffer, len, "cryptoworks global emm:");
					return;
				case 0x84:
					if (!emm_global_len) return;

					if (buffer[18] == 0x86) return;

					memcpy(emmbuf, buffer, 18);
					pos=18;
					for (k=5; k<emm_global[2]+2 && k<emm_global_len; k += emm_global[k+1]+2) {
						memcpy(emmbuf+pos, emm_global+k, emm_global[k+1]+2);
						pos += emm_global[k+1]+2;
					}
					memcpy(emmbuf+pos, buffer+18, len-18);
					emm_len=pos+(len-18);
					emmbuf[2]=emm_len-3;
					emmbuf[11]=emm_len-3-9;
					cs_ddump(buffer, len, "original emm:");
					memcpy(buffer, emmbuf, emm_len);
					len=emm_len;
				
					break;
			}
			break;
	}
		

	cs_ddump(buffer, len, "emm from fd %d:", demux[demux_index].demux_fd[filter_num].fd);

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
	int n,i,k=0,j;

	memset(global_caid_list, 0, sizeof global_caid_list);

	for (i=0;i<CS_MAXREADER;i++) {
		for (j=0;j<CS_MAXREADERCAID;j++) {
			if (reader[i].caid[j] != 0 && !(reader[i].typ & R_IS_NETWORK)) {
				if (k+1>=MAX_CAID) break;
				global_caid_list[k++]=reader[i].caid[j];	
			}
		}
	}

	demux[demux_index].max_status=0;
	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		demux[demux_index].ECMpids[n].status=0;
		
		for (i=0;i<CS_MAXCAIDTAB;i++) {
			ulong provid = (cfg->dvbapi_ignoretab.cmap[i] << 8 | cfg->dvbapi_ignoretab.mask[i]);
			if (cfg->dvbapi_ignoretab.caid[i] == demux[demux_index].ECMpids[n].CAID && (provid == demux[demux_index].ECMpids[n].PROVID || provid == 0)) {
				demux[demux_index].ECMpids[n].status=-1; //ignore
				cs_debug("[IGNORE PID %d] %04X:%06X", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID);
			}
		}

		for (i=0;i<CS_MAXCAIDTAB;i++) {
			ulong provid = (cfg->dvbapi_prioritytab.cmap[i] << 8 | cfg->dvbapi_prioritytab.mask[i]);
			if (cfg->dvbapi_prioritytab.caid[i] == demux[demux_index].ECMpids[n].CAID && (provid == demux[demux_index].ECMpids[n].PROVID || provid == 0 || demux[demux_index].ECMpids[n].PROVID == 0)) {
				demux[demux_index].ECMpids[n].status = i+1; //priority
				demux[demux_index].max_status = (i+1 > demux[demux_index].max_status) ? i+1 : demux[demux_index].max_status;
				cs_debug("[PRIORITIZE PID %d] %04X:%06X (position: %d)", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].status);
			}
		}

		if (!client[cs_idx].sidtabok && !client[cs_idx].sidtabno) continue;

		int nr;
		SIDTAB *sidtab;
		ECM_REQUEST er;
		er.caid  = demux[demux_index].ECMpids[n].CAID;
		er.prid  = demux[demux_index].ECMpids[n].PROVID;
		er.srvid = demux[demux_index].program_number;

		for (nr=0, sidtab=cfg->sidtab; sidtab; sidtab=sidtab->next, nr++) {
			if (sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid) {
				if ((client[cs_idx].sidtabno&(1<<nr)) && (chk_srvid_match(&er, sidtab))) {
					demux[demux_index].ECMpids[n].status = -1; //ignore
					cs_debug("[IGNORE PID %d] %04X:%06X (service %s) pos %d", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, sidtab->label, nr);
				}
				if ((client[cs_idx].sidtabok&(1<<nr)) && (chk_srvid_match(&er, sidtab))) {
					demux[demux_index].ECMpids[n].status = nr+1; //priority
					demux[demux_index].max_status = (nr+1 > demux[demux_index].max_status) ? nr+1 : demux[demux_index].max_status;
					cs_debug("[PRIORITIZE PID %d] %04X:%06X (service: %s position: %d)", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, sidtab->label, demux[demux_index].ECMpids[n].status);
				}
			}
		}
	}

	return;
}


void dvbapi_parse_descriptor(int demux_id, unsigned int info_length, unsigned char *buffer) {
	//int ca_pmt_cmd_id = buffer[i + 5];
	unsigned int descriptor_length=0;
	unsigned int j,u;

	if (info_length<1)
		return;

	if (buffer[0]==0x01) {
		buffer=buffer+1;
		info_length--;
	}

	for (j = 0; j < info_length; j += descriptor_length + 2) {
		descriptor_length = buffer[j+1];
		int descriptor_ca_system_id = (buffer[j+2] << 8) | buffer[j+3];
		int descriptor_ca_pid = ((buffer[j+4] & 0x1F) << 8) | buffer[j+5];
		int descriptor_ca_provider = 0;

		if (demux[demux_id].ECMpidcount>=ECM_PIDS)
			break;

		cs_debug("[pmt] type: %02x\tlength: %d", buffer[j], descriptor_length);

		if (buffer[j] != 0x09) continue;

		if (descriptor_ca_system_id >> 8 == 0x01) {
			for (u=2; u<descriptor_length; u+=15) { 
				descriptor_ca_pid = ((buffer[j+2+u] & 0x1F) << 8) | buffer[j+2+u+1];
				descriptor_ca_provider = (buffer[j+2+u+2] << 8) | buffer[j+2+u+3];
				dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider, 0);
			}
		} else {
			if (descriptor_ca_system_id >> 8 == 0x05 && descriptor_length == 0x0F && buffer[j+12] == 0x14)
				descriptor_ca_provider = buffer[j+14] << 16 | (buffer[j+15] << 8| (buffer[j+16] & 0xF0));

			if (descriptor_ca_system_id >> 8 == 0x18 && descriptor_length == 0x07)
				descriptor_ca_provider = buffer[j+6] << 16 | (buffer[j+7] << 8| (buffer[j+8]));
			
			dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider, 0);
		}
	}
}

void dvbapi_try_next_caid(int demux_id) {
	int num=-1, n, j;

	if (demux[demux_id].tries > 2) {
		cs_log("can't decode channel");
		dvbapi_stop_filter(demux_id, TYPE_ECM);
		return;
	}

	for (j = 1; j <= demux[demux_id].max_status && num == -1; j++) {	
		for (n=0; n<demux[demux_id].ECMpidcount; n++) {
			if (demux[demux_id].ECMpids[n].checked == 0 && demux[demux_id].ECMpids[n].status == j) {
				num=n;
				break;
			}
		}
	}

	if (num == -1) {
		j = 0;
		for (n=0; n<demux[demux_id].ECMpidcount; n++) {
			if (demux[demux_id].ECMpids[n].checked == 0 && demux[demux_id].ECMpids[n].status == j) {
				num=n;
				break;
			}
		}
	}

	if (num == -1) {
		demux[demux_id].tries++;
		cs_log("try pids again #%d", demux[demux_id].tries);
		for (n=0; n<demux[demux_id].ECMpidcount; n++) {
			demux[demux_id].ECMpids[n].checked=0;
		}
		dvbapi_try_next_caid(demux_id);
		return;
	}

	dvbapi_stop_filter(demux_id, TYPE_ECM);

	cs_debug("[TRY PID %d] CAID: %04X PROVID: %06X CA_PID: %04X", num, demux[demux_id].ECMpids[num].CAID, demux[demux_id].ECMpids[num].PROVID, demux[demux_id].ECMpids[num].ECM_PID);
#ifdef AZBOX
	openxcas_provid = demux[demux_id].ECMpids[num].PROVID;
	openxcas_caid = demux[demux_id].ECMpids[num].CAID;
	openxcas_ecm_pid = demux[demux_id].ECMpids[num].ECM_PID;
#endif
	demux[demux_id].curindex=num;

	//grep ecm
	dvbapi_start_filter(demux_id, num, demux[demux_id].ECMpids[num].ECM_PID, 0x80, 0xF0, 3000, TYPE_ECM); //ECM
	demux[demux_id].ECMpids[num].checked=1;
}

int dvbapi_parse_capmt(unsigned char *buffer, unsigned int length, int connfd) {
	unsigned int i, demux_id;
	unsigned short ca_mask=0x01, demux_index=0x00;

	//int ca_pmt_list_management = buffer[0];
	unsigned int program_number = (buffer[1] << 8) | buffer[2];
	unsigned int program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	if (buffer[17]==0x82 && buffer[18]==0x02) {
		//enigma2
		ca_mask = buffer[19];
		demux_index = buffer[20];
	}

	cs_ddump(buffer, length, "capmt:");
	
	for (i = 0; i < MAX_DEMUX; i++) {
		if (demux[i].demux_index == demux_index && demux[i].program_number == program_number) {
			return -1; //same pmt on same demux, exit
		}
	}

	for (demux_id=0; demux_id<MAX_DEMUX && demux[demux_id].program_number>0; demux_id++);

	if (demux_id>=MAX_DEMUX) {
		cs_log("error no free id (MAX_DEMUX)");
		return -1;
	}
	
	if (cfg->dvbapi_boxtype == BOXTYPE_IPBOX_PMT) {
		ca_mask = demux_id + 1;
		demux_index = demux_id;
	}
	
	dvbapi_stop_filter(demux_id, TYPE_ECM);
	dvbapi_stop_filter(demux_id, TYPE_EMM);

	memset(&demux[demux_id], 0, sizeof(demux[demux_id]));
	demux[demux_id].program_number=((buffer[1] << 8) | buffer[2]);
	demux[demux_id].demux_index=demux_index;
	demux[demux_id].ca_mask=ca_mask;
	demux[demux_id].socket_fd=connfd;
	demux[demux_id].rdr=NULL;
	demux[demux_id].pidindex=-1;

	cs_debug("id: %d\tdemux_index: %d\tca_mask: %02x\tprogram_info_length: %d", demux_id, demux[demux_id].demux_index, demux[demux_id].ca_mask, program_info_length);

	if (program_info_length > 1 && program_info_length < length)
		dvbapi_parse_descriptor(demux_id, program_info_length-1, buffer+7);

	unsigned int es_info_length=0;
	for (i = program_info_length + 6; i < length; i += es_info_length + 5) {
		int stream_type = buffer[i];
		unsigned short elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug("[pmt] stream_type: %02x\tpid: %04x\tlength: %d", stream_type, elementary_pid, es_info_length);

		if (demux[demux_id].STREAMpidcount >= ECM_PIDS)
			break;

		demux[demux_id].STREAMpids[demux[demux_id].STREAMpidcount++]=elementary_pid;

		if (es_info_length != 0 && es_info_length < length) {
			//int offset = (cfg->dvbapi_boxtype == BOXTYPE_IPBOX_PMT) ? i - 1 : i;         
			dvbapi_parse_descriptor(demux_id, es_info_length, buffer+i+5); 
		}
	}
	cs_debug("Found %d ECMpids and %d STREAMpids in PMT", demux[demux_id].ECMpidcount, demux[demux_id].STREAMpidcount);

	char *name = get_servicename(demux[demux_id].program_number, demux[demux_id].ECMpidcount>0 ? demux[demux_id].ECMpids[0].CAID : 0);
	cs_log("new program number: %04X (%s)", program_number, name);

#ifdef AZBOX
	openxcas_sid = program_number;
#endif

	if (demux[demux_id].ECMpidcount>0) {
		dvbapi_resort_ecmpids(demux_id);

#ifdef WITH_STAPI
		demux[demux_id].demux_index=stapi_get_device(demux_id, demux[demux_id].STREAMpids[0]);
#endif
		if (demux[demux_id].ECMpidcount>0)
			dvbapi_try_next_caid(demux_id);
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
					// check do we have any demux running on this fd
					short execlose = 1;
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

		if (((caid=a2i(ptr1, 2))|(prov=a2i(ptr3, 3)))) { 
			ctab->caid[i]=caid;
			ctab->cmap[i]=prov >> 8;
			ctab->mask[i++]=prov;
		}
	}
}

pthread_mutex_t event_handler_lock;

void event_handler(int signal) {
	struct stat pmt_info;
	char dest[1024];
	DIR *dirp;
	struct dirent *dp;
	int i, pmt_fd;

	signal=signal; //avoid compiler warnings
	pthread_mutex_lock(&event_handler_lock);
	
	int standby_fd = open(STANDBY_FILE, O_RDONLY);
	pausecam = (standby_fd > 0) ? 1 : 0;
	if (standby_fd) close(standby_fd);

	if (cfg->dvbapi_boxtype==BOXTYPE_IPBOX || cfg->dvbapi_pmtmode == 1) {
		pthread_mutex_unlock(&event_handler_lock);	
		return;
	}

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].pmt_file[0] != 0) {
			sprintf(dest, "%s%s", TMPDIR, demux[i].pmt_file);
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
		cs_log("opendir errno %d", errno);
		pthread_mutex_unlock(&event_handler_lock);	
		return;
	}
  
	while ((dp = readdir(dirp))) {
		if (strlen(dp->d_name) < 7)
  			continue; 
		if (strncmp(dp->d_name, "pmt", 3)!=0 || strncmp(dp->d_name+strlen(dp->d_name)-4, ".tmp", 4)!=0) 
			continue;
		
		sprintf(dest, "%s%s", TMPDIR, dp->d_name);
		pmt_fd = open(dest, O_RDONLY);
		if (pmt_fd < 0) 
			continue;
			
		if (fstat(pmt_fd, &pmt_info) != 0) 
			{ close(pmt_fd); continue; }
			 
		int found=0;
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

		unsigned int len = read(pmt_fd,mbuf,sizeof(mbuf));
		close(pmt_fd);
					
		if (len < 1) {
			cs_log("pmt file %s have invalid len!", dest);
			continue;
		}

		int pmt_id;
#ifdef QBOXHD
		uint j1,j2;
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

		cs_ddump(dest,len/2,"QboxHD pmt.tmp:");
	
		pmt_id = dvbapi_parse_capmt(dest+4, (len/2)-4, -1);
#else
		if (len>sizeof(dest)) { 
			cs_log("event_handler() dest buffer is to small for pmt data!");
			continue;
		}
		cs_ddump(mbuf,len,"pmt:");

		memcpy(dest, "\x00\xFF\xFF\x00\x00\x13\x00", 7);

		dest[1] = mbuf[3];
		dest[2] = mbuf[4];
		dest[5] = mbuf[11]+1;

		memcpy(dest + 7, mbuf + 12, len - 12 - 4);

		pmt_id = dvbapi_parse_capmt((uchar*)dest, 7 + len - 12 - 4, -1);
#endif
		strcpy(demux[pmt_id].pmt_file, dp->d_name);
		demux[pmt_id].pmt_time = pmt_info.st_mtime;

		if (cfg->dvbapi_pmtmode == 3) {
			disable_pmt_files=1;
			break;
		}
	}
	closedir(dirp);
	pthread_mutex_unlock(&event_handler_lock);	
}

void dvbapi_process_input(int demux_id, int filter_num, uchar *buffer, int len) {

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_ECM) {
		if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
			return;

		if (buffer[0] != 0x80 && buffer[0] != 0x81) 
			return;

		unsigned short caid = demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].CAID;
		unsigned long provid = demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].PROVID;

		if ((caid >> 8) == 0x06) {
			int i;
			//80 70 39 53 04 05 00 88
			if (buffer[5]>10) return;
			if (demux[demux_id].irdeto_numchids != buffer[5]) {
				cs_log("IRDETO ECM CHIDs: %d", buffer[5]);
				//TODO: remove no longer used chids
				for (i=1;i<=buffer[5];i++) {
					dvbapi_add_ecmpid(demux_id, caid, demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].ECM_PID, provid, i);
				}
				demux[demux_id].irdeto_numchids = buffer[5];
				//demux[demux_id].irdeto_curchid = 0;
			}
			if (buffer[4] != demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].irdeto_chid) {
				//wait for the correct chid
				return;
			}
		}

		if (demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].table == buffer[0])
			return;
							
		demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].table = buffer[0];

		int pid = dvbapi_check_array(cfg->dvbapi_prioritytab.caid, CS_MAXCAIDTAB, caid);
		if (pid>=0 && provid == 0) {
			if (cfg->dvbapi_prioritytab.mask[pid]>0)
				provid = (cfg->dvbapi_prioritytab.cmap[pid] << 8 | cfg->dvbapi_prioritytab.mask[pid]);
		}

		if (!provid)
			provid = chk_provid(buffer, caid);

		if (cfg->dvbapi_au==1)
			dvbapi_start_emm_filter(demux_id);

		ECM_REQUEST *er;
		if (!(er=get_ecmtask()))
			return;

		er->srvid = demux[demux_id].program_number;
		er->caid  = caid;
		er->pid   = demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex].ECM_PID;
		er->prid  = provid;

		er->l=len;
		memcpy(er->ecm, buffer, er->l);

		cs_debug("request cw for caid %04X provid %06X srvid %04X pid %04X chid %02X", er->caid, er->prid, er->srvid, er->pid, (caid >> 8) == 0x06 ? buffer[7] : 0);
		get_cw(er);
	}

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_EMM) {
		if (buffer[0]==0x01) { //CAT
			cs_debug("receiving cat");
			dvbapi_parse_cat(demux_id, buffer, len);
								
			dvbapi_stop_filternum(demux_id, filter_num);
			return;
		}
		dvbapi_process_emm(demux_id, filter_num, buffer, len);
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
	int i,rc,pfdcount,g,connfd,clilen,j;
	int ids[maxpfdsize], fdn[maxpfdsize], type[maxpfdsize];
	struct timeb tp;
	struct sockaddr_un servaddr;
	ssize_t len=0;

	for (i=0;i<MAX_DEMUX;i++) {
		memset(&demux[i], 0, sizeof(demux[i]));
		demux[i].pidindex=-1;
		demux[i].rdr=NULL;
	}
	memset(ca_fd, 0, sizeof(ca_fd));

	dvbapi_detect_api();

	if (selected_box == -1 || selected_api==-1) {
		cs_log("could not detect api version");
		return;
	}

	if (cfg->dvbapi_pmtmode == 1)
		disable_pmt_files=1;

	int listenfd = -1;
	if (cfg->dvbapi_boxtype != BOXTYPE_IPBOX_PMT && cfg->dvbapi_pmtmode != 2) {
		listenfd = dvbapi_init_listenfd();
		if (listenfd < 1) {
			cs_log("could not init camd.socket.");
			return;
		}
	}

	struct sigaction signal_action;
	signal_action.sa_handler = event_handler;
	sigemptyset(&signal_action.sa_mask);
	signal_action.sa_flags = SA_RESTART;
	sigaction(SIGRTMIN + 1, &signal_action, NULL);

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
	pthread_mutex_init(&event_handler_lock, &attr); 
	
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

		pfdcount = (listenfd > -1) ? 2 : 1; 

		chk_pending(tp);

		if (pausecam==1) {
			cs_sleepms(500);
			continue;
		}

		for (i=0;i<MAX_DEMUX;i++) {
			for (g=0;g<MAX_FILTER;g++) {
				if (demux[i].demux_fd[g].fd>0 && selected_api != STAPI) {
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
				cs_debug("event %d on fd %d", pfd2[i].revents, pfd2[i].fd);
			
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
						cs_debug("new socket connection fd: %d", connfd);

						disable_pmt_files=1;

						if (connfd <= 0) {
							cs_log("accept() returns error %d, fd event %d", errno, pfd2[i].revents);
							continue;
						}
					} else {
						cs_debug("PMT Update on socket %d. Please report.", pfd2[i].fd);
						dvbapi_stop_descrambling(ids[i]);
						connfd = pfd2[i].fd;
					}

					len = read(connfd, mbuf, sizeof(mbuf));

					if (len < 3) {
						cs_debug("camd.socket: too short message received");
						continue;
					}

					dvbapi_handlesockmsg(mbuf, len, connfd);
				} else { // type==0
					int demux_index=ids[i];
					int n=fdn[i];

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
	return;
}

void dvbapi_write_cw(int demux_id, uchar *cw) {
	int n;
	unsigned char nullcw[8];
	memset(nullcw, 0, 8);
	ca_descr_t ca_descr;
	memset(&ca_descr,0,sizeof(ca_descr));

	for (n=0;n<2;n++) {
		if (memcmp(cw+(n*8),demux[demux_id].lastcw[n],8)!=0 && memcmp(cw+(n*8),nullcw,8)!=0) {
			ca_descr.index = demux_id;
			ca_descr.parity = n;
			memcpy(demux[demux_id].lastcw[n],cw+(n*8),8);
			memcpy(ca_descr.cw,cw+(n*8),8);

			int i;
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {

					//cs_log("mask %02X write to %d", demux[demux_id].ca_mask, i);
					cs_debug("write cw%d index: %d (ca%d)", n, demux_id, i);

					if (ca_fd[i]<=0) {
						ca_fd[i]=dvbapi_open_device(demux_id, 1, i);
						if (ca_fd[i]<=0)
							return;
					}

					if (ioctl(ca_fd[i], CA_SET_DESCR, &ca_descr) < 0)
						cs_debug("Error CA_SET_DESCR");
				}
			}
		}
	}
}

void dvbapi_send_dcw(ECM_REQUEST *er) {
#ifdef AZBOX
	azbox_send_dcw(er);
	return;
#endif
	int i;

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].program_number==er->srvid) {
			demux[i].rdr=&reader[er->reader[0]];

			if (er->rc<=3 && demux[i].pidindex==-1 && er->caid!=0) {
				dvbapi_start_descrambling(i);
			}

			if (er->rc==4 && cfg->dvbapi_au==1 && dvbapi_check_array(global_caid_list, MAX_CAID, er->caid)>=0 && er->caid!=0x0500 && er->caid!=0x0100) {
				//local card and not found -> maybe card need emm
				dvbapi_start_descrambling(i);
			}

			if (er->rc>3 && demux[i].pidindex==-1) {
				dvbapi_try_next_caid(i);
				return;
			}

			if (er->rc>3) {
				cs_debug("cw not found");
				return;
			}

			int dindex = dvbapi_check_array(cfg->dvbapi_delaytab.caid, CS_MAXCAIDTAB, er->caid);
			if (dindex>=0) {
				char tmp1[5];
				sprintf(tmp1, "%04X", cfg->dvbapi_delaytab.mask[dindex]);
				int cw_delay = strtol(tmp1, '\0', 10);
				if (cw_delay<1000) {
					cs_debug("wait %d ms", cw_delay);
					cs_sleepms(cw_delay);
				}
			}


#ifdef WITH_STAPI
			stapi_write_cw(i, er->cw);
#else
			dvbapi_write_cw(i, er->cw);
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
				fprintf(ecmtxt, "protocol: %s\n", reader[er->reader[0]].ph.desc);
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

#ifdef AZBOX
	azbox_main();
#else
	dvbapi_main_local();
#endif

	cs_log("Module dvbapi error");
	cs_exit(0);

	return;
}


#ifdef AZBOX
void azbox_openxcas_ecm_callback(int stream_id, unsigned int seq, int cipher_index, unsigned int caid, unsigned char *ecm_data, int l, unsigned short pid) {
	cs_debug("openxcas: ecm callback received"); 

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

	cs_debug("request cw for caid %04X provid %06X srvid %04X pid %04X", er->caid, er->prid, er->srvid, er->pid);
	get_cw(er);

	//openxcas_stop_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);
	//openxcas_remove_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);

	openxcas_cipher_idx = cipher_index;

	struct timeb tp;
	cs_ftime(&tp);
	tp.time+=500;

	struct pollfd pfd;
	pfd.fd = client[cs_idx].fd_m2c_c;
	pfd.events = POLLIN | POLLPRI;
/*
	while(1) {
		chk_pending(tp);

		if (poll(&pfd, 1, 10) < 0)
			continue;

		if (pfd.revents & (POLLHUP | POLLNVAL)) {
			cs_debug("openxcas: ecm/cw error");
			break;
		}

		if (pfd.revents & (POLLIN | POLLPRI)) {
			chk_dcw(client[cs_idx].fd_m2c_c);
			break;
		}
	}*/
} 
	 

void azbox_openxcas_ex_callback(int stream_id, unsigned int seq, int idx, unsigned int pid, unsigned char *ecm_data, int l) {
	cs_debug("openxcas: ex callback received");

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

	cs_debug("request cw for caid %04X provid %06X srvid %04X pid %04X", er->caid, er->prid, er->srvid, er->pid);
	get_cw(er);
	 
	if (openxcas_stop_filter_ex(stream_id, seq, openxcas_filter_idx) < 0)
		cs_log("openxcas: unable to stop ex filter");
	else
		cs_debug("openxcas: ex filter stopped");
	 
	struct timeb tp;
	cs_ftime(&tp);
	tp.time+=500;

	chk_pending(tp);
	chk_dcw(client[cs_idx].fd_m2c_c);

	unsigned char mask[12];
	unsigned char comp[12];
	memset(&mask, 0x00, sizeof(mask));
	memset(&comp, 0x00, sizeof(comp));

	mask[0] = 0xff;
	comp[0] = ecm_data[0] ^ 1;

	if ((openxcas_filter_idx = openxcas_start_filter_ex(stream_id, seq, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ex_callback)) < 0)
		cs_log("openxcas: unable to start ex filter");
	else
		cs_debug("openxcas: ex filter started, pid = %x", openxcas_ecm_pid);
}

void azbox_main() {
	struct timeb tp;
	cs_ftime(&tp);
	tp.time+=500;

	openxcas_msg_t msg;
	int ret;
	while ((ret = openxcas_get_message(&msg, 0)) >= 0) {
		cs_sleepms(10);

	  chk_pending(tp);

		if (ret) {
			openxcas_stream_id = msg.stream_id;
			openxcas_seq = msg.sequence;

			switch(msg.cmd) {
				case OPENXCAS_SELECT_CHANNEL:
					cs_debug("openxcas: msg: OPENXCAS_SELECT_CHANNEL");

					// parse channel info
					struct stOpenXCASChannel chan;
					memcpy(&chan, msg.buf, msg.buf_len);

					cs_log("openxcas: channel change: sid = %x, vpid = %x. apid = %x", chan.service_id, chan.v_pid, chan.a_pid);

					openxcas_video_pid = chan.v_pid; 
					openxcas_audio_pid = chan.a_pid;
					openxcas_data_pid = chan.d_pid;
					break;
				case OPENXCAS_START_PMT_ECM: 
					cs_debug("openxcas: msg: OPENXCAS_START_PMT_ECM");

					 // parse pmt
					uchar *dest = malloc(msg.buf_len + 7 - 12 - 4);

					memcpy(dest, "\x00\xFF\xFF\x00\x00\x13\x00", 7);

					dest[1] = msg.buf[3];
					dest[2] = msg.buf[4];
					dest[5] = msg.buf[11]+1;

					memcpy(dest + 7, msg.buf + 12, msg.buf_len - 12 - 4);

					dvbapi_parse_capmt(dest, 7 + msg.buf_len - 12 - 4, -1);
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
						cs_debug("openxcas: ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);

					if (openxcas_start_filter(msg.stream_id, msg.sequence, OPENXCAS_FILTER_ECM) < 0)
						cs_log("openxcas: unable to start ecm filter");
					else
						cs_debug("openxcas: ecm filter started");

					if (!openxcas_create_cipher_ex(msg.stream_id, openxcas_seq, 0, openxcas_ecm_pid, openxcas_video_pid, 0xffff, openxcas_audio_pid, 0xffff, 0xffff, 0xffff))
						cs_log("openxcas: failed to create cipher ex");
					else
						cs_debug("openxcas: cipher created");
					break;
				case OPENXCAS_STOP_PMT_ECM:
					cs_debug("openxcas: msg: OPENXCAS_STOP_PMT_ECM");
					openxcas_stop_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
					openxcas_remove_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
					openxcas_stop_filter_ex(msg.stream_id, msg.sequence, openxcas_filter_idx);
					openxcas_destory_cipher_ex(msg.stream_id, msg.sequence);
					memset(&demux, 0, sizeof(demux));
					break;
				case OPENXCAS_ECM_CALLBACK:
					cs_debug("openxcas: msg: OPENXCAS_ECM_CALLBACK");
					struct stOpenXCAS_Data data;
					memcpy(&data, msg.buf, msg.buf_len);
					if (!openxcas_busy)
					  openxcas_filter_callback(msg.stream_id, msg.sequence, OPENXCAS_FILTER_ECM, &data);
					break;
				case OPENXCAS_PID_FILTER_CALLBACK:
					cs_debug("openxcas: msg: OPENXCAS_PID_FILTER_CALLBACK");
					openxcas_filter_callback_ex(msg.stream_id, msg.sequence, (struct stOpenXCAS_Data *)msg.buf);
					break;
				case OPENXCAS_QUIT:
					cs_debug("openxcas: msg: OPENXCAS_QUIT");
					openxcas_close();
					cs_log("openxcas: exited");
					return;
					break;
				case OPENXCAS_UKNOWN_MSG:
				default:
					cs_debug("openxcas: msg: OPENXCAS_UKNOWN_MSG (%d)", msg.cmd);
					//cs_ddump(&msg, sizeof(msg), "msg dump:");
					break;
			}
		}
	}
	cs_log("openxcas: invalid message");
	return;
}

void azbox_send_dcw(ECM_REQUEST *er) {
	cs_debug("openxcas: send_dcw");

	openxcas_busy = 0;

	int i;
	for (i=0; i < MAX_DEMUX; i++) {
		if (er->rc > 3) {
			cs_debug("cw not found");

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
					cs_debug("openxcas: ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, openxcas_caid);
			} else
				cs_debug("openxcas: ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);

			if (openxcas_start_filter(openxcas_stream_id, openxcas_seq, OPENXCAS_FILTER_ECM) < 0)
				cs_log("openxcas: unable to start ecm filter");
			else 
				cs_debug("openxcas: ecm filter started");

			return;
		}
	}

  unsigned char nullcw[8];
  memset(nullcw, 0, 8);

  int n;
  for (n=0;n<2;n++) {
    if (memcmp(er->cw + (n * 8), demux[0].lastcw[n], 8) && memcmp(er->cw + (n * 8), nullcw, 8)) {
      memcpy(demux[0].lastcw[n], er->cw + (n * 8), 8);
      memcpy(openxcas_cw + (n * 8), er->cw + (n * 8), 8);
    }
  }
 
	if (openxcas_set_key(openxcas_stream_id, openxcas_seq, 0, openxcas_cipher_idx, openxcas_cw, openxcas_cw + 8) != 1)
		cs_log("openxcas: set cw failed");
	else
		cs_ddump(openxcas_cw, 16, "openxcas: write cws to descrambler");
}
#endif
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
