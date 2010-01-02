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

#ifdef HAVE_DVBAPI_3

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "globals.h"

#include <linux/dvb/ca.h>
#include <linux/dvb/dmx.h>

#define CADEV		"/dev/dvb/adapter0/ca%d"
#define DMXDEV		"/dev/dvb/adapter0/demux%d"
#define CAMDSOCKET	"/tmp/camd.socket"

#define BUFSIZE 1024
#define MAX_CAID 50
#define MAX_DEMUX 3


static int listenfd = -1;


typedef struct ECMPIDS
{
	int CA_PID;
	int CA_System_ID;
} ECMPIDSTYPE;

typedef struct demux_s
{
	int demux_ecm_fd;
	int demux_emm_fd;
	int cadev_index;
	int ca_fd;
	unsigned short int program_number;
	short emm_pid;
	int ECMpidcount;
	ECMPIDSTYPE ECMpids[20];
	int ca_system_id;
	int ca_pid;
	unsigned char buffer_cache_dmx[12];
	unsigned char lastcw0[8];
	unsigned char lastcw1[8];
} DEMUXTYPE;

typedef struct demux_search_s
{
	int type;
	int index;
} demux_search;

DEMUXTYPE demux[MAX_DEMUX];


int dvbapi_open_demux(int index_demux)
{
	int dmx_fd;
	char device_path[256];
	
	sprintf(device_path, DMXDEV, index_demux);

	if ((dmx_fd = open(device_path, O_RDWR)) < 0)
		cs_log("error opening demux %s", device_path);

	cs_debug("DEMUX open: %s", device_path);
	return dmx_fd;
}


int dvbapi_open_ca(int index_demux)
{
	int ca_fd,i;
	char device_path[256];

	sprintf(device_path, CADEV, demux[index_demux].cadev_index);

	if ((ca_fd = open(device_path, O_RDWR)) < 0) {
		cs_log("error opening ca %s", device_path);
		return 0;
	}

	demux[index_demux].ca_fd=ca_fd;

	cs_debug("CA open: %s", device_path);
	return ca_fd;
}

unsigned short dvbapi_get_single_ecm(int demux_index, int caid, int pid, unsigned char filt, unsigned char mask)
{
	unsigned char buf[BUFSIZE];
	int dmx_fd, len;

	struct dmx_sct_filter_params sFP;

	memset(&sFP, 0, sizeof(sFP));
	memset(buf,0,BUFSIZE);

	sFP.pid 			= pid;
	sFP.timeout			= 2000;
	sFP.flags			= DMX_ONESHOT | DMX_CHECK_CRC | DMX_IMMEDIATE_START;
	sFP.filter.filter[0]		= filt;
	sFP.filter.mask[0]		= mask;

	cs_debug("dvbapi: filter for 1 ECM");

	dmx_fd = dvbapi_open_demux(demux_index);

	if (ioctl(dmx_fd, DMX_SET_FILTER, &sFP) < 0)
		return 0;

	len=read(dmx_fd, buf, BUFSIZE);
	cs_debug("Read %d bytes from demux", len);

	close(dmx_fd);

	if (len > 0) {
		ECM_REQUEST *er;

		if (!(er=get_ecmtask()))
			return 0;
	
		er->srvid = demux[demux_index].program_number;
		er->caid  = caid;
		er->pid   = pid;
		//er->prid  = 0x3411;

		er->l=len;
		memcpy(er->ecm, buf, er->l);

		get_cw(er);
	}
	return 0;
}

unsigned short dvbapi_parse_cat(int demux_index)
{
	unsigned char buf[BUFSIZE];
	unsigned short i, emmpid;
	int dmx_fd, len;

	unsigned short ca_system_id=demux[demux_index].ca_system_id;

	struct dmx_sct_filter_params sFP;

	memset(&sFP, 0, sizeof(sFP));

	memset(buf,0,BUFSIZE);

	sFP.filter.filter[0] = 0x01;
	sFP.filter.mask[0] = 0xFF;
	sFP.flags = DMX_ONESHOT | DMX_CHECK_CRC | DMX_IMMEDIATE_START;
	sFP.pid = 0x0001;
	sFP.timeout = 3000; //3secs
	
	
	dmx_fd = dvbapi_open_demux(demux_index);

	if (ioctl(dmx_fd, DMX_SET_FILTER, &sFP) < 0)
		return 0;

	len=read(dmx_fd, buf, BUFSIZE);


	cs_debug("Read %d bytes from demux", len);

	close(dmx_fd);

	if (len<=0)
		return 0;

	for (i = 8; i < (((buf[1] & 0x0F) << 8) | buf[2]) - 1; i += buf[i + 1] + 2)
	{
		if ((buf[i] == 0x09) && ((((buf[i + 2] & 0x1F) << 8) | buf[i + 3]) == ca_system_id))
		{
			emmpid=(((buf[i + 4] & 0x1F) << 8) | buf[i + 5]);
			return emmpid;
		}
	}

	return 0;
}

unsigned short dvbapi_parse_ecm(int demux_index, unsigned char *buf, int len)
{
	unsigned short provid;

	provid=(buf[3]<<8)|buf[4];
	cs_debug("Read %d bytes\tTable-id: %02x\tCA section length: %d\tProvider ID: %04x", len, buf[0], len ,provid);

	if (len>0) {
		ECM_REQUEST *er;

		if (!(er=get_ecmtask()))
			return 0;

		er->srvid = demux[demux_index].program_number;
		er->caid  =  demux[demux_index].ca_system_id;
		//er->prid  = 0x3411;

		er->l=len;
		memcpy(er->ecm, buf, er->l);

		get_cw(er);
	}

	return(provid);
}

int dvbapi_set_filter(int demux_index, int type, int pid, unsigned char filt, unsigned char mask)
{
	struct dmx_sct_filter_params sFP;
	cs_debug("Set filter pid:%d, value:%d...",pid, filt);

	memset(&sFP,0,sizeof(sFP));

	sFP.pid 			= pid;
	sFP.timeout			= 3000; //wait max 3 seconds for ECM message, should be repeated every 500ms
	sFP.flags			= DMX_CHECK_CRC | DMX_IMMEDIATE_START;
	sFP.filter.filter[0]		= filt;
	sFP.filter.mask[0]		= mask;

	int dmx_fd = dvbapi_open_demux(demux_index);

	if (ioctl(dmx_fd, DMX_SET_FILTER, &sFP) < 0)
	{
		perror(" Status");
		return 0;
	}

	if (type==0) 
		demux[demux_index].demux_ecm_fd=dmx_fd;

	if (type==1)
		demux[demux_index].demux_emm_fd=dmx_fd;

	return 1;
}

void dvbapi_stop_descramble(int demux_index) 
{

	/*
	if (global_capid != 0) {
		// unset pid?? (not working)
		ca_pid_t ca_pid;
		memset(&ca_pid,0,sizeof(ca_pid));
		ca_pid.pid = global_capid;
		ca_pid.index = -1;
		//if (ioctl(camfd, CA_SET_PID, &ca_pid)==-1) perror("Error Remove SET_PID");
	}
	*/

	cs_log("dvbapi: Stop descrambling CAID: %04x", demux[demux_index].ca_system_id);
	
	demux[demux_index].ca_system_id=0;
	demux[demux_index].ca_pid=0;
	demux[demux_index].emm_pid=0;


	if (demux[demux_index].demux_ecm_fd>0) {
		ioctl(demux[demux_index].demux_ecm_fd,DMX_STOP);			
		close(demux[demux_index].demux_ecm_fd);
		cs_debug("closing ecm dmx device");
		demux[demux_index].demux_ecm_fd=0;
	}

	if (demux[demux_index].demux_emm_fd>0) {
		ioctl(demux[demux_index].demux_emm_fd,DMX_STOP);
		close(demux[demux_index].demux_emm_fd);
		cs_debug("closing emm dmx device");
		demux[demux_index].demux_emm_fd=0;
	}

	if (demux[demux_index].ca_fd>0) {
		close(demux[demux_index].ca_fd);
		cs_debug("closing ca device");
		demux[demux_index].ca_fd=0;
	}

	return;
}

void dvbapi_start_descramble(int demux_index, int caid, int capid) {

	cs_log("dvbapi: Start descrambling CAID: %04x", caid);

	demux[demux_index].ca_pid=capid;
	demux[demux_index].ca_system_id=caid;

	if (!dvbapi_set_filter(demux_index,0,capid,0x80,0xF0))	//filter on ECM pid and 0x80 or 0x81 (mask 0xF0)
		cs_log("Error ECM filtering");

	/*
	 * get emm pid and start filter
	 * TODO: prase_cat blocks thread */

	if (cfg->dvbapi_au==1) {
		short emmpid;
		emmpid=dvbapi_parse_cat(demux_index);

		cs_log("EMMPid: %04x", emmpid);
		demux[demux_index].emm_pid=emmpid;
		dvbapi_set_filter(demux_index,1,emmpid,0x80,0xF0);
	}

	int camfd=dvbapi_open_ca(demux_index);
	if (camfd<=0) {
		dvbapi_stop_descramble(demux_index);
		return;
	}

	demux[demux_index].ca_fd=camfd;

	ca_pid_t ca_pid;
	memset(&ca_pid,0,sizeof(ca_pid));
	ca_pid.pid = capid;
	ca_pid.index = 0;
	if (ioctl(camfd, CA_SET_PID, &ca_pid)==-1)
		cs_log("dvbapi: Error SET_PID");
}

// from tuxbox camd
int dvbapi_parse_capmt(unsigned char *buffer, unsigned int length)
{
	unsigned short i, j;
	int n, added, ca_mask, demux_index;

	int ca_pmt_list_management = buffer[0];
	unsigned short int program_number = (buffer[1] << 8) | buffer[2];
	int program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	switch (ca_pmt_list_management)
	{
		case 0x01:
			//FIXME?? (first)
			break;
		case 0x03:
			//default (only)
			break;
		default:
			//FIXME?? (unknown)
			break;
	}

	if (buffer[17]==0x82) {
		ca_mask = buffer[19];
		demux_index = buffer[20];
	}
	
	if (demux[demux_index].program_number==((buffer[1] << 8) | buffer[2]))
		return 0;

	cs_dump(buffer, length, "capmt:");
	cs_log("dvbapi: new program number: %04x", program_number);
	//cs_debug("program_info_length: %d", program_info_length);

	demux[demux_index].program_number=((buffer[1] << 8) | buffer[2]);
	demux[demux_index].ECMpidcount=0;

	demux[demux_index].cadev_index=ca_mask;

	//CA_PIDS fr alle Streams
	if (program_info_length != 0)
	{
		int ca_pmt_cmd_id = buffer[6];
		//cs_debug("ca_pmt_id: %02x", ca_pmt_cmd_id);
		int descriptor_length=0;
		for (i = 0; i < program_info_length - 1; i += descriptor_length + 2)
		{
			descriptor_length = buffer[i + 8];
			int ca_system_id = (buffer[i + 9] << 8) | buffer[i + 10];
			int ca_pid = ((buffer[i + 11] & 0x1F) << 8)| buffer[i + 12];

			cs_debug("typ: %02x ca_system_id: %04x\t ca_pid: %04x\tca_descriptor_length %d", buffer[i + 7], ca_system_id, ca_pid, descriptor_length);

			if (buffer[i + 7] == 0x09) {
				demux[demux_index].ECMpids[demux[demux_index].ECMpidcount].CA_PID=ca_pid;
				demux[demux_index].ECMpids[demux[demux_index].ECMpidcount].CA_System_ID=ca_system_id;
				demux[demux_index].ECMpidcount++;
			}

			if (buffer[i + 7] == 0x82) {
				ca_mask = buffer[i + 9];
				demux_index = buffer[i + 10];
				demux[demux_index].cadev_index=ca_mask;
			}
		}
	}


	//CA_PIDs fr einzelne Streams
	unsigned short es_info_length=0;
	for (i = program_info_length + 6; i < length; i += es_info_length + 5)
	{
		int stream_type = buffer[i];
		int elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug("stream_type: %02x\telementary_pid: %04x\tes_info_length: %04x", stream_type, elementary_pid, es_info_length);

		if (es_info_length != 0)
		{
			int ca_pmt_cmd_id = buffer[i + 5];
			int descriptor_length=0;
			for (j = 0; j < es_info_length - 1; j += descriptor_length + 2)
			{
				descriptor_length = buffer[i + j + 7];
				int descriptor_ca_system_id = (buffer[i + j + 8] << 8) | buffer[i + j + 9];
				int descriptor_ca_pid = ((buffer[i + j + 10] & 0x1F) << 8) | buffer[i + j + 11];

				cs_debug("typ: %02x\tca_system_id: %04x\t ca_pid: %04x", buffer[i + j + 6], descriptor_ca_system_id, descriptor_ca_pid);

				if (buffer[i + j + 6] == 0x09) {
					added=0;
					for (n=0;n<demux[demux_index].ECMpidcount;n++) {
						if (demux[demux_index].ECMpids[n].CA_System_ID==descriptor_ca_system_id)
							added=1;
					}
					if (added==0) {
						demux[demux_index].ECMpids[demux[demux_index].ECMpidcount].CA_PID=descriptor_ca_pid;
						demux[demux_index].ECMpids[demux[demux_index].ECMpidcount].CA_System_ID=descriptor_ca_system_id;
						demux[demux_index].ECMpidcount++;
					}
				}
			}
		}
	}

	dvbapi_stop_descramble(demux_index);

	cs_log("dvbapi: Found %d ECMpids in PMT", demux[demux_index].ECMpidcount);

	for (n=0; n<demux[demux_index].ECMpidcount; n++) {

		cs_debug("dvbapi: trying CA_System_ID: %04x CA_PID: %04x", demux[demux_index].ECMpids[n].CA_System_ID, demux[demux_index].ECMpids[n].CA_PID);

		if (demux[demux_index].ca_system_id!=0)
			continue;

		dvbapi_get_single_ecm(demux_index, demux[demux_index].ECMpids[n].CA_System_ID,demux[demux_index].ECMpids[n].CA_PID,0x80,0xF0);
		sleep(3);
	}

	return 0;
}

void dvbapi_handlesockmsg (unsigned char *buffer, ssize_t len)
{
	int i;
	unsigned int val, size;

	//cs_dump(buffer, len, "handlesockmsg:");

	if (buffer[0] != 0x9F) {
		cs_log("handlesockmsg() unknown socket command: %02x", buffer[0]);
		return;
	}

	if (buffer[1] != 0x80) {
		cs_log("handlesockmsg() unknown apdu tag");
		return;
	}


	if (buffer[3] & 0x80) {
		val = 0;
		size = buffer[3] & 0x7F;
		for (i = 0; i < size; i++)
			val = (val << 8) | buffer[i + 1 + 3];
		size++;
	} else
	{
		val = buffer[3] & 0x7F;
		size = 1;
	}

	if (buffer[2] == 0x30) // ca_info_enq
		cs_debug("ca_info!!");
	else if (buffer[2] == 0x32) // ca_pmt
	{
		if ((3 + size + val) == len)
			dvbapi_parse_capmt(buffer + 3 + size, val);
		else
			cs_log("handlesockmsg() ca_pmt invalid length");
	}
	else if (buffer[2] == 0x3f)
	{
		//9F 80 3f 04 83 02 00 00
		//zap?
		//cs_debug("zap!");
	} else
	{
		cs_log("dvbapi: handlesockmsg() unknown command");
		cs_dump(buffer, len, "unknown command:");
	}
}

static int dvbapi_init_listenfd() {

	int clilen;
	struct sockaddr_un servaddr;

	memset(&servaddr, 0, sizeof(struct sockaddr_un));
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, cfg->dvbapi_socket);
	clilen = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

	if ((unlink(cfg->dvbapi_socket) < 0) && (errno != ENOENT))
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
		sleep(1); // check every second
		//cs_log("check zap");

		connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);

		if (connfd <= 0) //socket not available
			break;

		len = read(connfd, buffer, sizeof(buffer));

		if (len < 3) {
			cs_debug("Client: camd.socket: too short message received");
			break;
		}

		// if message begins with an apdu_tag and is longer than three bytes
		if ((buffer[0] == 0x9F) && ((buffer[1] >> 7) == 0x01) && ((buffer[2] >> 7) == 0x00)) {
			dvbapi_handlesockmsg(buffer, len);
		}

		close(connfd);

	}
	return 0;
}


demux_search dvbapi_find_dmx_by_fd(int fd)
{
	int i;
	demux_search s1;
	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].demux_ecm_fd==fd) {
			s1.type=0;
			s1.index=i;
			return s1;
		}
		if (demux[i].demux_emm_fd==fd) {
			s1.type=1;
			s1.index=i;
			return s1;
		}
	}
	
	return s1;
}

int dvbapi_get_index_by_prgnr(unsigned short int prognr)
{
	int i;
	for (i=0;i<MAX_DEMUX;i++) 
		if (demux[i].program_number==prognr)
			return i;
	
	return -1;
}

void *thread_check_demux(void *arg) {

	struct pollfd pfd2[MAX_DEMUX*2];
	int rc,len,i,pfdcount;
	unsigned char buffer[BUFSIZE];
	demux_search s1;

	while(1)
	{

		pfdcount=0;
		for (i=0;i<MAX_DEMUX;i++) {
			if (demux[i].demux_ecm_fd>0) {
				pfd2[pfdcount].fd = demux[i].demux_ecm_fd;
				pfd2[pfdcount].events = (POLLIN | POLLPRI);
				pfdcount++;
			}
			if (demux[i].demux_emm_fd>0) {
				pfd2[pfdcount].fd = demux[i].demux_emm_fd;
				pfd2[pfdcount].events = (POLLIN | POLLPRI);
				pfdcount++;
			}	
	
		}

		rc=poll(pfd2, pfdcount, 1000);

		for (i = 0; i < pfdcount; i++) {
			if (pfd2[i].revents & (POLLIN | POLLPRI)) {
				s1=dvbapi_find_dmx_by_fd(pfd2[i].fd);
				if (s1.type==0) {
					//ECM
					if ((len = read(pfd2[i].fd, buffer, BUFSIZE)) <= 0)
						break;

					if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
						break;

					if (buffer[0] == 0x80 | buffer[0] == 0x81)
					{
						if (memcmp(buffer, demux[s1.index].buffer_cache_dmx, 12) != 0) {
							memcpy(demux[s1.index].buffer_cache_dmx, buffer, 12);
							if (!dvbapi_parse_ecm(s1.index,buffer,len)) { cs_log("Error while parsing ECM"); }
						}
					}

				}
				if (s1.type==1) {
					//EMM
					if ((len = read(pfd2[i].fd, buffer, BUFSIZE)) <= 0)
						break;

					if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
						break;

					/*
					//nagra only???
					int emmtype;
					if( (buffer[0]==0x82) ) emmtype = 0; // U
					if( (buffer[0]==0x83) && (buffer[7]==0x10) ) emmtype = 1; // S
					if( (buffer[0]==0x83) && (buffer[7]==0x00) ) emmtype = 2; // G
					*/

					cs_log("EMM Type: 0x%02x", buffer[0]);

					//force emm output
					reader[ridx].logemm=9999;

					memset(&epg, 0, sizeof(epg));

					epg.caid[0] = (uchar)(demux[s1.index].ca_system_id>>8);
					epg.caid[1] = (uchar)(demux[s1.index].ca_system_id);
					if (reader[client[cs_idx].au].caid[0]!=b2i(2,epg.caid)) cs_log("caid %04x", b2i(2,epg.caid));
					//memcpy(epg.provid, prov, 4);

					epg.l=len;
					memcpy(epg.emm, buffer, epg.l);
					memcpy(epg.hexserial, reader[client[cs_idx].au].hexserial, 8);

					do_emm(&epg);

				}

			}
		}

	}
	return 0;
}


int dvbapi_main_local()
{
	struct pollfd pfd2[1];
	int i,rc;
	pthread_t p1, p2;

	if (cfg->dvbapi_socket[0]==0)
		strncpy(cfg->dvbapi_socket, CAMDSOCKET, sizeof(cfg->dvbapi_socket)-1);

	if (cfg->dvbapi_usr[0]==0) {
		//
	}


	for (i=0;i<MAX_DEMUX;i++) {

		demux[i].program_number=0;
		demux[i].demux_ecm_fd=0;
		demux[i].demux_emm_fd=0;
		demux[i].ca_system_id=0;
		demux[i].ca_pid=0;
		demux[i].emm_pid=0;
		demux[i].cadev_index=-1;
		demux[i].ca_fd=0;
		memset(demux[i].buffer_cache_dmx,0 ,12);

		for (i=0;i<20;i++)		//clean ECMpids array
		{
			demux[i].ECMpids[i].CA_PID		= 0;
			demux[i].ECMpids[i].CA_System_ID = 0;
		}
		
	}

	if (!dvbapi_init_listenfd()) return 1;

	pfd2[0].fd = fd_m2c;
	pfd2[0].events = (POLLIN | POLLPRI);

	pthread_create (&p1, NULL, thread_check_zap, NULL);
	pthread_create (&p2, NULL, thread_check_demux, NULL);


	while (1) {
		if (master_pid!=getppid()) {
			cs_log("master died");
			cs_exit(0);
		}

		rc=poll(pfd2, 1, 500);

		if (rc<0)
			break;

		if (pfd2[0].revents & (POLLIN | POLLPRI)) {
			chk_dcw(fd_m2c);
		}

	}
	return 0;
}


void dvbapi_send_dcw(ECM_REQUEST *er) {
	unsigned char cw_0[8], cw_1[8];

	memcpy(cw_0, er->cw, 8);
	memcpy(cw_1, er->cw+8, 8);

	ca_descr_t ca_descr;
	memset(&ca_descr,0,sizeof(ca_descr));

	//this is not working when both tuner on one channel
	int demux_index=dvbapi_get_index_by_prgnr(er->srvid);
	if (demux_index>=0) {
		if (er->rc==0 && demux[demux_index].ca_system_id==0)
			dvbapi_start_descramble(demux_index, er->caid, er->pid);		
	} else {
		cs_log("error cant find demux index");
	}

	if (memcmp(cw_0,demux[demux_index].lastcw0,8))
	{
		ca_descr.index = 0;
		ca_descr.parity = 0;
		memcpy(demux[demux_index].lastcw0,cw_0,8);
		memcpy(ca_descr.cw,cw_0,8);
		if (ioctl(demux[demux_index].ca_fd, CA_SET_DESCR, &ca_descr) < 0) perror("CA_SET_DESCR");
	}

	if (memcmp(cw_1,demux[demux_index].lastcw1,8))
	{
		ca_descr.index = 0;
		ca_descr.parity = 1;
		memcpy(demux[demux_index].lastcw1,cw_1,8);
		memcpy(ca_descr.cw,cw_1,8);
		if (ioctl(demux[demux_index].ca_fd, CA_SET_DESCR, &ca_descr) < 0) perror("CA_SET_DESCR");
	}

}

static void dvbapi_handler(int idx) {
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
	ph->multi=0;
	ph->watchdog=0;
	ph->s_handler=dvbapi_handler;
	ph->send_dcw=dvbapi_send_dcw;
}
#endif // HAVE_DVBAPI_3
