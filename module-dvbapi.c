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

#define BUFSIZE	1024
#define MAX_CAID 50
#define MAX_DEMUX 3

static int listenfd = -1;

typedef struct ECMPIDS
{
	int CA_PID;
	int CA_System_ID;
	int EMM_PID;
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
	int provider_id;
	int received_emm;
	int STREAMpidcount;
	short STREAMpids[20];
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

int dvbapi_read_device(int dmx_fd, unsigned char *buf, int length, int debug)
{
	int len;
	len=read(dmx_fd, buf, length);

	if (len==-1)
		cs_log("error %d", errno);

	if (debug==1)
		cs_debug("Read %d bytes from demux", len);

	return len;
}

int dvbapi_open_device(int index_demux, int type)
{
	int dmx_fd;
	int ca_offset=0;
	char device_path[256];

	if (type==0)
		sprintf(device_path, DMXDEV, index_demux);
	else
	{
		if (strcmp(cfg->dvbapi_boxtype, "ufs910")==0 || strcmp(cfg->dvbapi_boxtype, "dbox2")==0)
			ca_offset=1;

		sprintf(device_path, CADEV, index_demux+ca_offset);
	}

	if ((dmx_fd = open(device_path, O_RDWR)) < 0)
		cs_log("error opening device %s", device_path);

	cs_debug("dvbapi: DEVICE open (%s)", device_path);
	return dmx_fd;
}

int dvbapi_set_filter(int demux_index, int type, int pid, unsigned char filt, unsigned char mask, int timeout)
{
	struct dmx_sct_filter_params sFP;
	int dmx_fd;

	cs_debug("dvbapi: set filter pid:%04x, value:%04x",pid, filt);

	memset(&sFP,0,sizeof(sFP));

	sFP.pid 			= pid;
	sFP.timeout			= timeout;
	sFP.flags			= DMX_IMMEDIATE_START;
	sFP.filter.filter[0]		= filt;
	sFP.filter.mask[0]		= mask;

	if (type==0)
		dmx_fd=demux[demux_index].demux_ecm_fd;
	else
		dmx_fd=demux[demux_index].demux_emm_fd;

	if (ioctl(dmx_fd, DMX_SET_FILTER, &sFP) < 0)
	{
		cs_log("dvbapi: could not start demux filter");
		return 0;
	}

	ioctl(dmx_fd, DMX_START);

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

unsigned short dvbapi_get_provid(int demux_index, int pid)
{
	unsigned char buf[BUFSIZE];
	int dmx_fd, len;

	dmx_fd=dvbapi_set_filter(demux_index, 1, pid, 0x80, 0xF0, 8000);

	len=dvbapi_read_device(dmx_fd, buf, BUFSIZE, 1);

	if (len > 0) {
		short int provid = (buf[10] << 8) | buf[11];
		return provid;
	}

	return 0;
}

unsigned short dvbapi_get_single_ecm(int demux_index, int caid, int pid, unsigned short provid)
{
	unsigned char buf[BUFSIZE];
	int dmx_fd, len;

	dmx_fd=dvbapi_set_filter(demux_index, 0, pid, 0x80, 0xF0, 2000);

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
	}
	return 0;
}

void dvbapi_parse_cat(int demux_index)
{
	unsigned char buf[BUFSIZE];
	unsigned short i, j;
	int dmx_fd, len;
	//unsigned short ca_system_id=demux[demux_index].ca_system_id;

	dmx_fd=dvbapi_set_filter(demux_index, 0, 0x0001, 0x01, 0xFF, 2000);

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

	return;
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
	demux[demux_index].provider_id=0;

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

void dvbapi_start_descramble(int demux_index, int caid, int capid, unsigned short provider_id)
{
	int i;

	cs_log("dvbapi: Start descrambling CAID: %04x", caid);

	demux[demux_index].ca_pid=capid;
	demux[demux_index].ca_system_id=caid;
	demux[demux_index].provider_id=provider_id;


	int camfd=dvbapi_open_device(demux_index,1);
	if (camfd<=0) {
		dvbapi_stop_descramble(demux_index);
		return;
	}

	demux[demux_index].ca_fd=camfd;

	/*
	ca_pid_t ca_pid;
	memset(&ca_pid,0,sizeof(ca_pid));
	ca_pid.pid = capid;
	ca_pid.index = demux_index;
	if (ioctl(camfd, CA_SET_PID, &ca_pid)==-1)
		cs_debug("dvbapi: Error CAPID SET_PID");
	*/

	for (i=0;i<demux[demux_index].STREAMpidcount;i++)
	{

		ca_pid_t ca_pid2;
		memset(&ca_pid2,0,sizeof(ca_pid2));
		ca_pid2.pid = demux[demux_index].STREAMpids[i];
		ca_pid2.index = -1;
		if (ioctl(camfd, CA_SET_PID, &ca_pid2)==-1)
			cs_debug("dvbapi: Error Stream SET_PID");

		memset(&ca_pid2,0,sizeof(ca_pid2));
		ca_pid2.pid = demux[demux_index].STREAMpids[i];
		ca_pid2.index = demux_index;
		if (ioctl(camfd, CA_SET_PID, &ca_pid2)==-1)
			cs_debug("dvbapi: Error Stream SET_PID");
	}

}

// from tuxbox camd
int dvbapi_parse_capmt(unsigned char *buffer, unsigned int length)
{
	unsigned short i, j;
	int n, added, ca_mask=1, demux_index=0;

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

	cs_ddump(buffer, length, "capmt:");
	cs_log("dvbapi: new program number: %04x", program_number);
	//cs_debug("program_info_length: %d", program_info_length);

	demux[demux_index].program_number=((buffer[1] << 8) | buffer[2]);
	demux[demux_index].ECMpidcount=0;

	demux[demux_index].cadev_index=ca_mask;

	//CA_PIDS for all streams

	if (program_info_length != 0)
	{
		//int ca_pmt_cmd_id = buffer[6];
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
				demux[demux_index].ECMpids[demux[demux_index].ECMpidcount].EMM_PID=0;
				demux[demux_index].ECMpidcount++;
			}

			if (buffer[i + 7] == 0x82) {
				ca_mask = buffer[i + 9];
				demux_index = buffer[i + 10];
				demux[demux_index].cadev_index=ca_mask;
			}
		}
	}

	demux[demux_index].STREAMpidcount=0;

	//CA_PIDs for a single stream

	unsigned short es_info_length=0;
	for (i = program_info_length + 6; i < length; i += es_info_length + 5)
	{
		int stream_type = buffer[i];
		unsigned short elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug("stream_type: %02x\telementary_pid: %04x\tes_info_length: %04x", stream_type, elementary_pid, es_info_length);

		demux[demux_index].STREAMpids[demux[demux_index].STREAMpidcount]=elementary_pid;
		demux[demux_index].STREAMpidcount++;

		if (es_info_length != 0)
		{
			//int ca_pmt_cmd_id = buffer[i + 5];
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
						demux[demux_index].ECMpids[demux[demux_index].ECMpidcount].EMM_PID=0;
						demux[demux_index].ECMpidcount++;
					}
				}
			}
		}
	}

	dvbapi_stop_descramble(demux_index);

	int dmx1_fd,dmx2_fd;

	if (demux[demux_index].ECMpidcount>0) {
		dmx1_fd = dvbapi_open_device(demux_index,0); //ECM,CAT
		dmx2_fd = dvbapi_open_device(demux_index,0); //EMM

		demux[demux_index].demux_ecm_fd=dmx1_fd;
		demux[demux_index].demux_emm_fd=dmx2_fd;

		dvbapi_parse_cat(demux_index);
	}

	cs_log("dvbapi: Found %d ECMpids in PMT", demux[demux_index].ECMpidcount);
	cs_debug("dvbapi: Found %d STREAMpids in PMT", demux[demux_index].STREAMpidcount);

	for (n=0; n<demux[demux_index].ECMpidcount; n++) {

		if (demux[demux_index].ca_system_id!=0)
			continue;

		dvbapi_stop_filter(demux_index,0);
		dvbapi_stop_filter(demux_index,1);

		cs_debug("dvbapi: trying CA_System_ID: %04x CA_PID: %04x EEM_PID: %04x", demux[demux_index].ECMpids[n].CA_System_ID, demux[demux_index].ECMpids[n].CA_PID, demux[demux_index].ECMpids[n].EMM_PID);

		//grep emm provid

		unsigned short provid=0;
		if (cfg->dvbapi_au==1)
		{
			if (demux[demux_index].ECMpids[n].EMM_PID>0)
				provid=dvbapi_get_provid(demux_index, demux[demux_index].ECMpids[n].EMM_PID);
		}

		//cs_log("Provider ID: %04x", provid);

		//grep ecm
		dvbapi_get_single_ecm(demux_index, demux[demux_index].ECMpids[n].CA_System_ID,demux[demux_index].ECMpids[n].CA_PID, provid);


		sleep(3); //try next if no cw for .. secs
	}

	return 0;
}

void dvbapi_handlesockmsg (unsigned char *buffer, ssize_t len)
{
	int i;
	unsigned int val, size;

	//cs_dump(buffer, len, "handlesockmsg:");

	if (buffer[0] != 0x9F) {
		cs_log("dvbapi: unknown socket command: %02x", buffer[0]);
		return;
	}

	if (buffer[1] != 0x80) {
		cs_log("dvbapi: unknown apdu tag");
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
			cs_log("dvbapi: ca_pmt invalid length");
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
	strcpy(servaddr.sun_path, CAMDSOCKET);
	clilen = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

	if ((unlink(CAMDSOCKET) < 0) && (errno != ENOENT))
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
		//cs_debug("dvbapi: check zap");

		connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);

		if (connfd <= 0) { //socket not available
			cs_debug("dvbapi: socket not available");
			break;
		}

		len = read(connfd, buffer, sizeof(buffer));

		if (len < 3) {
			cs_debug("Client: camd.socket: too short message received");
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

demux_search dvbapi_find_dmx_by_fd(int fd)
{
	int i;
	demux_search s1;

	s1.type=0;
	s1.index=0;

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
			if (demux[i].ca_system_id==0) continue; // ignore inactive tuner

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

				if ((len=dvbapi_read_device(pfd2[i].fd, buffer, BUFSIZE, 0)) <= 0)
					break;

				if (s1.type==0) {					
					//ECM
					
					if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
						break;

					if (buffer[0] == 0x80 | buffer[0] == 0x81)
					{
						if (memcmp(buffer, demux[s1.index].buffer_cache_dmx, 12) != 0) {
							memcpy(demux[s1.index].buffer_cache_dmx, buffer, 12);
							//if (!dvbapi_parse_ecm(s1.index,buffer,len)) { cs_log("Error while parsing ECM"); }
							cs_debug("Read %d bytes\tTable-id: %02x\tCA section length: %d", len, buffer[0], len);

							if (len>0) {
								ECM_REQUEST *er;

								if (!(er=get_ecmtask()))
									break;

								er->srvid = demux[s1.index].program_number;
								er->caid  = demux[s1.index].ca_system_id;
								er->prid  = demux[s1.index].provider_id;

								er->l=len;
								memcpy(er->ecm, buffer, er->l);

								get_cw(er);
							}
						}
					}
				}
				if (s1.type==1) {					
					//EMM

					if (cfg->dvbapi_au!=1)
						break;

					cs_debug("EMM Type: 0x%02x", buffer[0]);

					cs_ddump(buffer, len, "emm:");
					
					//force emm output
					
					reader[ridx].logemm=9999;

					memset(&epg, 0, sizeof(epg));

					epg.caid[0] = (uchar)(demux[s1.index].ca_system_id>>8);
					epg.caid[1] = (uchar)(demux[s1.index].ca_system_id);
					//if (reader[client[cs_idx].au].caid[0]!=b2i(2,epg.caid)) cs_log("caid %04x", b2i(2,epg.caid));
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
		demux[i].received_emm=0;

		memset(demux[i].buffer_cache_dmx,0 ,12);
	}

	if (!dvbapi_init_listenfd())
	{
		cs_log("dvbapi: could not init camd.socket.");
		return 1;
	}

	pfd2[0].fd = fd_m2c;
	pfd2[0].events = (POLLIN | POLLPRI);

	pthread_create (&p1, NULL, thread_check_zap, NULL);
	pthread_create (&p2, NULL, thread_check_demux, NULL);

	struct timeb tp;
	cs_ftime(&tp);
	tp.time+=500;

	while (1) {
		if (master_pid!=getppid())
			cs_exit(0);

		rc=poll(pfd2, 1, 500);

		if (rc<0)
			break;

		if (pfd2[0].revents & (POLLIN | POLLPRI)) {
			chk_dcw(fd_m2c);
			chk_pending(tp);
		}

	}
	return 0;
}


void dvbapi_send_dcw(ECM_REQUEST *er)
{
	unsigned char cw_0[8], cw_1[8];

	cs_debug("dvbapi: ECM rc: %d", er->rc);

	memcpy(cw_0, er->cw, 8);
	memcpy(cw_1, er->cw+8, 8);

	//this is not working when both tuner on one channel

	int demux_index=dvbapi_get_index_by_prgnr(er->srvid);
	if (demux_index>=0) {
		if (er->rc<=3 && demux[demux_index].ca_system_id==0) {
			dvbapi_start_descramble(demux_index, er->caid, er->pid, er->prid);
		}
	} else {
		cs_log("dvbapi: error cant find demux index");
	}

	if (er->rc>3) {
		cs_debug("dvbapi: cw not found");
		return;
	}

	ca_descr_t ca_descr;
	memset(&ca_descr,0,sizeof(ca_descr));

	if (demux[demux_index].ca_fd<=0)
	{
		cs_log("dvbapi: could not write cw.");
		return;
	}

	if (memcmp(cw_0,demux[demux_index].lastcw0,8))
	{
		ca_descr.index = demux_index;
		ca_descr.parity = 0;
		memcpy(demux[demux_index].lastcw0,cw_0,8);
		memcpy(ca_descr.cw,cw_0,8);
		cs_debug("dvbapi: write cw1");
		if (ioctl(demux[demux_index].ca_fd, CA_SET_DESCR, &ca_descr) < 0) cs_debug("dvbapi: Error CA_SET_DESCR");
	}

	if (memcmp(cw_1,demux[demux_index].lastcw1,8))
	{
		ca_descr.index = demux_index;
		ca_descr.parity = 1;
		memcpy(demux[demux_index].lastcw1,cw_1,8);
		memcpy(ca_descr.cw,cw_1,8);
		cs_debug("dvbapi: write cw2");
		if (ioctl(demux[demux_index].ca_fd, CA_SET_DESCR, &ca_descr) < 0) cs_debug("dvbapi: Error CA_SET_DESCR");
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
	ph->multi=0;
	ph->watchdog=0;
	ph->s_handler=dvbapi_handler;
	ph->send_dcw=dvbapi_send_dcw;
}
#endif // HAVE_DVBAPI_3
