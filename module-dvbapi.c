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

#define CADEV		"/dev/dvb/adapter0/ca1"
#define DMXDEV		"/dev/dvb/adapter0/demux0"
#define CAMDSOCKET	"/tmp/camd.socket"

#define BUFSIZE 1024
#define MAX_CAID 50

typedef struct ca_descriptor_s
{
	unsigned char descriptor_tag		: 8;
	unsigned char descriptor_length 	: 8;
	unsigned short ca_system_id		: 16;
	unsigned char reserved			: 3;
	unsigned short ca_pid			: 13;
	unsigned char * private_data_byte;
} __attribute__ ((packed)) ca_descriptor;

typedef struct ca_pmt_program_info_s
{
	unsigned char ca_pmt_cmd_id		: 8;
	ca_descriptor * descriptor;
} __attribute__ ((packed)) ca_pmt_program_info;

typedef struct ca_pmt_es_info_s
{
	unsigned char stream_type		: 8;
	unsigned char reserved			: 3;
	unsigned short elementary_pid		: 13;
	unsigned char reserved2 		: 4;
	unsigned short es_info_length		: 12;
	ca_pmt_program_info * program_info;
} __attribute__ ((packed)) ca_pmt_es_info;

typedef struct ca_pmt_s
{
	unsigned char ca_pmt_list_management	: 8;
	unsigned short program_number		: 16;
	unsigned char reserved1 		: 2;
	unsigned char version_number		: 5;
	unsigned char current_next_indicator	: 1;
	unsigned char reserved2 		: 4;
	unsigned short program_info_length	: 12;
	ca_pmt_program_info * program_info;
	ca_pmt_es_info * es_info;
} __attribute__ ((packed)) ca_pmt;

static int camfd = -1;
static int dmxfd_ecm = -1;
static int dmxfd_emm = -1;
static int listenfd = -1;

// if set descrabling
unsigned short global_capid=0;
unsigned short global_caid=0;
unsigned short global_emmpid=0;

unsigned short global_caid_list[MAX_CAID];

unsigned short prg_nr=0;

unsigned char buffer_cache_dmx[12];
unsigned char buffer_cache_capmt[12];

unsigned char lastcw0[8], lastcw1[8];

typedef struct ECMPIDS
{
	int CA_PID;
	int CA_System_ID;
} ECMPIDSTYPE;

ECMPIDSTYPE ECMpids[20];
int ECMpidcount=0;

unsigned short dvbapi_get_single_ecm(int caid, int pid, unsigned char filt, unsigned char mask)
{
	unsigned char buf[BUFSIZE];
	int dmx_fd, len;

	struct dmx_sct_filter_params sFP;

	memset(&sFP, 0, sizeof(sFP));

	memset(buf,0,BUFSIZE);



	sFP.pid 			= pid;
	sFP.timeout			= 1000;
	sFP.flags			= DMX_ONESHOT | DMX_CHECK_CRC | DMX_IMMEDIATE_START;
	sFP.filter.filter[0]	= filt;
	sFP.filter.mask[0]		= mask;

	if ((dmx_fd = open(DMXDEV, O_RDWR)) < 0)
		return 0;

	if (ioctl(dmx_fd, DMX_SET_FILTER, &sFP) < 0)
		return 0;

	len=read(dmx_fd, buf, BUFSIZE);

	close(dmx_fd);

	ECM_REQUEST *er;

	if (!(er=get_ecmtask()))
		return 0;

	er->srvid = prg_nr;
	er->caid  =  caid;
	er->pid=pid;
	//er->prid  = provid; //FIXME

	er->l=len;
	memcpy(er->ecm, buf, er->l);

	get_cw(er);

	return 0;
}

unsigned short dvbapi_parse_cat(unsigned short ca_system_id)
{
	unsigned char buf[BUFSIZE];
	unsigned short i, emmpid;
	int dmx_fd, len;

	struct dmx_sct_filter_params sFP;

	memset(&sFP, 0, sizeof(sFP));

	memset(buf,0,BUFSIZE);

	sFP.filter.filter[0] = 0x01;
	sFP.filter.mask[0] = 0xFF;
	sFP.flags = DMX_ONESHOT | DMX_CHECK_CRC | DMX_IMMEDIATE_START;
	sFP.pid = 0x0001;
	sFP.timeout = 3000; //3secs

	if ((dmx_fd = open(DMXDEV, O_RDWR)) < 0)
		return 0;

	if (ioctl(dmx_fd, DMX_SET_FILTER, &sFP) < 0)
		return 0;

	len=read(dmx_fd, buf, BUFSIZE);

	close(dmx_fd);

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

int dvbapi_stop_filter(void)
{
	//cs_log("Stopping filtering...");

	if (ioctl(dmxfd_ecm,DMX_STOP)<0)
		return 0;

	if (ioctl(dmxfd_emm,DMX_STOP)<0)
		return 0;

	return 1;
}

unsigned short dvbapi_parse_ecm(unsigned char *buf, int len)
{
	unsigned short provid;

	provid=(buf[3]<<8)|buf[4];
	cs_debug("Read %d bytes\tTable-id: %02x\tCA section length: %d\tProvider ID: %04x", len, buf[0], len ,provid);

	//calen=((buf[1]<<8)+buf[2])&0x0fff;

	/*
	provid=b2i(2, buf+3);

	i=(buf[4]==0xD2) ? buf[5] + 2 : 0;  // skip d2 nano
	if ((buf[5+i]==3) && ((buf[4+i]==0x90) || (buf[4+i]==0x40)))
		provid=(b2i(3, buf+6+i) & 0xFFFFF0);

	//cs_log("PROVIDER: %04x", provid);
	*/

	if (len>0) {
		ECM_REQUEST *er;

		if (!(er=get_ecmtask()))
			return 0;

		er->srvid = prg_nr;
		er->caid  =  global_caid;
		//er->prid  = provid; //FIXME

		er->l=len;
		memcpy(er->ecm, buf, er->l);

		get_cw(er);
	}

	return(provid);
}

int dvbapi_set_filter(int fd, int pid, unsigned char filt, unsigned char mask)
{
	struct dmx_sct_filter_params sFP;
	cs_debug("Set filter pid:%d, value:%d...",pid, filt);

	memset(&sFP,0,sizeof(sFP));

	sFP.pid 			= pid;
	sFP.timeout			= 3000; //wait max 3 seconds for ECM message, should be repeated every 500ms
	sFP.flags			= DMX_CHECK_CRC | DMX_IMMEDIATE_START;
	sFP.filter.filter[0]	= filt;
	sFP.filter.mask[0]		= mask;

	if (ioctl(fd, DMX_SET_FILTER, &sFP) < 0)
	{
		perror(" Status");
		return 0;
	}

	return 1;
}

void dvbapi_stop_descramble() 
{
	dvbapi_stop_filter();

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

	global_capid=0;
	global_caid=0;
	global_emmpid=0;
}

void dvbapi_start_descramble(int caid, int capid) {

	cs_log("Softcam: Start descrambling CAID: %04x", caid);

	if (!dvbapi_set_filter(dmxfd_ecm,capid,0x80,0xF0))	//filter on ECM pid and 0x80 or 0x81 (mask 0xF0)
		cs_log("Error ECM filtering");

	global_capid=capid;
	global_caid=caid;

	/*
	 * get emm pid and start filter
	 * TODO: prase_cat blocks thread */

	if (cfg->dvbapi_au==1) {
		short emmpid;
		emmpid=dvbapi_parse_cat(caid);

		cs_log("EMMPid: %04x", emmpid);
		dvbapi_set_filter(dmxfd_emm,emmpid,0x80,0xF0);
		global_emmpid=emmpid;
	}

	ca_pid_t ca_pid;
	memset(&ca_pid,0,sizeof(ca_pid));
	ca_pid.pid = capid;
	ca_pid.index = 0;
	if (ioctl(camfd, CA_SET_PID, &ca_pid)==-1)
		cs_log("Softcam: Error SET_PID");
}

// from tuxbox camd
int dvbapi_parse_capmt(unsigned char *buffer, const unsigned int length)

{
	unsigned short i, j;
	ca_pmt *pmt;
	int n;

	cs_dump(buffer, length, "capmt:");
	pmt = (ca_pmt *) malloc(sizeof(ca_pmt));

	pmt->ca_pmt_list_management = buffer[0];
	pmt->program_number = (buffer[1] << 8) | buffer[2];
	prg_nr=pmt->program_number;

	pmt->program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	cs_log("program number: %04x", pmt->program_number);
	cs_debug("program_info_length: %d", pmt->program_info_length);

	switch (pmt->ca_pmt_list_management)
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

	ECMpidcount=0;

	//CA_PIDS fr alle Streams
	if (pmt->program_info_length != 0)
	{
		pmt->program_info = (ca_pmt_program_info *) malloc(sizeof(ca_pmt_program_info));
		pmt->program_info->ca_pmt_cmd_id = buffer[6];
		//cs_debug("ca_pmt_id: %04x", pmt->program_info->ca_pmt_cmd_id);
		pmt->program_info->descriptor = (ca_descriptor *) malloc(sizeof(ca_descriptor));

		for (i = 0; i < pmt->program_info_length - 1; i += pmt->program_info->descriptor->descriptor_length + 2)
		{
			pmt->program_info->descriptor->descriptor_length = buffer[i + 8];
			pmt->program_info->descriptor->ca_system_id = (buffer[i + 9] << 8) | buffer[i + 10];
			pmt->program_info->descriptor->ca_pid = ((buffer[i + 11] & 0x1F) << 8)| buffer[i + 12];

			cs_debug("typ: %02x ca_system_id: %04x\t ca_pid: %04x\tca_descriptor_length %d", buffer[i + 7], pmt->program_info->descriptor->ca_system_id, pmt->program_info->descriptor->ca_pid,pmt->program_info->descriptor->descriptor_length);

			if (buffer[i + 7] == 0x09) {
				ECMpids[ECMpidcount].CA_PID=pmt->program_info->descriptor->ca_pid;			//add the PID
				ECMpids[ECMpidcount].CA_System_ID=pmt->program_info->descriptor->ca_system_id;	//add the system id
				ECMpidcount++;
			}
		}

		free(pmt->program_info->descriptor);
		free(pmt->program_info);
	}


	//CA_PIDs fr einzelne Streams
	//
	pmt->es_info = (ca_pmt_es_info *) malloc(sizeof(ca_pmt_es_info));

	for (i = pmt->program_info_length + 6; i < length; i += pmt->es_info->es_info_length + 5)
	{

		pmt->es_info->stream_type = buffer[i];
		pmt->es_info->elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		pmt->es_info->es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug("stream_type: %02x\telementary_pid: %04x\tes_info_length: %04x", pmt->es_info->stream_type, pmt->es_info->elementary_pid, pmt->es_info->es_info_length);

		if (pmt->es_info->es_info_length != 0)
		{
			pmt->es_info->program_info = (ca_pmt_program_info *) malloc(sizeof(ca_pmt_program_info));

			pmt->es_info->program_info->ca_pmt_cmd_id = buffer[i + 5];
			pmt->es_info->program_info->descriptor = (ca_descriptor *)malloc(sizeof(ca_descriptor));

			for (j = 0; j < pmt->es_info->es_info_length - 1; j += pmt->es_info->program_info->descriptor->descriptor_length + 2)
			{
				pmt->es_info->program_info->descriptor->descriptor_length = buffer[i + j + 7];
				pmt->es_info->program_info->descriptor->ca_system_id = (buffer[i + j + 8] << 8) | buffer[i + j + 9];
				pmt->es_info->program_info->descriptor->ca_pid = ((buffer[i + j + 10] & 0x1F) << 8) | buffer[i + j + 11];

				cs_debug("typ: %02x\tca_system_id: %04x\t ca_pid: %04x", buffer[i + j + 6], pmt->es_info->program_info->descriptor->ca_system_id, pmt->es_info->program_info->descriptor->ca_pid);

				if (buffer[i + j + 6] == 0x09) {
					ECMpids[ECMpidcount].CA_PID=pmt->program_info->descriptor->ca_pid;			//add the PID
					ECMpids[ECMpidcount].CA_System_ID=pmt->program_info->descriptor->ca_system_id;	//add the system id
					ECMpidcount++;
				}
			}

			free(pmt->es_info->program_info->descriptor);
			free(pmt->es_info->program_info);
		}
	}

	free(pmt->es_info);
	free(pmt);

	dvbapi_stop_descramble();

	cs_log("Softcam: Found %d ECMpids in PMT", ECMpidcount);

	for (n=0; n<ECMpidcount; n++) {

		cs_debug("CA_System_ID: %04x CA_PID: %04x", ECMpids[n].CA_System_ID, ECMpids[n].CA_PID);

		if (global_caid!=0) continue;

		dvbapi_get_single_ecm(ECMpids[n].CA_System_ID,ECMpids[n].CA_PID,0x80,0xF0);
		sleep(3);
	}

	return 0;
}

void dvbapi_handlesockmsg (unsigned char *buffer, ssize_t len)
{
	int i;
	unsigned int val;
	unsigned int size;
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
		cs_log("client: handlesockmsg() unknown command");
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
			if (memcmp(buffer, buffer_cache_capmt, 8) != 0) {
				memcpy(buffer_cache_capmt, buffer, 8);
				dvbapi_handlesockmsg(buffer, len);
			}
		}

		close(connfd);

	}
	return 0;
}

void *thread_check_dmx(void *arg) {

	struct pollfd pfd2[2];
	int rc,len,i;
	unsigned char buffer[BUFSIZE];

	pfd2[0].fd = dmxfd_ecm;
	pfd2[0].events = (POLLIN | POLLPRI);
	pfd2[1].fd = dmxfd_emm;
	pfd2[1].events = (POLLIN | POLLPRI);

	while(1)
	{

		rc=poll(pfd2, 2, -1);

		if (global_capid == 0) {
			dvbapi_stop_filter();
			break;
		}

		for (i = 0; i < 2; i++) {
			if (pfd2[i].revents & (POLLIN | POLLPRI)) {
				if (pfd2[i].fd == dmxfd_ecm) {
					if ((len = read(dmxfd_ecm, buffer, BUFSIZE)) <= 0)
						break;

					if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3) //invaild CAT length
						break;

					if (buffer[0] == 0x80 | buffer[0] == 0x81)
					{
						if (memcmp(buffer, buffer_cache_dmx, 12) != 0) {
							memcpy(buffer_cache_dmx, buffer, 12);
							if (!dvbapi_parse_ecm(buffer,len)) { cs_log("Error while parsing ECM"); }
						}
					}

				}

				if (pfd2[i].fd == dmxfd_emm) {
					if ((len = read(dmxfd_emm, buffer, BUFSIZE)) <= 0)
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

					epg.caid[0] = (uchar)(global_caid>>8);
					epg.caid[1] = (uchar)(global_caid);
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


	if (cfg->dvbapi_demux[0]==0)
		strncpy(cfg->dvbapi_demux, DMXDEV, sizeof(cfg->dvbapi_demux)-1);

	if (cfg->dvbapi_ca[0]==0)
		strncpy(cfg->dvbapi_ca, CADEV, sizeof(cfg->dvbapi_ca)-1);

	if (cfg->dvbapi_socket[0]==0)
		strncpy(cfg->dvbapi_socket, CAMDSOCKET, sizeof(cfg->dvbapi_socket)-1);

	if (cfg->dvbapi_usr[0]==0) {
		//
	}

	for (i=0;i<20;i++)		//clean ECMpids array
	{
		ECMpids[i].CA_PID		= 0;
		ECMpids[i].CA_System_ID = 0;
	}


	if ((dmxfd_ecm = open(cfg->dvbapi_demux, O_RDWR)) < 0) {
		cs_log("Could not open dmx device");
		return 1;
	}

	if ((dmxfd_emm = open(cfg->dvbapi_demux, O_RDWR)) < 0) {
		cs_log("Could not open dmx device");
		return 1;
	}

	if ((camfd = open(cfg->dvbapi_ca, O_RDWR)) < 0) {
		cs_log("Could not open ca device");
		return 1;
	}

	if (!dvbapi_init_listenfd()) return 1;

	pfd2[0].fd = fd_m2c;
	pfd2[0].events = (POLLIN | POLLPRI);

	memset(buffer_cache_capmt,0 ,12);
	memset(buffer_cache_dmx,0 ,12);

	pthread_create (&p1, NULL, thread_check_zap, NULL);
	pthread_create (&p2, NULL, thread_check_dmx, NULL);

	pfd=dmxfd_ecm;

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

static void dvbapi_send_dcw(ECM_REQUEST *er) {
	unsigned char cw_0[8], cw_1[8];

	memcpy(cw_0, er->cw, 8);
	memcpy(cw_1, er->cw+8, 8);

	ca_descr_t ca_descr;
	memset(&ca_descr,0,sizeof(ca_descr));


	if (er->rc==0 && global_caid==0)
	{
		dvbapi_start_descramble(er->caid, er->pid);
	}

	if (memcmp(cw_0,lastcw0,8))
	{
		ca_descr.index = 0;
		ca_descr.parity = 0;
		memcpy(lastcw0,cw_0,8);
		memcpy(ca_descr.cw,cw_0,8);
		if (ioctl(camfd,CA_SET_DESCR,&ca_descr) < 0) perror("CA_SET_DESCR");
	}

	if (memcmp(cw_1,lastcw1,8))
	{
		ca_descr.index = 0;
		ca_descr.parity = 1;
		memcpy(lastcw1,cw_1,8);
		memcpy(ca_descr.cw,cw_1,8);
		if (ioctl(camfd,CA_SET_DESCR,&ca_descr) < 0) perror("CA_SET_DESCR");
	}

}

static void dvbapi_handler(int idx) {
	static struct s_auth *account=0;

	if (cfg->dvbapi_enabled != 1) {
		cs_log("client disabled");
		return;
	}

	cs_log("client loaded fd=%d", idx);

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

	cs_log("Module client error");
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

void module_dvbapi(struct s_module *ph) {}

#endif // HAVE_DVBAPI_3
