#define MODULE_LOG_PREFIX "gbox/sms"

#include "globals.h"

#ifdef MODULE_GBOX
#include "module-gbox.h"
#include "module-gbox-sms.h"
#include "oscam-string.h"
#include "oscam-files.h"
#include "oscam-string.h"
#include "oscam-client.h"
#include "oscam-time.h"

static uint32_t poll_gsms_data (uint16_t *boxid, uint8_t *num, char *text)
{
	char *fext= FILE_GSMS_TXT; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "r");
	if(!fhandle)
		{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return -1;
		}
	uint32_t length1;
	uint8_t length;
	char buffer[140];
	char *tail;
	memset(buffer, 0, sizeof(buffer));
	fseek (fhandle,0L,SEEK_END);
	length1 = ftell(fhandle);
	fseek (fhandle,0L,SEEK_SET);
	if (length1 < 13)
		{
		cs_log("min msg char in %s = 6, actual = %d",fname, length1-7);
		fclose(fhandle);
		unlink(fname);
		return -1;
		}
	if(fgets(buffer,140,fhandle) != NULL)
		{	
		*boxid = strtol (buffer, &tail, 16);
		*num = atoi (tail);
		}
	fclose(fhandle);
	unlink(fname);
	if (length1 > (127+7))
		{
		length = 127+7;
		}
	else
		{
		length = length1;
		}
	cs_log_dbg(D_READER, "total msg length taken from %s = %d, limitted to %d",fname, length1, length);
	strncpy(text, &(buffer[7]),length-7);
	return 0;
}
static void write_gsms_to_osd_file(struct s_client *cli, unsigned char *gsms)
{
#ifdef GBOX_ENABLE_UNSAFE_OSD
	char *fext= FILE_OSD_MSG; 
	char *fname = get_gbox_tmp_fname(fext); 
	if (file_exists(fname))
	{
	char gsms_buf[150];
	memset(gsms_buf, 0, sizeof(gsms_buf));
	snprintf(gsms_buf, sizeof(gsms_buf), "%s %s:%s %s", fname, username(cli), cli->reader->device, gsms);
	cs_log_dbg(D_READER, "found OSD 'driver' %s - write gsms to OSD", fname);
	char *cmd = gsms_buf;
              FILE *p;
              if ((p = popen(cmd, "w")) == NULL)
		{	
		cs_log("Error %s",fname);
		return;
		}
              pclose(p);
	}
#else
	cs_log("OSD: username=%s dev=%s msg=%s", username(cli), cli->reader->device, gsms);
	cs_log_dbg(D_READER, "OSD is disabled because it is a security risk, to enable it recompile OSCAM.");
#endif
	return;
}

void write_gsms_ack (struct s_client *cli, uint8_t gsms_prot)
{
	char tsbuf[28];
	time_t walltime = cs_time();
	cs_ctime_r(&walltime, tsbuf);
	struct gbox_peer *peer = cli->gbox;
	char *fext= FILE_GSMS_ACK; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "a+");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}
	fprintf(fhandle, "Peer %04X (%s) confirmed receipt of GSMS_%d on %s",peer->gbox.id, cli->reader->device, gsms_prot, tsbuf);
	fclose(fhandle);
	return;
}

static void write_gsms_nack (struct s_client *cl, uint8_t gsms_prot, uint8_t inf)
{
	char tsbuf[28];
	time_t walltime = cs_time();
	cs_ctime_r(&walltime, tsbuf);
	struct gbox_peer *peer = cl->gbox;
	char *fext= FILE_GSMS_NACK; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "a+");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}
	if(inf)
	{
	fprintf(fhandle, "INFO: GSMS_%d to all: Peer %04X (%s) was OFFLINE %s",gsms_prot,peer->gbox.id, cl->reader->device,tsbuf);
	}
	else
	{
	fprintf(fhandle, "WARNING: GSMS_%d private to Peer %04X (%s) failed - was OFFLINE %s",gsms_prot,peer->gbox.id, cl->reader->device,tsbuf);
	}
	fclose(fhandle);
	return;
}

void write_gsms_msg (struct s_client *cli, uchar *gsms, uint16_t type, uint16_t UNUSED(msglen))
{
	char tsbuf[28];
	time_t walltime = cs_time();
	cs_ctime_r(&walltime, tsbuf);
	struct gbox_peer *peer = cli->gbox;
	struct s_reader *rdr = cli->reader;
	char *fext= FILE_GSMS_MSG; 
	char *fname = get_gbox_tmp_fname(fext); 
	FILE *fhandle = fopen(fname, "a+");
	if(!fhandle)
	{
		cs_log("Couldn't open %s: %s", fname, strerror(errno));
		return;
	}
	if(type == 0x30)
		{
		fprintf(fhandle, "Normal message received from %04X %s on %s%s\n\n",peer->gbox.id, cli->reader->device, tsbuf, gsms);
		snprintf(rdr->last_gsms, sizeof(rdr->last_gsms), "%s %s", gsms, tsbuf); //added for easy handling of gsms by webif
		}
	else if(type == 0x31)
		{
		fprintf(fhandle, "OSD message received from %04X %s on %s%s\n\n",peer->gbox.id, cli->reader->device, tsbuf, gsms);
		write_gsms_to_osd_file(cli, gsms);
		snprintf(rdr->last_gsms, sizeof(rdr->last_gsms), "%s %s", gsms, tsbuf); //added for easy handling of gsms by webif
		}
	else 
		{fprintf(fhandle, "Corrupted message received from %04X %s on %s%s\n\n",peer->gbox.id, cli->reader->device, tsbuf, gsms);}
		fclose(fhandle);
	return;
}

void gsms_unavail(void)
{
	cs_log("INFO: GSMS feature disabled by conf");
}

static void gbox_send_gsms2peer(struct s_client *cl, char *gsms, uint8_t msg_type, uint8_t gsms_prot, int8_t gsms_len)
{
	uchar outbuf[150];
	struct gbox_peer *peer = cl->gbox;
	uint16_t local_gbox_id = gbox_get_local_gbox_id();
	uint32_t local_gbox_pw = gbox_get_local_gbox_password();
	struct s_reader *rdr = cl->reader;

			if (gsms_prot == 1)
			{
				gbox_message_header(outbuf, MSG_GSMS_1, 0, 0);
				outbuf[2] = gsms_len; // gsms len 
				outbuf[3] = msg_type;  //msg type
				memcpy(&outbuf[4], gsms,gsms_len);
				cs_log("<-[gbx] send GSMS_1 to %s:%d id: %04X", rdr->device, rdr->r_port, peer->gbox.id);
				gbox_send(cl, outbuf, gsms_len + 4);
			}
			if (gsms_prot == 2)
			{
				gbox_message_header(outbuf, MSG_GSMS_2, peer->gbox.password, local_gbox_pw);
				outbuf[10] = (peer->gbox.id >> 8) & 0xff;
				outbuf[11] = peer->gbox.id & 0xff;
				outbuf[12] = (local_gbox_id >> 8) & 0xff;
				outbuf[13] = local_gbox_id & 0xff;								
				outbuf[14] = msg_type; //msg type
				outbuf[15] = gsms_len; // gsms length
				memcpy(&outbuf[16], gsms,gsms_len);
				outbuf[16 + gsms_len] = 0; //last byte 0x00
				cs_log("<-[gbx] send GSMS_2 to %s:%d id: %04X", rdr->device, rdr->r_port, peer->gbox.id);
				gbox_send(cl, outbuf, gsms_len + 17);
			}
	return;
}

void gbox_init_send_gsms(void)
{
	uint16_t boxid = 0;
	uint8_t num = 0;
	uint8_t gsms_prot = 0;
	uint8_t msg_type = 0;
	char text[150];
	memset(text, 0, sizeof(text));
	char *fext= FILE_GSMS_TXT; 
	char *fname = get_gbox_tmp_fname(fext); 
	if(cfg.gsms_dis)
	{
	unlink(fname);
	gsms_unavail();
	return;
	}
	if (poll_gsms_data( &boxid, &num, text))
	{
	cs_log("ERROR polling file %s", fname);
	return;
	}
	int8_t gsms_len = strlen(text);
	cs_log_dbg(D_READER,"got from %s: box_ID = %04X  num = %d  gsms_length = %d  txt = %s",fname, boxid, num, gsms_len, text);

	switch(num)
	{
	case 0: {gsms_prot = 1; msg_type = 0x30; break;}
	case 1: {gsms_prot = 1; msg_type = 0x31; break;}
	case 2: {gsms_prot = 2;	msg_type = 0x30; break;}
	case 3: {gsms_prot = 2;	msg_type = 0x31; break;}
	default:{cs_log("ERROR unknown gsms protocol"); return;}
	}
	cs_log_dbg(D_READER,"init gsms_length=%d  msg_type=%02X msg_prot=%d",gsms_len, msg_type, gsms_prot);

	struct s_client *cl;
	for (cl = first_client; cl; cl = cl->next)
	{
		if(cl->gbox && cl->typ == 'p')
		{

			struct gbox_peer *peer = cl->gbox;
			if (peer->online && boxid == 0xFFFF) //send gsms to all peers online
			{
			gbox_send_gsms2peer(cl, text, msg_type, gsms_prot, gsms_len); 
			}
			if (!peer->online && boxid == 0xFFFF)
			{
			cs_log("Info: peer %04X is OFFLINE",peer->gbox.id); 
			write_gsms_nack( cl, gsms_prot, 1); 
			}
			if (peer->online && boxid == peer->gbox.id)
			{
			gbox_send_gsms2peer(cl, text, msg_type, gsms_prot, gsms_len); 
			}
			if (!peer->online && boxid == peer->gbox.id)
			{
			cs_log("WARNING: send GSMS failed - peer %04X is OFFLINE",peer->gbox.id);
			write_gsms_nack( cl, gsms_prot, 0);  
			}
		}
	}
	return;
}

void gbox_send_gsms_ack(struct s_client *cli, uint8_t gsms_prot)
{
	uchar outbuf[20];
	struct gbox_peer *peer = cli->gbox;
	uint16_t local_gbox_id = gbox_get_local_gbox_id();
	uint32_t local_gbox_pw = gbox_get_local_gbox_password();
	struct s_reader *rdr = cli->reader;
		if (peer->online && gsms_prot == 1)
		{
		gbox_message_header(outbuf, MSG_GSMS_ACK_1, 0x90989098, 0x90989098);
		gbox_send(cli, outbuf, 10);
		cs_log_dbg(D_READER,"<-[gbx] send GSMS_ACK_1 to %s:%d id: %04X",rdr->device, rdr->r_port, peer->gbox.id);
		}
		if (peer->online && gsms_prot == 2)
		{
		gbox_message_header(outbuf, MSG_GSMS_ACK_2, peer->gbox.password, local_gbox_pw);
		outbuf[10] = 0;
		outbuf[11] = 0;
		outbuf[12] = (local_gbox_id >> 8) & 0xff;
		outbuf[13] = local_gbox_id & 0xff;									
		outbuf[14] = 0x1;
		outbuf[15] = 0;
		cs_log_dbg(D_READER,"<-[gbx] send GSMS_ACK_2 to %s:%d id: %04X",rdr->device, rdr->r_port, peer->gbox.id);
		gbox_send(cli, outbuf, 16);
		}
}

static pthread_t sms_sender_thread;
static int32_t sms_sender_active = 0;
static pthread_cond_t sleep_cond;
static pthread_mutex_t sleep_cond_mutex;
static pthread_mutex_t sms_mutex = PTHREAD_MUTEX_INITIALIZER;

static void sms_sender(void)
{
 	char *fext= FILE_GSMS_TXT;
	char *fname = get_gbox_tmp_fname(fext);
			
	while(sms_sender_active)
	{
    	if (file_exists(fname))
        {
			gbox_init_send_gsms();
        } 		
		
		sleepms_on_cond(&sleep_cond_mutex, &sleep_cond, 1000);
	}
	pthread_exit(NULL);
}

void start_sms_sender(void)
{
	int32_t is_active;
	
	pthread_mutex_lock(&sms_mutex);
	is_active = sms_sender_active;
	if(!sms_sender_active)
	{
		sms_sender_active = 1;
	}
	pthread_mutex_unlock(&sms_mutex);
	
	if(is_active)
	{
		return;	
	}
	
	cs_pthread_cond_init(&sleep_cond_mutex, &sleep_cond);

	pthread_attr_t attr;
	pthread_attr_init(&attr);

	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	int32_t ret = pthread_create(&sms_sender_thread, &attr, (void *)&sms_sender, NULL);
	if(ret)
	{
		cs_log("ERROR: can't create sms_sender_thread thread (errno=%d %s)", ret, strerror(ret));
		pthread_attr_destroy(&attr);
		cs_exit(1);
	}
	pthread_attr_destroy(&attr);
}

void stop_sms_sender(void)
{
	pthread_mutex_lock(&sms_mutex);
	
	if(sms_sender_active)
	{
		sms_sender_active = 0;
		pthread_cond_signal(&sleep_cond);
		pthread_join(sms_sender_thread, NULL);
	}
	
	pthread_mutex_unlock(&sms_mutex);
}


#endif
