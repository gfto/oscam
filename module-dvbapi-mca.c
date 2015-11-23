#define MODULE_LOG_PREFIX "dvbmca"

/**
 * dvbapi-support for Matrix Cam Air
 *
 * The code is based partially on module-dvbapi-azbox.
 * the (closed source) oscam that comes with the MCA is
 * apparently based on svn-revision 5124-5242.
 * DEMUXMATRIX is essentially the old DEMUXTYPE which
 * has changed since then.
 *
 * We may be able to implement add/remove-filter
 * by adding/removing them from DEMUXMATRIX
 * and reexecute mca_write_flt
 * In some cases the MCA will send ECMs for multiple PIDS
 * So it is apparently able to handle multiple filters
 *
 * @author dirtyharry123
 */

#include "globals.h"

#if defined(HAVE_DVBAPI) && defined(WITH_MCA)

#include "extapi/openxcas/openxcas_message.h"

#include "module-dvbapi.h"
#include "module-dvbapi-mca.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"

int8_t dummy(void)
{
	return 0;
}
#define openxcas_start_filter_ex(...) dummy()
#define openxcas_stop_filter_ex(...) dummy()
#define openxcas_get_message mca_get_message
#define azbox_openxcas_ex_callback mca_ex_callback
#define openxcas_stop_filter(...) do { } while(0)
#define openxcas_remove_filter(...)  do { } while(0)
#define openxcas_destory_cipher_ex(...) do { } while(0)

// These variables are declared in module-dvbapi.c
extern void *dvbapi_client;
extern DEMUXTYPE demux[MAX_DEMUX];

// These are used in module-dvbapi.c
int32_t openxcas_provid;
uint16_t openxcas_sid, openxcas_caid, openxcas_ecm_pid;

static unsigned char openxcas_cw[16];
static int32_t openxcas_seq, openxcas_filter_idx, openxcas_stream_id, openxcas_cipher_idx, openxcas_busy = 0;
static uint16_t openxcas_video_pid, openxcas_audio_pid, openxcas_data_pid;
static uint8_t found[MAX_DEMUX];

static int fd_mdvbi = -1;
static int fd_mdesc = -1;
static int fd_mflt = -1;

#define MCA_DVBI "/tmp/mdvbi"
#define MCA_DESC "/tmp/mdesc"
#define MCA_FLT  "/tmp/mflt"

enum eOPENXCAS_FILTER_TYPE
{
	OPENXCAS_FILTER_UNKNOWN = 0,
	OPENXCAS_FILTER_ECM,
	OPENXCAS_FILTER_EMM,
};

#define ECM_PIDS_MATRIX 20
#define MAX_FILTER_MATRIX 10

struct s_ecmpids_matrix
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t ECM_PID;
	uint16_t EMM_PID;
	int32_t irdeto_maxindex;
	int32_t irdeto_curindex;
	int32_t irdeto_cycle;
	int32_t checked;
	int32_t status;
	unsigned char table;
	int32_t index;
	uint32_t streams;
};

typedef struct filter_s_matrix
{
	uint32_t fd; //FilterHandle
	int32_t pidindex;
	int32_t pid;
	uint16_t type;
	int32_t count;
} FILTERTYPE_MATRIX;

struct s_emmpids_matrix
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t PID;
	uint8_t type;
};

typedef struct demux_s_matrix
{
	int32_t demux_index;
	FILTERTYPE_MATRIX demux_fd[MAX_FILTER_MATRIX];
	int32_t ca_mask;
	int32_t adapter_index;
	int32_t socket_fd;
	int32_t ECMpidcount;
	struct s_ecmpids_matrix ECMpids[ECM_PIDS_MATRIX];
	int32_t EMMpidcount;
	struct s_emmpids_matrix EMMpids[ECM_PIDS_MATRIX];
	int32_t STREAMpidcount;
	uint16_t STREAMpids[ECM_PIDS_MATRIX];
	int32_t pidindex;
	int32_t curindex;
	int32_t tries;
	int32_t max_status;
	uint16_t program_number;
	unsigned char lastcw[2][8];
	int32_t emm_filter;
	uchar hexserial[8];
	struct s_reader *rdr;
	char pmt_file[30];
	int32_t pmt_time;
} DEMUXMATRIX;

static int mca_open(void)
{
	if((fd_mdvbi = open(MCA_DVBI, O_RDONLY)) < 0)
	{
		cs_log("can't open \"%s\" (err=%d %s)", MCA_DVBI, errno, strerror(errno));
		return -1;
	}
	if((fd_mdesc = open(MCA_DESC, O_WRONLY)) < 0)
	{
		cs_log("can't open \"%s\" (err=%d %s)", MCA_DESC, errno, strerror(errno));
		return -1;
	}
	if((fd_mflt = open(MCA_FLT, O_WRONLY)) < 0)
	{
		cs_log("can't open \"%s\" (err=%d %s)", MCA_FLT, errno, strerror(errno));
		return -1;
	}
	return 0;
}

static int mca_exit(void)
{
	if((fd_mdvbi = close(fd_mdvbi)) < 0)
	{
		cs_log("can't close \"%s\" (err=%d %s)", MCA_DVBI, errno, strerror(errno));
		return -1;
	}
	if((fd_mdvbi = close(fd_mdesc)) < 0)
	{
		cs_log("can't close \"%s\" (err=%d %s)", MCA_DESC, errno, strerror(errno));
		return -1;
	}
	if((fd_mdvbi = close(fd_mflt)) < 0)
	{
		cs_log("can't close \"%s\" (err=%d %s)", MCA_FLT, errno, strerror(errno));
		return -1;
	}
	return 0;
}

void mca_init(void)
{
	if(mca_open() < 0)
	{
		cs_log("could not init");
	}
}

void mca_close(void)
{
	if(mca_exit() < 0)
	{
		cs_log("could not close");
	}
}

static int mca_get_message(openxcas_msg_t *message, int timeout)
{
	int rval = -1;
	struct pollfd mdvbi_poll_fd;
	mdvbi_poll_fd.fd = fd_mdvbi;
	mdvbi_poll_fd.events = POLLIN | POLLPRI;
	rval = poll(&mdvbi_poll_fd, 1, timeout == 0 ? -1 : timeout);
	if((rval >= 1) && (mdvbi_poll_fd.revents & (POLLIN | POLLPRI)))
	{
		rval = read(fd_mdvbi, message, 568);
	}
	else { rval = -1; }
	return rval;
}

static int mca_write_flt(DEMUXMATRIX *demux_matrix, int timeout)
{
	int rval = -1;
	struct pollfd mflt_poll_fd;
	mflt_poll_fd.fd = fd_mflt;
	mflt_poll_fd.events = POLLOUT;
	rval = poll(&mflt_poll_fd, 1, timeout);
	if((rval >= 1) && (mflt_poll_fd.revents & POLLOUT))
	{
		rval = write(fd_mflt, demux_matrix, sizeof(DEMUXMATRIX));
	}
	else { rval = -1; }
	return rval;
}

static int mca_set_key(unsigned char *mca_cw)
{
	int rval = -1;
	struct pollfd mdesc_poll_fd;
	mdesc_poll_fd.fd = fd_mdesc;
	mdesc_poll_fd.events = POLLOUT;
	rval = poll(&mdesc_poll_fd, 1, 0);
	if((rval >= 1) && (mdesc_poll_fd.revents & POLLOUT))
	{
		rval = write(fd_mdesc, mca_cw, 16);
	}
	else { rval = -1; }
	return rval;
}

static int mca_capmt_remove_duplicates(uchar *capmt, int len)
{
	int i, newlen = len;
	uint16_t descriptor_length = 0;
	uint32_t program_info_length = ((capmt[4] & 0x0F) << 8) | capmt[5];
	for(i = 7; i < len; i += descriptor_length + 2)
	{
		descriptor_length = capmt[i + 1];
		if(capmt[i] != 0x09) { continue; }
		if(!memcmp(&(capmt[i]), &(capmt[i + descriptor_length + 2]), descriptor_length + 2))
		{
			memmove(&(capmt[i + descriptor_length + 2]), &(capmt[i + (2 * (descriptor_length + 2))]), newlen - (descriptor_length + 2));
			newlen -= descriptor_length + 2;
		}
	}
	program_info_length -= (len - newlen);
	capmt[4] = (uchar)((capmt[4] & 0xF0) | ((program_info_length & 0xF00) >> 8));
	capmt[5] = (uchar)(program_info_length & 0x0FF);
	return newlen;
}

static void mca_demux_convert(DEMUXTYPE *demux_orig, DEMUXMATRIX *demux_matrix)
{
	int i = 0;
	memset(demux_matrix, 0, sizeof(DEMUXMATRIX));
	demux_matrix->demux_index = (int32_t)demux_orig->demux_index;
	for(i = 0; i < MAX_FILTER_MATRIX; ++i)
	{
		demux_matrix->demux_fd[i].fd = (uint32_t) demux_orig->demux_fd[i].fd;
		demux_matrix->demux_fd[i].pidindex = (int32_t) demux_orig->demux_fd[i].pidindex;
		demux_matrix->demux_fd[i].pid = (int32_t) demux_orig->demux_fd[i].pid;
		demux_matrix->demux_fd[i].type = (uint16_t) demux_orig->demux_fd[i].type;
		demux_matrix->demux_fd[i].count = (int32_t) demux_orig->demux_fd[i].count;
	}
	demux_matrix->ca_mask = (int32_t)demux_orig->ca_mask;
	demux_matrix->adapter_index = (int32_t)demux_orig->adapter_index;
	demux_matrix->socket_fd = (int32_t)demux_orig->socket_fd;
	demux_matrix->ECMpidcount = (int32_t)demux_orig->ECMpidcount;
	for(i = 0; i < demux_matrix->ECMpidcount; ++i)
	{
		demux_matrix->ECMpids[i].CAID = (uint16_t)demux_orig->ECMpids[i].CAID;
		demux_matrix->ECMpids[i].PROVID = (uint32_t)demux_orig->ECMpids[i].PROVID;
		demux_matrix->ECMpids[i].ECM_PID = (uint16_t)demux_orig->ECMpids[i].ECM_PID;
		demux_matrix->ECMpids[i].EMM_PID = (uint16_t)demux_orig->ECMpids[i].EMM_PID;
		demux_matrix->ECMpids[i].irdeto_maxindex = (int32_t)demux_orig->ECMpids[i].irdeto_maxindex;
		demux_matrix->ECMpids[i].irdeto_curindex = (int32_t)demux_orig->ECMpids[i].irdeto_curindex;
		demux_matrix->ECMpids[i].irdeto_cycle = (int32_t)demux_orig->ECMpids[i].irdeto_cycle;
		demux_matrix->ECMpids[i].checked = (int32_t)demux_orig->ECMpids[i].checked;
		demux_matrix->ECMpids[i].status = (int32_t)demux_orig->ECMpids[i].status;
		demux_matrix->ECMpids[i].table = (unsigned char)demux_orig->ECMpids[i].table;
		demux_matrix->ECMpids[i].streams = (uint32_t)demux_orig->ECMpids[i].streams;
	}
	demux_matrix->STREAMpidcount = (int32_t)demux->STREAMpidcount;
	memcpy(&demux_matrix->STREAMpids, &demux_orig->STREAMpids, demux_matrix->STREAMpidcount * sizeof(uint16_t));
	demux_matrix->pidindex = (int32_t)demux_orig->pidindex;
	demux_matrix->curindex = (int32_t)demux_orig->curindex;
	demux_matrix->max_status = (int32_t)demux_orig->max_status;
	demux_matrix->program_number = (uint16_t)demux_orig->program_number;
	memcpy(&demux_matrix->lastcw, &demux_orig->lastcw, 2 * 8 * sizeof(unsigned char));
	demux_matrix->emm_filter = (int32_t)demux_orig->emm_filter;
	memcpy(&demux_matrix->hexserial, &demux_orig->hexserial, 8 * sizeof(uchar));
	demux_matrix->rdr = (struct s_reader *)demux_orig->rdr;
	memcpy(&demux_matrix->pmt_file, &demux_orig->pmt_file, 30);
	demux_matrix->pmt_time = (int32_t)demux_orig->pmt_time;
}

static void mca_ecm_callback(int32_t stream_id, uint32_t UNUSED(seq), int32_t cipher_index, uint32_t caid, unsigned char *ecm_data, int32_t l, uint16_t pid)
{
	cs_log_dbg(D_DVBAPI, "ecm callback received");

	openxcas_stream_id = stream_id;
	//openxcas_seq = seq;
	//openxcas_caid = caid;
	openxcas_ecm_pid = pid;
	openxcas_busy = 1;
	//char tmp[1024];

	//As soon as we have received a valid CW we lock onto that CAID, otherwise we will have freezers.
	if(openxcas_caid && caid && openxcas_caid != caid)
	{
		cs_log("ignoring caid: %04X, waiting for %04X", caid, openxcas_caid);
		openxcas_busy = 0;
		return;
	}

	if(l < 0 || l > MAX_ECM_SIZE)
		{ return; }

	ECM_REQUEST *er;
	if(!(er = get_ecmtask()))
		{ return; }

	er->srvid = openxcas_sid;
	er->caid  = openxcas_caid;
	er->pid   = openxcas_ecm_pid;
	er->prid  = openxcas_provid;

	er->ecmlen = l;
	memcpy(er->ecm, ecm_data, er->ecmlen);

	request_cw(dvbapi_client, er, 0, 0);

	openxcas_stop_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);
	openxcas_remove_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);

	openxcas_cipher_idx = cipher_index;

	struct timeb tp;
	cs_ftime(&tp);
	tp.time += 500;
}


static void mca_ex_callback(int32_t stream_id, uint32_t UNUSED(seq), int32_t idx, uint32_t pid, unsigned char *ecm_data, int32_t l)
{
	cs_log_dbg(D_DVBAPI, "ex callback received");

	openxcas_stream_id = stream_id;
	openxcas_ecm_pid = pid;
	openxcas_cipher_idx = idx; // is this really cipher_idx?

	if(l < 0 || l > MAX_ECM_SIZE)
		{ return; }
	
	ECM_REQUEST *er;
	if(!(er = get_ecmtask()))
		{ return; }

	er->srvid = openxcas_sid;
	er->caid  = openxcas_caid;
	er->pid   = openxcas_ecm_pid;
	er->prid  = openxcas_provid;

	er->ecmlen = l;
	memcpy(er->ecm, ecm_data, er->ecmlen);

	request_cw(dvbapi_client, er, 0, 0);

	if(openxcas_stop_filter_ex(stream_id, seq, openxcas_filter_idx) < 0)
		{ cs_log("unable to stop ex filter"); }
	else
		{ cs_log_dbg(D_DVBAPI, "ex filter stopped"); }



	unsigned char mask[12];
	unsigned char comp[12];
	memset(&mask, 0x00, sizeof(mask));
	memset(&comp, 0x00, sizeof(comp));

	mask[0] = 0xff;
	comp[0] = ecm_data[0] ^ 1;

	if((openxcas_filter_idx = openxcas_start_filter_ex(stream_id, seq, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ex_callback)) < 0)
		{ cs_log("unable to start ex filter"); }
	else
		{ cs_log_dbg(D_DVBAPI, "ex filter started, pid = %x", openxcas_ecm_pid); }
}

static void *mca_main_thread(void *cli)
{
	struct s_client *client = (struct s_client *) cli;
	client->thread = pthread_self();
	SAFE_SETSPECIFIC(getclient, cli);
	dvbapi_client = cli;

	struct s_auth *account;
	int32_t ok = 0;
	for(account = cfg.account; account; account = account->next)
	{
		if((ok = is_dvbapi_usr(account->usr)))
			{ break; }
	}
	cs_auth_client(client, ok ? account : (struct s_auth *)(-1), "dvbapi");

	dvbapi_read_priority();

	openxcas_msg_t msg;
	int32_t ret;
	while((ret = openxcas_get_message(&msg, 0)) >= 0)
	{
		cs_sleepms(10);

		if(ret)
		{
			openxcas_stream_id = msg.stream_id;
			openxcas_seq = msg.sequence;
			struct stOpenXCAS_Data data;

			switch(msg.cmd)
			{
			case OPENXCAS_SELECT_CHANNEL:
				cs_log_dbg(D_DVBAPI, "OPENXCAS_SELECT_CHANNEL");

				// parse channel info
				struct stOpenXCASChannel chan;
				memcpy(&chan, msg.buf, msg.buf_len);

				cs_log("channel change: sid = %x, vpid = %x. apid = %x", chan.service_id, chan.v_pid, chan.a_pid);

				openxcas_video_pid = chan.v_pid;
				openxcas_audio_pid = chan.a_pid;
				openxcas_data_pid = chan.d_pid;
				break;
			case OPENXCAS_START_PMT_ECM:
				//FIXME: Apparently this is what the original MCA-oscam does
				cs_log_dbg(D_DVBAPI, "OPENXCAS_STOP_PMT_ECM");
				memset(&demux, 0, sizeof(demux));
				memset(&found, 0, sizeof(found));

				cs_log_dbg(D_DVBAPI, "OPENXCAS_START_PMT_ECM");

				// parse pmt
				cs_log_dump_dbg(D_DVBAPI, msg.buf + 2, msg.buf_len - 2, "capmt:");
				// For some reason the mca sometimes sends duplicate ECMpids,
				// we remove them here so dvbapi will not try them twice.
				int new_len = mca_capmt_remove_duplicates(msg.buf + 2, msg.buf_len - 2);
				if(new_len < msg.buf_len - 2)
					{ cs_log_dump_dbg(D_DVBAPI, msg.buf + 2, new_len, "capmt (duplicates removed):"); }
				int demux_id = dvbapi_parse_capmt(msg.buf + 2, new_len, -1, NULL, 0, 0, 0);


				unsigned char mask[12];
				unsigned char comp[12];
				memset(&mask, 0x00, sizeof(mask));
				memset(&comp, 0x00, sizeof(comp));

				mask[0] = 0xfe;
				comp[0] = 0x80;

				if(demux_id < 0)
				{
					cs_log("could not parse pmt");
					break;
				}

				//if ((ret = openxcas_add_filter(msg.stream_id, OPENXCAS_FILTER_ECM, 0, 0xffff, openxcas_ecm_pid, mask, comp, (void *)mca_ecm_callback)) < 0)
				DEMUXMATRIX demux_matrix;
				mca_demux_convert(&demux[demux_id], &demux_matrix);
				if((ret = mca_write_flt(&demux_matrix, 0)) < 0)
					{ cs_log("unable to add ecm filter"); }
				else
				{
					cs_log_dbg(D_DVBAPI, "ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);
					cs_log_dbg(D_DVBAPI, "ecm filter started");
				}

				//if (!openxcas_create_cipher_ex(msg.stream_id, openxcas_seq, 0, openxcas_ecm_pid, openxcas_video_pid, 0xffff, openxcas_audio_pid, 0xffff, 0xffff, 0xffff))
				//  cs_log("failed to create cipher ex");
				//else
				cs_log_dbg(D_DVBAPI, "cipher created");
				break;
			case OPENXCAS_STOP_PMT_ECM:
				cs_log_dbg(D_DVBAPI, "OPENXCAS_STOP_PMT_ECM");
				openxcas_stop_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
				openxcas_remove_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
				openxcas_stop_filter_ex(msg.stream_id, msg.sequence, openxcas_filter_idx);
				openxcas_destory_cipher_ex(msg.stream_id, msg.sequence);
				memset(&demux, 0, sizeof(demux));
				memset(&found, 0, sizeof(found));
				break;
			case OPENXCAS_ECM_CALLBACK:
				cs_log_dbg(D_DVBAPI, "OPENXCAS_ECM_CALLBACK");
				memcpy(&data, msg.buf, msg.buf_len);
				if(!openxcas_busy)
					//openxcas_filter_callback(msg.stream_id, msg.sequence, OPENXCAS_FILTER_ECM, &data);
					{ mca_ecm_callback(msg.stream_id, msg.sequence, data.cipher_index, data.ca_system_id, (unsigned char *)&data.buf, data.len, data.pid); }
				break;
			case OPENXCAS_PID_FILTER_CALLBACK:
				cs_log_dbg(D_DVBAPI, "OPENXCAS_PID_FILTER_CALLBACK");
				memcpy(&data, msg.buf, msg.buf_len);
				//openxcas_filter_callback_ex(msg.stream_id, msg.sequence, (struct stOpenXCAS_Data *)msg.buf);
				mca_ex_callback(msg.stream_id, msg.sequence, data.cipher_index, data.pid, (unsigned char *)&data.buf, data.len);
				break;
			case OPENXCAS_QUIT:
				cs_log_dbg(D_DVBAPI, "OPENXCAS_QUIT");
				mca_exit();
				cs_log("exited");
				return NULL;
				break;
			case OPENXCAS_UKNOWN_MSG:
			default:
				cs_log_dbg(D_DVBAPI, "OPENXCAS_UKNOWN_MSG (%d)", msg.cmd);
				//cs_log_dump_dbg(D_DVBAPI, &msg, sizeof(msg), "msg dump:");
				break;
			}
		}
	}
	cs_log("invalid message");
	return NULL;
}

void mca_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
	struct s_dvbapi_priority *delayentry = dvbapi_check_prio_match(0, demux[0].pidindex, 'd');
	uint32_t delay = 0;

	cs_log_dbg(D_DVBAPI, "send_dcw");
		
	if(delayentry)
	{
		if(delayentry->delay < 1000)
		{
			delay = delayentry->delay;
			cs_log_dbg(D_DVBAPI, "specific delay: write cw %d ms after ecmrequest", delay);
		}
	}
	else if (cfg.dvbapi_delayer > 0)
	{
		delay = cfg.dvbapi_delayer;
		cs_log_dbg(D_DVBAPI, "generic delay: write cw %d ms after ecmrequest", delay);
	}
		
	delayer(er, delay);

	dvbapi_write_ecminfo_file(client, er, demux[0].lastcw[0], demux[0].lastcw[1]);

	openxcas_busy = 0;

	int32_t i;
	for(i = 0; i < MAX_DEMUX; i++)
	{

		if(er->rc >= E_NOTFOUND && !found[i])
		{
			cs_log_dbg(D_DVBAPI, "cw not found");

			if(demux[i].pidindex == -1)
				{ dvbapi_try_next_caid(i, 0); }

			openxcas_stop_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);
			openxcas_remove_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);

			unsigned char mask[12];
			unsigned char comp[12];
			memset(&mask, 0x00, sizeof(mask));
			memset(&comp, 0x00, sizeof(comp));

			mask[0] = 0xfe;
			comp[0] = 0x80;

			DEMUXMATRIX demux_matrix;
			mca_demux_convert(&demux[0], &demux_matrix);
			if(mca_write_flt(&demux_matrix, 0) < 0)
				{ cs_log("unable to add ecm filter (0)"); }
			else
			{
				cs_log_dbg(D_DVBAPI, "ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);
				cs_log_dbg(D_DVBAPI, "ecm filter started");
			}

			return;
		}
		else
		{
			found[i] = 1;
		}
	}

	unsigned char nullcw[8];
	memset(nullcw, 0, 8);

	int32_t n;
	for(n = 0; n < 2; n++)
	{
		if((memcmp(er->cw + (n * 8), demux[0].lastcw[0], 8) && memcmp(er->cw + (n * 8), demux[0].lastcw[1], 8)) && memcmp(er->cw + (n * 8), nullcw, 8))
		{
			memcpy(demux[0].lastcw[n], er->cw + (n * 8), 8);
			memcpy(openxcas_cw + (n * 8), er->cw + (n * 8), 8);
			if(mca_set_key(openxcas_cw) < 0)
				{ cs_log("set cw failed"); }
			else
				{ cs_log_dump_dbg(D_DVBAPI, openxcas_cw, 16, "write cws to descrambler"); }
		}
	}
}

void *mca_handler(struct s_client *cl, uchar *mbuf, int32_t module_idx)
{
	return dvbapi_start_handler(cl, mbuf, module_idx, mca_main_thread);
}

#endif
