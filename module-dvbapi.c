#define MODULE_LOG_PREFIX "dvbapi"

#include "globals.h"

#ifdef HAVE_DVBAPI

#include "module-dvbapi.h"
#include "module-cacheex.h"
#include "module-dvbapi-azbox.h"
#include "module-dvbapi-mca.h"
#include "module-dvbapi-coolapi.h"
#include "module-dvbapi-stapi.h"
#include "module-dvbapi-chancache.h"
#include "module-stat.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-ecm.h"
#include "oscam-emm.h"
#include "oscam-files.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"
#include "reader-irdeto.h"

#if defined (__CYGWIN__)
#define F_NOTIFY 0
#define F_SETSIG 0
#define DN_MODIFY 0
#define DN_CREATE 0
#define DN_DELETE 0
#define DN_MULTISHOT 0
#endif

static int is_samygo;

static int dvbapi_ioctl(int fd, uint32_t request, ...)
{ 
	int ret = 0;
	va_list args; 
	va_start(args, request);
	if (!is_samygo)
	{
		void *param = va_arg(args, void *);
		ret = ioctl(fd, request, param);
	} 
	else 
	{
		switch(request) 
		{
			case DMX_SET_FILTER:
			{
				struct dmxSctFilterParams *sFP = va_arg(args, struct dmxSctFilterParams *);
				// prepare packet
				unsigned char packet[sizeof(request) + sizeof(struct dmxSctFilterParams)];
				memcpy(&packet, &request, sizeof(request));
				memcpy(&packet[sizeof(request)], sFP, sizeof(struct dmxSctFilterParams));
				ret = send(fd, packet, sizeof(packet), 0);
				break;
			}
			case DMX_SET_FILTER1:
			{
				struct dmx_sct_filter_params *sFP = va_arg(args, struct dmx_sct_filter_params *);
				ret = send(fd, sFP, sizeof(struct dmx_sct_filter_params), 0);
				break;
			}
			case DMX_STOP:
			{
				ret = send(fd, &request, sizeof(request), 0);
				ret = 1;
				break;
			}
			case CA_SET_PID:
			{
				ret = 1;
				break;
			}
			case CA_SET_DESCR:
			{
				ret = 1;
				break;
			}
		}
		if (ret > 0) // send() may return larger than 1
			ret = 1;
	}
#if defined(__powerpc__)
	// Old dm500 boxes (ppc old) are using broken kernel, se we need some fixups
	switch (request)
	{
		case DMX_STOP:
		case CA_SET_DESCR:
		case CA_SET_PID:
		ret = 1;
	}
#endif
	// FIXME: Workaround for su980 bug
	// See: http://www.streamboard.tv/wbb2/thread.php?postid=533940
	if(boxtype_is("su980"))
		ret = 1;
	va_end(args);
	return ret;
}

// tunemm_caid_map
#define FROM_TO 0
#define TO_FROM 1

int32_t pausecam = 0, disable_pmt_files = 0, pmt_stopmarking = 0, pmthandling = 0;
DEMUXTYPE demux[MAX_DEMUX];
struct s_dvbapi_priority *dvbapi_priority;
struct s_client *dvbapi_client;

const char *boxdesc[] = { "none", "dreambox", "duckbox", "ufs910", "dbox2", "ipbox", "ipbox-pmt", "dm7000", "qboxhd", "coolstream", "neumo", "pc", "pc-nodmx" };

static const struct box_devices devices[BOX_COUNT] =
{
	/* QboxHD (dvb-api-3)*/     { "/tmp/virtual_adapter/",  "ca%d",         "demux%d",      "/tmp/camd.socket", DVBAPI_3    },
	/* dreambox (dvb-api-3)*/   { "/dev/dvb/adapter%d/",    "ca%d",         "demux%d",      "/tmp/camd.socket", DVBAPI_3    },
	/* dreambox (dvb-api-1)*/   { "/dev/dvb/card%d/",       "ca%d",         "demux%d",      "/tmp/camd.socket", DVBAPI_1    },
	/* neumo (dvb-api-1)*/      { "/dev/",                  "demuxapi",     "demuxapi",     "/tmp/camd.socket", DVBAPI_1    },
	/* sh4      (stapi)*/       { "/dev/stapi/",            "stpti4_ioctl", "stpti4_ioctl", "/tmp/camd.socket", STAPI       },
	/* coolstream*/             { "/dev/cnxt/",             "null",         "null",         "/tmp/camd.socket", COOLAPI     }
};

static int32_t selected_box = -1;
static int32_t selected_api = -1;
static int32_t maxfilter = MAX_FILTER;
static int32_t dir_fd = -1;
char *client_name = NULL;
static uint16_t client_proto_version = 0;

static int32_t ca_fd[MAX_DEMUX]; // holds fd handle of each ca device 0 = not in use
static LLIST * ll_activestreampids; // list of all enabled streampids on ca devices

static int32_t unassoc_fd[MAX_DEMUX];

bool is_dvbapi_usr(char *usr) {
	return streq(cfg.dvbapi_usr, usr);
}

struct s_emm_filter
{
	int32_t      demux_id;
	uchar        filter[32];
	uint16_t     caid;
	uint32_t     provid;
	uint16_t     pid;
	uint32_t     num;
	struct timeb time_started;
};

static LLIST *ll_emm_active_filter;
static LLIST *ll_emm_inactive_filter;
static LLIST *ll_emm_pending_filter;

int32_t add_emmfilter_to_list(int32_t demux_id, uchar *filter, uint16_t caid, uint32_t provid, uint16_t emmpid, int32_t num, bool enable)
{
	if(!ll_emm_active_filter)
		{ ll_emm_active_filter = ll_create("ll_emm_active_filter"); }

	if(!ll_emm_inactive_filter)
		{ ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter"); }

	if(!ll_emm_pending_filter)
		{ ll_emm_pending_filter = ll_create("ll_emm_pending_filter"); }

	struct s_emm_filter *filter_item;
	if(!cs_malloc(&filter_item, sizeof(struct s_emm_filter)))
		{ return 0; }

	filter_item->demux_id       = demux_id;
	memcpy(filter_item->filter, filter, 32);
	filter_item->caid           = caid;
	filter_item->provid         = provid;
	filter_item->pid            = emmpid;
	filter_item->num            = num;
	if (enable)
	{
		cs_ftime(&filter_item->time_started);
	}
	else
	{
		memset(&filter_item->time_started, 0, sizeof(filter_item->time_started));
	}
		
	if(num > 0)
	{
		ll_append(ll_emm_active_filter, filter_item);
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d added to active emmfilters (CAID %04X PROVID %06X EMMPID %04X)",
					  filter_item->demux_id, filter_item->num, filter_item->caid, filter_item->provid, filter_item->pid);
	}
	else if(num < 0)
	{
		ll_append(ll_emm_pending_filter, filter_item);
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter added to pending emmfilters (CAID %04X PROVID %06X EMMPID %04X)",
					  filter_item->demux_id, filter_item->caid, filter_item->provid, filter_item->pid);
	}
	else
	{
		ll_append(ll_emm_inactive_filter, filter_item);
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter added to inactive emmfilters (CAID %04X PROVID %06X EMMPID %04X)",
					  filter_item->demux_id, filter_item->caid, filter_item->provid, filter_item->pid);
	}
	return 1;
}

int32_t is_emmfilter_in_list_internal(LLIST *ll, uchar *filter, uint16_t emmpid, uint32_t provid, uint16_t caid)
{
	struct s_emm_filter *filter_item;
	LL_ITER itr;
	if(ll_count(ll) > 0)
	{
		itr = ll_iter_create(ll);
		while((filter_item = ll_iter_next(&itr)) != NULL)
		{
			if(!memcmp(filter_item->filter, filter, 32) && (filter_item->pid == emmpid) && (filter_item->provid == provid) && (filter_item->caid == caid))
			{ return 1; }
		}
	}
	return 0;
}

int32_t is_emmfilter_in_list(uchar *filter, uint16_t emmpid, uint32_t provid, uint16_t caid)
{
	if(!ll_emm_active_filter)
		{ ll_emm_active_filter = ll_create("ll_emm_active_filter"); }

	if(!ll_emm_inactive_filter)
		{ ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter"); }

	if(!ll_emm_pending_filter)
		{ ll_emm_pending_filter = ll_create("ll_emm_pending_filter"); }

	if(is_emmfilter_in_list_internal(ll_emm_active_filter, filter, emmpid, provid, caid))
		{ return 1; }
	if(is_emmfilter_in_list_internal(ll_emm_inactive_filter, filter, emmpid, provid, caid))
		{ return 1; }
	if(is_emmfilter_in_list_internal(ll_emm_pending_filter, filter, emmpid, provid, caid))
		{ return 1; }

	return 0;
}

struct s_emm_filter *get_emmfilter_by_filternum_internal(LLIST *ll, int32_t demux_id, uint32_t num)
{
	struct s_emm_filter *filter;
	LL_ITER itr;
	if(ll_count(ll) > 0)
	{
		itr = ll_iter_create(ll);
		while((filter = ll_iter_next(&itr)))
		{
			if(filter->demux_id == demux_id && filter->num == num)
				{ return filter; }
		}
	}
	return NULL;
}

struct s_emm_filter *get_emmfilter_by_filternum(int32_t demux_id, uint32_t num)
{
	if(!ll_emm_active_filter)
		{ ll_emm_active_filter = ll_create("ll_emm_active_filter"); }

	if(!ll_emm_inactive_filter)
		{ ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter"); }

	if(!ll_emm_pending_filter)
		{ ll_emm_pending_filter = ll_create("ll_emm_pending_filter"); }

	struct s_emm_filter *emm_filter = NULL;
	emm_filter = get_emmfilter_by_filternum_internal(ll_emm_active_filter, demux_id, num);
	if(emm_filter)
		{ return emm_filter; }
	emm_filter = get_emmfilter_by_filternum_internal(ll_emm_inactive_filter, demux_id, num);
	if(emm_filter)
		{ return emm_filter; }
	emm_filter = get_emmfilter_by_filternum_internal(ll_emm_pending_filter, demux_id, num);
	if(emm_filter)
		{ return emm_filter; }

	return NULL;
}

int8_t remove_emmfilter_from_list_internal(LLIST *ll, int32_t demux_id, uint16_t caid, uint32_t provid, uint16_t pid, uint32_t num)
{
	struct s_emm_filter *filter;
	LL_ITER itr;
	if(ll_count(ll) > 0)
	{
		itr = ll_iter_create(ll);
		while((filter = ll_iter_next(&itr)))
		{
			if(filter->demux_id == demux_id && filter->caid == caid && filter->provid == provid && filter->pid == pid && filter->num == num)
			{
				ll_iter_remove_data(&itr);
				return 1;
			}
		}
	}
	return 0;
}

void remove_emmfilter_from_list(int32_t demux_id, uint16_t caid, uint32_t provid, uint16_t pid, uint32_t num)
{
	if(ll_emm_active_filter && remove_emmfilter_from_list_internal(ll_emm_active_filter, demux_id, caid, provid, pid, num))
		{ return; }
	if(ll_emm_inactive_filter && remove_emmfilter_from_list_internal(ll_emm_inactive_filter, demux_id, caid, provid, pid, num))
		{ return; }
	if(ll_emm_pending_filter && remove_emmfilter_from_list_internal(ll_emm_pending_filter, demux_id, caid, provid, pid, num))
		{ return; }
}

int32_t dvbapi_net_send(uint32_t request, int32_t socket_fd, int32_t demux_index, uint32_t filter_number, unsigned char *data)
{
	unsigned char packet[262];                                          //maximum possible packet size
	int32_t size = 0;

	// not connected?
	if (socket_fd <= 0)
		return 0;

	// preparing packet - header
	// in old protocol client expect this first byte as adapter index, changed in the new protocol
	// to be always after request type (opcode)
	if (client_proto_version <= 0)
		packet[size++] = demux[demux_index].adapter_index;          //adapter index - 1 byte

	// type of request
	uint32_t req = request;
	if (client_proto_version >= 1)
		req = htonl(req);
	memcpy(&packet[size], &req, 4);                                     //request - 4 bytes
	size += 4;

	// preparing packet - adapter index for proto >= 1
	if ((request != DVBAPI_SERVER_INFO) && client_proto_version >= 1)
		packet[size++] = demux[demux_index].adapter_index;          //adapter index - 1 byte

	// struct with data
	switch (request)
	{
		case DVBAPI_SERVER_INFO:
		{
			int16_t proto_version = htons(DVBAPI_PROTOCOL_VERSION);           //our protocol version
			memcpy(&packet[size], &proto_version, 2);
			size += 2;

			unsigned char *info_len = &packet[size];   //info string length
			size += 1;

			*info_len = snprintf((char *) &packet[size], sizeof(packet) - size, "OSCam v%s, build r%s (%s)", CS_VERSION, CS_SVN_VERSION, CS_TARGET);
			size += *info_len;
			break;
		}
		case DVBAPI_CA_SET_PID:
		{
			int sct_capid_size = sizeof(ca_pid_t);

			if (client_proto_version >= 1)
			{
				ca_pid_t *capid = (ca_pid_t *) data;
				capid->pid = htonl(capid->pid);
				capid->index = htonl(capid->index);
			}
			memcpy(&packet[size], data, sct_capid_size);

			size += sct_capid_size;
			break;
		}
		case DVBAPI_CA_SET_DESCR:
		{
			int sct_cadescr_size = sizeof(ca_descr_t);

			if (client_proto_version >= 1)
			{
				ca_descr_t *cadesc = (ca_descr_t *) data;
				cadesc->index = htonl(cadesc->index);
				cadesc->parity = htonl(cadesc->parity);
			}
			memcpy(&packet[size], data, sct_cadescr_size);

			size += sct_cadescr_size;
			break;
		}
		case DVBAPI_DMX_SET_FILTER:
		case DVBAPI_DMX_STOP:
		{
			int32_t sct_filter_size = sizeof(struct dmx_sct_filter_params);
			packet[size++] = demux_index;                               //demux index - 1 byte
			packet[size++] = filter_number;                             //filter number - 1 byte

			if (data)       // filter data when starting
			{
				if (client_proto_version >= 1)
				{
					struct dmx_sct_filter_params *fp = (struct dmx_sct_filter_params *) data;

					// adding all dmx_sct_filter_params structure fields
					// one by one to avoid padding problems
					uint16_t pid = htons(fp->pid);
					memcpy(&packet[size], &pid, 2);
					size += 2;

					memcpy(&packet[size], fp->filter.filter, 16);
					size += 16;
					memcpy(&packet[size], fp->filter.mask, 16);
					size += 16;
					memcpy(&packet[size], fp->filter.mode, 16);
					size += 16;

					uint32_t timeout = htonl(fp->timeout);
					memcpy(&packet[size], &timeout, 4);
					size += 4;

					uint32_t flags = htonl(fp->flags);
					memcpy(&packet[size], &flags, 4);
					size += 4;
				}
				else
				{
					memcpy(&packet[size], data, sct_filter_size);       //dmx_sct_filter_params struct
					size += sct_filter_size;
				}
			}
			else            // pid when stopping
			{
				if (client_proto_version >= 1)
				{
					uint16_t pid = htons(demux[demux_index].demux_fd[filter_number].pid);
					memcpy(&packet[size], &pid, 2);
					size += 2;
				}
				else
				{
					uint16_t pid = demux[demux_index].demux_fd[filter_number].pid;
					packet[size++] = pid >> 8;
					packet[size++] = pid & 0xff;
				}
			}
			break;
		}
		default:  //unknown request
		{
			cs_log("ERROR: dvbapi_net_send: invalid request");
			return 0;
		}
	}

	// sending
	cs_log_dump_dbg(D_DVBAPI, packet, size, "Sending packet to dvbapi client (fd=%d):", socket_fd);
	send(socket_fd, &packet, size, MSG_DONTWAIT);

	// always returning success as the client could close socket
	return 0;
}

int32_t dvbapi_set_filter(int32_t demux_id, int32_t api, uint16_t pid, uint16_t caid, uint32_t provid, uchar *filt, uchar *mask, int32_t timeout, int32_t pidindex, int32_t type,
	int8_t add_to_emm_list)
{
	openxcas_set_caid(demux[demux_id].ECMpids[pidindex].CAID);
	openxcas_set_ecm_pid(pid);
	if (USE_OPENXCAS)
		return 1;

	int32_t ret = -1, n = -1, i;

	for(i = 0; i < maxfilter && demux[demux_id].demux_fd[i].fd > 0; i++) { ; }

	if(i >= maxfilter)
	{
		cs_log_dbg(D_DVBAPI, "no free filter");
		return -1;
	}
	n = i;

	demux[demux_id].demux_fd[n].pidindex = pidindex;
	demux[demux_id].demux_fd[n].pid      = pid;
	demux[demux_id].demux_fd[n].caid     = caid;
	demux[demux_id].demux_fd[n].provid   = provid;
	demux[demux_id].demux_fd[n].type     = type;

	switch(api)
	{
	case DVBAPI_3:
		if (cfg.dvbapi_listenport || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
			ret = demux[demux_id].demux_fd[n].fd = DUMMY_FD;
		else
			ret = demux[demux_id].demux_fd[n].fd = dvbapi_open_device(0, demux[demux_id].demux_index, demux[demux_id].adapter_index);
		if(ret < 0) { return ret; }  // return if device cant be opened!
		struct dmx_sct_filter_params sFP2;

		memset(&sFP2, 0, sizeof(sFP2));

		sFP2.pid            = pid;
		sFP2.timeout        = timeout;
		sFP2.flags          = DMX_IMMEDIATE_START;
		if(cfg.dvbapi_boxtype == BOXTYPE_NEUMO)
		{
			//DeepThought: on dgs/cubestation and neumo images, perhaps others
			//the following code is needed to descramble
			sFP2.filter.filter[0] = filt[0];
			sFP2.filter.mask[0] = mask[0];
			sFP2.filter.filter[1] = 0;
			sFP2.filter.mask[1] = 0;
			sFP2.filter.filter[2] = 0;
			sFP2.filter.mask[2] = 0;
			memcpy(sFP2.filter.filter + 3, filt + 1, 16 - 3);
			memcpy(sFP2.filter.mask + 3, mask + 1, 16 - 3);
			//DeepThought: in the drivers of the dgs/cubestation and neumo images,
			//dvbapi 1 and 3 are somehow mixed. In the kernel drivers, the DMX_SET_FILTER
			//ioctl expects to receive a dmx_sct_filter_params structure (DVBAPI 3) but
			//due to a bug its sets the "positive mask" wrongly (they should be all 0).
			//On the other hand, the DMX_SET_FILTER1 ioctl also uses the dmx_sct_filter_params
			//structure, which is incorrect (it should be  dmxSctFilterParams).
			//The only way to get it right is to call DMX_SET_FILTER1 with the argument
			//expected by DMX_SET_FILTER. Otherwise, the timeout parameter is not passed correctly.
			ret = dvbapi_ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER1, &sFP2);
		}
		else
		{
			memcpy(sFP2.filter.filter, filt, 16);
			memcpy(sFP2.filter.mask, mask, 16);
			if (cfg.dvbapi_listenport || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
				ret = dvbapi_net_send(DVBAPI_DMX_SET_FILTER, demux[demux_id].socket_fd, demux_id, n, (unsigned char *) &sFP2);
			else
				ret = dvbapi_ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER, &sFP2);
		}
		break;

	case DVBAPI_1:
		ret = demux[demux_id].demux_fd[n].fd = dvbapi_open_device(0, demux[demux_id].demux_index, demux[demux_id].adapter_index);
		if(ret < 0) { return ret; }  // return if device cant be opened!
		struct dmxSctFilterParams sFP1;

		memset(&sFP1, 0, sizeof(sFP1));

		sFP1.pid            = pid;
		sFP1.timeout        = timeout;
		sFP1.flags          = DMX_IMMEDIATE_START;
		memcpy(sFP1.filter.filter, filt, 16);
		memcpy(sFP1.filter.mask, mask, 16);
		ret = dvbapi_ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER1, &sFP1);

		break;
#ifdef WITH_STAPI
	case STAPI:
		ret = stapi_set_filter(demux_id, pid, filt, mask, n, demux[demux_id].pmt_file);
		if(ret != 0)
			{ demux[demux_id].demux_fd[n].fd = ret; }
		else
			{ ret = -1; } // error setting filter!
		break;
#endif
#ifdef WITH_COOLAPI
	case COOLAPI:
		demux[demux_id].demux_fd[n].fd = coolapi_open_device(demux[demux_id].demux_index, demux_id);
		if(demux[demux_id].demux_fd[n].fd > 0)
			{ ret = coolapi_set_filter(demux[demux_id].demux_fd[n].fd, n, pid, filt, mask, type); }
		break;
#endif
	default:
		break;
	}
	if(ret != -1)  // filter set successful
	{
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d started successfully (caid %04X provid %06X pid %04X)", demux_id, n + 1, caid, provid, pid);
		if(type == TYPE_EMM && add_to_emm_list){ 
			add_emmfilter_to_list(demux_id, filt, caid, provid, pid, n + 1, true);
		}
	}
	else
	{
		cs_log("ERROR: Could not start demux filter (api: %d errno=%d %s)", selected_api, errno, strerror(errno));
	}
	return ret;
}

static int32_t dvbapi_detect_api(void)
{
#ifdef WITH_COOLAPI
	selected_api = COOLAPI;
	selected_box = 5;
	disable_pmt_files = 1;
	cfg.dvbapi_listenport = 0;
	cs_log("Detected Coolstream API");
	return 1;
#else
	if (cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX || cfg.dvbapi_boxtype == BOXTYPE_PC ) {
		selected_api = DVBAPI_3;
		selected_box = 1;
		if (cfg.dvbapi_listenport)
		{
			cs_log("Using TCP listen socket, API forced to DVBAPIv3 (%d), userconfig boxtype: %d", selected_api, cfg.dvbapi_boxtype);
		}
		else
		{
			cs_log("Using %s listen socket, API forced to DVBAPIv3 (%d), userconfig boxtype: %d", devices[selected_box].cam_socket_path, selected_api, cfg.dvbapi_boxtype);
		}
		return 1;
	}
	else
	{
		cfg.dvbapi_listenport = 0;
	}
	
	int32_t i = 0, n = 0, devnum = -1, dmx_fd = 0, ret = 0, boxnum = sizeof(devices) / sizeof(struct box_devices);
	char device_path[128], device_path2[128];

	while (i < boxnum)
	{
		snprintf(device_path2, sizeof(device_path2), devices[i].demux_device, 0);
		snprintf(device_path, sizeof(device_path), devices[i].path, n);
		strncat(device_path, device_path2, sizeof(device_path) - strlen(device_path) - 1);
		// FIXME: *THIS SAMYGO CHECK IS UNTESTED*
		// FIXME: Detect samygo, checking if default DVBAPI_3 device paths are sockets
		if (i == 1) { // We need boxnum 1 only
			struct stat sb;
			if (stat(device_path, &sb) > 0 && S_ISSOCK(sb.st_mode)) {
				selected_box = 0;
				disable_pmt_files = 1;
				is_samygo = 1;
				devnum = i;
				break;
			}
		}
		if((dmx_fd = open(device_path, O_RDWR | O_NONBLOCK)) > 0)
		{
			devnum = i;
			ret = close(dmx_fd);
			break;
		}
		/* try at least 8 adapters */
		if ((strchr(devices[i].path, '%') != NULL) && (n < 8)) n++; else { n = 0; i++; }
	}

	if(devnum == -1) { return 0; }
	selected_box = devnum;
	if(selected_box > -1)
		{ selected_api = devices[selected_box].api; }
	
	if(ret < 0) { cs_log("ERROR: Could not close demuxer fd (errno=%d %s)", errno, strerror(errno)); } // log it here since some needed var are not inited before!
	if(is_samygo){ cs_log("SAMYGO detected."); } // log it here since some needed var are not inited before!
#ifdef WITH_STAPI
	if(devnum == 4 && stapi_open() == 0)
	{
		cs_log("ERROR: stapi: setting up stapi failed.");
		return 0;
	}
#endif
	if(cfg.dvbapi_boxtype == BOXTYPE_NEUMO)
	{
		selected_api = DVBAPI_3; //DeepThought
	}
	cs_log("Detected %s Api: %d, userconfig boxtype: %d", device_path, selected_api, cfg.dvbapi_boxtype);
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
	if(rc < 1)
	{
		cs_log("ERROR: Read on %d timed out (errno=%d %s)", dmx_fd, errno, strerror(errno));
		return -1;
	}

	len = read(dmx_fd, buf, length);
		
	if(len < 1)
	{ 
		if(errno == EOVERFLOW)
		{
			cs_log("fd %d no valid data present since receiver reported an internal bufferoverflow!", dmx_fd);
			return 0;
		}
		else
		{
			cs_log("ERROR: Read error on fd %d (errno=%d %s)", dmx_fd, errno, strerror(errno));
		}
	}
	else { cs_log_dump_dbg(D_TRACE, buf, len, "Readed:"); }
	return len;
}

int32_t dvbapi_open_device(int32_t type, int32_t num, int32_t adapter)
{
	int32_t dmx_fd, ret;
	int32_t ca_offset = 0;
	char device_path[128], device_path2[128];

	if(cfg.dvbapi_listenport || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
		return DUMMY_FD;
	
	if(type == 0)
	{
		snprintf(device_path2, sizeof(device_path2), devices[selected_box].demux_device, num);
		snprintf(device_path, sizeof(device_path), devices[selected_box].path, adapter);

		strncat(device_path, device_path2, sizeof(device_path) - strlen(device_path) - 1);
	}
	else
	{
		if(cfg.dvbapi_boxtype == BOXTYPE_DUCKBOX || cfg.dvbapi_boxtype == BOXTYPE_DBOX2 || cfg.dvbapi_boxtype == BOXTYPE_UFS910)
			{ ca_offset = 1; }

		if(cfg.dvbapi_boxtype == BOXTYPE_QBOXHD)
			{ num = 0; }

		if(cfg.dvbapi_boxtype == BOXTYPE_PC)
			{ num = 0; }

		snprintf(device_path2, sizeof(device_path2), devices[selected_box].ca_device, num + ca_offset);
		snprintf(device_path, sizeof(device_path), devices[selected_box].path, adapter);

		strncat(device_path, device_path2, sizeof(device_path) - strlen(device_path) - 1);
	}

	if (is_samygo) {
		struct sockaddr_un saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sun_family = AF_UNIX;
		strncpy(saddr.sun_path, device_path, sizeof(saddr.sun_path) - 1);
		dmx_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		ret = connect(dmx_fd, (struct sockaddr *)&saddr, sizeof(saddr));
		if (ret < 0)
			close(dmx_fd);
	} else {
		dmx_fd = ret = open(device_path, O_RDWR | O_NONBLOCK);
	}

	if(ret < 0)
	{
		cs_log("ERROR: Can't open device %s (errno=%d %s)", device_path, errno, strerror(errno));
		return -1;
	}

	cs_log_dbg(D_DVBAPI, "Open device %s (fd %d)", device_path, dmx_fd);

	return dmx_fd;
}

uint16_t tunemm_caid_map(uint8_t direct, uint16_t caid, uint16_t srvid)
{
	int32_t i;
	struct s_client *cl = cur_client();
	TUNTAB *ttab = &cl->ttab;

	if (!ttab->ttnum)
		return caid;

	if(direct)
	{
		for(i = 0; i < ttab->ttnum; i++)
		{
			if(caid == ttab->ttdata[i].bt_caidto
					&& (srvid == ttab->ttdata[i].bt_srvid || ttab->ttdata[i].bt_srvid == 0xFFFF || !ttab->ttdata[i].bt_srvid))
				{ return ttab->ttdata[i].bt_caidfrom; }
		}
	}
	else
	{
		for(i = 0; i < ttab->ttnum; i++)
		{
			if(caid == ttab->ttdata[i].bt_caidfrom
					&& (srvid == ttab->ttdata[i].bt_srvid || ttab->ttdata[i].bt_srvid == 0xFFFF || !ttab->ttdata[i].bt_srvid))
				{ return ttab->ttdata[i].bt_caidto; }
		}
	}
	return caid;
}

int32_t dvbapi_stop_filter(int32_t demux_index, int32_t type)
{
	int32_t g, ret = -1;

	for(g = 0; g < MAX_FILTER; g++) // just stop them all, we dont want to risk leaving any stale filters running due to lowering of maxfilters
	{
		if(demux[demux_index].demux_fd[g].type == type)
		{
			ret = dvbapi_stop_filternum(demux_index, g);
		}
	}
	if(ret == -1) { return 0; }  // on error return 0
	else { return 1; }
}

int32_t dvbapi_stop_filternum(int32_t demux_index, int32_t num)
{
	int32_t retfilter = -1, retfd = -1, fd = demux[demux_index].demux_fd[num].fd;
	if(fd > 0)
	{
		cs_log_dbg(D_DVBAPI, "Demuxer %d stop Filter %d (fd: %d api: %d, caid: %04X, provid: %06X, %spid: %04X)",
					  demux_index, num + 1, fd, selected_api, demux[demux_index].demux_fd[num].caid, demux[demux_index].demux_fd[num].provid,
					  (demux[demux_index].demux_fd[num].type == TYPE_ECM ? "ecm" : "emm"), demux[demux_index].demux_fd[num].pid);

		switch(selected_api)
		{
		case DVBAPI_3:
			if (cfg.dvbapi_listenport || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
				retfilter = dvbapi_net_send(DVBAPI_DMX_STOP, demux[demux_index].socket_fd, demux_index, num, NULL);
			else
				retfilter = dvbapi_ioctl(fd, DMX_STOP, NULL);
			break;

		case DVBAPI_1:
			retfilter = dvbapi_ioctl(fd, DMX_STOP, NULL);
			break;

#ifdef WITH_STAPI
		case STAPI:
			retfilter = stapi_remove_filter(demux_index, num, demux[demux_index].pmt_file);
			if(retfilter != 1)   // stapi returns 0 for error, 1 for all ok
			{
				retfilter = -1;
			}
			break;
#endif
#ifdef WITH_COOLAPI
		case COOLAPI:
			retfilter = coolapi_remove_filter(fd, num);
			retfd = coolapi_close_device(fd);
			break;
#endif
		default:
			break;
		}
		if(retfilter < 0)
		{
			cs_log("ERROR: Demuxer %d could not stop Filter %d (fd:%d api:%d errno=%d %s)", demux_index, num + 1, fd, selected_api, errno, strerror(errno));
		}
#ifndef WITH_COOLAPI // no fd close for coolapi and stapi, all others do close fd!
		if (!cfg.dvbapi_listenport && cfg.dvbapi_boxtype != BOXTYPE_PC_NODMX)
		{
			retfd = close(fd);
			if(errno == 9) { retfd = 0; }  // no error on bad file descriptor
			if(selected_api == STAPI) { retfd = 0; }  // stapi closes its own filter fd!
		}
		else
			retfd = 0;
#endif
		if(retfd)
		{
			cs_log("ERROR: Demuxer %d could not close fd of Filter %d (fd=%d api:%d errno=%d %s)", demux_index, num + 1, fd,
				   selected_api, errno, strerror(errno));
		}

		if(demux[demux_index].demux_fd[num].type == TYPE_ECM)   //ecm filter stopped: reset index!
		{
			int32_t idx = demux[demux_index].ECMpids[demux[demux_index].demux_fd[num].pidindex].index;
			demux[demux_index].ECMpids[demux[demux_index].demux_fd[num].pidindex].index = 0;
			int32_t i;
			for(i = 0; i < demux[demux_index].STREAMpidcount && idx; i++){
				dvbapi_set_pid(demux_index, i, idx - 1, false); // disable all streampids for this index!
			}
		}

		if(demux[demux_index].demux_fd[num].type == TYPE_EMM)   // If emm type remove from emm filterlist
		{
			remove_emmfilter_from_list(demux_index, demux[demux_index].demux_fd[num].caid, demux[demux_index].demux_fd[num].provid, demux[demux_index].demux_fd[num].pid, num + 1);
		}
		demux[demux_index].demux_fd[num].fd = 0;
		demux[demux_index].demux_fd[num].type = 0;
	}
	if(retfilter < 0) { return retfilter; }  // error on remove filter
	if(retfd < 0) { return retfd; }  // error on close filter fd
	return 1; // all ok!
}

void dvbapi_start_filter(int32_t demux_id, int32_t pidindex, uint16_t pid, uint16_t caid, uint32_t provid, uchar table, uchar mask, int32_t timeout, int32_t type)
{
	uchar filter[32];
	memset(filter, 0, 32);

	filter[0] = table;
	filter[16] = mask;

	cs_log_dbg(D_DVBAPI, "Demuxer %d try to start new filter for caid: %04X, provid: %06X, pid: %04X", demux_id, caid, provid, pid);
	dvbapi_set_filter(demux_id, selected_api, pid, caid, provid, filter, filter + 16, timeout, pidindex, type, 0);
}

void dvbapi_start_emm_filter(int32_t demux_index)
{
	unsigned int j;
	if(!demux[demux_index].EMMpidcount)
		{ return; }

	//if (demux[demux_index].emm_filter)
	//  return;


	struct s_csystem_emm_filter *dmx_filter = NULL;
	unsigned int filter_count = 0;
	uint16_t caid, ncaid;
	uint32_t provid;

	struct s_reader *rdr = NULL;
	struct s_client *cl = cur_client();
	if(!cl || !cl->aureader_list)
		{ return; }

	LL_ITER itr = ll_iter_create(cl->aureader_list);
	while((rdr = ll_iter_next(&itr)))
	{
		if(rdr->audisabled || !rdr->enable || (!is_network_reader(rdr) && rdr->card_status != CARD_INSERTED))
			{ continue; }

		struct s_cardsystem *csystem;
		uint16_t c, match;
		cs_log_dbg(D_DVBAPI, "Demuxer %d matching reader %s against available emmpids -> START!", demux_index, rdr->label);
		for(c = 0; c < demux[demux_index].EMMpidcount; c++)
		{
			caid = ncaid = demux[demux_index].EMMpids[c].CAID;
			if(!caid) continue;

			if(chk_is_betatunnel_caid(caid) == 2)
			{
				ncaid = tunemm_caid_map(FROM_TO, caid, demux[demux_index].program_number);
			}
			provid = demux[demux_index].EMMpids[c].PROVID;
			if (caid == ncaid)
			{
				match = emm_reader_match(rdr, caid, provid);
			}
			else
			{
				match = emm_reader_match(rdr, ncaid, provid);
			}
			if(match)
			{
				csystem = get_cardsystem_by_caid(caid);
				if(csystem)
				{
					if(caid != ncaid)
					{
						csystem = get_cardsystem_by_caid(ncaid);
						if(csystem && csystem->get_tunemm_filter)
						{
							csystem->get_tunemm_filter(rdr, &dmx_filter, &filter_count);
							cs_log_dbg(D_DVBAPI, "Demuxer %d setting emm filter for betatunnel: %04X -> %04X", demux_index, ncaid, caid);
						}
						else
						{
							cs_log_dbg(D_DVBAPI, "Demuxer %d cardsystem for emm filter for caid %04X of reader %s not found", demux_index, ncaid, rdr->label);
							continue;
						}
					}
					else if (csystem->get_emm_filter)
					{
						csystem->get_emm_filter(rdr, &dmx_filter, &filter_count);
					}
				}
				else
				{
					cs_log_dbg(D_DVBAPI, "Demuxer %d cardsystem for emm filter for caid %04X of reader %s not found", demux_index, caid, rdr->label);
					continue;
				}

				for(j = 0; j < filter_count ; j++)
				{
					if(dmx_filter[j].enabled == 0)
					{ continue; }

					uchar filter[32];
					memset(filter, 0, sizeof(filter));  // reset filter
					uint32_t usefilterbytes = 16; // default use all filters
					memcpy(filter, dmx_filter[j].filter, usefilterbytes);
					memcpy(filter + 16, dmx_filter[j].mask, usefilterbytes);
					int32_t emmtype = dmx_filter[j].type;

					if(filter[0] && (((1 << (filter[0] % 0x80)) & rdr->b_nano) && !((1 << (filter[0] % 0x80)) & rdr->s_nano)))
					{ 
						cs_log_dbg(D_DVBAPI, "Demuxer %d reader %s emmfilter %d/%d blocked by userconfig -> SKIP!", demux_index, rdr->label, j+1, filter_count);
						continue; 
					}

					if((rdr->blockemm & emmtype) && !(((1 << (filter[0] % 0x80)) & rdr->s_nano) || (rdr->saveemm & emmtype)))
					{ 
						cs_log_dbg(D_DVBAPI, "Demuxer %d reader %s emmfilter %d/%d blocked by userconfig -> SKIP!", demux_index, rdr->label, j+1, filter_count);
						continue;
					}
				
					if(demux[demux_index].EMMpids[c].type & emmtype)
					{
						cs_log_dbg(D_DVBAPI, "Demuxer %d reader %s emmfilter %d/%d type match -> ENABLE!", demux_index, rdr->label, j+1, filter_count);
						check_add_emmpid(demux_index, filter, c, emmtype);
					}
					else
					{
						cs_log_dbg(D_DVBAPI, "Demuxer %d reader %s emmfilter %d/%d type mismatch -> SKIP!", demux_index, rdr->label, j+1, filter_count);
					}
				}
					
				// dmx_filter not use below this point;
				NULLFREE(dmx_filter);
			}
		}
		cs_log_dbg(D_DVBAPI, "Demuxer %d matching reader %s against available emmpids -> DONE!", demux_index, rdr->label);
	}
	if(demux[demux_index].emm_filter == -1) // first run -1
	{
		demux[demux_index].emm_filter = 0;
	}
	cs_log_dbg(D_DVBAPI, "Demuxer %d handles %i emm filters", demux_index, demux[demux_index].emm_filter);
}

void dvbapi_add_ecmpid_int(int32_t demux_id, uint16_t caid, uint16_t ecmpid, uint32_t provid) 
{
	int32_t n, added = 0;

	if(ecmpid==0) {
		//DeepThought: attach zero pids to tunneled pid
		//(Hack for nagra/seca tunneling on canaal digitaal and tv vlaanderen)
		int i;
		for(i=0;i<demux[demux_id].ECMpidcount;i++) 
			if((demux[demux_id].ECMpids[i].PROVID&0xff)==provid) {
				ecmpid=demux[demux_id].ECMpids[i].ECM_PID;
				if(ecmpid) {
					cs_log("Demuxer %d, DT: mapped 0 to 0x%x\n",demux_id, ecmpid);
					break;
				}
			}
	}
	
	if(demux[demux_id].ECMpidcount >= ECM_PIDS)
		{ return; }

	int32_t stream = demux[demux_id].STREAMpidcount - 1;
	for(n = 0; n < demux[demux_id].ECMpidcount; n++)
	{
		if(stream > -1 && demux[demux_id].ECMpids[n].CAID == caid && demux[demux_id].ECMpids[n].ECM_PID == ecmpid && demux[demux_id].ECMpids[n].PROVID == provid)
		{
			if(!demux[demux_id].ECMpids[n].streams)
			{
				//we already got this caid/ecmpid as global, no need to add the single stream
				cs_log("Demuxer %d skipped stream CAID: %04X ECM_PID: %04X PROVID: %06X (Same as ECMPID %d)", demux_id, caid, ecmpid, provid, n);
				continue;
			}
			added = 1;
			demux[demux_id].ECMpids[n].streams |= (1 << stream);
			cs_log("Demuxer %d added stream to ecmpid %d CAID: %04X ECM_PID: %04X PROVID: %06X", demux_id, n, caid, ecmpid, provid);
		}
	}

	if(added == 1)
		{ return; }
	for(n = 0; n < demux[demux_id].ECMpidcount; n++)  // check for existing pid
	{
		if(demux[demux_id].ECMpids[n].CAID == caid && demux[demux_id].ECMpids[n].ECM_PID == ecmpid && demux[demux_id].ECMpids[n].PROVID == provid)
			{ return; } // found same pid -> skip
	}
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].ECM_PID = ecmpid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CAID = caid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].PROVID = provid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CHID = 0x10000; // reset CHID
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].checked = 0;
	//demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].index = 0;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].status = 0;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].tries = 0xFE;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].streams = 0; // reset streams!
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_curindex = 0xFE; // reset
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_curindex = 0xFE; // reset
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_maxindex = 0; // reset
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_cycle = 0xFE; // reset
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].table = 0;

	if(stream > -1)
		{ demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].streams |= (1 << stream); }

	cs_log("Demuxer %d added new ecmpid %d CAID: %04X ECM_PID: %04X PROVID: %06X", demux_id, demux[demux_id].ECMpidcount, caid, ecmpid, provid);
	if(caid >> 8 == 0x06) { demux[demux_id].emmstart.time = 1; }  // marker to fetch emms early irdeto needs them!

	demux[demux_id].ECMpidcount++;
}

void dvbapi_add_ecmpid(int32_t demux_id, uint16_t caid, uint16_t ecmpid, uint32_t provid)
{;
	dvbapi_add_ecmpid_int(demux_id, caid, ecmpid, provid);
	struct s_dvbapi_priority *joinentry;

	for(joinentry = dvbapi_priority; joinentry != NULL; joinentry = joinentry->next)
	{
		if((joinentry->type != 'j')
				|| (joinentry->caid && joinentry->caid != caid)
				|| (joinentry->provid && joinentry->provid != provid)
				|| (joinentry->ecmpid && joinentry->ecmpid  != ecmpid)
				|| (joinentry->srvid && joinentry->srvid != demux[demux_id].program_number))
			{ continue; }
		cs_log_dbg(D_DVBAPI, "Join ecmpid %04X:%06X:%04X to %04X:%06X:%04X",
					  caid, provid, ecmpid, joinentry->mapcaid, joinentry->mapprovid, joinentry->mapecmpid);
		dvbapi_add_ecmpid_int(demux_id, joinentry->mapcaid, joinentry->mapecmpid, joinentry->mapprovid);
	}
}

void dvbapi_add_emmpid(int32_t demux_id, uint16_t caid, uint16_t emmpid, uint32_t provid, uint8_t type)
{
	char typetext[40];
	cs_strncpy(typetext, ":", sizeof(typetext));

	if(type & 0x01) { strcat(typetext, "UNIQUE:"); }
	if(type & 0x02) { strcat(typetext, "SHARED:"); }
	if(type & 0x04) { strcat(typetext, "GLOBAL:"); }
	if(type & 0xF8) { strcat(typetext, "UNKNOWN:"); }

	uint16_t i;
	for(i = 0; i < demux[demux_id].EMMpidcount; i++)
	{
		if(demux[demux_id].EMMpids[i].PID == emmpid && demux[demux_id].EMMpids[i].CAID == caid && demux[demux_id].EMMpids[i].PROVID == provid)
		{
			if(!(demux[demux_id].EMMpids[i].type&type)){
				demux[demux_id].EMMpids[i].type |= type; // register this emm kind to this emmpid
				cs_log_dbg(D_DVBAPI, "Added to existing emmpid %d additional emmtype %s", demux[demux_id].EMMpidcount - 1, typetext);
			}
			return;
		}
	}
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PID = emmpid;
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].CAID = caid;
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PROVID = provid;
	demux[demux_id].EMMpids[demux[demux_id].EMMpidcount++].type = type;
	cs_log_dbg(D_DVBAPI, "Added new emmpid %d CAID: %04X EMM_PID: %04X PROVID: %06X TYPE %s", demux[demux_id].EMMpidcount - 1, caid, emmpid, provid, typetext);
}

void dvbapi_parse_cat(int32_t demux_id, uchar *buf, int32_t len)
{
#ifdef WITH_COOLAPI
	// driver sometimes reports error if too many emm filter
	// but adding more ecm filter is no problem
	// ... so ifdef here instead of limiting MAX_FILTER
	demux[demux_id].max_emm_filter = 14;
#else
	if(cfg.dvbapi_requestmode == 1)
	{
		uint16_t ecm_filter_needed = 0, n;
		for(n = 0; n < demux[demux_id].ECMpidcount; n++)
		{
			if(demux[demux_id].ECMpids[n].status > -1)
				{ ecm_filter_needed++; }
		}
		if(maxfilter - ecm_filter_needed <= 0)
			{ demux[demux_id].max_emm_filter = 0; }
		else
			{ demux[demux_id].max_emm_filter = maxfilter - ecm_filter_needed; }
	}
	else
	{
		demux[demux_id].max_emm_filter = maxfilter - 1;
	}
#endif
	uint16_t i, k;

	cs_log_dump_dbg(D_DVBAPI, buf, len, "cat:");

	for(i = 8; i < (b2i(2, buf + 1)&0xFFF) - 1; i += buf[i + 1] + 2)
	{
		if(buf[i] != 0x09) { continue; }
		if(demux[demux_id].EMMpidcount >= ECM_PIDS) { break; }

		uint16_t caid = b2i(2, buf + i + 2);
		uint16_t emm_pid = b2i(2, buf + i +4)&0x1FFF;
		uint32_t emm_provider = 0;

		switch(caid >> 8)
		{
			case 0x01:
				dvbapi_add_emmpid(demux_id, caid, emm_pid, 0, EMM_UNIQUE | EMM_GLOBAL);
				for(k = i + 7; k < i + buf[i + 1] + 2; k += 4)
				{
					emm_provider = b2i(2, buf + k + 2);
					emm_pid = b2i(2, buf + k)&0xFFF;
					dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider, EMM_SHARED);
				}
				break;
			case 0x05:
				for(k = i + 6; k < i + buf[i + 1] + 2; k += buf[k + 1] + 2)
				{
					if (buf[k] == 0x14)
					{
						emm_provider = b2i(3, buf + k + 2);
						dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE | EMM_SHARED | EMM_GLOBAL);
					}
				}
				break;
			case 0x18:
				if(buf[i + 1] == 0x07 || buf[i + 1] == 0x0B)
				{
					for(k = i + 7; k < i + 7 + buf[i + 6]; k += 2)
					{
						emm_provider = b2i(2, buf + k);
						dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE | EMM_SHARED | EMM_GLOBAL);
					}
				}
				else
				{
					dvbapi_add_emmpid(demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE | EMM_SHARED | EMM_GLOBAL);
				}
				break;
			default:
				dvbapi_add_emmpid(demux_id, caid, emm_pid, 0, EMM_UNIQUE | EMM_SHARED | EMM_GLOBAL);
				break;
		}
	}
	return;
}

static pthread_mutex_t lockindex;
int32_t dvbapi_get_descindex(int32_t demux_index)
{
	int32_t i, j, idx = 1, fail = 1;
	if(cfg.dvbapi_boxtype == BOXTYPE_NEUMO)
	{
		idx = 0;
		sscanf(demux[demux_index].pmt_file, "pmt%3d.tmp", &idx);
		idx++; // fixup
		return idx;
	}
	pthread_mutex_lock(&lockindex); // to avoid race when readers become responsive!
	while(fail)
	{
		fail = 0;
		for(i = 0; i < MAX_DEMUX; i++)
		{
			for(j = 0; j < demux[i].ECMpidcount; j++)
			{
				if(demux[i].ECMpids[j].index == idx)
				{
					idx++;
					fail = 1;
					break;
				}
			}
		}
	}
	pthread_mutex_unlock(&lockindex); // and release it!
	return idx;
}

void dvbapi_set_pid(int32_t demux_id, int32_t num, int32_t idx, bool enable)
{
	int32_t i, currentfd;
	//if (demux[demux_id].pidindex == -1) return;

	switch(selected_api)
	{
#ifdef WITH_STAPI
	case STAPI:
		if(!enable) idx = -1;
		stapi_set_pid(demux_id, num, idx, demux[demux_id].STREAMpids[num], demux[demux_id].pmt_file); // only used to disable pids!!!
		break;
#endif
#ifdef WITH_COOLAPI
	case COOLAPI:
		break;
#endif
	default:
		for(i = 0; i < MAX_DEMUX; i++)
		{
			if(demux[demux_id].ca_mask & (1 << i))
			{	
				int8_t action = 0;
				if(enable){
					action = update_streampid_list(i, demux[demux_id].STREAMpids[num], idx);
				}
				if(!enable){
					action = remove_streampid_from_list(i, demux[demux_id].STREAMpids[num], idx);
				}
				if(action != NO_STREAMPID_LISTED && action != FOUND_STREAMPID_INDEX)
				{
					ca_pid_t ca_pid2;
					memset(&ca_pid2, 0, sizeof(ca_pid2));
					ca_pid2.pid = demux[demux_id].STREAMpids[num];
					if(action == REMOVED_STREAMPID_LASTINDEX) idx = -1; // removed last index of streampid -> disable pid with -1
					ca_pid2.index = idx;

					cs_log_dbg(D_DVBAPI, "Demuxer %d %s stream %d pid=0x%04x index=%d on ca%d", demux_id,
						(enable ? "enable" : "disable"), num + 1, ca_pid2.pid, ca_pid2.index, i);

					if(cfg.dvbapi_boxtype == BOXTYPE_PC || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
						dvbapi_net_send(DVBAPI_CA_SET_PID, demux[demux_id].socket_fd, demux_id, -1 /*unused*/, (unsigned char *) &ca_pid2);
					else
					{
						currentfd = ca_fd[i];
						if(currentfd <= 0)
						{
							currentfd = dvbapi_open_device(1, i, demux[demux_id].adapter_index);
							ca_fd[i] = currentfd; // save fd of this ca
						}
						if(currentfd > 0)
						{
							if(dvbapi_ioctl(currentfd, CA_SET_PID, &ca_pid2) == -1)
								cs_log_dbg(D_TRACE | D_DVBAPI,"CA_SET_PID ioctl error (errno=%d %s)", errno, strerror(errno));
							int8_t result = is_ca_used(i);
							if(!enable && result == CA_IS_CLEAR){
								cs_log_dbg(D_DVBAPI, "Demuxer %d close now unused CA%d device", demux_id, i);
								int32_t ret = close(currentfd);
								if(ret < 0) { cs_log("ERROR: Could not close demuxer fd (errno=%d %s)", errno, strerror(errno)); }
								currentfd = ca_fd[i] = 0;
							}
						}
					}
				}
			}
		}
		break;
	}
	return;
}

void dvbapi_stop_descrambling(int32_t demux_id)
{
	int32_t i;
	if(demux[demux_id].program_number == 0) { return; }
	char channame[32];
	i = demux[demux_id].pidindex;
	if(i < 0) { i = 0; }
	int32_t idx = demux[demux_id].ECMpids[i].index;
	get_servicename(dvbapi_client, demux[demux_id].program_number, demux[demux_id].ECMpidcount > 0 ? demux[demux_id].ECMpids[i].CAID : 0, channame);
	cs_log_dbg(D_DVBAPI, "Demuxer %d stop descrambling program number %04X (%s)", demux_id, demux[demux_id].program_number, channame);
	dvbapi_stop_filter(demux_id, TYPE_EMM);
	if(demux[demux_id].ECMpidcount > 0)
	{
		dvbapi_stop_filter(demux_id, TYPE_ECM);
		demux[demux_id].pidindex = -1;
		demux[demux_id].curindex = -1;
		for(i = 0; i < demux[demux_id].STREAMpidcount; i++)
		{
			dvbapi_set_pid(demux_id, i, idx - 1, false); // disable all streampids for this index!
		}
	}

	memset(&demux[demux_id], 0 , sizeof(DEMUXTYPE));
	demux[demux_id].pidindex = -1;
	demux[demux_id].curindex = -1;
	if (!cfg.dvbapi_listenport && cfg.dvbapi_boxtype != BOXTYPE_PC_NODMX)
		unlink(ECMINFO_FILE);
	return;
}

int32_t dvbapi_start_descrambling(int32_t demux_id, int32_t pid, int8_t checked)
{
	int32_t started = 0; // in case ecmfilter started = 1
	int32_t fake_ecm = 0;
	ECM_REQUEST *er;
	struct s_reader *rdr;
	if(!(er = get_ecmtask())) { return started; }
	demux[demux_id].ECMpids[pid].checked = checked + 1; // mark this pid as checked!

	struct s_dvbapi_priority *p;
	for(p = dvbapi_priority; p != NULL ; p = p->next)
	{
		if((p->type != 'p')
				|| (p->caid && p->caid != demux[demux_id].ECMpids[pid].CAID)
				|| (p->provid && p->provid != demux[demux_id].ECMpids[pid].PROVID)
				|| (p->ecmpid && p->ecmpid != demux[demux_id].ECMpids[pid].ECM_PID)
				|| (p->srvid && p->srvid != demux[demux_id].program_number)
				|| (p->pidx && p->pidx-1 != pid))
			{ continue; }
		// if found chid and first run apply chid filter, on forced pids always apply!
		if(p->type == 'p' && p->chid < 0x10000 && (demux[demux_id].ECMpids[pid].checked == 1 || (p && p->force)))
		{
			if(demux[demux_id].ECMpids[pid].CHID < 0x10000)   // channelcache delivered chid
			{
				er->chid = demux[demux_id].ECMpids[pid].CHID;
			}
			else
			{
				er->chid = p->chid; // no channelcache or no chid in use, so use prio chid
				demux[demux_id].ECMpids[pid].CHID = p->chid;
			}
			//cs_log("********* CHID %04X **************", demux[demux_id].ECMpids[pid].CHID);
			break; // we only accept one!
		}
		else
		{
			if(demux[demux_id].ECMpids[pid].CHID < 0x10000)   // channelcache delivered chid
			{
				er->chid = demux[demux_id].ECMpids[pid].CHID;
			}
			else   // no channelcache or no chid in use
			{
				er->chid = 0;
				demux[demux_id].ECMpids[pid].CHID = 0x10000;
			}
		}
	}
	er->srvid = demux[demux_id].program_number;
	er->caid  = demux[demux_id].ECMpids[pid].CAID;
	er->pid   = demux[demux_id].ECMpids[pid].ECM_PID;
	er->prid  = demux[demux_id].ECMpids[pid].PROVID;
	er->vpid  = demux[demux_id].ECMpids[pid].VPID;
	er->pmtpid  = demux[demux_id].pmtpid;

	struct timeb now;
	cs_ftime(&now);
	for(rdr = first_active_reader; rdr != NULL ; rdr = rdr->next)
	{
		int8_t match = matching_reader(er, rdr); // check for matching reader
		int64_t gone = comp_timeb(&now, &rdr->emm_last);
		if(gone > 3600*1000 && rdr->needsemmfirst && er->caid >> 8 == 0x06)
		{
			cs_log("Warning reader %s received no emms for the last %d seconds -> skip, this reader needs emms first!", rdr->label,
				   (int)(gone/1000));
			continue; // skip this card needs to process emms first before it can be used for descramble
		}
		if(p && p->force) { match = 1; }  // forced pid always started!

		if(!match) // if this reader does not match, check betatunnel for it
			match = lb_check_auto_betatunnel(er, rdr);

		if(!match && chk_is_betatunnel_caid(er->caid))  // these caids might be tunneled invisible by peers
			{ match = 1; } // so make it a match to try it!

		if(config_enabled(CS_CACHEEX) && (!match && (cacheex_is_match_alias(dvbapi_client, er))))   // check if cache-ex is matching
		{
			match = 1; // so make it a match to try it!
		}

		// BISS or FAKE CAID
		// ecm stream pid is fake, so send out one fake ecm request
		// special treatment: if we asked the cw first without starting a filter the cw request will be killed due to no ecmfilter started
		if(demux[demux_id].ECMpids[pid].CAID == 0xFFFF || (demux[demux_id].ECMpids[pid].CAID >> 8) == 0x26)
		{
			int32_t j, n;
			er->ecmlen = 5;
			er->ecm[0] = 0x80; // to pass the cache check it must be 0x80 or 0x81
			er->ecm[1] = 0x00;
			er->ecm[2] = 0x02;
			i2b_buf(2, er->srvid, er->ecm + 3);

			for(j = 0, n = 5; j < demux[demux_id].STREAMpidcount; j++, n += 2)
			{
				i2b_buf(2, demux[demux_id].STREAMpids[j], er->ecm + n);
				er->ecm[2] += 2;
				er->ecmlen += 2;
			}

			cs_log("Demuxer %d trying to descramble PID %d CAID %04X PROVID %06X ECMPID %04X ANY CHID PMTPID %04X VPID %04X", demux_id, pid,
				   demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID,
				   demux[demux_id].pmtpid, demux[demux_id].ECMpids[pid].VPID);

			demux[demux_id].curindex = pid; // set current pid to the fresh started one

			dvbapi_start_filter(demux_id, pid, demux[demux_id].ECMpids[pid].ECM_PID, demux[demux_id].ECMpids[pid].CAID,
								demux[demux_id].ECMpids[pid].PROVID, 0x80, 0xF0, 3000, TYPE_ECM);
			started = 1;

			request_cw(dvbapi_client, er, demux_id, 0); // do not register ecm since this try!
			fake_ecm = 1;
			break; // we started an ecmfilter so stop looking for next matching reader!
		}
		if(match)   // if matching reader found check for irdeto cas if local irdeto card check if it received emms in last 60 minutes
		{

			if(er->caid >> 8 == 0x06)   // irdeto cas init irdeto_curindex to wait for first index (00)
			{
				if(demux[demux_id].ECMpids[pid].irdeto_curindex == 0xFE) { demux[demux_id].ECMpids[pid].irdeto_curindex = 0x00; }
			}

			if(p && p->chid < 0x10000)  // do we prio a certain chid?
			{
				cs_log("Demuxer %d trying to descramble PID %d CAID %04X PROVID %06X ECMPID %04X CHID %04X PMTPID %04X VPID %04X", demux_id, pid,
					   demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID,
					   demux[demux_id].ECMpids[pid].CHID, demux[demux_id].pmtpid, demux[demux_id].ECMpids[pid].VPID);
			}
			else
			{
				cs_log("Demuxer %d trying to descramble PID %d CAID %04X PROVID %06X ECMPID %04X ANY CHID PMTPID %04X VPID %04X", demux_id, pid,
					   demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID,
					   demux[demux_id].pmtpid, demux[demux_id].ECMpids[pid].VPID);
			}

			demux[demux_id].curindex = pid; // set current pid to the fresh started one

			dvbapi_start_filter(demux_id, pid, demux[demux_id].ECMpids[pid].ECM_PID, demux[demux_id].ECMpids[pid].CAID,
								demux[demux_id].ECMpids[pid].PROVID, 0x80, 0xF0, 3000, TYPE_ECM);
			started = 1;
			break; // we started an ecmfilter so stop looking for next matching reader!
		}
	}
	if(demux[demux_id].curindex != pid)
	{
		cs_log("Demuxer %d impossible to descramble PID %d CAID %04X PROVID %06X ECMPID %04X PMTPID %04X (NO MATCHING READER)", demux_id, pid,
			   demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID, demux[demux_id].pmtpid);
		demux[demux_id].ECMpids[pid].checked = 4; // flag this pid as checked
		demux[demux_id].ECMpids[pid].status = -1; // flag this pid as unusable
		dvbapi_edit_channel_cache(demux_id, pid, 0); // remove this pid from channelcache
	}
	if(!fake_ecm) { NULLFREE(er); }
	return started;
}

struct s_dvbapi_priority *dvbapi_check_prio_match_emmpid(int32_t demux_id, uint16_t caid, uint32_t provid, char type)
{
	struct s_dvbapi_priority *p;
	int32_t i;

	uint16_t ecm_pid = 0;
	for(i = 0; i < demux[demux_id].ECMpidcount; i++)
	{
		if((demux[demux_id].ECMpids[i].CAID == caid) && (demux[demux_id].ECMpids[i].PROVID == provid))
		{
			ecm_pid = demux[demux_id].ECMpids[i].ECM_PID;
			break;
		}
	}

	if(!ecm_pid)
		{ return NULL; }

	for(p = dvbapi_priority; p != NULL; p = p->next)
	{
		if(p->type != type
				|| (p->caid && p->caid != caid)
				|| (p->provid && p->provid != provid)
				|| (p->ecmpid && p->ecmpid != ecm_pid)
				|| (p->srvid && p->srvid != demux[demux_id].program_number)
				|| (p->pidx && p->pidx-1 !=i)
				|| (p->type == 'i' && (p->chid < 0x10000)))
			{ continue; }
		return p;
	}
	return NULL;
}

struct s_dvbapi_priority *dvbapi_check_prio_match(int32_t demux_id, int32_t pidindex, char type)
{
	struct s_dvbapi_priority *p;
	struct s_ecmpids *ecmpid = &demux[demux_id].ECMpids[pidindex];

	for(p = dvbapi_priority; p != NULL; p = p->next)
	{
		if(p->type != type
				|| (p->caid && p->caid != ecmpid->CAID)
				|| (p->provid && p->provid != ecmpid->PROVID)
				|| (p->ecmpid && p->ecmpid != ecmpid->ECM_PID)
				|| (p->srvid && p->srvid != demux[demux_id].program_number)
				//|| (p->type == 'i' && (p->chid > -1)))  ///????
				|| (p->pidx && p->pidx-1 != pidindex)
				|| (p->chid < 0x10000 && p->chid != ecmpid->CHID))
			{ continue; }
		return p;
	}
	return NULL;
}

void dvbapi_process_emm(int32_t demux_index, int32_t filter_num, unsigned char *buffer, uint32_t len)
{
	EMM_PACKET epg;

	cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d fetched emm data", demux_index, filter_num + 1); // emm shown with -d64

	struct s_emm_filter *filter = get_emmfilter_by_filternum(demux_index, filter_num + 1);

	if(!filter)
	{
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d no filter matches -> SKIP!", demux_index, filter_num +1);
		return;
	}

	uint32_t provider = filter->provid;
	uint16_t caid = filter->caid;

	struct s_dvbapi_priority *mapentry = dvbapi_check_prio_match_emmpid(filter->demux_id, filter->caid, filter->provid, 'm');
	if(mapentry)
	{
		cs_log_dbg(D_DVBAPI, "Demuxer %d mapping EMM from %04X:%06X to %04X:%06X", demux_index, caid, provider, mapentry->mapcaid,
					  mapentry->mapprovid);
		caid = mapentry->mapcaid;
		provider = mapentry->mapprovid;
	}

	memset(&epg, 0, sizeof(epg));

	i2b_buf(2, caid, epg.caid);
	i2b_buf(4, provider, epg.provid);

	epg.emmlen = len > sizeof(epg.emm) ? sizeof(epg.emm) : len;
	memcpy(epg.emm, buffer, epg.emmlen);

	if(config_enabled(READER_IRDETO) && chk_is_betatunnel_caid(caid) == 2)
	{
		uint16_t ncaid = tunemm_caid_map(FROM_TO, caid, demux[demux_index].program_number);
		if(caid != ncaid)
		{
			irdeto_add_emm_header(&epg);
			i2b_buf(2, ncaid, epg.caid);
		}
	}

	do_emm(dvbapi_client, &epg);
}

void dvbapi_read_priority(void)
{
	FILE *fp;
	char token[128], str1[128];
	char type;
	int32_t i, ret, count = 0;

	const char *cs_prio = "oscam.dvbapi";

	fp = fopen(get_config_filename(token, sizeof(token), cs_prio), "r");

	if(!fp)
	{
		cs_log_dbg(D_DVBAPI, "ERROR: Can't open priority file %s", token);
		return;
	}

	if(dvbapi_priority)
	{
		cs_log_dbg(D_DVBAPI, "reread priority file %s", cs_prio);
		struct s_dvbapi_priority *o, *p;
		for(p = dvbapi_priority; p != NULL; p = o)
		{
			o = p->next;
			NULLFREE(p);
		}
		dvbapi_priority = NULL;
	}

	while(fgets(token, sizeof(token), fp))
	{
		// Ignore comments and empty lines
		if(token[0] == '#' || token[0] == '/' || token[0] == '\n' || token[0] == '\r' || token[0] == '\0')
			{ continue; }
		if(strlen(token) > 100) { continue; }

		memset(str1, 0, 128);

		for(i = 0; i < (int)strlen(token) && token[i] == ' '; i++) { ; }
		if(i  == (int)strlen(token) - 1)  //empty line or all spaces
			{ continue; }

		for(i = 0; i < (int)strlen(token); i++)
		{
			if((token[i] == ':' || token[i] == ' ') && token[i + 1] == ':')  // if "::" or " :"
			{
				memmove(token + i + 2, token + i + 1, strlen(token) - i + 1); //insert extra position
				token[i + 1] = '0'; //and fill it with NULL
			}
			if(token[i] == '#' || token[i] == '/')
			{
				token[i] = '\0';
				break;
			}
		}

		type = 0;
#ifdef WITH_STAPI
		uint32_t disablefilter = 0;
		ret = sscanf(trim(token), "%c: %63s %63s %d", &type, str1, str1 + 64, &disablefilter);
#else
		ret = sscanf(trim(token), "%c: %63s %63s", &type, str1, str1 + 64);
#endif
		type = tolower((uchar)type);

		if(ret < 1 || (type != 'p' && type != 'i' && type != 'm' && type != 'd' && type != 's' && type != 'l'
					   && type != 'j' && type != 'a' && type != 'x'))
		{
			//fprintf(stderr, "Warning: line containing %s in %s not recognized, ignoring line\n", token, cs_prio);
			//fprintf would issue the warning to the command line, which is more consistent with other config warnings
			//however it takes OSCam a long time (>4 seconds) to reach this part of the program, so the warnings are reaching tty rather late
			//which leads to confusion. So send the warnings to log file instead
			cs_log_dbg(D_DVBAPI, "WARN: line containing %s in %s not recognized, ignoring line\n", token, cs_prio);
			continue;
		}

		struct s_dvbapi_priority *entry;
		if(!cs_malloc(&entry, sizeof(struct s_dvbapi_priority)))
		{
			ret = fclose(fp);
			if(ret < 0) { cs_log("ERROR: Could not close oscam.dvbapi fd (errno=%d %s)", errno, strerror(errno)); }
			return;
		}

		entry->type = type;
		entry->next = NULL;

		count++;

#ifdef WITH_STAPI
		if(type == 's')
		{
			strncpy(entry->devname, str1, 29);
			strncpy(entry->pmtfile, str1 + 64, 29);

			entry->disablefilter = disablefilter;

			cs_log_dbg(D_DVBAPI, "stapi prio: ret=%d | %c: %s %s | disable %d",
						  ret, type, entry->devname, entry->pmtfile, disablefilter);

			if(!dvbapi_priority)
			{
				dvbapi_priority = entry;
			}
			else
			{
				struct s_dvbapi_priority *p;
				for(p = dvbapi_priority; p->next != NULL; p = p->next) { ; }
				p->next = entry;
			}
			continue;
		}
#endif

		char c_srvid[34];
		c_srvid[0] = '\0';
		uint32_t caid = 0, provid = 0, srvid = 0, ecmpid = 0;
		uint32_t chid = 0x10000; //chid=0 is a valid chid
		ret = sscanf(str1, "%4x:%6x:%33[^:]:%4x:%4x"SCNx16, &caid, &provid, c_srvid, &ecmpid, &chid);
		if(ret < 1)
		{
			cs_log("Error in oscam.dvbapi: ret=%d | %c: %04X %06X %s %04X %04X",
				   ret, type, caid, provid, c_srvid, ecmpid, chid);
			continue; // skip this entry!
		}
		else
		{
			cs_log_dbg(D_DVBAPI, "Parsing rule: ret=%d | %c: %04X %06X %s %04X %04X",
						  ret, type, caid, provid, c_srvid, ecmpid, chid);
		}

		entry->caid = caid;
		entry->provid = provid;
		entry->ecmpid = ecmpid;
		entry->chid = chid;

		uint32_t delay = 0, force = 0, mapcaid = 0, mapprovid = 0, mapecmpid = 0, pidx = 0;
		switch(type)
		{
		case 'i':
			ret = sscanf(str1 + 64, "%1d", &pidx);
			entry->pidx = pidx+1;
			if(ret < 1) entry->pidx = 0;
			break;
		case 'd':
			sscanf(str1 + 64, "%4d", &delay);
			entry->delay = delay;
			break;
		case 'l':
			entry->delay = dyn_word_atob(str1 + 64);
			if(entry->delay == -1) { entry->delay = 0; }
			break;
		case 'p':
			ret = sscanf(str1 + 64, "%1d:%1d", &force, &pidx);
			entry->force = force;
			entry->pidx = pidx+1;
			if(ret < 2) entry->pidx = 0;
			break;
		case 'm':
			sscanf(str1 + 64, "%4x:%6x", &mapcaid, &mapprovid);
			if(!mapcaid) { mapcaid = 0xFFFF; }
			entry->mapcaid = mapcaid;
			entry->mapprovid = mapprovid;
			break;
		case 'a':
		case 'j':
			sscanf(str1 + 64, "%4x:%6x:%4x", &mapcaid, &mapprovid, &mapecmpid);
			if(!mapcaid) { mapcaid = 0xFFFF; }
			entry->mapcaid = mapcaid;
			entry->mapprovid = mapprovid;
			entry->mapecmpid = mapecmpid;
			break;
		}

		if(c_srvid[0] == '=')
		{
			struct s_srvid *this;

			for(i = 0; i < 16; i++)
				for(this = cfg.srvid[i]; this != NULL; this = this->next)
				{
					if(strcmp(this->prov, c_srvid + 1) == 0)
					{
						struct s_dvbapi_priority *entry2;
						if(!cs_malloc(&entry2, sizeof(struct s_dvbapi_priority)))
							{ continue; }
						memcpy(entry2, entry, sizeof(struct s_dvbapi_priority));

						entry2->srvid = this->srvid;

						cs_log_dbg(D_DVBAPI, "prio srvid: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X %04X | prio %d | delay %d",
									  ret, entry2->type, entry2->caid, entry2->provid, entry2->srvid, entry2->ecmpid, entry2->chid,
									  entry2->mapcaid, entry2->mapprovid, entry2->mapecmpid, entry2->force, entry2->delay);

						if(!dvbapi_priority)
						{
							dvbapi_priority = entry2;
						}
						else
						{
							struct s_dvbapi_priority *p;
							for(p = dvbapi_priority; p->next != NULL; p = p->next) { ; }
							p->next = entry2;
						}
					}
				}
			NULLFREE(entry);
			continue;
		}
		else
		{
			sscanf(c_srvid, "%4x", &srvid);
			entry->srvid = srvid;
		}

		cs_log_dbg(D_DVBAPI, "prio: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X %04X | prio %d | delay %d",
					  ret, entry->type, entry->caid, entry->provid, entry->srvid, entry->ecmpid, entry->chid, entry->mapcaid,
					  entry->mapprovid, entry->mapecmpid, entry->force, entry->delay);

		if(!dvbapi_priority)
		{
			dvbapi_priority = entry;
		}
		else
		{
			struct s_dvbapi_priority *p;
			for(p = dvbapi_priority; p->next != NULL; p = p->next) { ; }
			p->next = entry;
		}
	}

	cs_log_dbg(D_DVBAPI, "Read %d entries from %s", count, cs_prio);

	ret = fclose(fp);
	if(ret < 0) { cs_log("ERROR: Could not close oscam.dvbapi fd (errno=%d %s)", errno, strerror(errno)); }
	return;
}

void dvbapi_resort_ecmpids(int32_t demux_index)
{
	int32_t n, cache = 0, prio = 1, highest_prio = 0, matching_done = 0, found = -1;
	uint16_t btun_caid = 0;
	struct timeb start,end;
	cs_ftime(&start);
	for(n = 0; n < demux[demux_index].ECMpidcount; n++)
	{
		demux[demux_index].ECMpids[n].status = 0;
		demux[demux_index].ECMpids[n].checked = 0;
	}

	demux[demux_index].max_status = 0;
	demux[demux_index].curindex = -1;
	demux[demux_index].pidindex = -1;

	struct s_channel_cache *c = NULL;

	for(n = 0; n < demux[demux_index].ECMpidcount; n++)
	{
		c = dvbapi_find_channel_cache(demux_index, n, 0); // find exact channel match
		if(c != NULL)
		{
			found = n;
			cache = 2; //found cache entry with higher priority
			demux[demux_index].ECMpids[n].status = prio * 2; // prioritize CAIDs which already decoded same caid:provid:srvid
			if(c->chid < 0x10000) { demux[demux_index].ECMpids[n].CHID = c->chid; } // if chid registered in cache -> use it!
			cs_log_dbg(D_DVBAPI, "Demuxer %d prio ecmpid %d %04X:%06X:%04X (found caid/provid/srvid in cache - weight: %d)", demux_index, n,
				demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, demux[demux_index].ECMpids[n].status);
			break;
		}
	}
	
	if(found == -1)
	{
		// prioritize CAIDs which already decoded same caid:provid
		for(n = 0; n < demux[demux_index].ECMpidcount; n++)
		{
			c = dvbapi_find_channel_cache(demux_index, n, 1);
			if(c != NULL)
			{
				cache = 1; //found cache entry
				demux[demux_index].ECMpids[n].status = prio;
				cs_log_dbg(D_DVBAPI, "Demuxer %d prio ecmpid %d %04X:%06X:%04X (found caid/provid in cache - weight: %d)", demux_index, n,
					demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, demux[demux_index].ECMpids[n].status);
			}
		}
	}

	// prioritize & ignore according to oscam.dvbapi and cfg.preferlocalcards
	if(!dvbapi_priority) { cs_log_dbg(D_DVBAPI, "Demuxer %d no oscam.dvbapi found or no valid rules are parsed!", demux_index); }

	if(dvbapi_priority)
	{
		struct s_reader *rdr;
		ECM_REQUEST *er;
		if(!cs_malloc(&er, sizeof(ECM_REQUEST)))
			{ return; }

		int32_t add_prio = 0; // make sure that p: values overrule cache
		if(cache == 1)
			{ add_prio = prio; }
		else if(cache == 2)
			{ add_prio = prio * 2; }

		// reverse order! makes sure that user defined p: values are in the right order
		int32_t p_order = demux[demux_index].ECMpidcount;

		highest_prio = (prio * demux[demux_index].ECMpidcount) + p_order;

		struct s_dvbapi_priority *p;
		for(p = dvbapi_priority; p != NULL; p = p->next)
		{
			if(p->type != 'p' && p->type != 'i')
				{ continue; }
			for(n = 0; n < demux[demux_index].ECMpidcount; n++)
			{
				if(!cache && demux[demux_index].ECMpids[n].status != 0)
					{ continue; }
				else if(cache == 1 && (demux[demux_index].ECMpids[n].status < 0 || demux[demux_index].ECMpids[n].status > prio))
					{ continue; }
				else if(cache == 2 && (demux[demux_index].ECMpids[n].status < 0 || demux[demux_index].ECMpids[n].status > prio * 2))
					{ continue; }

				er->caid = er->ocaid = demux[demux_index].ECMpids[n].CAID;
				er->prid = demux[demux_index].ECMpids[n].PROVID;
				er->pid = demux[demux_index].ECMpids[n].ECM_PID;
				er->srvid = demux[demux_index].program_number;
				er->client = cur_client();

				btun_caid = chk_on_btun(SRVID_MASK, er->client, er);
				if(p->type == 'p' && btun_caid)
					{ er->caid = btun_caid; }

				if(p->caid && p->caid != er->caid)
					{ continue; }
				if(p->provid && p->provid != er->prid)
					{ continue; }
				if(p->ecmpid && p->ecmpid != er->pid)
					{ continue; }
				if(p->srvid && p->srvid != er->srvid)
					{ continue; }
				if (p->pidx && p->pidx-1 != n)
					{ continue; }

				if(p->type == 'i')    // check if ignored by dvbapi
				{
					if(p->chid == 0x10000)   // ignore all? disable pid
					{
						demux[demux_index].ECMpids[n].status = -1;
					}
					cs_log_dbg(D_DVBAPI, "Demuxer %d ignore ecmpid %d %04X:%06X:%04X:%04X (file)", demux_index, n, demux[demux_index].ECMpids[n].CAID,
								  demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) p->chid);
					continue;
				}

				if(p->type == 'p')
				{
					if(demux[demux_index].ECMpids[n].status == -1)  //skip ignores
						{ continue; }

					matching_done = 1;
					for(rdr = first_active_reader; rdr ; rdr = rdr->next)
					{
						if(cfg.preferlocalcards && !is_network_reader(rdr)
								&& rdr->card_status == CARD_INSERTED)   // cfg.preferlocalcards = 1 local reader
						{

							if(matching_reader(er, rdr))
							{
								if(cache == 2 && demux[demux_index].ECMpids[n].status == 1)
									{ demux[demux_index].ECMpids[n].status++; }
								else if(cache && !demux[demux_index].ECMpids[n].status)
									{ demux[demux_index].ECMpids[n].status += add_prio; }
								//priority*ECMpidcount should overrule network reader
								demux[demux_index].ECMpids[n].status += (prio * demux[demux_index].ECMpidcount) + (p_order--);
								cs_log_dbg(D_DVBAPI, "Demuxer %d prio ecmpid %d %04X:%06X:%04X:%04X (localrdr: %s weight: %d)", demux_index,
											  n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
											  demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) p->chid, rdr->label,
											  demux[demux_index].ECMpids[n].status);
								break;
							}
						}
						else        // cfg.preferlocalcards = 0 or cfg.preferlocalcards = 1 and no local reader
						{
							if(matching_reader(er, rdr))
							{
								if(cache == 2 && demux[demux_index].ECMpids[n].status == 1)
									{ demux[demux_index].ECMpids[n].status++; }
								else if(cache && !demux[demux_index].ECMpids[n].status)
									{ demux[demux_index].ECMpids[n].status += add_prio; }
								demux[demux_index].ECMpids[n].status += prio + (p_order--);
								cs_log_dbg(D_DVBAPI, "Demuxer %d prio ecmpid %d %04X:%06X:%04X:%04X (rdr: %s weight: %d)", demux_index,
											  n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
											  demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) p->chid, rdr->label,
											  demux[demux_index].ECMpids[n].status);
								break;
							}
						}
					}
				}
			}
		}
		NULLFREE(er);
	}

	if(!matching_done)      //works if there is no oscam.dvbapi or if there is oscam.dvbapi but not p rules in it
	{
		if(dvbapi_priority && !matching_done)
			{ cs_log_dbg(D_DVBAPI, "Demuxer %d no prio rules in oscam.dvbapi matches!", demux_index); }

		struct s_reader *rdr;
		ECM_REQUEST *er;
		if(!cs_malloc(&er, sizeof(ECM_REQUEST)))
			{ return; }

		highest_prio = prio * 2;

		for(n = 0; n < demux[demux_index].ECMpidcount; n++)
		{
			if(demux[demux_index].ECMpids[n].status == -1)  //skip ignores
				{ continue; }

			er->caid = er->ocaid = demux[demux_index].ECMpids[n].CAID;
			er->prid = demux[demux_index].ECMpids[n].PROVID;
			er->pid = demux[demux_index].ECMpids[n].ECM_PID;
			er->srvid = demux[demux_index].program_number;
			er->client = cur_client();

			btun_caid = chk_on_btun(SRVID_MASK, er->client, er);
			if(btun_caid)
				{ er->caid = btun_caid; }

			for(rdr = first_active_reader; rdr ; rdr = rdr->next)
			{
				if(cfg.preferlocalcards
						&& !is_network_reader(rdr)
						&& rdr->card_status == CARD_INSERTED)   // cfg.preferlocalcards = 1 local reader
				{
					if(matching_reader(er, rdr))
					{
						demux[demux_index].ECMpids[n].status += prio * 2;
						cs_log_dbg(D_DVBAPI, "Demuxer %d prio ecmpid %d %04X:%06X:%04X (localrdr: %s weight: %d)", demux_index,
									  n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
									  demux[demux_index].ECMpids[n].ECM_PID, rdr->label,
									  demux[demux_index].ECMpids[n].status);
						break;
					}
				}
				else        // cfg.preferlocalcards = 0 or cfg.preferlocalcards = 1 and no local reader
				{
					if(matching_reader(er, rdr))
					{
						demux[demux_index].ECMpids[n].status += prio;
						cs_log_dbg(D_DVBAPI, "Demuxer %d prio ecmpid %d %04X:%06X:%04X (rdr: %s weight: %d)", demux_index,
									  n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
									  demux[demux_index].ECMpids[n].ECM_PID, rdr->label, demux[demux_index].ECMpids[n].status);
						break;
					}
				}
			}
		}
		NULLFREE(er);
	}

	if(cache == 1)
		{ highest_prio += prio; }
	else if(cache == 2)
		{ highest_prio += prio * 2; };

	highest_prio++;

	for(n = 0; n < demux[demux_index].ECMpidcount; n++)
	{
		int32_t nr;
		SIDTAB *sidtab;
		ECM_REQUEST er;
		er.caid  = demux[demux_index].ECMpids[n].CAID;
		er.prid  = demux[demux_index].ECMpids[n].PROVID;
		er.srvid = demux[demux_index].program_number;

		for(nr = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, nr++)
		{
			if(sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid)
			{
				if((cfg.dvbapi_sidtabs.no & ((SIDTABBITS)1 << nr)) && (chk_srvid_match(&er, sidtab)))
				{
					demux[demux_index].ECMpids[n].status = -1; //ignore
					cs_log_dbg(D_DVBAPI, "Demuxer %d ignore ecmpid %d %04X:%06X:%04X (service %s) pos %d", demux_index,
								  n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
								  demux[demux_index].ECMpids[n].ECM_PID, sidtab->label, nr);
				}
				if((cfg.dvbapi_sidtabs.ok & ((SIDTABBITS)1 << nr)) && (chk_srvid_match(&er, sidtab)))
				{
					demux[demux_index].ECMpids[n].status = highest_prio++; //priority
					cs_log_dbg(D_DVBAPI, "Demuxer %d prio ecmpid %d %04X:%06X:%04X (service: %s position: %d)", demux_index,
								  n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
								  demux[demux_index].ECMpids[n].ECM_PID, sidtab->label,
								  demux[demux_index].ECMpids[n].status);
				}
			}
		}
	}

	struct s_reader *rdr;
	ECM_REQUEST *er;
	if(!cs_malloc(&er, sizeof(ECM_REQUEST)))
		{ return; }
	
	for(n = 0; n < demux[demux_index].ECMpidcount; n++)
	{
		er->caid = er->ocaid = demux[demux_index].ECMpids[n].CAID;
		er->prid = demux[demux_index].ECMpids[n].PROVID;
		er->pid = demux[demux_index].ECMpids[n].ECM_PID;
		er->srvid = demux[demux_index].program_number;
		er->client = cur_client();
		btun_caid = chk_on_btun(SRVID_MASK, er->client, er);
		if(btun_caid)
		{ 
			er->caid = btun_caid;
		}
		
		int32_t match = 0;
		for(rdr = first_active_reader; rdr ; rdr = rdr->next)
		{
			if(matching_reader(er, rdr))
			{
				match++;
			}
		}
		if (match == 0)
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d ignore ecmpid %d %04X:%06X:%04X:%04X (no matching reader)", demux_index, n, demux[demux_index].ECMpids[n].CAID,
				demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, demux[demux_index].ECMpids[n].CHID);
			demux[demux_index].ECMpids[n].status = -1;
		}
	}
	NULLFREE(er);
	
	highest_prio = 0;
	int32_t highest_priopid = -1;
	for(n = 0; n < demux[demux_index].ECMpidcount; n++)
	{
		if(demux[demux_index].ECMpids[n].status > highest_prio) // find highest prio pid 
		{ 
			highest_prio = demux[demux_index].ECMpids[n].status;
			highest_priopid = n;
		}  
		if(demux[demux_index].ECMpids[n].status == 0) { demux[demux_index].ECMpids[n].checked = 2; }  // set pids with no status to no prio run
	}

	struct s_dvbapi_priority *match;
	for(match = dvbapi_priority; match != NULL; match = match->next)
	{
		if(match->type != 'p')
			{ continue; }
		if(!match || !match->force)  // only evaluate forced prio's
			{ continue; }
		for(n = 0; n < demux[demux_index].ECMpidcount; n++)
		{
			if(match->caid &&  match->caid != demux[demux_index].ECMpids[n].CAID) { continue; }
			if(match->provid && match->provid != demux[demux_index].ECMpids[n].PROVID) { continue; }
			if(match->srvid && match->srvid != demux[demux_index].program_number) { continue; }
			if(match->ecmpid && match->ecmpid != demux[demux_index].ECMpids[n].ECM_PID) { continue; }
			if(match->pidx && match->pidx-1 != n) { continue; }
			if(match->chid < 0x10000) { demux[demux_index].ECMpids[n].CHID = match->chid; }
			demux[demux_index].ECMpids[n].status = ++highest_prio;
			cs_log_dbg(D_DVBAPI, "Demuxer %d forced ecmpid %d %04X:%06X:%04X:%04X", demux_index, n, demux[demux_index].ECMpids[n].CAID,
						  demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) match->chid);
			demux[demux_index].max_status = highest_prio; // register maxstatus
			demux[demux_index].ECMpids[n].checked = 0; // set forced pid to prio run
			return; // we only accept one forced pid!
		}
	}
	demux[demux_index].max_status = highest_prio; // register maxstatus
	if(highest_priopid != -1 && found == highest_priopid)     // Found in cache
	{
		for(n = 0; n < demux[demux_index].ECMpidcount; n++)
		{
			if(n != found)
			{
				// disable non matching pid
				demux[demux_index].ECMpids[n].status = -1;
			}
			else
			{
				demux[demux_index].ECMpids[n].status = 1;
			}
		}
		demux[demux_index].max_emm_filter = maxfilter - 1;
		demux[demux_index].max_status = 1;
		cs_log("Demuxer %d found channel in cache and matching prio -> start descrambling ecmpid %d ", demux_index, found);
	}
	cs_ftime(&end);
	int64_t gone = comp_timeb(&end, &start);
	cs_log_dbg(D_DVBAPI, "Demuxer %d sorting the ecmpids took %"PRId64" ms", demux_index, gone);
	return;
}

void dvbapi_parse_descriptor(int32_t demux_id, uint32_t info_length, unsigned char *buffer)
{
	// int32_t ca_pmt_cmd_id = buffer[i + 5];
	uint32_t descriptor_length = 0;
	uint32_t j, u;

	if(info_length < 1)
		{ return; }

	if(buffer[0] == 0x01)
	{
		buffer = buffer + 1;
		info_length--;
	}

	for(j = 0; j < info_length; j += descriptor_length + 2)
	{
		descriptor_length = buffer[j + 1];

		if(buffer[j] == 0x81 && descriptor_length == 8)    // private descriptor of length 8, assume enigma/tvh
		{
			demux[demux_id].enigma_namespace = b2i(4, buffer + j + 2);
			demux[demux_id].tsid = b2i(2, buffer + j + 6);
			demux[demux_id].onid = b2i(2, buffer + j + 8);
			cs_log_dbg(D_DVBAPI, "Found pmt type: %02x length: %d (assuming enigma private descriptor: namespace %04x tsid %02x onid %02x)",
						  buffer[j], descriptor_length, demux[demux_id].enigma_namespace, demux[demux_id].tsid, demux[demux_id].onid);
		}
		else
		{
			cs_log_dbg(D_DVBAPI, "Found pmt type: %02x length: %d", buffer[j], descriptor_length);
		}

		if(buffer[j] != 0x09) { continue; }
		if(demux[demux_id].ECMpidcount >= ECM_PIDS) { break; }

		int32_t descriptor_ca_system_id = b2i(2, buffer + j + 2);
		int32_t descriptor_ca_pid = b2i(2, buffer + j + 4)&0x1FFF;
		int32_t descriptor_ca_provider = 0;

		if(descriptor_ca_system_id >> 8 == 0x01)
		{
			for(u = 2; u < descriptor_length; u += 15)
			{
				descriptor_ca_pid = b2i(2, buffer + j + u + 2)&0x1FFF;
				descriptor_ca_provider = b2i(2, buffer + j + u + 4);
				dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider);
			}
		}
		else
		{
			if(descriptor_ca_system_id >> 8 == 0x05 && descriptor_length == 0x0F && buffer[j + 12] == 0x14)
				{ descriptor_ca_provider = b2i(3, buffer + j + 14) &0xFFFFF0; }

			if(descriptor_ca_system_id >> 8 == 0x18 && descriptor_length == 0x07)
				{ descriptor_ca_provider = b2i(2, buffer + j + 7); }
			
			if(descriptor_ca_system_id >> 8 == 0x4A && descriptor_length == 0x05)
				{ descriptor_ca_provider = buffer[j + 6]; }

			dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider);
			
		}
	}

	// Apply mapping:
	if(dvbapi_priority)
	{
		struct s_dvbapi_priority *mapentry;
		for(j = 0; (int32_t)j < demux[demux_id].ECMpidcount; j++)
		{
			mapentry = dvbapi_check_prio_match(demux_id, j, 'm');
			if(mapentry)
			{
				cs_log_dbg(D_DVBAPI, "Demuxer %d mapping ecmpid %d from %04X:%06X to %04X:%06X", demux_id, j,
							  demux[demux_id].ECMpids[j].CAID, demux[demux_id].ECMpids[j].PROVID,
							  mapentry->mapcaid, mapentry->mapprovid);
				demux[demux_id].ECMpids[j].CAID = mapentry->mapcaid;
				demux[demux_id].ECMpids[j].PROVID = mapentry->mapprovid;
			}
		}
	}
}

void request_cw(struct s_client *client, ECM_REQUEST *er, int32_t demux_id, uint8_t delayed_ecm_check)
{
	int32_t filternum = dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd -> even and visaversa

	if(!USE_OPENXCAS && filternum < 0)
	{
		cs_log_dbg(D_DVBAPI, "Demuxer %d not requesting cw -> ecm filter was killed!", demux_id);
		return;
	}

	cs_log_dbg(D_DVBAPI, "Demuxer %d get controlword!", demux_id);
	get_cw(client, er);

	if (!USE_OPENXCAS) {
		if(delayed_ecm_check) { memcpy(demux[demux_id].demux_fd[filternum].ecmd5, er->ecmd5, CS_ECMSTORESIZE); }  // register this ecm as latest request for this filter
		else { memset(demux[demux_id].demux_fd[filternum].ecmd5, 0, CS_ECMSTORESIZE); } // zero out ecmcheck!
	}

#ifdef WITH_DEBUG
	char buf[ECM_FMT_LEN];
	format_ecm(er, buf, ECM_FMT_LEN);
	cs_log_dbg(D_DVBAPI, "Demuxer %d request controlword for ecm %s", demux_id, buf);
#endif
}

void dvbapi_try_next_caid(int32_t demux_id, int8_t checked)
{

	int32_t n, j, found = -1, started = 0;

	int32_t status = demux[demux_id].max_status;

	for(j = status; j >= 0; j--)    // largest status first!
	{

		for(n = 0; n < demux[demux_id].ECMpidcount; n++)
		{
			//cs_log_dbg(D_DVBAPI,"Demuxer %d PID %d checked = %d status = %d (searching for pid with status = %d)", demux_id, n,
			//  demux[demux_id].ECMpids[n].checked, demux[demux_id].ECMpids[n].status, j);
			if(demux[demux_id].ECMpids[n].checked == checked && demux[demux_id].ECMpids[n].status == j)
			{
				found = n;

				openxcas_set_provid(demux[demux_id].ECMpids[found].PROVID);
				openxcas_set_caid(demux[demux_id].ECMpids[found].CAID);
				openxcas_set_ecm_pid(demux[demux_id].ECMpids[found].ECM_PID);

				// fixup for cas that need emm first!
				if((demux[demux_id].ECMpids[found].CAID >> 8) == 0x06) { demux[demux_id].emmstart.time = 0; }
				started = dvbapi_start_descrambling(demux_id, found, checked);
				if(cfg.dvbapi_requestmode == 0 && started == 1) { return; }  // in requestmode 0 we only start 1 ecm request at the time
			}
		}
	}

	if(found == -1 && demux[demux_id].pidindex == -1)
	{
		cs_log("Demuxer %d no suitable readers found that can be used for decoding!", demux_id);
		return;
	}
}

static void getDemuxOptions(int32_t demux_id, unsigned char *buffer, uint16_t *ca_mask, uint16_t *demux_index, uint16_t *adapter_index, uint16_t *pmtpid)
{
	*ca_mask = 0x01, *demux_index = 0x00, *adapter_index = 0x00, *pmtpid = 0x00;

	if(buffer[17] == 0x82 && buffer[18] == 0x02)
	{
		// enigma2
		*ca_mask = buffer[19];
		uint32_t demuxid = buffer[20];
		if (demuxid == 0xff) demuxid = 0; // tryfix prismcube (0xff -> "demux-1" = error! )
		*demux_index = demuxid;
		if (buffer[21]==0x84 && buffer[22]==0x02) *pmtpid = b2i(2, buffer+23);
		if (buffer[25]==0x83 && buffer[26]==0x01) *adapter_index=buffer[27]; // from code cahandler.cpp 0x83 index of adapter
	}

	if(cfg.dvbapi_boxtype == BOXTYPE_IPBOX_PMT)
	{
		*ca_mask = demux_id + 1;
		*demux_index = demux_id;
	}

	if(cfg.dvbapi_boxtype == BOXTYPE_QBOXHD && buffer[17] == 0x82 && buffer[18] == 0x03)
	{
		// ca_mask = buffer[19]; // with STONE 1.0.4 always 0x01
		*demux_index = buffer[20]; // with STONE 1.0.4 always 0x00
		*adapter_index = buffer[21]; // with STONE 1.0.4 adapter index can be 0,1,2
		*ca_mask = (1 << *adapter_index); // use adapter_index as ca_mask (used as index for ca_fd[] array)
	}

	if((cfg.dvbapi_boxtype == BOXTYPE_PC || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX) && buffer[7] == 0x82 && buffer[8] == 0x02)
	{
		*demux_index = buffer[9]; // it is always 0 but you never know
		*adapter_index = buffer[10]; // adapter index can be 0,1,2
		*ca_mask = (1 << *adapter_index); // use adapter_index as ca_mask (used as index for ca_fd[] array)
	}
}

static void dvbapi_capmt_notify(struct demux_s *dmx)
{
	struct s_client *cl;
	for(cl = first_client->next; cl ; cl = cl->next)
	{
		if((cl->typ == 'p' || cl->typ == 'r') && cl->reader && cl->reader->ph.c_capmt)
		{
			struct demux_s *curdemux;
			if(cs_malloc(&curdemux, sizeof(struct demux_s)))
			{
				memcpy(curdemux, dmx, sizeof(struct demux_s));
				add_job(cl, ACTION_READER_CAPMT_NOTIFY, curdemux, sizeof(struct demux_s));
			}
		}
	}
}

int32_t dvbapi_parse_capmt(unsigned char *buffer, uint32_t length, int32_t connfd, char *pmtfile)
{
	uint32_t i = 0, running = 0;
	int32_t j = 0;
	int32_t demux_id = -1;
	uint16_t ca_mask, demux_index, adapter_index, pmtpid;

#define LIST_MORE 0x00    //*CA application should append a 'MORE' CAPMT object to the list and start receiving the next object
#define LIST_FIRST 0x01   //*CA application should clear the list when a 'FIRST' CAPMT object is received, and start receiving the next object
#define LIST_LAST 0x02   //*CA application should append a 'LAST' CAPMT object to the list and start working with the list
#define LIST_ONLY 0x03   //*CA application should clear the list when an 'ONLY' CAPMT object is received, and start working with the object
#define LIST_ADD 0x04    //*CA application should append an 'ADD' CAPMT object to the current list and start working with the updated list
#define LIST_UPDATE 0x05 //*CA application should replace an entry in the list with an 'UPDATE' CAPMT object, and start working with the updated list

#ifdef WITH_COOLAPI
	int32_t ca_pmt_list_management = LIST_ONLY;
#else
	int32_t ca_pmt_list_management = buffer[0];
#endif
	uint32_t program_number = b2i(2, buffer + 1);
	uint32_t program_info_length = b2i(2, buffer + 4) &0xFFF;
	
	cs_log_dump_dbg(D_DVBAPI, buffer, length, "capmt:");
	cs_log_dbg(D_DVBAPI, "Receiver sends PMT command %d for channel %04X", ca_pmt_list_management, program_number);
	if((ca_pmt_list_management == LIST_FIRST || ca_pmt_list_management == LIST_ONLY) && pmt_stopmarking == 0)
	{
		for(i = 0; i < MAX_DEMUX; i++)
		{
			if(demux[i].program_number == 0) { continue; }  // skip empty demuxers
			if(demux[i].socket_fd != connfd) { continue; }  // skip demuxers belonging to other ca pmt connection
			demux[i].stopdescramble = 1; // Mark for deletion if not used again by following pmt objects.
			cs_log_dbg(D_DVBAPI, "Marked demuxer %d/%d to stop decoding", i, MAX_DEMUX);
			pmt_stopmarking = 1;
		}
	}
	getDemuxOptions(i, buffer, &ca_mask, &demux_index, &adapter_index, &pmtpid);
	cs_log_dbg(D_DVBAPI,"Receiver wants to demux srvid %04X on adapter %04X camask %04X index %04X pmtpid %04X",
		program_number, adapter_index, ca_mask, demux_index, pmtpid);
	
	for(i = 0; i < MAX_DEMUX; i++)    // search current demuxers for running the same program as the one we received in this PMT object
	{
		if(demux[i].program_number == 0) { continue; }
		if(cfg.dvbapi_boxtype == BOXTYPE_IPBOX_PMT) demux_index = i; // fixup for ipbox

		bool full_check = 1, matched = 0;
		if (config_enabled(WITH_COOLAPI) || is_samygo)
			full_check = 0;

		if (full_check)
			matched = (connfd > 0 && demux[i].socket_fd == connfd) && demux[i].program_number == program_number;
		else
			matched = connfd > 0 && demux[i].program_number == program_number;

		if(matched)
		{
			if (full_check) {
				if (demux[i].adapter_index != adapter_index) continue; // perhaps next demuxer matches?
				if (demux[i].ca_mask != ca_mask) continue; // perhaps next demuxer matches?
				if (demux[i].demux_index != demux_index) continue; // perhaps next demuxer matches?
			}
			if(ca_pmt_list_management == LIST_UPDATE){
				cs_log("Demuxer %d PMT update for decoding of SRVID %04X! ", i, program_number);
			}

			demux_id = i;

#if defined WITH_STAPI || defined WITH_COOLAPI || defined WITH_MCA || defined WITH_AZBOX
			dvbapi_stop_descrambling(i); // stop descrambling for all boxes except dvbapi based boxes
#else
			cs_log("Demuxer %d continue decoding of SRVID %04X", i, demux[i].program_number);
#endif

			openxcas_set_sid(program_number);

			demux[i].stopdescramble = 0; // dont stop current demuxer!
			if(demux[demux_id].ECMpidcount != 0) { running = 1; }  // fix for channel changes from fta to scrambled		
			break; // no need to explore other demuxers since we have a found!
		}
	}

	// stop descramble old demuxers from this ca pmt connection that arent used anymore
	if((ca_pmt_list_management == LIST_LAST) || (ca_pmt_list_management == LIST_ONLY))
	{
		for(j = 0; j < MAX_DEMUX; j++)
		{
			if(demux[j].program_number == 0) { continue; }
			if(demux[j].stopdescramble == 1) { dvbapi_stop_descrambling(j); }  // Stop descrambling and remove all demuxer entries not in new PMT.
		}
	}

	if(demux_id == -1)
	{
		for(demux_id = 0; demux_id < MAX_DEMUX && demux[demux_id].program_number > 0; demux_id++) { ; }
	}

	if(demux_id >= MAX_DEMUX)
	{
		cs_log("ERROR: No free id (MAX_DEMUX)");
		return -1;
	}
	
	demux[demux_id].program_number = program_number; // do this early since some prio items use them!

	demux[demux_id].enigma_namespace = 0;
	demux[demux_id].tsid = 0;
	demux[demux_id].onid = 0;
	demux[demux_id].pmtpid = pmtpid;

	if(pmtfile)
	{
		cs_strncpy(demux[demux_id].pmt_file, pmtfile, sizeof(demux[demux_id].pmt_file));
	}

	if(program_info_length > 1 && program_info_length < length)
	{
		dvbapi_parse_descriptor(demux_id, program_info_length - 1, buffer + 7);
	}

	uint32_t es_info_length = 0, vpid = 0;
	struct s_dvbapi_priority *addentry;

	for(j = 0; j < demux[demux_id].ECMpidcount; j++){  // check for existing pid
		demux[demux_id].ECMpids[j].streams = 0; // reset streams!
	}
	demux[demux_id].STREAMpidcount = 0; // reset numer of streams

	for(i = program_info_length + 6; i < length; i += es_info_length + 5)
	{
		int32_t stream_type = buffer[i];
		uint16_t elementary_pid = b2i(2, buffer + i + 1)&0x1FFF;
		es_info_length = b2i(2, buffer + i +3)&0x0FFF;
		cs_log_dbg(D_DVBAPI, "Found stream type: %02x pid: %04x length: %d", stream_type, elementary_pid, es_info_length);

		if(demux[demux_id].STREAMpidcount >= ECM_PIDS)
		{
			break;
		}

		demux[demux_id].STREAMpids[demux[demux_id].STREAMpidcount++] = elementary_pid;
		// find and register videopid
		if(!vpid && (stream_type == 01 || stream_type == 02 || stream_type == 0x10 || stream_type == 0x1B)) { vpid = elementary_pid; }

		if(es_info_length != 0 && es_info_length < length)
		{
			dvbapi_parse_descriptor(demux_id, es_info_length, buffer + i + 5);
		}
		else
		{
			for(addentry = dvbapi_priority; addentry != NULL; addentry = addentry->next)
			{
				if(addentry->type != 'a'
						|| (addentry->ecmpid && pmtpid && addentry->ecmpid != pmtpid) // ecmpid is misused to hold pmtpid in case of A: rule
						|| (addentry->ecmpid && !pmtpid && addentry->ecmpid != vpid) // some receivers dont forward pmtpid, use vpid instead
						|| (addentry->srvid != demux[demux_id].program_number))
					{ continue; }
				cs_log_dbg(D_DVBAPI, "Added fake ecmpid %04X:%06x:%04x for unencrypted stream on srvid %04X", addentry->mapcaid, addentry->mapprovid,
					addentry->mapecmpid, demux[demux_id].program_number);
				dvbapi_add_ecmpid(demux_id, addentry->mapcaid, addentry->mapecmpid, addentry->mapprovid);
				break;
			}
		}
	}
	for(j = 0; j < demux[demux_id].ECMpidcount; j++)
	{
		demux[demux_id].ECMpids[j].VPID = vpid; // register found vpid on all ecmpids of this demuxer
	}
	cs_log("Demuxer %d found %d ECMpids and %d STREAMpids in PMT", demux_id, demux[demux_id].ECMpidcount, demux[demux_id].STREAMpidcount-1);

	getDemuxOptions(demux_id, buffer, &ca_mask, &demux_index, &adapter_index, &pmtpid);
	cs_log("Demuxer %d receiver wants to demux srvid %04X on adapter %04X camask %04X index %04X pmtpid %04X", demux_id,
		   demux[demux_id].program_number, adapter_index, ca_mask, demux_index, pmtpid);
	demux[demux_id].adapter_index = adapter_index;
	demux[demux_id].ca_mask = ca_mask;
	demux[demux_id].rdr = NULL;
	demux[demux_id].demux_index = demux_index;
	demux[demux_id].socket_fd = connfd;
	demux[demux_id].stopdescramble = 0; // remove deletion mark!

	// remove from unassoc_fd when necessary
	for (j = 0; j < MAX_DEMUX; j++)
			if (unassoc_fd[j] == connfd)
					unassoc_fd[j] = 0;

	char channame[32];
	get_servicename(dvbapi_client, demux[demux_id].program_number, demux[demux_id].ECMpidcount > 0 ? demux[demux_id].ECMpids[0].CAID : NO_CAID_VALUE, channame);
	cs_log("Demuxer %d new program number: %04X (%s) [pmt_list_management %d]", demux_id, program_number, channame, ca_pmt_list_management);

	dvbapi_capmt_notify(&demux[demux_id]);

	cs_log_dbg(D_DVBAPI, "Demuxer %d demux_index: %2d ca_mask: %02x program_info_length: %3d ca_pmt_list_management %02x",
				  demux_id, demux[demux_id].demux_index, demux[demux_id].ca_mask, program_info_length, ca_pmt_list_management);

	struct s_dvbapi_priority *xtraentry;
	int32_t k, l, m, xtra_demux_id;

	for(xtraentry = dvbapi_priority; xtraentry != NULL; xtraentry = xtraentry->next)
	{
		if(xtraentry->type != 'x') { continue; }

		for(j = 0; j <= demux[demux_id].ECMpidcount; ++j)
		{
			if((xtraentry->caid && xtraentry->caid != demux[demux_id].ECMpids[j].CAID)
					|| (xtraentry->provid && xtraentry->provid  != demux[demux_id].ECMpids[j].PROVID)
					|| (xtraentry->ecmpid && xtraentry->ecmpid  != demux[demux_id].ECMpids[j].ECM_PID)
					|| (xtraentry->srvid && xtraentry->srvid != demux[demux_id].program_number))
				{ continue; }

			cs_log("Mapping ecmpid %04X:%06X:%04X:%04X to xtra demuxer/ca-devices", xtraentry->caid, xtraentry->provid, xtraentry->ecmpid, xtraentry->srvid);

			for(xtra_demux_id = 0; xtra_demux_id < MAX_DEMUX && demux[xtra_demux_id].program_number > 0; xtra_demux_id++)
				{ ; }

			if(xtra_demux_id >= MAX_DEMUX)
			{
				cs_log("Found no free demux device for xtra streams.");
				continue;
			}
			// copy to new demuxer
			getDemuxOptions(demux_id, buffer, &ca_mask, &demux_index, &adapter_index, &pmtpid);
			demux[xtra_demux_id].ECMpids[0] = demux[demux_id].ECMpids[j];
			demux[xtra_demux_id].ECMpidcount = 1;
			demux[xtra_demux_id].STREAMpidcount = 0;
			demux[xtra_demux_id].program_number = demux[demux_id].program_number;
			demux[xtra_demux_id].pmtpid = demux[demux_id].pmtpid;
			demux[xtra_demux_id].demux_index = demux_index;
			demux[xtra_demux_id].adapter_index = adapter_index;
			demux[xtra_demux_id].ca_mask = ca_mask;
			demux[xtra_demux_id].socket_fd = connfd;
			demux[xtra_demux_id].stopdescramble = 0; // remove deletion mark!
			demux[xtra_demux_id].rdr = NULL;
			demux[xtra_demux_id].curindex = -1;

			// add streams to xtra demux
			for(k = 0; k < demux[demux_id].STREAMpidcount; ++k)
			{
				if(!demux[demux_id].ECMpids[j].streams || demux[demux_id].ECMpids[j].streams & (1 << k))
				{
					demux[xtra_demux_id].ECMpids[0].streams |= (1 << demux[xtra_demux_id].STREAMpidcount);
					demux[xtra_demux_id].STREAMpids[demux[xtra_demux_id].STREAMpidcount] = demux[demux_id].STREAMpids[k];
					++demux[xtra_demux_id].STREAMpidcount;

					// shift stream associations in normal demux because we will remove the stream entirely
					for(l = 0; l < demux[demux_id].ECMpidcount; ++l)
					{
						for(m = k; m < demux[demux_id].STREAMpidcount - 1; ++m)
						{
							if(demux[demux_id].ECMpids[l].streams & (1 << (m + 1)))
							{
								demux[demux_id].ECMpids[l].streams |= (1 << m);
							}
							else
							{
								demux[demux_id].ECMpids[l].streams &= ~(1 << m);
							}
						}
					}

					// remove stream association from normal demux device
					for(l = k; l < demux[demux_id].STREAMpidcount - 1; ++l)
					{
						demux[demux_id].STREAMpids[l] = demux[demux_id].STREAMpids[l + 1];
					}
					--demux[demux_id].STREAMpidcount;
					--k;
				}
			}

			// remove ecmpid from normal demuxer
			for(k = j; k < demux[demux_id].ECMpidcount; ++k)
			{
				demux[demux_id].ECMpids[k] = demux[demux_id].ECMpids[k + 1];
			}
			--demux[demux_id].ECMpidcount;
			--j;

			if(demux[xtra_demux_id].STREAMpidcount > 0)
			{
				dvbapi_resort_ecmpids(xtra_demux_id);
				dvbapi_try_next_caid(xtra_demux_id, 0);
			}
			else
			{
				cs_log("Found no streams for xtra demuxer. Not starting additional decoding on it.");
			}

			if(demux[demux_id].STREAMpidcount < 1)
			{
				cs_log("Found no streams for normal demuxer. Not starting additional decoding on it.");
				openxcas_set_sid(program_number);
				return xtra_demux_id;
			}
		}
	}

	if(running == 0) // only do emm setup on non-running channels!
	{
		demux[demux_id].emm_filter = -1; // to register first run emmfilter start
		if(cfg.dvbapi_au > 0 && demux[demux_id].emmstart.time == 1)   // irdeto fetch emm cat direct!
		{
			cs_ftime(&demux[demux_id].emmstart); // trick to let emm fetching start after 30 seconds to speed up zapping
			dvbapi_start_filter(demux_id, demux[demux_id].pidindex, 0x001, 0x001, 0x01, 0x01, 0xFF, 0, TYPE_EMM); //CAT
		}
		else { cs_ftime(&demux[demux_id].emmstart); } // for all other caids delayed start!
	}
	
	openxcas_set_sid(program_number);
	
	if(demux[demux_id].ECMpidcount == 0) { // for FTA it ends here, but do logging and part of ecmhandler since there will be no ecms asked!
		if(cfg.usrfileflag) { cs_statistics(dvbapi_client);} // add to user log previous channel + time on channel
		dvbapi_client->last_srvid = demux[demux_id].program_number; // set new channel srvid
		dvbapi_client->last_caid = NO_CAID_VALUE; // FTA channels have no caid!
		dvbapi_client->lastswitch = dvbapi_client->last = time((time_t *)0); // reset idle-Time & last switch
		return demux_id; 
	}

#if !defined WITH_STAPI && !defined WITH_COOLAPI && !defined WITH_MCA && !defined WITH_AZBOX
	if (running) disable_unused_streampids(demux_id); // disable all streampids not in use anymore
#endif
	if(running == 0)   // only start demuxer if it wasnt running
	{
		demux[demux_id].decodingtries = -1;
		dvbapi_resort_ecmpids(demux_id);
		dvbapi_try_next_caid(demux_id, 0);
	}
	return demux_id;
}


void dvbapi_handlesockmsg(unsigned char *buffer, uint32_t len, int32_t connfd)
{
	uint32_t val = 0, size = 0, i, k;

	for(k = 0; k < len; k += 3 + size + val)
	{
		if(buffer[0 + k] != 0x9F || buffer[1 + k] != 0x80)
		{
			cs_log_dbg(D_DVBAPI, "Received unknown PMT command: %02x", buffer[0 + k]);
			break;
		}

		if(k > 0)
			cs_log_dump_dbg(D_DVBAPI, buffer + k, len - k, "Parsing next PMT object(s):");

		if(buffer[3 + k] & 0x80)
		{
			val = 0;
			size = buffer[3 + k] & 0x7F;
			for(i = 0; i < size; i++)
				{ val = (val << 8) | buffer[i + 1 + 3 + k]; }
			size++;
		}
		else
		{
			val = buffer[3 + k] & 0x7F;
			size = 1;
		}
		switch(buffer[2 + k])
		{
		case 0x32:
			dvbapi_parse_capmt(buffer + size + 3 + k, val, connfd, NULL);
			break;
		case 0x3f:
			// 9F 80 3f 04 83 02 00 <demux index>
			cs_log_dump_dbg(D_DVBAPI, buffer, len, "capmt 3f:");
			// ipbox fix
			if(cfg.dvbapi_boxtype == BOXTYPE_IPBOX || cfg.dvbapi_listenport)
			{
				int32_t demux_index = buffer[7 + k];
				for(i = 0; i < MAX_DEMUX; i++)
				{
					// 0xff demux_index is a wildcard => close all related demuxers
					if (demux_index == 0xff)
					{
						if (demux[i].socket_fd == connfd)
							dvbapi_stop_descrambling(i);
					}
					else if (demux[i].demux_index == demux_index)
					{
						dvbapi_stop_descrambling(i);
						break;
					}
				}
				if (cfg.dvbapi_boxtype == BOXTYPE_IPBOX)
				{
					// check do we have any demux running on this fd
					int16_t execlose = 1;
					for(i = 0; i < MAX_DEMUX; i++)
					{
						if(demux[i].socket_fd == connfd)
						{
							execlose = 0;
							break;
						}
					}
					if(execlose)
					{
						int32_t ret = close(connfd);
						if(ret < 0) { cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno)); }
					}
				}
			}
			else
			{
				if(cfg.dvbapi_pmtmode != 6)
				{
					int32_t ret = close(connfd);
					if(ret < 0) { cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno)); }
				}
			}
			break;
		default:
			cs_log_dbg(D_DVBAPI, "handlesockmsg() unknown command");
			cs_log_dump(buffer, len, "unknown command:");
			break;
		}
	}
}

int32_t dvbapi_init_listenfd(void)
{
	int32_t clilen, listenfd;
	struct sockaddr_un servaddr;

	memset(&servaddr, 0, sizeof(struct sockaddr_un));
	servaddr.sun_family = AF_UNIX;
	cs_strncpy(servaddr.sun_path, devices[selected_box].cam_socket_path, sizeof(servaddr.sun_path));
	clilen = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

	if((unlink(devices[selected_box].cam_socket_path) < 0) && (errno != ENOENT))
		{ return 0; }
	if((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{ return 0; }
	if(bind(listenfd, (struct sockaddr *)&servaddr, clilen) < 0)
		{ return 0; }
	if(listen(listenfd, 5) < 0)
		{ return 0; }

	// change the access right on the camd.socket
	// this will allow oscam to run as root if needed
	// and still allow non root client to connect to the socket
	chmod(devices[selected_box].cam_socket_path, S_IRWXU | S_IRWXG | S_IRWXO);

	return listenfd;
}

int32_t dvbapi_net_init_listenfd(void)
{
	int32_t listenfd;
	struct SOCKADDR servaddr;

	memset(&servaddr, 0, sizeof(servaddr));
	SIN_GET_FAMILY(servaddr) = DEFAULT_AF;
	SIN_GET_ADDR(servaddr) = ADDR_ANY;
	SIN_GET_PORT(servaddr) = htons((uint16_t)cfg.dvbapi_listenport);

	if((listenfd = socket(DEFAULT_AF, SOCK_STREAM, 0)) < 0)
		{ return 0; }

	int32_t opt = 0;
#ifdef IPV6SUPPORT
	// set the server socket option to listen on IPv4 and IPv6 simultaneously
	setsockopt(listenfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&opt, sizeof(opt));
#endif

	opt = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt));
	set_so_reuseport(listenfd);

	if(bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		{ return 0; }
	if(listen(listenfd, 5) < 0)
		{ return 0; }

	return listenfd;
}

static pthread_mutex_t event_handler_lock;

void event_handler(int32_t UNUSED(signal))
{
	struct stat pmt_info;
	char dest[1024];
	DIR *dirp;
	struct dirent entry, *dp = NULL;
	int32_t i, pmt_fd;
	uchar mbuf[2048]; // dirty fix: larger buffer needed for CA PMT mode 6 with many parallel channels to decode
	if(dvbapi_client != cur_client()) { return; }

	pthread_mutex_lock(&event_handler_lock);

	if(cfg.dvbapi_boxtype == BOXTYPE_PC || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
		{ pausecam = 0; }
	else
	{
		int32_t standby_fd = open(STANDBY_FILE, O_RDONLY);
		pausecam = (standby_fd > 0) ? 1 : 0;
		if(standby_fd > 0)
		{
			int32_t ret = close(standby_fd);
			if(ret < 0) { cs_log("ERROR: Could not close standby fd (errno=%d %s)", errno, strerror(errno)); }
		}
	}

	if(cfg.dvbapi_boxtype == BOXTYPE_IPBOX || cfg.dvbapi_pmtmode == 1)
	{
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	for(i = 0; i < MAX_DEMUX; i++)
	{
		if(demux[i].pmt_file[0] != 0)
		{
			snprintf(dest, sizeof(dest), "%s%s", TMPDIR, demux[i].pmt_file);
			pmt_fd = open(dest, O_RDONLY);
			if(pmt_fd > 0)
			{
				if(fstat(pmt_fd, &pmt_info) != 0)
				{
					int32_t ret = close(pmt_fd);
					if(ret < 0) { cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno)); }
					continue;
				}

				if((time_t)pmt_info.st_mtime != demux[i].pmt_time)
				{
					dvbapi_stop_descrambling(i);
				}

				int32_t ret = close(pmt_fd);
				if(ret < 0) { cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno)); }
				continue;
			}
			else
			{
				cs_log("Demuxer %d Unable to open PMT file %s -> stop descrambling!", i, dest);
				dvbapi_stop_descrambling(i);
			}
		}
	}

	if(disable_pmt_files)
	{
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	dirp = opendir(TMPDIR);
	if(!dirp)
	{
		cs_log_dbg(D_DVBAPI, "opendir failed (errno=%d %s)", errno, strerror(errno));
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	while(!cs_readdir_r(dirp, &entry, &dp))
	{
		if(!dp) { break; }

		if(strlen(dp->d_name) < 7)
			{ continue; }
		if(strncmp(dp->d_name, "pmt", 3) != 0 || strncmp(dp->d_name + strlen(dp->d_name) - 4, ".tmp", 4) != 0)
			{ continue; }
#ifdef WITH_STAPI
		struct s_dvbapi_priority *p;
		for(p = dvbapi_priority; p != NULL; p = p->next)  // stapi: check if there is a device connected to this pmt file!
		{
			if(p->type != 's') { continue; }  // stapi rule?
			if(strcmp(dp->d_name, p->pmtfile) != 0) { continue; }  // same file?
			break; // found match!
		}
		if(p == NULL)
		{
			cs_log_dbg(D_DVBAPI, "No matching S: line in oscam.dvbapi for pmtfile %s -> skip!", dp->d_name);
			continue;
		}
#endif
		snprintf(dest, sizeof(dest), "%s%s", TMPDIR, dp->d_name);
		pmt_fd = open(dest, O_RDONLY);
		if(pmt_fd < 0)
			{ continue; }

		if(fstat(pmt_fd, &pmt_info) != 0)
		{
			int32_t ret = close(pmt_fd);
			if(ret < 0) { cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno)); }
			continue;
		}

		int32_t found = 0;
		for(i = 0; i < MAX_DEMUX; i++)
		{
			if(strcmp(demux[i].pmt_file, dp->d_name) == 0)
			{
				if((time_t)pmt_info.st_mtime == demux[i].pmt_time)
				{
					found = 1;
					continue;
				}
				dvbapi_stop_descrambling(i);
			}
		}
		if(found)
		{
			int32_t ret = close(pmt_fd);
			if(ret < 0) { cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno)); }
			continue;
		}

		cs_log_dbg(D_DVBAPI, "found pmt file %s", dest);
		cs_sleepms(100);

		uint32_t len = read(pmt_fd, mbuf, sizeof(mbuf));
		int32_t ret = close(pmt_fd);
		if(ret < 0) { cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno)); }

		if(len < 1)
		{
			cs_log_dbg(D_DVBAPI, "pmt file %s have invalid len!", dest);
			continue;
		}

		int32_t pmt_id;

#ifdef QBOXHD
		uint32_t j1, j2;
		// QboxHD pmt.tmp is the full capmt written as a string of hex values
		// pmt.tmp must be longer than 3 bytes (6 hex chars) and even length
		if((len < 6) || ((len % 2) != 0) || ((len / 2) > sizeof(dest)))
		{
			cs_log_dbg(D_DVBAPI, "error parsing QboxHD pmt.tmp, incorrect length");
			continue;
		}

		for(j2 = 0, j1 = 0; j2 < len; j2 += 2, j1++)
		{
			unsigned int tmp;
			if(sscanf((char *)mbuf + j2, "%02X", &tmp) != 1)
			{
				cs_log_dbg(D_DVBAPI, "error parsing QboxHD pmt.tmp, data not valid in position %d", j2);
				pthread_mutex_unlock(&event_handler_lock);
				return;
			}
			else
			{
				memcpy(dest + j1, &tmp, 4);
			}
		}

		cs_log_dump_dbg(D_DVBAPI, (unsigned char *)dest, len / 2, "QboxHD pmt.tmp:");
		pmt_id = dvbapi_parse_capmt((unsigned char *)dest + 4, (len / 2) - 4, -1, dp->d_name);
#else
		if(len > sizeof(dest))
		{
			cs_log_dbg(D_DVBAPI, "event_handler() dest buffer is to small for pmt data!");
			continue;
		}
		if(len < 16)
		{
			cs_log_dbg(D_DVBAPI, "event_handler() received pmt is too small! (%d < 16 bytes!)", len);
			continue;
		}
		cs_log_dump_dbg(D_DVBAPI, mbuf, len, "pmt:");

		dest[0] = 0x03;
		dest[1] = mbuf[3];
		dest[2] = mbuf[4];
		uint32_t pmt_program_length = b2i(2, mbuf + 10)&0xFFF;
		i2b_buf(2, pmt_program_length + 1, (uchar *) dest + 4);
		dest[6] = 0;

		memcpy(dest + 7, mbuf + 12, len - 12 - 4);

		pmt_id = dvbapi_parse_capmt((uchar *)dest, 7 + len - 12 - 4, -1, dp->d_name);
#endif

		if(pmt_id >= 0)
		{
			cs_strncpy(demux[pmt_id].pmt_file, dp->d_name, sizeof(demux[pmt_id].pmt_file));
			demux[pmt_id].pmt_time = (time_t)pmt_info.st_mtime;
		}

		if(cfg.dvbapi_pmtmode == 3)
		{
			disable_pmt_files = 1;
			break;
		}
	}
	closedir(dirp);
	pthread_mutex_unlock(&event_handler_lock);
}

void *dvbapi_event_thread(void *cli)
{
	struct s_client *client = (struct s_client *) cli;
	pthread_setspecific(getclient, client);
	set_thread_name(__func__);
	while(1)
	{
		cs_sleepms(750);
		event_handler(0);
	}

	return NULL;
}

void dvbapi_process_input(int32_t demux_id, int32_t filter_num, uchar *buffer, int32_t len)
{
	struct s_ecmpids *curpid = &demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex];
	int32_t pid = demux[demux_id].demux_fd[filter_num].pidindex; //DeepThought: pid could be -1
	uint32_t chid = 0x10000;
	uint32_t ecmlen = (b2i(2, buffer + 1)&0xFFF)+3;

	if(demux[demux_id].demux_fd[filter_num].type == TYPE_ECM)
	{
		if(len != 0)  // len = 0 receiver encountered an internal bufferoverflow!
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d fetched ECM data (ecmlength = %03X)", demux_id, filter_num + 1, ecmlen);
			if((uint) len  < ecmlen) // invalid CAT length
			{
				cs_log_dbg(D_DVBAPI, "Received data with total length %03X but ECM length is %03X -> invalid CAT length!", len, ecmlen);
				return;
			}

			if(!(buffer[0] == 0x80 || buffer[0] == 0x81))
			{
				cs_log_dbg(D_DVBAPI, "Received an ECM with invalid ecmtable ID %02X -> ignoring!", buffer[0]);
				return;
			}

			if(curpid->table == buffer[0] && curpid->CAID >> 8 != 0x06)  // wait for odd / even ecm change (only not for irdeto!)
				{ return; }

			if(curpid->CAID >> 8 == 0x06)  //irdeto cas
			{
				// 80 70 39 53 04 05 00 88
				// 81 70 41 41 01 06 00 13 00 06 80 38 1F 52 93 D2
				//if (buffer[5]>20) return;
				if(curpid->irdeto_maxindex != buffer[5])    //6, register max irdeto index
				{
					cs_log_dbg(D_DVBAPI, "Found %d IRDETO ECM CHIDs", buffer[5] + 1);
					curpid->irdeto_maxindex = buffer[5]; // numchids = 7 (0..6)
				}
			}
		}
		ECM_REQUEST *er;
		if(!(er = get_ecmtask())) { return; }

		er->srvid = demux[demux_id].program_number;

		er->tsid = demux[demux_id].tsid;
		er->onid = demux[demux_id].onid;
		er->pmtpid = demux[demux_id].pmtpid;
		er->ens = demux[demux_id].enigma_namespace;

		er->caid  = curpid->CAID;
		er->pid   = curpid->ECM_PID;
		er->prid  = curpid->PROVID;
		er->vpid  = curpid->VPID;
		er->ecmlen = ecmlen;
		memcpy(er->ecm, buffer, er->ecmlen);

		chid = get_subid(er); // fetch chid or fake chid
		er->chid = chid;
		
		if(len == 0) // only used on receiver internal bufferoverflow to get quickly fresh ecm filterdata otherwise freezing! 
		{
			curpid->table = 0;
			dvbapi_set_section_filter(demux_id, er);
			NULLFREE(er);
			return;
		}

		if(curpid->CAID >> 8 == 0x06)  //irdeto cas
		{

			if(curpid->irdeto_curindex != buffer[4])   // old style wrong irdeto index
			{
				if(curpid->irdeto_curindex == 0xFE)  // check if this ecmfilter just started up
				{
					curpid->irdeto_curindex = buffer[4]; // on startup set the current index to the irdeto index of the ecm
				}
				else   // we are already running and not interested in this ecm
				{
					if(curpid->table != buffer[0]) curpid->table = 0; // fix for receivers not supporting section filtering
					dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
					NULLFREE(er);
					return;
				}
			}
			else //fix for receivers not supporting section filtering
			{
				if(curpid->table == buffer[0]){
					NULLFREE(er);
					return;
				}
			}
			cs_log_dbg(D_DVBAPI, "Demuxer %d ECMTYPE %02X CAID %04X PROVID %06X ECMPID %04X IRDETO INDEX %02X MAX INDEX %02X CHID %04X CYCLE %02X VPID %04X", demux_id, er->ecm[0], er->caid, er->prid, er->pid, er->ecm[4], er->ecm[5], er->chid, curpid->irdeto_cycle, er->vpid);
		}
		else
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d ECMTYPE %02X CAID %04X PROVID %06X ECMPID %04X FAKECHID %04X (unique part in ecm)",
						  demux_id, er->ecm[0], er->caid, er->prid, er->pid, er->chid);
		}

		// check for matching chid (unique ecm part in case of non-irdeto cas) + added fix for seca2 monthly changing fakechid 
		if((curpid->CHID < 0x10000) && !((chid == curpid->CHID) || ((curpid->CAID >> 8 == 0x01) && (chid&0xF0FF) == (curpid->CHID&0xF0FF)) ) )  
		{
			if(curpid->CAID >> 8 == 0x06)
			{

				if((curpid->irdeto_cycle < 0xFE) && curpid->irdeto_cycle == buffer[4])   // if same: we cycled all indexes but no luck!
				{
					struct s_dvbapi_priority *forceentry = dvbapi_check_prio_match(demux_id, pid, 'p');
					if(!forceentry || !forceentry->force)   // forced pid? keep trying the forced ecmpid, no force kill ecm filter
					{
						if(curpid->checked == 2) { curpid->checked = 4; }
						if(curpid->checked == 1)
						{
							curpid->checked = 2;
							curpid->CHID = 0x10000;
						}
						dvbapi_stop_filternum(demux_id, filter_num); // stop this ecm filter!
						NULLFREE(er);
						return;
					}
				}
				if(curpid->irdeto_cycle == 0xFE) { curpid->irdeto_cycle = buffer[4]; }  // register irdeto index of current ecm

				curpid->irdeto_curindex++; // set check on next index
				if(curpid->irdeto_curindex > curpid->irdeto_maxindex) { curpid->irdeto_curindex = 0; }  // check if we reached max irdeto index, if so reset to 0

				curpid->table = 0;
				dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
				NULLFREE(er);
				return;
			}
			else  // all nonirdeto cas systems
			{
				struct s_dvbapi_priority *forceentry = dvbapi_check_prio_match(demux_id, pid, 'p');
				curpid->table = 0;
				dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
				if(forceentry && forceentry->force)
				{
					NULLFREE(er);
					return; // forced pid? keep trying the forced ecmpid!
				}
				if(curpid->checked == 2) { curpid->checked = 4; }
				if(curpid->checked == 1)
				{
					curpid->checked = 2;
					curpid->CHID = 0x10000;
				}
				dvbapi_stop_filternum(demux_id, filter_num); // stop this ecm filter!
				NULLFREE(er);
				return;
			}
		}

		struct s_dvbapi_priority *p;

		for(p = dvbapi_priority; p != NULL; p = p->next)
		{
			if(p->type != 'l'
					|| (p->caid && p->caid != curpid->CAID)
					|| (p->provid && p->provid != curpid->PROVID)
					|| (p->ecmpid && p->ecmpid != curpid->ECM_PID)
					|| (p->srvid && p->srvid != demux[demux_id].program_number))
				{ continue; }

			if((uint)p->delay == ecmlen && p->force < 6)
			{
				p->force++;
				NULLFREE(er);
				return;
			}
			if(p->force >= 6)
				{ p->force = 0; }
		}

		if(!curpid->PROVID)
			{ curpid->PROVID = chk_provid(buffer, curpid->CAID); }

		if((curpid->CAID >> 8) == 0x06)   // irdeto: wait for the correct index
		{
			if(buffer[4] != curpid->irdeto_curindex)
			{
				curpid->table = 0;
				dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
				NULLFREE(er);
				return;
			}
		}
		// we have an ecm with the correct irdeto index (or fakechid)
		for(p = dvbapi_priority; p != NULL ; p = p->next)  // check for ignore!
		{
			if((p->type != 'i')
					|| (p->caid && p->caid != curpid->CAID)
					|| (p->provid && p->provid != curpid->PROVID)
					|| (p->ecmpid && p->ecmpid != curpid->ECM_PID)
					|| (p->pidx && p->pidx-1 != pid) 
					|| (p->srvid && p->srvid != demux[demux_id].program_number))
				{ continue; }

			if(p->type == 'i' && (p->chid < 0x10000 && p->chid == chid))    // found a ignore chid match with current ecm -> ignoring this irdeto index
			{
				curpid->irdeto_curindex++;
				if(curpid->irdeto_curindex > curpid->irdeto_maxindex)    // check if curindex is over the max
				{
					curpid->irdeto_curindex = 0;
				}
				curpid->table = 0;
				if((curpid->CAID >> 8) == 0x06)   // irdeto: wait for the correct index
				{
					dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this chid has to be ignored!
				}
				else // this fakechid has to be ignored, kill this filter!
				{
					if(curpid->checked == 2) { curpid->checked = 4; }
					if(curpid->checked == 1)
					{
						curpid->checked = 2;
						curpid->CHID = 0x10000;
					}
					dvbapi_stop_filternum(demux_id, filter_num); // stop this ecm filter!
				}
				NULLFREE(er);
				return;
			}
		}
		if (er){
			curpid->table = er->ecm[0];
		}
		request_cw(dvbapi_client, er, demux_id, 1); // register this ecm for delayed ecm response check
		return; // end of ecm filterhandling!
	}

	if(demux[demux_id].demux_fd[filter_num].type == TYPE_EMM)
	{
		if(demux[demux_id].demux_fd[filter_num].pid == 0x01) // CAT
		{
			cs_log_dbg(D_DVBAPI, "receiving cat");
			dvbapi_parse_cat(demux_id, buffer, len);

			dvbapi_stop_filternum(demux_id, filter_num);
			return;
		}
		dvbapi_process_emm(demux_id, filter_num, buffer, len);
	}

	// emm filter iteration
	if(!ll_emm_active_filter)
		{ ll_emm_active_filter = ll_create("ll_emm_active_filter"); }

	if(!ll_emm_inactive_filter)
		{ ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter"); }

	if(!ll_emm_pending_filter)
		{ ll_emm_pending_filter = ll_create("ll_emm_pending_filter"); }

	uint32_t filter_count = ll_count(ll_emm_active_filter) + ll_count(ll_emm_inactive_filter);

	if(demux[demux_id].max_emm_filter > 0
			&& ll_count(ll_emm_inactive_filter) > 0
			&& filter_count > demux[demux_id].max_emm_filter)
	{

		int32_t filter_queue = ll_count(ll_emm_inactive_filter);
		int32_t stopped = 0, started = 0;
		struct timeb now;
		cs_ftime(&now);

		struct s_emm_filter *filter_item;
		LL_ITER itr;
		itr = ll_iter_create(ll_emm_active_filter);

		while((filter_item = ll_iter_next(&itr)) != NULL)
		{
			if(!ll_count(ll_emm_inactive_filter) || started == filter_queue)
				{ break; }
			int64_t gone = comp_timeb(&now, &filter_item->time_started); 
			if( gone > 45*1000)
			{
				struct s_dvbapi_priority *forceentry = dvbapi_check_prio_match_emmpid(filter_item->demux_id, filter_item->caid,
													   filter_item->provid, 'p');

				if(!forceentry || (forceentry && !forceentry->force))
				{
					cs_log_dbg(D_DVBAPI, "Removing emm filter %d on demux index %d", filter_item->num, filter_item->demux_id);
					dvbapi_stop_filternum(filter_item->demux_id, filter_item->num - 1);
					ll_iter_remove_data(&itr);
					add_emmfilter_to_list(filter_item->demux_id, filter_item->filter, filter_item->caid,
										  filter_item->provid, filter_item->pid, -1, false);
					stopped++;
				}
			}

			int32_t ret;
			if(stopped > started)
			{
				struct s_emm_filter *filter_item2;
				LL_ITER itr2 = ll_iter_create(ll_emm_inactive_filter);

				while((filter_item2 = ll_iter_next(&itr2)))
				{
					cs_log_dump_dbg(D_DVBAPI, filter_item2->filter, 32, "Starting emm filter pid: 0x%04X on demux index %i", filter_item2->pid, filter_item2->demux_id);
					ret = dvbapi_set_filter(filter_item2->demux_id, selected_api, filter_item2->pid, filter_item2->caid,
											filter_item2->provid, filter_item2->filter, filter_item2->filter + 16, 0,
											demux[filter_item2->demux_id].pidindex, TYPE_EMM, 1);
					if(ret != -1)
					{
						ll_iter_remove_data(&itr2);
						started++;
						break;
					}
				}
			}
		}

		itr = ll_iter_create(ll_emm_pending_filter);

		while((filter_item = ll_iter_next(&itr)) != NULL)
		{
			add_emmfilter_to_list(filter_item->demux_id, filter_item->filter, filter_item->caid, filter_item->provid, filter_item->pid, 0, false);
			ll_iter_remove_data(&itr);
		}
	}
}

static void *dvbapi_main_local(void *cli)
{
	int32_t i, j;
	struct s_client *client = (struct s_client *) cli;
	client->thread = pthread_self();
	pthread_setspecific(getclient, cli);

	dvbapi_client = cli;

	int32_t maxpfdsize = (MAX_DEMUX * maxfilter) + MAX_DEMUX + 2;
	struct pollfd pfd2[maxpfdsize];
	struct timeb start, end;  // start time poll, end time poll
#define PMT_SERVER_SOCKET "/tmp/.listen.camd.socket"
	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, PMT_SERVER_SOCKET, 107);
	saddr.sun_path[107] = '\0';

	int32_t rc, pfdcount, g, connfd, clilen;
	int32_t ids[maxpfdsize], fdn[maxpfdsize], type[maxpfdsize];
	struct SOCKADDR servaddr;
	ssize_t len = 0;
	uchar mbuf[1024];

	struct s_auth *account;
	int32_t ok = 0;
	for(account = cfg.account; account != NULL; account = account->next)
	{
		if((ok = is_dvbapi_usr(account->usr)))
			{ break; }
	}
	cs_auth_client(client, ok ? account : (struct s_auth *)(-1), "dvbapi");

	memset(demux, 0, sizeof(struct demux_s) * MAX_DEMUX);
	memset(ca_fd, 0, sizeof(ca_fd));
	memset(unassoc_fd, 0, sizeof(unassoc_fd));

	dvbapi_read_priority();
	dvbapi_load_channel_cache();
	dvbapi_detect_api();

	if(selected_box == -1 || selected_api == -1)
	{
		cs_log("ERROR: Could not detect DVBAPI version.");
		return NULL;
	}

	if(cfg.dvbapi_pmtmode == 1)
		{ disable_pmt_files = 1; }

	int32_t listenfd = -1;
	if(cfg.dvbapi_boxtype != BOXTYPE_IPBOX_PMT && cfg.dvbapi_pmtmode != 2 && cfg.dvbapi_pmtmode != 5 && cfg.dvbapi_pmtmode != 6)
	{
		if (!cfg.dvbapi_listenport)
			listenfd = dvbapi_init_listenfd();
		else
			listenfd = dvbapi_net_init_listenfd();
		if(listenfd < 1)
		{
			cs_log("ERROR: Could not init socket: (errno=%d: %s)", errno, strerror(errno));
			return NULL;
		}
	}

	pthread_mutex_init(&event_handler_lock, NULL);

	for(i = 0; i < MAX_DEMUX; i++)  // init all demuxers!
	{
		demux[i].pidindex = -1;
		demux[i].curindex = -1;
	}

	if(cfg.dvbapi_pmtmode != 4 && cfg.dvbapi_pmtmode != 5 && cfg.dvbapi_pmtmode != 6)
	{
		struct sigaction signal_action;
		signal_action.sa_handler = event_handler;
		sigemptyset(&signal_action.sa_mask);
		signal_action.sa_flags = SA_RESTART;
		sigaction(SIGRTMIN + 1, &signal_action, NULL);

		dir_fd = open(TMPDIR, O_RDONLY);
		if(dir_fd >= 0)
		{
			fcntl(dir_fd, F_SETSIG, SIGRTMIN + 1);
			fcntl(dir_fd, F_NOTIFY, DN_MODIFY | DN_CREATE | DN_DELETE | DN_MULTISHOT);
			event_handler(SIGRTMIN + 1);
		}
	}
	else
	{
		pthread_t event_thread;
		int32_t ret = pthread_create(&event_thread, NULL, dvbapi_event_thread, (void *) dvbapi_client);
		if(ret)
		{
			cs_log("ERROR: Can't create dvbapi event thread (errno=%d %s)", ret, strerror(ret));
			return NULL;
		}
		else
			{ pthread_detach(event_thread); }
	}

	if(listenfd != -1)
	{
		pfd2[0].fd = listenfd;
		pfd2[0].events = (POLLIN | POLLPRI);
		type[0] = 1;
	}

#ifdef WITH_COOLAPI
	system("pzapit -rz");
#endif
	cs_ftime(&start); // register start time
	while(1)
	{
		if(pausecam)  // for dbox2, STAPI or PC in standby mode dont parse any ecm/emm or try to start next filter
			{ continue; }

		if(cfg.dvbapi_pmtmode == 6)
		{
			if(listenfd < 0)
			{
				cs_log("PMT6: Trying connect to enigma CA PMT listen socket...");
				/* socket init */
				if((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
				{
					
					cs_log("socket error (errno=%d %s)", errno, strerror(errno));
					listenfd = -1;
				}
				else if(connect(listenfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
				{
					cs_log("socket connect error (errno=%d %s)", errno, strerror(errno));
					close(listenfd);
					listenfd = -1;
				}
				else
				{
					pfd2[0].fd = listenfd;
					pfd2[0].events = (POLLIN | POLLPRI);
					type[0] = 1;
					cs_log("PMT6 CA PMT Server connected on fd %d!", listenfd);
				}
			}

		}
		pfdcount = (listenfd > -1) ? 1 : 0;

		for(i = 0; i < MAX_DEMUX; i++)
		{	
			// add client fd's which are not yet associated with the demux but needs to be polled for data
			if (unassoc_fd[i]) {
				pfd2[pfdcount].fd = unassoc_fd[i];
				pfd2[pfdcount].events = (POLLIN | POLLPRI);
				type[pfdcount++] = 1;
			}

			if(demux[i].program_number == 0) { continue; }  // only evalutate demuxers that have channels assigned
			
			uint32_t ecmcounter = 0, emmcounter = 0;
			for(g = 0; g < maxfilter; g++)
			{
				if(demux[i].demux_fd[g].fd <= 0) continue; // deny obvious invalid fd!
				
				if(!cfg.dvbapi_listenport && cfg.dvbapi_boxtype != BOXTYPE_PC_NODMX && selected_api != STAPI && selected_api != COOLAPI)
				{
					pfd2[pfdcount].fd = demux[i].demux_fd[g].fd;
					pfd2[pfdcount].events = (POLLIN | POLLPRI);
					ids[pfdcount] = i;
					fdn[pfdcount] = g;
					type[pfdcount++] = 0;
				}
				if(demux[i].demux_fd[g].type == TYPE_ECM) { ecmcounter++; }  // count ecm filters to see if demuxing is possible anyway
				if(demux[i].demux_fd[g].type == TYPE_EMM) { emmcounter++; }  // count emm filters also
			}
			if(ecmcounter != demux[i].old_ecmfiltercount || emmcounter != demux[i].old_emmfiltercount)   // only produce log if something changed
			{
				cs_log_dbg(D_DVBAPI, "Demuxer %d has %d ecmpids, %d streampids, %d ecmfilters and %d of max %d emmfilters", i, demux[i].ECMpidcount,
							  demux[i].STREAMpidcount-1, ecmcounter, emmcounter, demux[i].max_emm_filter);
				demux[i].old_ecmfiltercount = ecmcounter; // save new amount of ecmfilters
				demux[i].old_emmfiltercount = emmcounter; // save new amount of emmfilters
			}

			// delayed emm start for non irdeto caids, start emm cat if not already done for this demuxer!
			
			struct timeb now;
			cs_ftime(&now);
			
			if(cfg.dvbapi_au > 0 && demux[i].emm_filter == -1 && demux[i].EMMpidcount == 0 && emmcounter == 0)
			{
				int64_t gone = comp_timeb(&now, &demux[i].emmstart);
				if(gone > 30*1000){
					cs_ftime(&demux[i].emmstart); // trick to let emm fetching start after 30 seconds to speed up zapping
					dvbapi_start_filter(i, demux[i].pidindex, 0x001, 0x001, 0x01, 0x01, 0xFF, 0, TYPE_EMM); //CAT
				}
				//continue; // proceed with next demuxer
			}

			//early start for irdeto since they need emm before ecm (pmt emmstart = 1 if detected caid 0x06)
			int32_t emmstarted = demux[i].emm_filter;
			if(cfg.dvbapi_au && demux[i].EMMpidcount > 0)   // check every time since share readers might give us new filters due to hexserial change
			{
				if(!emmcounter && emmstarted == -1)
				{
					demux[i].emmstart = now;
					dvbapi_start_emm_filter(i); // start emmfiltering if emmpids are found
				}
				else
				{
					int64_t gone = comp_timeb(&now, &demux[i].emmstart);
					if(gone > 30*1000)
					{
						demux[i].emmstart = now;
						dvbapi_start_emm_filter(i); // start emmfiltering delayed if filters already were running
					}
				}
				//if(emmstarted != demux[i].emm_filter && !emmcounter) { continue; }  // proceed with next demuxer if no emms where running before
			}

			if(ecmcounter == 0 && demux[i].ECMpidcount > 0)   // Restart decoding all caids we have ecmpids but no ecm filters!
			{

				int32_t started = 0;

				for(g = 0; g < demux[i].ECMpidcount; g++)  // avoid race: not all pids are asked and checked out yet!
				{
					if(demux[i].ECMpids[g].checked == 0 && demux[i].ECMpids[g].status >= 0)  // check if prio run is done
					{
						dvbapi_try_next_caid(i, 0); // not done, so start next prio pid
						started = 1;
						break;
					}
				}
				if(started) { continue; }  // if started a filter proceed with next demuxer

				if(g == demux[i].ECMpidcount)   // all usable pids (with prio) are tried, lets start over again without prio!
				{
					for(g = 0; g < demux[i].ECMpidcount; g++)  // avoid race: not all pids are asked and checked out yet!
					{
						if(demux[i].ECMpids[g].checked == 2 && demux[i].ECMpids[g].status >= 0)  // check if noprio run is done
						{
							demux[i].ECMpids[g].irdeto_curindex = 0xFE;
							demux[i].ECMpids[g].irdeto_maxindex = 0;
							demux[i].ECMpids[g].irdeto_cycle = 0xFE;
							demux[i].ECMpids[g].tries = 0xFE;
							demux[i].ECMpids[g].table = 0;
							demux[i].ECMpids[g].CHID = 0x10000; // remove chid prio
							dvbapi_try_next_caid(i, 2); // not done, so start next no prio pid
							started = 1;
							break;
						}
					}
				}
				if(started) { continue; }  // if started a filter proceed with next demuxer

				if(g == demux[i].ECMpidcount)   // all usable pids are tried, lets start over again!
				{
					if(demux[i].decodingtries == -1) // first redecoding attempt?
					{
						cs_ftime(&demux[i].decstart);
						for(g = 0; g < demux[i].ECMpidcount; g++)  // reinit some used things from second run (without prio)
						{
							demux[i].ECMpids[g].checked = 0;
							demux[i].ECMpids[g].irdeto_curindex = 0xFE;
							demux[i].ECMpids[g].irdeto_maxindex = 0;
							demux[i].ECMpids[g].irdeto_cycle = 0xFE;
							demux[i].ECMpids[g].table = 0;
							demux[i].decodingtries = 0;
							dvbapi_edit_channel_cache(i, g, 0); // remove this pid from channelcache since we had no founds on any ecmpid!
						}
					}
					uint8_t number_of_enabled_pids = 0;
					demux[i].decodingtries++;
					dvbapi_resort_ecmpids(i);
					
					for(g = 0; g < demux[i].ECMpidcount; g++)  // count number of enabled pids!
					{
						if(demux[i].ECMpids[g].status >= 0) number_of_enabled_pids++;
					}
					if(!number_of_enabled_pids)
					{
						if(demux[i].decodingtries == 10)
						{
							demux[i].decodingtries = 0;
							cs_log("Demuxer %d no enabled matching ecmpids -> decoding is waiting for matching readers!",i);
						}
					}
					else
					{
						cs_ftime(&demux[i].decend);
						demux[i].decodingtries = -1; // reset to first run again!
						int64_t gone = comp_timeb(&demux[i].decend, &demux[i].decstart);
						cs_log("Demuxer %d restarting decodingrequests after %"PRId64" ms with %d enabled and %d disabled ecmpids!", i, gone, number_of_enabled_pids,
							(demux[i].ECMpidcount-number_of_enabled_pids));
						dvbapi_try_next_caid(i, 0);
					}
				}
			}

			if(demux[i].socket_fd > 0 && cfg.dvbapi_pmtmode != 6)
			{
				rc = 0;
				for(j = 0; j < pfdcount; j++)
				{
					if(pfd2[j].fd == demux[i].socket_fd)
					{
						rc = 1;
						break;
					}
				}
				if(rc == 1) { continue; }

				pfd2[pfdcount].fd = demux[i].socket_fd;
				pfd2[pfdcount].events = (POLLIN | POLLPRI);
				ids[pfdcount] = i;
				type[pfdcount++] = 1;
			}
		}

		while(1)
		{
			rc = poll(pfd2, pfdcount, 300);
			if(listenfd == -1 && cfg.dvbapi_pmtmode == 6) { break; }
			if(rc < 0)
				{ continue; }
			break;
		}

		if(rc > 0)
		{
			cs_ftime(&end); // register end time
			int64_t timeout = comp_timeb(&end, &start);
			if (timeout < 0) {
				cs_log("*** WARNING: BAD TIME AFFECTING WHOLE OSCAM ECM HANDLING ****");
			}
			cs_log_dbg(D_TRACE, "New events occurred on %d of %d handlers after %"PRId64" ms inactivity", rc, pfdcount, timeout);
			cs_ftime(&start); // register new start time for next poll
		}

		for(i = 0; i < pfdcount && rc > 0; i++)
		{
			if(pfd2[i].revents == 0) { continue; }  // skip sockets with no changes
			rc--; //event handled!
			cs_log_dbg(D_TRACE, "Now handling fd %d that reported event %d", pfd2[i].fd, pfd2[i].revents);

			if(pfd2[i].revents & (POLLHUP | POLLNVAL | POLLERR))
			{
				if(type[i] == 1)
				{
					for(j = 0; j < MAX_DEMUX; j++)
					{
						if(demux[j].socket_fd == pfd2[i].fd)  // if listenfd closes stop all assigned decoding!
						{
							dvbapi_stop_descrambling(j);
						}
					}
					int32_t ret = close(pfd2[i].fd);
					if(ret < 0 && errno != 9) { cs_log("ERROR: Could not close demuxer socket fd (errno=%d %s)", errno, strerror(errno)); }
					if(pfd2[i].fd == listenfd && cfg.dvbapi_pmtmode == 6)
					{
						listenfd = -1;
					}
				}
				else   // type = 0
				{
					int32_t demux_index = ids[i];
					int32_t n = fdn[i];
					dvbapi_stop_filternum(demux_index, n); // stop filter since its giving errors and wont return anything good.
				}
				continue; // continue with other events
			}

			if(pfd2[i].revents & (POLLIN | POLLPRI))
			{
				if(type[i] == 1 && pmthandling == 0)
				{
					pmthandling = 1;     // pmthandling in progress!
					pmt_stopmarking = 0; // to stop_descrambling marking in PMT 6 mode
					connfd = -1;         // initially no socket to read from
					int add_to_poll = 0; // we may need to additionally poll this socket when no PMT data comes in

					if (pfd2[i].fd == listenfd)
					{
						if (cfg.dvbapi_pmtmode == 6) {
							connfd = listenfd;
							disable_pmt_files = 1;
						} else {
							clilen = sizeof(servaddr);
							connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);
							cs_log_dbg(D_DVBAPI, "new socket connection fd: %d", connfd);
							if (cfg.dvbapi_listenport)
							{
								//update webif data
								client->ip = SIN_GET_ADDR(servaddr);
								client->port = ntohs(SIN_GET_PORT(servaddr));
							}
							add_to_poll = 1;

							if(cfg.dvbapi_pmtmode == 3 || cfg.dvbapi_pmtmode == 0) { disable_pmt_files = 1; }

							if(connfd <= 0)
								cs_log_dbg(D_DVBAPI, "accept() returns error on fd event %d (errno=%d %s)", pfd2[i].revents, errno, strerror(errno));
						}
					}
					else
					{
						cs_log_dbg(D_DVBAPI, "PMT Update on socket %d.", pfd2[i].fd);
						connfd = pfd2[i].fd;
					}

					//reading and completing data from socket
					if (connfd > 0) {
						uint32_t pmtlen = 0, chunks_processed = 0;

						int tries = 100;
						do {
							len = recv(connfd, mbuf + pmtlen, sizeof(mbuf) - pmtlen, MSG_DONTWAIT);
							if (len > 0)
								pmtlen += len;
							if ((cfg.dvbapi_listenport || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX) &&
								(len == 0 || (len == -1 && (errno != EINTR && errno != EAGAIN))))
							{
								//client disconnects, stop all assigned decoding
								cs_log_dbg(D_DVBAPI, "Socket %d reported connection close", connfd);
								int active_conn = 0; //other active connections counter
								for (j = 0; j < MAX_DEMUX; j++)
								{
									if (demux[j].socket_fd == connfd)
										dvbapi_stop_descrambling(j);
									else if (demux[j].socket_fd)
										active_conn++;
									// remove from unassoc_fd when necessary
									if (unassoc_fd[j] == connfd)
										unassoc_fd[j] = 0;
								}
								close(connfd);
								connfd = -1;
								add_to_poll = 0;
								if (!active_conn) //last connection closed
								{
									client_proto_version = 0;
									if (client_name)
									{
										free(client_name);
										client_name = NULL;
									}
									if (cfg.dvbapi_listenport)
									{
										//update webif data
										client->ip = get_null_ip();
										client->port = 0;
									}
								}
								break;
							}
							if (pmtlen >= 8) //if we received less then 8 bytes, than it's not complete for sure
							{
								// check and try to process complete PMT objects and filter data by chunks to avoid PMT buffer overflows
								uint32_t opcode_ptr;
								memcpy(&opcode_ptr, &mbuf[0], 4);                     //used only to silent compiler warning about dereferencing type-punned pointer
								uint32_t opcode = ntohl(opcode_ptr);                  //get the client opcode (4 bytes)
								uint32_t chunksize = 0;                               //size of complete chunk in the buffer (an opcode with the data)
								uint32_t data_len = 0;                                //variable for internal data length (eg. for the filter data size, PMT len)

								//detect the opcode, its size (chunksize) and its internal data size (data_len)
								if ((opcode & 0xFFFFF000) == DVBAPI_AOT_CA)
								{
									// parse packet size (ASN.1)
									uint32_t size = 0;
									if (mbuf[3] & 0x80)
									{
										data_len = 0;
										size = mbuf[3] & 0x7F;
										if (pmtlen > 4 + size)
										{
											uint32_t k;
											for (k = 0; k < size; k++)
												data_len = (data_len << 8) | mbuf[3 + 1 + k];
											size++;
										}
									}
									else
									{
										data_len = mbuf[3] & 0x7F;
										size = 1;
									}
									chunksize = 3 + size + data_len;
								}
								else switch (opcode)
								{
									case DVBAPI_FILTER_DATA:
									{
										data_len = b2i(2, mbuf + 7) & 0x0FFF;
										chunksize = 6 + 3 + data_len;
										break;
									}
									case DVBAPI_CLIENT_INFO:
									{
										data_len = mbuf[6];
										chunksize = 6 + 1 + data_len;
										break;
									}
									default:
										cs_log("Unknown socket command received: 0x%08X", opcode);
								}

								//processing the complete data according to type
								if (chunksize < sizeof(mbuf) && chunksize <= pmtlen) // only handle if we fetched a complete chunksize!
								{
									chunks_processed++;
									if ((opcode & 0xFFFFF000) == DVBAPI_AOT_CA)
									{
										cs_log_dump_dbg(D_DVBAPI, mbuf, chunksize, "Parsing %d PMT object(s):", chunks_processed);
										dvbapi_handlesockmsg(mbuf, chunksize, connfd);
										add_to_poll = 0;
										if (cfg.dvbapi_listenport && opcode == DVBAPI_AOT_CA_STOP)
											add_to_poll = 1;
									}
									else switch (opcode)
									{
										case DVBAPI_FILTER_DATA:
										{
											int32_t demux_index = mbuf[4];
											int32_t filter_num = mbuf[5];
											dvbapi_process_input(demux_index, filter_num, mbuf + 6, data_len + 3);
											break;
										}
										case DVBAPI_CLIENT_INFO:
										{
											uint16_t client_proto_ptr;
											memcpy(&client_proto_ptr, &mbuf[4], 2);
											uint16_t client_proto = ntohs(client_proto_ptr);
											if (client_name)
												free(client_name);
											if (cs_malloc(&client_name, data_len + 1))
											{
												memcpy(client_name, &mbuf[7], data_len);
												client_name[data_len] = 0;
												cs_log("Client connected: '%s' (protocol version = %d)", client_name, client_proto);
											}
											client_proto_version = client_proto; //setting the global var according to the client

											// as a response we are sending our info to the client:
											dvbapi_net_send(DVBAPI_SERVER_INFO, connfd, -1, -1, NULL);
											break;
										}
									}

									if (pmtlen == chunksize) // if we fetched and handled the exact chunksize reset buffer counter! 
										pmtlen = 0;

									// if we read more data then processed, move it to beginning
									if (pmtlen > chunksize)
									{
										memmove(mbuf, mbuf + chunksize, pmtlen - chunksize);
										pmtlen -= chunksize;
									}
									continue;
								}
							}
							if (len <= 0) {
								if (pmtlen > 0 || chunks_processed > 0) //all data read
									break;
								else {          //wait for data become available and try again

									// remove from unassoc_fd if the socket fd is invalid
									if (errno == EBADF)
										for (j = 0; j < MAX_DEMUX; j++)
											if (unassoc_fd[j] == connfd)
												unassoc_fd[j] = 0;
									cs_sleepms(20);
									continue;
								}
							}
						} while (pmtlen < sizeof(mbuf) && tries--);

						// if the connection is new and we read no PMT data, then add it to the poll,
						// otherwise this socket will not be checked with poll when data arives
						// because fd it is not yet assigned with the demux
						if (add_to_poll) {
							for (j = 0; j < MAX_DEMUX; j++) {
								if (!unassoc_fd[j]) {
									unassoc_fd[j] = connfd;
									break;
								}
							}
						}

						if (pmtlen > 0) {
							if (pmtlen < 3)
								cs_log_dbg(D_DVBAPI, "CA PMT server message too short!");
							else {
								if (pmtlen >= sizeof(mbuf))
									cs_log("***** WARNING: PMT BUFFER OVERFLOW, PLEASE REPORT! ****** ");
								cs_log_dump_dbg(D_DVBAPI, mbuf, pmtlen, "New PMT info from socket (total size: %d)", pmtlen);
								dvbapi_handlesockmsg(mbuf, pmtlen, connfd);
							}
						}
					}
					pmthandling = 0; // pmthandling done!
					continue; // continue with other events!
				}
				else     // type==0
				{
					int32_t demux_index = ids[i];
					int32_t n = fdn[i];

					if((len = dvbapi_read_device(pfd2[i].fd, mbuf, sizeof(mbuf))) <= 0) // always read to empty receiver databuffer
					{
						if((int)demux[demux_index].demux_fd[n].fd != pfd2[i].fd) { continue; } // but if filter already killed no need to process the data!
						
						if(len < 0) // serious filterdata read error
						{
							dvbapi_stop_filternum(demux_index, n); // stop filter since its giving errors and wont return anything good.
							maxfilter--; // lower maxfilters to avoid this with new filter setups!
							continue;
						}
						if(!len) // receiver internal filterbuffer overflow
						{
							memset(mbuf, 0, sizeof(mbuf));
						}
					}

					dvbapi_process_input(demux_index, n, mbuf, len);
				}
				continue; // continue with other events!
			}
		}
	}
	return NULL;
}

void dvbapi_write_cw(int32_t demux_id, uchar *cw, int32_t pid)
{
	int32_t n;
	int8_t cwEmpty = 0;
	unsigned char nullcw[8];
	memset(nullcw, 0, 8);
	ca_descr_t ca_descr;

	memset(&ca_descr, 0, sizeof(ca_descr));

	if(memcmp(demux[demux_id].lastcw[0], nullcw, 8) == 0
			&& memcmp(demux[demux_id].lastcw[1], nullcw, 8) == 0)
		{ cwEmpty = 1; } // to make sure that both cws get written on constantcw


	for(n = 0; n < 2; n++)
	{
		char lastcw[9 * 3];
		char newcw[9 * 3];
		cs_hexdump(0, demux[demux_id].lastcw[n], 8, lastcw, sizeof(lastcw));
		cs_hexdump(0, cw + (n * 8), 8, newcw, sizeof(newcw));

		if((memcmp(cw + (n * 8), demux[demux_id].lastcw[n], 8) != 0 || cwEmpty)
				&& memcmp(cw + (n * 8), nullcw, 8) != 0) // check if already delivered and new cw part is valid!
		{
			int32_t idx = dvbapi_ca_setpid(demux_id, pid);  // prepare ca
			ca_descr.index = idx;
			ca_descr.parity = n;
			cs_log_dbg(D_DVBAPI, "Demuxer %d writing %s part (%s) of controlword, replacing expired (%s)", demux_id, (n == 1 ? "even" : "odd"),
						  newcw, lastcw);
			memcpy(demux[demux_id].lastcw[n], cw + (n * 8), 8);
			memcpy(ca_descr.cw, cw + (n * 8), 8);

#ifdef WITH_COOLAPI
			cs_log_dbg(D_DVBAPI, "Demuxer %d write cw%d index: %d (ca_mask %d)", demux_id, n, ca_descr.index, demux[demux_id].ca_mask);
			coolapi_write_cw(demux[demux_id].ca_mask, demux[demux_id].STREAMpids, demux[demux_id].STREAMpidcount, &ca_descr);
#else
			int32_t i;
			for(i = 0; i < MAX_DEMUX; i++)
			{
				if(demux[demux_id].ca_mask & (1 << i))
				{
					cs_log_dbg(D_DVBAPI, "Demuxer %d write cw%d index: %d (ca%d)", demux_id, n, ca_descr.index, i);

					if(cfg.dvbapi_boxtype == BOXTYPE_PC || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
						dvbapi_net_send(DVBAPI_CA_SET_DESCR, demux[demux_id].socket_fd, demux_id, -1 /*unused*/, (unsigned char *) &ca_descr);
					else
					{
						if(ca_fd[i] <= 0)
						{
							ca_fd[i] = dvbapi_open_device(1, i, demux[demux_id].adapter_index);
							if(ca_fd[i] <= 0)
								{ continue; } // proceed next stream
						}
						if (dvbapi_ioctl(ca_fd[i], CA_SET_DESCR, &ca_descr) < 0) {
							cs_log("ERROR: ioctl(CA_SET_DESCR): %s", strerror(errno));
						}
					}
				}
			}
#endif
		}
	}
}

void delayer(ECM_REQUEST *er)
{
	if(cfg.dvbapi_delayer <= 0) { return; }

	struct timeb tpe;
	cs_ftime(&tpe);
	int64_t gone = comp_timeb(&tpe, &er->tps);
	if( gone < cfg.dvbapi_delayer)
	{
		cs_log_dbg(D_DVBAPI, "delayer: gone=%"PRId64" ms, cfg=%d ms -> delay=%"PRId64" ms", gone, cfg.dvbapi_delayer, cfg.dvbapi_delayer - gone);
		cs_sleepms(cfg.dvbapi_delayer - gone);
	}
}

void dvbapi_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
	int32_t i, j, handled = 0;

	for(i = 0; i < MAX_DEMUX; i++)
	{
		uint32_t nocw_write = 0; // 0 = write cw, 1 = dont write cw to hardware demuxer
		if(demux[i].program_number == 0) { continue; }  // ignore empty demuxers
		if(demux[i].program_number != er->srvid) { continue; }  // skip ecm response for other srvid
		demux[i].rdr = er->selected_reader;
		for(j = 0; j < demux[i].ECMpidcount; j++)  // check for matching ecmpid
		{
			if((demux[i].ECMpids[j].CAID == er->caid || demux[i].ECMpids[j].CAID == er->ocaid)
					&& demux[i].ECMpids[j].ECM_PID == er->pid
					&& demux[i].ECMpids[j].PROVID == er->prid
					&& demux[i].ECMpids[j].VPID == er->vpid)
				{ break; }
		}
		if(j == demux[i].ECMpidcount) { continue; }  // ecm response srvid ok but no matching ecmpid, perhaps this for other demuxer

		cs_log_dbg(D_DVBAPI, "Demuxer %d %scontrolword received for PID %d CAID %04X PROVID %06X ECMPID %04X CHID %04X VPID %04X", i,
					  (er->rc >= E_NOTFOUND ? "no " : ""), j, er->caid, er->prid, er->pid, er->chid, er->vpid);

		uint32_t status = dvbapi_check_ecm_delayed_delivery(i, er);

		uint32_t comparecw0 = 0, comparecw1 = 0;
		char ecmd5[17 * 3];
		cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));

		if(status == 1 && er->rc)   // wrong ecmhash
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d not interested in response ecmhash %s (requested different one)", i, ecmd5);
				continue;
		}
		if(status == 2)   // no filter
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d not interested in response ecmhash %s (filter already killed)", i, ecmd5);
			continue;
		}
		if(status == 5)   // empty cw
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d not interested in response ecmhash %s (delivered cw is empty!)", i, ecmd5);
			nocw_write = 1;
			if(er->rc < E_NOTFOUND) { er->rc = E_NOTFOUND; }
		}

		if((status == 0 || status == 3 || status == 4) && er->rc < E_NOTFOUND)   // 0=matching ecm hash, 2=no filter, 3=table reset, 4=cache-ex response
		{
			if(memcmp(er->cw, demux[i].lastcw[0], 8) == 0 && memcmp(er->cw + 8, demux[i].lastcw[1], 8) == 0)    // check for matching controlword
			{
				comparecw0 = 1;
			}
			else if(memcmp(er->cw, demux[i].lastcw[1], 8) == 0 && memcmp(er->cw + 8, demux[i].lastcw[0], 8) == 0)    // check for matching controlword
			{
				comparecw1 = 1;
			}
			if(comparecw0 == 1 || comparecw1 == 1)
			{
				cs_log_dbg(D_DVBAPI, "Demuxer %d duplicate controlword ecm response hash %s (duplicate controlword!)", i, ecmd5);
				nocw_write = 1;
			}
		}

		if(status == 3)   // table reset
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d luckyshot new controlword ecm response hash %s (ecm table reset)", i, ecmd5);
		}

		if(status == 4)   // no check on cache-ex responses!
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d new controlword from cache-ex reader (no ecmhash check possible)", i);
		}
		
		handled = 1; // mark this ecm response as handled
		if(er->rc < E_NOTFOUND && cfg.dvbapi_requestmode == 0 && (demux[i].pidindex == -1) && er->caid != 0)
		{
			demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry flag
			demux[i].ECMpids[j].irdeto_cycle = 0xFE; // reset irdetocycle
			demux[i].pidindex = j; // set current index as *the* pid to descramble
			demux[i].ECMpids[j].checked = 4;
			cs_log_dbg(D_DVBAPI, "Demuxer %d descrambling PID %d CAID %04X PROVID %06X ECMPID %04X CHID %02X VPID %04X",
						  i, demux[i].pidindex, er->caid, er->prid, er->pid, er->chid, er->vpid);
		}

		if(er->rc < E_NOTFOUND && cfg.dvbapi_requestmode == 1 && er->caid != 0) // FOUND
		{
			pthread_mutex_lock(&demux[i].answerlock); // only process one ecm answer
			if(demux[i].ECMpids[j].checked != 4)
			{

				int32_t t, o, ecmcounter = 0;

				for(t = 0; t < demux[i].ECMpidcount; t++)  //check this pid with controlword FOUND for higher status:
				{
					if(t != j && demux[i].ECMpids[j].status >= demux[i].ECMpids[t].status)
					{
#if !defined WITH_STAPI && !defined WITH_COOLAPI && !defined WITH_MCA && !defined WITH_AZBOX
						int32_t pidindex = demux[i].pidindex;
						if(pidindex == t) // check if lower status pid already descrambling!
						{ 
							int32_t idx = demux[i].ECMpids[j].index = demux[i].ECMpids[pidindex].index; // swap index with lower status pid
							demux[i].ECMpids[pidindex].index = 0; // reset index of the old pid!
							int32_t n;
							for(n = 0; n < demux[i].STREAMpidcount; n++)
							{
								if(!demux[i].ECMpids[j].streams || demux[i].ECMpids[j].streams & (1 << n))
								{
									dvbapi_set_pid(i, n, idx - 1, true); // enable streampid used by new pid
								}
								else
								{   
									dvbapi_set_pid(i, n, idx - 1, false); // disable streampid not used by new pid  
								}
							}
							dvbapi_edit_channel_cache(i, pidindex, 0); // remove lowerstatus pid from channelcache

						}
#endif
						demux[i].ECMpids[t].checked = 4; // mark index t as low status

						for(o = 0; o < maxfilter; o++)    // check if ecmfilter is in use & stop all ecmfilters of lower status pids
						{
							if(demux[i].demux_fd[o].fd > 0 && demux[i].demux_fd[o].type == TYPE_ECM && demux[i].demux_fd[o].pidindex == t)
							{
								dvbapi_stop_filternum(i, o); // ecmfilter belongs to lower status pid -> kill!
							}
						}
					}
				}
	

				for(o = 0; o < maxfilter; o++) if(demux[i].demux_fd[o].type == TYPE_ECM) { ecmcounter++; }   // count all ecmfilters

				demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry flag
				demux[i].ECMpids[j].irdeto_cycle = 0xFE; // reset irdetocycle
				demux[i].pidindex = j; // set current index as *the* pid to descramble

				if(ecmcounter == 1)   // if total found running ecmfilters is 1 -> we found the "best" pid
				{
					dvbapi_edit_channel_cache(i, j, 1);
					demux[i].ECMpids[j].checked = 4; // mark best pid last ;)
				}

				cs_log_dbg(D_DVBAPI, "Demuxer %d descrambling PID %d CAID %04X PROVID %06X ECMPID %04X CHID %02X VPID %04X",
					i, demux[i].pidindex, er->caid, er->prid, er->pid, er->chid, er->vpid);
			}
			pthread_mutex_unlock(&demux[i].answerlock); // and release it!
		}

		if(er->rc >= E_NOTFOUND)    // not found on requestmode 0 + 1
		{
			if(er->rc == E_SLEEPING)
			{
				dvbapi_stop_descrambling(i);
				return;
			}
			
			struct s_dvbapi_priority *forceentry = dvbapi_check_prio_match(i, j, 'p');

			if(forceentry && forceentry->force)   // forced pid? keep trying the forced ecmpid!
			{
				if((er->caid >> 8) != 0x06 || forceentry->chid < 0x10000)   //all cas or irdeto cas with forced prio chid
				{
					demux[i].ECMpids[j].table = 0;
					dvbapi_set_section_filter(i, er);
					continue;
				}
				else   // irdeto cas without chid prio forced
				{
					if(demux[i].ECMpids[j].irdeto_curindex == 0xFE) { demux[i].ECMpids[j].irdeto_curindex = 0x00; }  // init irdeto current index to first one
					if(!(demux[i].ECMpids[j].irdeto_curindex + 1 > demux[i].ECMpids[j].irdeto_maxindex))  // check for last / max chid
					{
						cs_log_dbg(D_DVBAPI, "Demuxer %d trying next irdeto chid of FORCED PID %d CAID %04X PROVID %06X ECMPID %04X", i,
									  j, er->caid, er->prid, er->pid);
						demux[i].ECMpids[j].irdeto_curindex++; // irdeto index one up
						demux[i].ECMpids[j].table = 0;
						dvbapi_set_section_filter(i, er);
						continue;
					}
				}
			}

			// in case of timeout or fatal LB event give this pid another try but no more than 1 try
			if((er->rc == E_TIMEOUT || (er->rcEx && er->rcEx <= E2_CCCAM_NOCARD)) && demux[i].ECMpids[j].tries == 0xFE)
			{
				demux[i].ECMpids[j].tries = 1;
				demux[i].ECMpids[j].table = 0;
				dvbapi_set_section_filter(i, er);
				continue;
			}
			else  // all not found responses exception: first timeout response and first fatal loadbalancer response
			{
				demux[i].ECMpids[j].CHID = 0x10000; // get rid of this prio chid since it failed!
				demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry
			}

			if((er->caid >> 8) == 0x06)
			{
				if(demux[i].ECMpids[j].irdeto_curindex == 0xFE) { demux[i].ECMpids[j].irdeto_curindex = 0x00; }  // init irdeto current index to first one
				if(!(demux[i].ECMpids[j].irdeto_curindex + 1 > demux[i].ECMpids[j].irdeto_maxindex))  // check for last / max chid
				{
					cs_log_dbg(D_DVBAPI, "Demuxer %d trying next irdeto chid of PID %d CAID %04X PROVID %06X ECMPID %04X VPID %04X", i,
								  j, er->caid, er->prid, er->pid, er->vpid);
					demux[i].ECMpids[j].irdeto_curindex++; // irdeto index one up
					demux[i].ECMpids[j].table = 0;
					dvbapi_set_section_filter(i, er);
					continue;
				}
			}

			dvbapi_edit_channel_cache(i, j, 0); // remove this pid from channelcache
			if(demux[i].pidindex == j)
			{
				demux[i].pidindex = -1; // current pid delivered a notfound so this pid isnt being used to descramble any longer-> clear pidindex
			}
			demux[i].ECMpids[j].irdeto_maxindex = 0;
			demux[i].ECMpids[j].irdeto_curindex = 0xFE;
			demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry flag
			demux[i].ECMpids[j].irdeto_cycle = 0xFE; // reset irdetocycle
			demux[i].ECMpids[j].table = 0;
			demux[i].ECMpids[j].checked = 4; // flag ecmpid as checked
			demux[i].ECMpids[j].status = -1; // flag ecmpid as unusable
			int32_t found = 1; // setup for first run
			int32_t filternum = -1;

			while(found > 0)  // disable all ecm + emm filters for this notfound
			{
				found = 0;
				filternum = dvbapi_get_filternum(i, er, TYPE_ECM); // get ecm filternumber
				if(filternum > -1)   // in case valid filter found
				{
					int32_t fd = demux[i].demux_fd[filternum].fd;
					if(fd > 0)  // in case valid fd
					{
						dvbapi_stop_filternum(i, filternum); // stop ecmfilter
						found = 1;
					}
				}
				if(er->caid >> 8 == 0x06)   // in case irdeto cas stop old emm filters
				{
					filternum = dvbapi_get_filternum(i, er, TYPE_EMM); // get emm filternumber
					if(filternum > -1)   // in case valid filter found
					{
						int32_t fd = demux[i].demux_fd[filternum].fd;
						if(fd > 0)  // in case valid fd
						{
							dvbapi_stop_filternum(i, filternum); // stop emmfilter
							found = 1;
						}
					}
				}
			}

			continue;
		}


		// below this should be only run in case of ecm answer is found

		uint32_t chid = get_subid(er); // derive current chid in case of irdeto, or a unique part of ecm on other cas systems
		demux[i].ECMpids[j].CHID = (chid != 0 ? chid : 0x10000); // if not zero apply, otherwise use no chid value 0x10000
		dvbapi_edit_channel_cache(i, j, 1); // do it here to here after the right CHID is registered

		//dvbapi_set_section_filter(i, er);  is not needed anymore (unsure)
		demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry flag
		demux[i].ECMpids[j].irdeto_cycle = 0xFE; // reset irdeto cycle

		if(nocw_write || demux[i].pidindex != j) { continue; }  // cw was already written by another filter or current pid isnt pid used to descramble so it ends here!

		struct s_dvbapi_priority *delayentry = dvbapi_check_prio_match(i, demux[i].pidindex, 'd');
		if(delayentry)
		{
			if(delayentry->delay < 1000)
			{
				cs_log_dbg(D_DVBAPI, "wait %d ms", delayentry->delay);
				cs_sleepms(delayentry->delay);
			}
		}

		delayer(er);

		switch(selected_api)
		{
#ifdef WITH_STAPI
		case STAPI:
			stapi_write_cw(i, er->cw, demux[i].STREAMpids, demux[i].STREAMpidcount, demux[i].pmt_file);
			break;
#endif
		default:
			dvbapi_write_cw(i, er->cw, j);
			break;
		}

		// reset idle-Time
		client->last = time((time_t *)0); // ********* TO BE FIXED LATER ON ******

		FILE *ecmtxt = NULL;
		if (!cfg.dvbapi_listenport && cfg.dvbapi_boxtype != BOXTYPE_PC_NODMX)
			ecmtxt = fopen(ECMINFO_FILE, "w");
		if(ecmtxt != NULL && er->rc < E_NOTFOUND)
		{
			char tmp[25];
			fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
			switch(er->rc)
			{
			case E_FOUND:
				if(er->selected_reader)
				{
					fprintf(ecmtxt, "reader: %s\n", er->selected_reader->label);
					if(is_network_reader(er->selected_reader))
						{ fprintf(ecmtxt, "from: %s\n", er->selected_reader->device); }
					else
						{ fprintf(ecmtxt, "from: local\n"); }
					fprintf(ecmtxt, "protocol: %s\n", reader_get_type_desc(er->selected_reader, 1));
					fprintf(ecmtxt, "hops: %d\n", er->selected_reader->currenthops);
				}
				break;

			case E_CACHE1:
				fprintf(ecmtxt, "reader: Cache\n");
				fprintf(ecmtxt, "from: cache1\n");
				fprintf(ecmtxt, "protocol: none\n");
				break;

			case E_CACHE2:
				fprintf(ecmtxt, "reader: Cache\n");
				fprintf(ecmtxt, "from: cache2\n");
				fprintf(ecmtxt, "protocol: none\n");
				break;

			case E_CACHEEX:
				fprintf(ecmtxt, "reader: Cache\n");
				fprintf(ecmtxt, "from: cache3\n");
				fprintf(ecmtxt, "protocol: none\n");
				break;
			}
			fprintf(ecmtxt, "ecm time: %.3f\n", (float) client->cwlastresptime / 1000);
			fprintf(ecmtxt, "cw0: %s\n", cs_hexdump(1, demux[i].lastcw[0], 8, tmp, sizeof(tmp)));
			fprintf(ecmtxt, "cw1: %s\n", cs_hexdump(1, demux[i].lastcw[1], 8, tmp, sizeof(tmp)));
		}
		if(ecmtxt)
		{
			int32_t ret = fclose(ecmtxt);
			if(ret < 0) { cs_log("ERROR: Could not close ecmtxt fd (errno=%d %s)", errno, strerror(errno)); }
			ecmtxt = NULL;
		}

	}
	if(handled == 0)
	{
		cs_log_dbg(D_DVBAPI, "Unhandled ECM response received for CAID %04X PROVID %06X ECMPID %04X CHID %04X VPID %04X",
					  er->caid, er->prid, er->pid, er->chid, er->vpid);
	}

}

void *dvbapi_start_handler(struct s_client *cl, uchar *UNUSED(mbuf), int32_t module_idx, void * (*_main_func)(void *))
{
	// cs_log("dvbapi loaded fd=%d", idx);
	if(cfg.dvbapi_enabled == 1)
	{
		cl = create_client(get_null_ip());
		cl->module_idx = module_idx;
		cl->typ = 'c';
		int32_t ret = pthread_create(&cl->thread, NULL, _main_func, (void *) cl);
		if(ret)
		{
			cs_log("ERROR: Can't create dvbapi handler thread (errno=%d %s)", ret, strerror(ret));
			return NULL;
		}
		else
			{ pthread_detach(cl->thread); }
	}

	return NULL;
}

void *dvbapi_handler(struct s_client *cl, uchar *mbuf, int32_t module_idx)
{
	return dvbapi_start_handler(cl, mbuf, module_idx, dvbapi_main_local);
}

int32_t dvbapi_set_section_filter(int32_t demux_index, ECM_REQUEST *er)
{
	if(!er) { return -1; }

	if(selected_api != DVBAPI_3 && selected_api != DVBAPI_1 && selected_api != STAPI)   // only valid for dvbapi3, dvbapi1 and STAPI
	{
		return 0;
	}
	int32_t n = dvbapi_get_filternum(demux_index, er, TYPE_ECM);
	if(n < 0) { return -1; }  // in case no valid filter found;

	int32_t fd = demux[demux_index].demux_fd[n].fd;
	if(fd < 1) { return -1 ; }  // in case no valid fd

	uchar filter[16];
	uchar mask[16];
	memset(filter, 0, 16);
	memset(mask, 0, 16);

	struct s_ecmpids *curpid = &demux[demux_index].ECMpids[demux[demux_index].demux_fd[n].pidindex];
	if(curpid->table != er->ecm[0] && curpid->table != 0) { return -1; }  // if current ecmtype differs from latest requested ecmtype do not apply section filtering!
	uint8_t ecmfilter = 0;

	if(er->ecm[0] == 0x80) { ecmfilter = 0x81; }  // current processed ecm is even, next will be filtered for odd
	else { ecmfilter = 0x80; } // current processed ecm is odd, next will be filtered for even

	if(curpid->table != 0)   // cycle ecmtype from odd to even or even to odd
	{
		filter[0] = ecmfilter; // only accept new ecms (if previous odd, filter for even and visaversa)
		mask[0] = 0xFF;
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d set ecmtable to %s (CAID %04X PROVID %06X FD %d)", demux_index, n + 1,
					  (ecmfilter == 0x80 ? "EVEN" : "ODD"), curpid->CAID, curpid->PROVID, fd);
	}
	else  // not decoding right now so we are interessted in all ecmtypes!
	{
		filter[0] = 0x80; // set filter to wait for any ecms
		mask[0] = 0xF0;
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d set ecmtable to ODD+EVEN (CAID %04X PROVID %06X FD %d)", demux_index, n + 1,
					  curpid->CAID, curpid->PROVID, fd);
	}
	uint32_t offset = 0, extramask = 0xFF;
	uint32_t pid = demux[demux_index].demux_fd[n].pidindex;

	struct s_dvbapi_priority *forceentry = dvbapi_check_prio_match(demux_index, pid, 'p');
	//cs_log("**** curpid->CHID %04X, checked = %d, er->chid = %04X *****", curpid->CHID, curpid->checked, er->chid);
	// checked 4 to make sure we dont set chid filter and no such ecm in dvbstream except for forced pids!
	if(curpid->CHID < 0x10000 && (curpid->checked == 4 || (forceentry && forceentry->force)))
	{

		switch(er->caid >> 8)
		{
		case 0x01:
			offset = 7;
			extramask = 0xF0;
			break; // seca
		case 0x05:
			offset = 8;
			break; // viaccess
		case 0x06:
			offset = 6;
			break; // irdeto
		case 0x09:
			offset = 11;
			break; // videoguard
		case 0x4A:  // DRE-Crypt, Bulcrypt,Tongang and others?
			if(!(er->caid == 0x4AEE))  // Bulcrypt excluded for now
				{ offset = 6; }
			break;
		}
	}

	int32_t irdetomatch = 1; // check if wanted irdeto index is the one the delivers current chid!
	if(curpid->CAID >> 8 == 0x06)
	{
		if(curpid->irdeto_curindex == er->ecm[4]) { irdetomatch = 1; }  // ok apply chid filtering
		else { irdetomatch = 0; } // skip chid filtering but apply irdeto index filtering
	}

	if(offset && irdetomatch)  // we have a cas with chid or unique part in checked ecm
	{
		i2b_buf(2, curpid->CHID, filter + (offset - 2));
		mask[(offset - 2)] = 0xFF&extramask; // additional mask seca2 chid can be FC10 or FD10 varies each month so only apply F?10
		mask[(offset - 1)] = 0xFF;
		cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d set chid to %04X on fd %d", demux_index, n + 1, curpid->CHID, fd);
	}
	else
	{
		if(curpid->CAID >> 8 == 0x06 && (curpid->irdeto_curindex < 0xFE))  // on irdeto we can always apply irdeto index filtering!
		{
			filter[2] = curpid->irdeto_curindex;
			mask[2] = 0xFF;
			cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d set irdetoindex to %d on fd %d", demux_index, n + 1, curpid->irdeto_curindex, fd);
		}
		else  // all other cas systems also cas systems without chid or unique ecm part
		{
			cs_log_dbg(D_DVBAPI, "Demuxer %d Filter %d set chid to ANY CHID on fd %d", demux_index, n + 1, fd);
		}
	}

	int32_t ret = dvbapi_activate_section_filter(demux_index, n, fd, curpid->ECM_PID, filter, mask);
	if(ret < 0)   // something went wrong setting filter!
	{
		cs_log("Demuxer %d Filter %d (fd %d) error setting section filtering -> stop filter!", demux_index, n + 1, fd);
		ret = dvbapi_stop_filternum(demux_index, n);
		if(ret == -1)
		{
			cs_log("Demuxer %d Filter %d (fd %d) stopping filter failed -> kill all filters of this demuxer!", demux_index, n + 1, fd);
			dvbapi_stop_filter(demux_index, TYPE_EMM);
			dvbapi_stop_filter(demux_index, TYPE_ECM);
		}
		return -1;
	}
	return n;
}

int32_t dvbapi_activate_section_filter(int32_t demux_index, int32_t num, int32_t fd, int32_t pid, uchar *filter, uchar *mask)
{

	int32_t ret = -1;
	switch(selected_api)
	{
	case DVBAPI_3:
	{
		struct dmx_sct_filter_params sFP2;
		memset(&sFP2, 0, sizeof(sFP2));
		sFP2.pid            = pid;
		sFP2.timeout        = 0;
		sFP2.flags          = DMX_IMMEDIATE_START;
		if(cfg.dvbapi_boxtype == BOXTYPE_NEUMO)
		{
			//DeepThought: on dgs/cubestation and neumo images, perhaps others
			//the following code is needed to descramble
			sFP2.filter.filter[0] = filter[0];
			sFP2.filter.mask[0] = mask[0];
			sFP2.filter.filter[1] = 0;
			sFP2.filter.mask[1] = 0;
			sFP2.filter.filter[2] = 0;
			sFP2.filter.mask[2] = 0;
			memcpy(sFP2.filter.filter + 3, filter + 1, 16 - 3);
			memcpy(sFP2.filter.mask + 3, mask + 1, 16 - 3);
			//DeepThought: in the drivers of the dgs/cubestation and neumo images,
			//dvbapi 1 and 3 are somehow mixed. In the kernel drivers, the DMX_SET_FILTER
			//ioctl expects to receive a dmx_sct_filter_params structure (DVBAPI 3) but
			//due to a bug its sets the "positive mask" wrongly (they should be all 0).
			//On the other hand, the DMX_SET_FILTER1 ioctl also uses the dmx_sct_filter_params
			//structure, which is incorrect (it should be  dmxSctFilterParams).
			//The only way to get it right is to call DMX_SET_FILTER1 with the argument
			//expected by DMX_SET_FILTER. Otherwise, the timeout parameter is not passed correctly.
			ret = dvbapi_ioctl(fd, DMX_SET_FILTER1, &sFP2);
		}
		else
		{
			memcpy(sFP2.filter.filter, filter, 16);
			memcpy(sFP2.filter.mask, mask, 16);
			if (cfg.dvbapi_listenport || cfg.dvbapi_boxtype == BOXTYPE_PC_NODMX)
				ret = dvbapi_net_send(DVBAPI_DMX_SET_FILTER, demux[demux_index].socket_fd, demux_index, num, (unsigned char *) &sFP2);
			else
				ret = dvbapi_ioctl(fd, DMX_SET_FILTER, &sFP2);
		}
		break;
	}

	case DVBAPI_1:
	{
		struct dmxSctFilterParams sFP1;
		memset(&sFP1, 0, sizeof(sFP1));
		sFP1.pid = pid;
		sFP1.timeout = 0;
		sFP1.flags = DMX_IMMEDIATE_START;
		memcpy(sFP1.filter.filter, filter, 16);
		memcpy(sFP1.filter.mask, mask, 16);
		ret = dvbapi_ioctl(fd, DMX_SET_FILTER1, &sFP1);
		break;
	}
#ifdef WITH_STAPI
	case STAPI:
	{
		ret = stapi_activate_section_filter(fd, filter, mask);
		break;
	}
#endif
	/*#ifdef WITH_COOLAPI    ******* NOT IMPLEMENTED YET ********
	        case COOLAPI: {
	            coolapi_set_filter(demux[demux_id].demux_fd[n].fd, n, pid, filter, mask, TYPE_ECM);
	            break;
	        }
	#endif
	*/
	default:
		break;
	}
	return ret;
}


int32_t dvbapi_check_ecm_delayed_delivery(int32_t demux_index, ECM_REQUEST *er)
{
	char nullcw[CS_ECMSTORESIZE];
	memset(nullcw, 0, CS_ECMSTORESIZE);
	if(memcmp(er->cw, nullcw, 8) == 0 && memcmp(er->cw+8, nullcw, 8) == 0) {return 5;} // received a null cw -> not usable!
	int32_t filternum = dvbapi_get_filternum(demux_index, er, TYPE_ECM);
	if(filternum < 0) { return 2; }  // if no matching filter act like ecm response is delayed
	struct s_ecmpids *curpid = &demux[demux_index].ECMpids[demux[demux_index].demux_fd[filternum].pidindex];
	if(curpid->table == 0) { return 3; }  // on change table act like ecm response is found
	if(er->rc == E_CACHEEX) { return 4; }  // on cache-ex response act like ecm response is found
	
	if(memcmp(demux[demux_index].demux_fd[filternum].ecmd5, nullcw, CS_ECMSTORESIZE))
	{
		char ecmd5[17 * 3];
		cs_hexdump(0, demux[demux_index].demux_fd[filternum].ecmd5, 16, ecmd5, sizeof(ecmd5));
		cs_log_dbg(D_DVBAPI, "Demuxer %d requested controlword for ecm %s on fd %d", demux_index, ecmd5, demux[demux_index].demux_fd[filternum].fd);
		return memcmp(demux[demux_index].demux_fd[filternum].ecmd5, er->ecmd5, CS_ECMSTORESIZE); // 1 = no response on the ecm we request last for this fd!
	}
	else { return 0; }
}

int32_t dvbapi_get_filternum(int32_t demux_index, ECM_REQUEST *er, int32_t type)
{
	if(!er) { return -1; }

	int32_t n;
	int32_t fd = -1;

	for(n = 0; n < maxfilter; n++)    // determine fd
	{
		if(demux[demux_index].demux_fd[n].fd > 0 && demux[demux_index].demux_fd[n].type == type)     // check for valid and right type (ecm or emm)
		{
			if((demux[demux_index].demux_fd[n].pid == er->pid) &&
					((demux[demux_index].demux_fd[n].provid == er->prid) || demux[demux_index].demux_fd[n].provid == 0) &&
					((demux[demux_index].demux_fd[n].caid == er->caid) || (demux[demux_index].demux_fd[n].caid == er->ocaid))) // current ecm pid?
			{
				fd = demux[demux_index].demux_fd[n].fd; // found!
				break;
			}
		}
	}
	if(fd > 0 && demux[demux_index].demux_fd[n].provid == 0) { demux[demux_index].demux_fd[n].provid = er->prid; }  // hack to fill in provid into demuxer

	return (fd > 0 ? n : fd); // return -1(fd) on not found, on found return filternumber(n)
}

int32_t dvbapi_ca_setpid(int32_t demux_index, int32_t pid)
{
	int32_t idx = -1, n;
	for(n = 0; n < demux[demux_index].ECMpidcount; n++)  // cleanout old indexes of pids that have now status ignore (=no decoding possible!)
	{
		idx = demux[demux_index].ECMpids[n].index;
		if (!idx) continue; // skip ecmpids that are not used to decrypt 
		if(demux[demux_index].ECMpids[n].status == -1 || demux[demux_index].ECMpids[n].checked == 0) { // reset index!
			demux[demux_index].ECMpids[n].index = 0;
			int32_t i;
			for(i = 0; i < demux[demux_index].STREAMpidcount && idx; i++){
				dvbapi_set_pid(demux_index, i, idx - 1, false); // disable all streampids for this index!
			}
		}
	}

	idx = demux[demux_index].ECMpids[pid].index;

	if(!idx)   // if no indexer for this pid get one!
	{
		idx = dvbapi_get_descindex(demux_index);
		demux[demux_index].ECMpids[pid].index = idx;
		cs_log_dbg(D_DVBAPI, "Demuxer %d PID: %d CAID: %04X ECMPID: %04X is using index %d", demux_index, pid,
					  demux[demux_index].ECMpids[pid].CAID, demux[demux_index].ECMpids[pid].ECM_PID, idx - 1);
	}

	for(n = 0; n < demux[demux_index].STREAMpidcount; n++)
	{
		if(!demux[demux_index].ECMpids[pid].streams || demux[demux_index].ECMpids[pid].streams & (1 << n)){
			dvbapi_set_pid(demux_index, n, idx - 1, true); // enable streampid
		}
		else{
			dvbapi_set_pid(demux_index, n, idx - 1, false); // disable streampid
		} 
	}

	return idx - 1; // return caindexer
}

int8_t update_streampid_list(uint8_t cadevice, uint16_t pid, int32_t idx)
{
	struct s_streampid *listitem, *newlistitem;
	if(!ll_activestreampids)
		{ ll_activestreampids = ll_create("ll_activestreampids"); }
	LL_ITER itr;
	if(ll_count(ll_activestreampids) > 0)
	{
		itr = ll_iter_create(ll_activestreampids);
		while((listitem = ll_iter_next(&itr)))
		{
			if (cadevice == listitem->cadevice && pid == listitem->streampid){
				if(listitem->activeindexers & (1 << idx)){
					return FOUND_STREAMPID_INDEX; // match found
				}else{
					listitem->activeindexers|=(1 << idx); // ca + pid found but not this index -> add this index
					cs_log_dbg(D_DVBAPI, "Added existing streampid %04X with new index %d to ca%d", pid, idx, cadevice);
					return ADDED_STREAMPID_INDEX;
				}
			}
		}
	}
	if(!cs_malloc(&newlistitem, sizeof(struct s_streampid)))
		{ return ADDED_STREAMPID_INDEX; }
	newlistitem->cadevice = cadevice;
	newlistitem->streampid = pid;
	newlistitem->activeindexers = (1 << idx);
	ll_append(ll_activestreampids, newlistitem);
	cs_log_dbg(D_DVBAPI, "Added new streampid %04X with index %d to ca%d", pid, idx, cadevice);
	return ADDED_STREAMPID_INDEX;
}

int8_t remove_streampid_from_list(uint8_t cadevice, uint16_t pid, int32_t idx)
{
	if(!ll_activestreampids) return NO_STREAMPID_LISTED;
	
	struct s_streampid *listitem;
	
	LL_ITER itr;
	if(ll_count(ll_activestreampids) > 0)
	{
		itr = ll_iter_create(ll_activestreampids);
		while((listitem = ll_iter_next(&itr)))
		{
			if (cadevice == listitem->cadevice && pid == listitem->streampid){
				if(idx != -1 && listitem->activeindexers & (1 << idx)){
					listitem->activeindexers &= ~(1 << idx); // flag it as disabled for this index
				}
				if(idx == -1){ // idx -1 means disable all!
					listitem->activeindexers = 0;
				}
				cs_log_dbg(D_DVBAPI, "Remove streampid %04X using indexer %d from ca%d", pid, idx, cadevice);
				if (listitem->activeindexers == 0){ // all indexers disabled? -> remove pid from list!
					ll_iter_remove_data(&itr);
					cs_log_dbg(D_DVBAPI, "Removed last indexer of streampid %04X from ca%d", pid, cadevice);
					return REMOVED_STREAMPID_LASTINDEX;
				}
				return REMOVED_STREAMPID_INDEX;
			}
		}
	}
	return NO_STREAMPID_LISTED;
}

void disable_unused_streampids(int16_t demux_id)
{
	if(!ll_activestreampids) return;
	if(ll_count(ll_activestreampids) == 0) return; // no items in list? 
	
	int32_t ecmpid = demux[demux_id].pidindex;
	if (ecmpid == -1) return; // no active ecmpid!
	
	int32_t idx = demux[demux_id].ECMpids[ecmpid].index;
	int32_t i,n;
	struct s_streampid *listitem;
	// search for old enabled streampids on all ca devices that have to be disabled, index 0 is skipped as it belongs to fta!
	for(i = 0; i < MAX_DEMUX && idx; i++){
		if(!(demux[demux_id].ca_mask & (1 << i))) continue; // continue if ca is unused by this demuxer
		
		LL_ITER itr;
		itr = ll_iter_create(ll_activestreampids);
		while((listitem = ll_iter_next(&itr)))
		{
			if (i != listitem->cadevice) continue; // ca doesnt match
			if (!(listitem->activeindexers & (1 << (idx-1)))) continue; // index doesnt match
			for(n = 0; n < demux[demux_id].STREAMpidcount; n++){
				if (listitem->streampid == demux[demux_id].STREAMpids[n]){ // check if pid matches with current streampid on demuxer
					break;
				}
			}
			if (n == demux[demux_id].STREAMpidcount){
				demux[demux_id].STREAMpids[n] = listitem->streampid; // put it temp here!
				dvbapi_set_pid(demux_id, n, idx - 1, false); // no match found so disable this now unused streampid
				demux[demux_id].STREAMpids[n] = 0; // remove temp!
			}
		}
	}
}


int8_t is_ca_used(uint8_t cadevice)
{
	if(!ll_activestreampids) return CA_IS_CLEAR;
	
	struct s_streampid *listitem;
	
	LL_ITER itr;
	if(ll_count(ll_activestreampids) > 0)
	{
		itr = ll_iter_create(ll_activestreampids);
		while((listitem = ll_iter_next(&itr)))
		{
			if (listitem->cadevice != cadevice) continue;
			return CA_IS_IN_USE;
		}
	}
	return CA_IS_CLEAR;
}

const char *dvbapi_get_client_name(void)
{
	return client_name;
}

void check_add_emmpid(int32_t demux_index, uchar *filter, int32_t l, int32_t emmtype)
{
	if (l<0) return;
	
	uint32_t typtext_idx = 0;
	int32_t ret = -1;
	const char *typtext[] = { "UNIQUE", "SHARED", "GLOBAL", "UNKNOWN" };

	while(((emmtype >> typtext_idx) & 0x01) == 0 && typtext_idx < sizeof(typtext) / sizeof(const char *))
	{
		++typtext_idx;
	}
	
	//filter already in list?
	if(is_emmfilter_in_list(filter, demux[demux_index].EMMpids[l].PID, demux[demux_index].EMMpids[l].PROVID, demux[demux_index].EMMpids[l].CAID))
	{
		cs_log_dbg(D_DVBAPI, "Demuxer %d duplicate emm filter type %s, emmpid: 0x%04X, emmcaid: %04X, emmprovid: %06X -> SKIPPED!", demux_index,
			typtext[typtext_idx], demux[demux_index].EMMpids[l].PID, demux[demux_index].EMMpids[l].CAID, demux[demux_index].EMMpids[l].PROVID);
		return;
	}

	if(demux[demux_index].emm_filter >= demux[demux_index].max_emm_filter) // can this filter be started? if not add to list of inactive emmfilters
	{
		add_emmfilter_to_list(demux_index, filter, demux[demux_index].EMMpids[l].CAID, demux[demux_index].EMMpids[l].PROVID, demux[demux_index].EMMpids[l].PID, 0, false);
	}
	else // activate this emmfilter
	{
		ret = dvbapi_set_filter(demux_index, selected_api, demux[demux_index].EMMpids[l].PID, demux[demux_index].EMMpids[l].CAID,
			demux[demux_index].EMMpids[l].PROVID, filter, filter + 16, 0, demux[demux_index].pidindex, TYPE_EMM, 1);
	}
	if(ret != -1)
	{
		if(demux[demux_index].emm_filter == -1) // first run -1
		{
			demux[demux_index].emm_filter = 0;
		}
		demux[demux_index].emm_filter++; // increase total active filters
		cs_log_dump_dbg(D_DVBAPI, filter, 32, "Demuxer %d started emm filter type %s, pid: 0x%04X", demux_index, typtext[typtext_idx], demux[demux_index].EMMpids[l].PID);
		return;
	}
	else   // not set successful, so add it to the list for try again later on!
	{
		add_emmfilter_to_list(demux_index, filter, demux[demux_index].EMMpids[l].CAID, demux[demux_index].EMMpids[l].PROVID, demux[demux_index].EMMpids[l].PID, 0, false);
		cs_log_dump_dbg(D_DVBAPI, filter, 32, "Demuxer %d added inactive emm filter type %s, pid: 0x%04X", demux_index, typtext[typtext_idx], demux[demux_index].EMMpids[l].PID);
	}
	return;
}

uint16_t dvbapi_get_client_proto_version(void)
{
	return client_proto_version;
}

/*
 *  protocol structure
 */

void module_dvbapi(struct s_module *ph)
{
	ph->desc = "dvbapi";
	ph->type = MOD_CONN_SERIAL;
	ph->listenertype = LIS_DVBAPI;
#if defined(WITH_AZBOX)
	ph->s_handler = azbox_handler;
	ph->send_dcw = azbox_send_dcw;
#elif defined(WITH_MCA)
	ph->s_handler = mca_handler;
	ph->send_dcw = mca_send_dcw;
	selected_box = selected_api = 0; // HACK: This fixes incorrect warning about out of bounds array access in functionas that are not even called when WITH_MCA is defined
#else
	ph->s_handler = dvbapi_handler;
	ph->send_dcw = dvbapi_send_dcw;
#endif
}
#endif // HAVE_DVBAPI
