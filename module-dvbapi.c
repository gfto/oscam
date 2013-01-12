#include "globals.h"

#ifdef HAVE_DVBAPI

#include "module-dvbapi.h"
#include "module-dvbapi-azbox.h"
#include "module-dvbapi-mca.h"
#include "module-dvbapi-coolapi.h"
#include "module-dvbapi-stapi.h"
#include "module-stat.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-files.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"

// These are declared in module-dvbapi-azbox.c
extern int32_t openxcas_provid;
extern uint16_t openxcas_sid, openxcas_caid, openxcas_ecm_pid;

const char *boxdesc[] = { "none", "dreambox", "duckbox", "ufs910", "dbox2", "ipbox", "ipbox-pmt", "dm7000", "qboxhd", "coolstream", "neumo", "pc" };

const struct box_devices devices[BOX_COUNT] = {
	/* QboxHD (dvb-api-3)*/	{ "/tmp/virtual_adapter/", 	"ca%d",		"demux%d",			"/tmp/camd.socket", DVBAPI_3  },
	/* dreambox (dvb-api-3)*/	{ "/dev/dvb/adapter%d/",	"ca%d", 		"demux%d",			"/tmp/camd.socket", DVBAPI_3 },
	/* dreambox (dvb-api-1)*/	{ "/dev/dvb/card%d/",	"ca%d",		"demux%d",			"/tmp/camd.socket", DVBAPI_1 },
	/* neumo (dvb-api-1)*/	{ "/dev/",			"demuxapi",		"demuxapi",			"/tmp/camd.socket", DVBAPI_1 },
	/* sh4      (stapi)*/	{ "/dev/stapi/", 		"stpti4_ioctl",	"stpti4_ioctl",		"/tmp/camd.socket", STAPI },
	/* coolstream*/		{ "/dev/cnxt/", 		"null",		"null",			"/tmp/camd.socket", COOLAPI }
};

int32_t selected_box=-1;
int32_t selected_api=-1;
int32_t disable_pmt_files=0;
int32_t dir_fd=-1, pausecam=0;
DEMUXTYPE demux[MAX_DEMUX];
int32_t ca_fd[8];
LLIST *channel_cache;

struct s_dvbapi_priority *dvbapi_priority=NULL;
struct s_client *dvbapi_client=NULL;

typedef struct s_emm_filter {	
	int32_t 	demux_id;
	uchar 		filter[32];
	uint16_t 	caid;
	uint32_t	provid;
	uint16_t	pid;
	int32_t 	count;
	uint32_t 	num;
	time_t 		time_started;
} S_EMM_FILTER;
LLIST	*ll_emm_active_filter 	= NULL;
LLIST	*ll_emm_inactive_filter = NULL;
LLIST	*ll_emm_pending_filter 	= NULL;

struct s_channel_cache {
	uint16_t	caid;
	uint32_t 	prid;
	uint16_t	srvid;
	uint16_t	pid;
	int8_t		chid;
} CHANNEL_CACHE;

struct s_channel_cache *find_channel_cache(int32_t demux_id, int32_t pidindex, int8_t caid_and_prid_only)
{
	struct s_ecmpids *p = &demux[demux_id].ECMpids[pidindex];
	struct s_channel_cache *c;
	LL_ITER it;

	if (!channel_cache)
		channel_cache = ll_create("channel cache");

	it = ll_iter_create(channel_cache);
	while ((c=ll_iter_next(&it))) {

		if (caid_and_prid_only) {
			if (p->CAID == c->caid && p->PROVID == c->prid)
				return c;
		} else if (demux[demux_id].program_number == c->srvid &&
					p->CAID == c->caid &&
					p->ECM_PID == c->pid &&
					p->PROVID == c->prid &&
					p->irdeto_curchid == c->chid) {

#ifdef WITH_DEBUG
			char buf[ECM_FMT_LEN];
			ecmfmt(c->caid, c->prid, c->chid, c->pid, c->srvid, 0, 0, 0, 0, buf, ECM_FMT_LEN);
			cs_debug_mask(D_DVBAPI, "found in channel cache: %s", buf);
#endif
			return c;
		}
	}
	return NULL;
}

int32_t edit_channel_cache(int32_t demux_id, int32_t pidindex, uint8_t add)
{
	struct s_ecmpids *p = &demux[demux_id].ECMpids[pidindex];
	struct s_channel_cache *c;
	LL_ITER it;
	int32_t count = 0;

	if (!channel_cache)
		channel_cache = ll_create("channel cache");

	it = ll_iter_create(channel_cache);
	while ((c=ll_iter_next(&it))) {
		if (demux[demux_id].program_number == c->srvid &&
				p->CAID == c->caid &&
				p->ECM_PID == c->pid &&
				p->PROVID == c->prid &&
				p->irdeto_curchid == c->chid) {
			if (add)
				return 0; //already added
			ll_iter_remove_data(&it);
			count++;
		}
	}

	if (add) {
		if (!cs_malloc(&c, sizeof(struct s_channel_cache)))
			return count;
		c->srvid = demux[demux_id].program_number;
		c->caid = p->CAID;
		c->pid = p->ECM_PID;
		c->prid = p->PROVID;
		c->chid = p->irdeto_curchid;
		ll_append(channel_cache, c);
#ifdef WITH_DEBUG
		char buf[ECM_FMT_LEN];
		ecmfmt(c->caid, c->prid, c->chid, c->pid, c->srvid, 0, 0, 0, 0, buf, ECM_FMT_LEN);
		cs_debug_mask(D_DVBAPI, "added to channel cache: %s", buf);
#endif
		count++;
	}

	return count;
}

int32_t add_emmfilter_to_list(int32_t demux_id, uchar *filter, uint16_t caid, uint32_t provid, uint16_t emmpid, int32_t count, int32_t num, time_t now) 
{
	if (!ll_emm_active_filter)
		ll_emm_active_filter = ll_create("ll_emm_active_filter");

	if (!ll_emm_inactive_filter)
		ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter");

	if (!ll_emm_pending_filter)
		ll_emm_pending_filter = ll_create("ll_emm_pending_filter");

	S_EMM_FILTER *filter_item;
	if (!cs_malloc(&filter_item,sizeof(S_EMM_FILTER)))
		return 0;

	filter_item->demux_id 		= demux_id;
	memcpy(filter_item->filter, filter, 32);
	filter_item->caid 			= caid;
	filter_item->provid 		= provid;
	filter_item->pid 			= emmpid;
	filter_item->count 			= count;
	filter_item->num	 		= num;
	filter_item->time_started	= now;
	if (num>0)
		ll_append(ll_emm_active_filter, filter_item);
	else if (num<0)
		ll_append(ll_emm_pending_filter, filter_item);
	else
		ll_append(ll_emm_inactive_filter, filter_item);
	return 1;
}

int32_t find_emmfilter_in_list(uchar *filter, uint16_t emmpid, uint32_t provid) 
{
	if (!ll_emm_active_filter)
		ll_emm_active_filter = ll_create("ll_emm_active_filter");

	if (!ll_emm_inactive_filter)
		ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter");

	if (!ll_emm_pending_filter)
		ll_emm_pending_filter = ll_create("ll_emm_pending_filter");

	S_EMM_FILTER *filter_item;
	LL_ITER itr;
	if (ll_count(ll_emm_active_filter) > 0) {
		itr = ll_iter_create(ll_emm_active_filter);
		while ((filter_item=ll_iter_next(&itr))) {
			if (!memcmp(filter_item->filter, filter, 32) && filter_item->pid == emmpid && filter_item->provid == provid)
				return 1;
		}
	}
	if (ll_count(ll_emm_inactive_filter) > 0) {
		itr = ll_iter_create(ll_emm_inactive_filter);
		while ((filter_item=ll_iter_next(&itr))) {
			if (!memcmp(filter_item->filter, filter, 32)  && filter_item->pid == emmpid && filter_item->provid == provid)
				return 1;
		}
	}
	if (ll_count(ll_emm_pending_filter) > 0) {
		itr = ll_iter_create(ll_emm_pending_filter);
		while ((filter_item=ll_iter_next(&itr))) {
			if (!memcmp(filter_item->filter, filter, 32)  && filter_item->pid == emmpid && filter_item->provid == provid)
				return 1;
		}
	}
	return 0;
}

int32_t dvbapi_set_filter(int32_t demux_id, int32_t api, uint16_t pid, uint16_t caid, uint32_t provid, uchar *filt, uchar *mask, int32_t timeout, int32_t pidindex, int32_t count, int32_t type, int8_t add_to_emm_list) {
#if defined WITH_AZBOX || defined WITH_MCA
	openxcas_caid = demux[demux_id].ECMpids[pidindex].CAID;
	openxcas_ecm_pid = pid;

 	return 1;
#endif
	int32_t ret=-1,n=-1,i;

	for (i=0; i<MAX_FILTER && demux[demux_id].demux_fd[i].fd>0; i++);

	if (i>=MAX_FILTER) {
		cs_debug_mask(D_DVBAPI,"no free filter");
		return -1;
	}
	n=i;

	demux[demux_id].demux_fd[n].pidindex = pidindex;
	demux[demux_id].demux_fd[n].pid      = pid;
	demux[demux_id].demux_fd[n].caid     = caid;
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
#ifdef WITH_COOLAPI
		case COOLAPI:
			demux[demux_id].demux_fd[n].fd = coolapi_open_device(demux[demux_id].demux_index, demux_id);
			if(demux[demux_id].demux_fd[n].fd > 0)
				ret = coolapi_set_filter(demux[demux_id].demux_fd[n].fd, n, pid, filt, mask, type);
			break;
#endif
		default:
			break;
	}

	if (ret < 0)
		cs_log("ERROR: Could not start demux filter (errno=%d %s)", errno, strerror(errno));

	if (type==TYPE_EMM && add_to_emm_list)
		add_emmfilter_to_list(demux_id, filt, caid, provid, pid, count, n, time((time_t *) 0));

	return ret;
}

static int32_t dvbapi_detect_api(void) {
#ifdef WITH_COOLAPI
	selected_api=COOLAPI;
	selected_box = 5;
	disable_pmt_files = 1;
	cs_log("Detected Coolstream API");
	return 1;
#else
	int32_t i,devnum=-1, dmx_fd=0, boxnum = sizeof(devices)/sizeof(struct box_devices);
	char device_path[128], device_path2[128];

	for (i=0;i<boxnum;i++) {
		snprintf(device_path2, sizeof(device_path2), devices[i].demux_device, 0);
		snprintf(device_path, sizeof(device_path), devices[i].path, 0);

		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);

		if ((dmx_fd = open(device_path, O_RDWR)) > 0) {
			devnum=i;
			close(dmx_fd);
			break;
		}
	}

	if (devnum == -1) return 0;
	selected_box = devnum;
	if (selected_box > -1)
		selected_api=devices[selected_box].api;

#ifdef WITH_STAPI
	if (devnum == 4 && stapi_open() == 0) {
		cs_log("ERROR: stapi: setting up stapi failed.");
		return 0;
	}
#endif
	if (cfg.dvbapi_boxtype == BOXTYPE_NEUMO) {
		selected_api=DVBAPI_1;
	}

	cs_log("Detected %s Api: %d", device_path, selected_api);
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
		cs_log("ERROR: Read on %d timed out", dmx_fd);
		return -1;
	}

	len = read(dmx_fd, buf, length);

	if (len==-1)
		cs_log("ERROR: Read error on fd %d (errno=%d %s)", dmx_fd, errno, strerror(errno));

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

		if (cfg.dvbapi_boxtype==BOXTYPE_PC)
			num=0;

		snprintf(device_path2, sizeof(device_path2), devices[selected_box].ca_device, num+ca_offset);
		snprintf(device_path, sizeof(device_path), devices[selected_box].path, adapter);

		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);
	}

	if ((dmx_fd = open(device_path, O_RDWR)) < 0) {
		cs_log("ERROR: Can't open device %s (errno=%d %s)", device_path, errno, strerror(errno));
		return -1;
	}

	cs_debug_mask(D_DVBAPI, "DEVICE open (%s) fd %d", device_path, dmx_fd);
	return dmx_fd;
}

int32_t dvbapi_open_netdevice(int32_t UNUSED(type), int32_t UNUSED(num), int32_t adapter) {
	int32_t socket_fd;

	socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket_fd == -1) {
		cs_log("ERROR: Failed create socket (%d %s)", errno, strerror(errno));
	} else {
		struct sockaddr_in saddr;
		fcntl(socket_fd, F_SETFL, O_NONBLOCK);
		bzero(&saddr, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(PORT + adapter); // port = PORT + adapter number
		saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		int32_t r = connect(socket_fd, (struct sockaddr *) &saddr, sizeof(saddr));
		if (r<0) {
			cs_log("ERROR: Failed to connect socket (%d %s), at localhost, port=%d", errno, strerror(errno), PORT + adapter);
			close(socket_fd);
			socket_fd = -1;
		}
	}

	cs_debug_mask(D_DVBAPI, "NET DEVICE open (port = %d) fd %d", PORT + adapter, socket_fd);
	return socket_fd;
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
#ifdef WITH_COOLAPI
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
		if (demux[demux_index].demux_fd[num].type == TYPE_ECM)
			demux[demux_index].ECMpids[demux[demux_index].demux_fd[num].pidindex].index=0; //filter stopped, reset index

		demux[demux_index].demux_fd[num].fd=0;
	}
	return ret;
}

void dvbapi_start_filter(int32_t demux_id, int32_t pidindex, uint16_t pid, uint16_t caid, uchar table, uchar mask, int32_t timeout, int32_t type, int32_t count)
{
	uchar filter[32];

	cs_debug_mask(D_DVBAPI, "set filter pid: %04x", pid);

	memset(filter,0,32);

	filter[0]=table;
	filter[16]=mask;

	dvbapi_set_filter(demux_id, selected_api, pid, caid, 0, filter, filter+16, timeout, pidindex, count, type, 0);
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

static int32_t dvbapi_find_emmpid(int32_t demux_id, uint8_t type, uint16_t caid, uint32_t provid) {
	int32_t k;
	int32_t bck = -1;
	for (k=0; k<demux[demux_id].EMMpidcount; k++) {
		if (demux[demux_id].EMMpids[k].CAID == caid
		 && demux[demux_id].EMMpids[k].PROVID == provid
		 && (demux[demux_id].EMMpids[k].type & type))
			return k;
		else if (demux[demux_id].EMMpids[k].CAID == caid
		 && (!demux[demux_id].EMMpids[k].PROVID || !provid)
		 && (demux[demux_id].EMMpids[k].type & type) && bck)
			bck = k;
	}
	return bck;
}

void dvbapi_start_emm_filter(int32_t demux_index) {
	int32_t j, fcount=0, fcount_added=0;
	const char *typtext[] = { "UNIQUE", "SHARED", "GLOBAL", "UNKNOWN" };

	if (demux[demux_index].pidindex==-1) 
		return;

	if (!demux[demux_index].EMMpidcount)
		return;

	if (demux[demux_index].emm_filter)
		return;


	uchar dmx_filter[342]; // 10 filter + 2 byte header

	struct s_reader *rdr = NULL;
	struct s_client *cl = cur_client();
	LL_ITER itr = ll_iter_create(cl->aureader_list);
	while ((rdr = ll_iter_next(&itr))) {

		if (rdr->audisabled != 0) 
			continue;

		memset(dmx_filter, 0, sizeof(dmx_filter));
		dmx_filter[0]=0xFF;
		dmx_filter[1]=0;

		struct s_cardsystem *cs;
		if (!rdr->caid)
			cs = get_cardsystem_by_caid(rdr->csystem.caids[0]);
		else
			cs = get_cardsystem_by_caid(rdr->caid);

		if (cs)
			cs->get_emm_filter(rdr, dmx_filter);
		else {
			cs_debug_mask(D_DVBAPI, "[EMM Filter] cardsystem for emm filter for %s not found", rdr->label);
			continue;
		}

		int32_t filter_count=dmx_filter[1];

		for (j=1;j<=filter_count && j <= 10;j++) {
			int32_t startpos=2+(34*(j-1));

			if (dmx_filter[startpos+1] != 0x00)
				continue;

			uchar filter[32];
			memcpy(filter, dmx_filter+startpos+2, 32);
			int32_t emmtype=dmx_filter[startpos];
			//int32_t count=dmx_filter[startpos+1];
			int32_t l=-1;

			if ( (filter[0] && (((1<<(filter[0] % 0x80)) & rdr->b_nano) && !((1<<(filter[0] % 0x80)) & rdr->s_nano))) )
				continue;

			if ((rdr->blockemm & emmtype) && !(((1<<(filter[0] % 0x80)) & rdr->s_nano) || (rdr->saveemm & emmtype)))
				continue;

			if(rdr->caid == 0x100) {
				uint32_t seca_provid = 0;
				if (emmtype == EMM_SHARED)
					seca_provid = ((filter[1] << 8) | filter[2]);
				l = dvbapi_find_emmpid(demux_index, emmtype, 0x0100, seca_provid);
			} else {
				//.. provid 0 is safe since oscam sets filter with e.g. rdr->sa & doesn't add filter twice (find_emmfilter_in_list)
				if (!rdr->caid) {
					l = dvbapi_find_emmpid(demux_index, emmtype, rdr->csystem.caids[0], 0);
					if (l<0)
						l = dvbapi_find_emmpid(demux_index, emmtype, rdr->csystem.caids[1], 0);
				} else {
					l = dvbapi_find_emmpid(demux_index, emmtype, rdr->caid, 0);
				}
			}
			if (l>-1) {
				 //filter already in list?
				if (find_emmfilter_in_list(filter, demux[demux_index].EMMpids[l].PID, demux[demux_index].EMMpids[l].PROVID)) {
					fcount_added++; 
					continue;
				}

				uint32_t typtext_idx = 0;
				while (((emmtype >> typtext_idx) & 0x01) == 0 && typtext_idx < sizeof(typtext) / sizeof(const char *)){
					++typtext_idx;
				}

				cs_ddump_mask(D_DVBAPI, filter, 32, "[EMM Filter] starting emm filter type %s, pid: 0x%04X", typtext[typtext_idx], demux[demux_index].EMMpids[l].PID);
				if (fcount>=demux[demux_index].max_emm_filter) {
					add_emmfilter_to_list(demux_index, filter, demux[demux_index].EMMpids[l].CAID, demux[demux_index].EMMpids[l].PROVID, demux[demux_index].EMMpids[l].PID, fcount+1, 0, 0);
				} else {
					dvbapi_set_filter(demux_index, selected_api, demux[demux_index].EMMpids[l].PID, demux[demux_index].EMMpids[l].CAID, demux[demux_index].EMMpids[l].PROVID, filter, filter+16, 0, demux[demux_index].pidindex, fcount+1, TYPE_EMM, 1);
				}
				fcount++;
				demux[demux_index].emm_filter=1;
			}
		}
	}
	if (fcount)
		cs_debug_mask(D_DVBAPI,"[EMM Filter] %i matching emm filter found", fcount);
	if (fcount_added) {
		demux[demux_index].emm_filter=1;
		cs_debug_mask(D_DVBAPI,"[EMM Filter] %i matching emm filter skipped because they are already active on same emmpid:provid", fcount_added);
	}
}

void dvbapi_add_ecmpid_int(int32_t demux_id, uint16_t caid, uint16_t ecmpid, uint32_t provid) {
	int32_t n,added=0;

	if (demux[demux_id].ECMpidcount>=ECM_PIDS)
		return;

	int32_t stream = demux[demux_id].STREAMpidcount-1;
	for (n=0;n<demux[demux_id].ECMpidcount;n++) {
		if (stream>-1 && demux[demux_id].ECMpids[n].CAID == caid && demux[demux_id].ECMpids[n].ECM_PID == ecmpid) {
			if (!demux[demux_id].ECMpids[n].streams) {
				//we already got this caid/ecmpid as global, no need to add the single stream
				cs_log("[SKIP STREAM %d] CAID: %04X ECM_PID: %04X PROVID: %06X", n, caid, ecmpid, provid);
				continue;
			}
			added=1;
			demux[demux_id].ECMpids[n].streams |= (1 << stream);
			cs_log("[ADD STREAM %d] CAID: %04X ECM_PID: %04X PROVID: %06X", n, caid, ecmpid, provid);
		}
	}

	if (added==1)
		return;

	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].ECM_PID = ecmpid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CAID = caid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].PROVID = provid;
	if (stream>-1)
		demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].streams |= (1 << stream);

	cs_log("[ADD PID %d] CAID: %04X ECM_PID: %04X PROVID: %06X", demux[demux_id].ECMpidcount, caid, ecmpid, provid);
	demux[demux_id].ECMpidcount++;
}

void dvbapi_add_ecmpid(int32_t demux_id, uint16_t caid, uint16_t ecmpid, uint32_t provid) {
	dvbapi_add_ecmpid_int(demux_id, caid, ecmpid, provid);
	struct s_dvbapi_priority *joinentry;
	for (joinentry=dvbapi_priority; joinentry != NULL; joinentry=joinentry->next) {
		if (joinentry->type != 'j') continue;
		if (joinentry->caid 	&& joinentry->caid 	!= caid)	continue;
		if (joinentry->provid && joinentry->provid 	!= provid)	continue;
		if (joinentry->ecmpid	&& joinentry->ecmpid 	!= ecmpid)	continue;
		if (joinentry->srvid	&& joinentry->srvid 	!= demux[demux_id].program_number) continue;
		cs_debug_mask(D_DVBAPI,"[PMT] Join ECMPID %04X:%06X:%04X to %04X:%06X:%04X", caid, provid, ecmpid, joinentry->mapcaid, joinentry->mapprovid, joinentry->mapecmpid);
		dvbapi_add_ecmpid_int(demux_id, joinentry->mapcaid, joinentry->mapecmpid, joinentry->mapprovid);
	}
}

void dvbapi_add_emmpid(struct s_reader *testrdr, int32_t demux_id, uint16_t caid, uint16_t emmpid, uint32_t provid, uint8_t type) {
	if (emm_reader_match(testrdr, caid, provid)){
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PID = emmpid;
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].CAID = caid;
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PROVID = provid;
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount++].type = type;
		cs_debug_mask(D_DVBAPI,"[ADD EMMPID] CAID: %04X EMM_PID: %04X PROVID: %06X - (type %d) ENABLED!", caid, emmpid, provid, type);
	}
	else {
		cs_debug_mask(D_DVBAPI,"[ADD EMMPID] CAID: %04X EMM_PID: %04X PROVID: %06X - (type %d) DISABLED!", caid, emmpid, provid, type);
	}
}

void dvbapi_parse_cat(int32_t demux_id, uchar *buf, int32_t len) {
	uint16_t i, k;
	struct s_reader *testrdr = NULL;
	
	cs_ddump_mask(D_DVBAPI, buf, len, "cat:");

	struct s_client *cl = cur_client();
	LL_ITER itr = ll_iter_create(cl->aureader_list);
	while ((testrdr = ll_iter_next(&itr))) { // make a list of all readers
		if ((testrdr->audisabled !=0) || (!testrdr->enable)){ //only parse au enabled readers that are enabled
			cs_debug_mask(D_DVBAPI,"Reader %s au disabled or not enabled-> skip!", testrdr->label);
			continue; 
		} 
		else cs_debug_mask(D_DVBAPI,"Reader %s au enabled -> parsing cat for emm pids!", testrdr->label);
		
		for (i = 8; i < (((buf[1] & 0x0F) << 8) | buf[2]) - 1; i += buf[i + 1] + 2) {
			if (buf[i] != 0x09) continue;
			if (demux[demux_id].EMMpidcount >= ECM_PIDS) break;
			
			uint16_t caid=((buf[i + 2] << 8) | buf[i + 3]);
			uint16_t emm_pid=(((buf[i + 4] & 0x1F) << 8) | buf[i + 5]);
			uint32_t emm_provider = 0;
			
			
			switch (caid >> 8) {
				case 0x01:
					dvbapi_add_emmpid(testrdr, demux_id, caid, emm_pid, 0, EMM_UNIQUE|EMM_GLOBAL);
					for (k = i+7; k < i+buf[i+1]+2; k += 4) {
						emm_provider = (buf[k+2] << 8| buf[k+3]);
						emm_pid = (buf[k] & 0x0F) << 8 | buf[k+1];
						dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, emm_provider, EMM_SHARED);
					}
					continue;
				case 0x05:
					for (k = i+6; k < i+buf[i+1]+2; k += buf[k+1]+2) {
						if (buf[k]==0x14) {
							emm_provider = buf[k+2] << 16 | (buf[k+3] << 8| (buf[k+4] & 0xF0));
							dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
						}
					}
					continue;
				case 0x18:
					emm_provider = (buf[i+1] == 0x07) ? (buf[i+6] << 16 | (buf[i+7] << 8| (buf[i+8]))) : 0;
					dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
					continue;
				default:
					dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, 0, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
					continue;
			}
		}
	}
		
	return;
}

static pthread_mutex_t lockindex = PTHREAD_MUTEX_INITIALIZER;
int32_t dvbapi_get_descindex(void) {
	pthread_mutex_lock(&lockindex); // to avoid race when readers become responsive!
	int32_t i,j,idx=1,fail=1;
	while (fail) {
		fail=0;
		cs_sleepus(0);
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
	pthread_mutex_unlock(&lockindex); // and release it!
	return idx;
}

void dvbapi_set_pid(int32_t demux_id, int32_t num, int32_t idx) {
	int32_t i;

	if (demux[demux_id].pidindex == -1) return;

	switch(selected_api) {
#ifdef WITH_STAPI
		case STAPI:
			stapi_set_pid(demux_id, num, idx, demux[demux_id].STREAMpids[num], demux[demux_id].pmt_file);
			break;
#endif
#ifdef WITH_COOLAPI
		case COOLAPI:
			break;
#endif
		default:
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {
					if (ca_fd[i]<=0) {
						if (cfg.dvbapi_boxtype == BOXTYPE_PC)
							ca_fd[i]=dvbapi_open_netdevice(1, i, demux[demux_id].adapter_index);
						else
							ca_fd[i]=dvbapi_open_device(1, i, demux[demux_id].adapter_index);
					}
					if (ca_fd[i]>0) {
						ca_pid_t ca_pid2;
						memset(&ca_pid2,0,sizeof(ca_pid2));
						ca_pid2.pid = demux[demux_id].STREAMpids[num];
						ca_pid2.index = idx;

						if (cfg.dvbapi_boxtype == BOXTYPE_PC) {
							// preparing packet
							int32_t request = CA_SET_PID;
							unsigned char packet[sizeof(request) + sizeof(ca_pid2)];
							memcpy(&packet, &request, sizeof(request));
							memcpy(&packet[sizeof(request)], &ca_pid2, sizeof(ca_pid2));

							// sending data
							send(ca_fd[i], &packet, sizeof(packet), 0);
						} else {
							// This ioctl fails on dm500 but that is OK.
							if (ioctl(ca_fd[i], CA_SET_PID, &ca_pid2)==-1)
								cs_debug_mask(D_TRACE|D_DVBAPI,"ERROR: ioctl(CA_SET_PID) pid=0x%04x index=%d (errno=%d %s)", ca_pid2.pid, ca_pid2.index, errno, strerror(errno));
							else
								cs_debug_mask(D_DVBAPI, "CA_SET_PID pid=0x%04x index=%d", ca_pid2.pid, ca_pid2.index);
						}
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
	if (ll_emm_active_filter)
		ll_clear_data(ll_emm_active_filter);
	if (ll_emm_inactive_filter)
		ll_clear_data(ll_emm_inactive_filter);
	if (ll_emm_pending_filter)
		ll_clear_data(ll_emm_pending_filter);

	for (i=0;i<demux[demux_id].STREAMpidcount;i++) {
		dvbapi_set_pid(demux_id, i, -1);
	}
	if(cfg.dvbapi_reopenonzap && selected_api != STAPI){
		for (i=0;i<8;i++) {
			if (ca_fd[i] && (demux[demux_id].ca_mask & (1 << i))) {
				int8_t j, found = 0;
				// Check for other demuxes running on same ca device
				for(j = 0; j < MAX_DEMUX; ++j){
					if(j != demux_id && demux[j].pidindex != -1 && (demux[j].ca_mask & (1 << i))) {
						found = 1;
						break;
					}
				}
				if(!found){
					cs_debug_mask(D_DVBAPI, "Closing unused demux device ca%d (fd=%d).", i, ca_fd[i]);
					close(ca_fd[i]);
					ca_fd[i] = 0;
				}
			}
		}
	}

	memset(&demux[demux_id], 0 ,sizeof(DEMUXTYPE));
	demux[demux_id].pidindex=-1;

	unlink(ECMINFO_FILE);

	return;
}

void dvbapi_start_descrambling(int32_t demux_id) {
	int32_t j,k,n;
	int32_t streamcount=0;

	int32_t last_pidindex = demux[demux_id].pidindex;
  	demux[demux_id].pidindex = demux[demux_id].curindex;
	
	for (n=0; n<demux[demux_id].ECMpidcount; n++) { // cleanout old indexes of pids that have now status ignore (=no decoding possible!) 
		if (demux[demux_id].ECMpids[n].status == -1) demux[demux_id].ECMpids[n].index = 0; // reset index!
	}
	for (j=0; j<demux[demux_id].ECMpidcount; j++) {
		if (demux[demux_id].curindex == j || (demux[demux_id].ECMpids[demux[demux_id].curindex].CAID == demux[demux_id].ECMpids[j].CAID
				&& demux[demux_id].ECMpids[demux[demux_id].curindex].PROVID == demux[demux_id].ECMpids[j].PROVID
				&& demux[demux_id].ECMpids[j].PROVID > 0 
				&& demux[demux_id].ECMpids[demux[demux_id].curindex].ECM_PID == demux[demux_id].ECMpids[j].ECM_PID)) {

			if (demux[demux_id].curindex != j) {
				if (demux[demux_id].ECMpids[j].status < 0 || !demux[demux_id].ECMpids[demux[demux_id].curindex].streams)
					continue;

				dvbapi_start_filter(demux_id, j, demux[demux_id].ECMpids[j].ECM_PID, demux[demux_id].ECMpids[j].CAID, 0x80, 0xF0, 3000, TYPE_ECM, 0);
			}

			if (!demux[demux_id].ECMpids[j].index && demux[demux_id].ECMpids[j].status != -1) // status of pid = ignore -> skip!
				demux[demux_id].ECMpids[j].index=dvbapi_get_descindex();

			if (!demux[demux_id].ECMpids[j].checked)
				demux[demux_id].ECMpids[j].checked=1;
			demux[demux_id].ECMpids[j].irdeto_curchid=demux[demux_id].ECMpids[demux[demux_id].curindex].irdeto_curchid;

			for (k=0;k<demux[demux_id].STREAMpidcount;k++) {
				if (!demux[demux_id].ECMpids[j].streams || (demux[demux_id].ECMpids[j].streams & (1 << k))) {
					dvbapi_set_pid(demux_id, k, demux[demux_id].ECMpids[j].index-1);
				}
				else
				        dvbapi_set_pid(demux_id, k, -1);
			}

			streamcount++;
		}
	}

	cs_log("Start descrambling PID #%d (CAID: %04X) %d", demux[demux_id].curindex, demux[demux_id].ECMpids[demux[demux_id].curindex].CAID, streamcount);

	if (cfg.dvbapi_au>0  && last_pidindex != demux[demux_id].pidindex && !demux[demux_id].EMMpidcount) {
		if (last_pidindex != -1) {
			dvbapi_stop_filter(demux_id, TYPE_EMM);
			demux[demux_id].emm_filter=0;
			if (ll_emm_active_filter)
				ll_clear_data(ll_emm_active_filter);
			if (ll_emm_inactive_filter)
				ll_clear_data(ll_emm_inactive_filter);
			if (ll_emm_pending_filter)
				ll_clear_data(ll_emm_pending_filter);
		}
		dvbapi_start_filter(demux_id, demux[demux_id].pidindex, 0x001, 0x001, 0x01, 0xFF, 0, TYPE_EMM, 0); //CAT
	}
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


	cs_debug_mask(D_DVBAPI, "emm from fd %d", demux[demux_index].demux_fd[filter_num].fd); //emm shown with -d64

	struct s_dvbapi_priority *mapentry = dvbapi_check_prio_match(demux_index, demux[demux_index].pidindex, 'm');
	if (mapentry) {
		cs_debug_mask(D_DVBAPI, "Mapping EMM from %04X:%06X to %04X:%06X", caid, provider, mapentry->mapcaid, mapentry->mapprovid);
		caid = mapentry->mapcaid;
		provider = mapentry->mapprovid;
	}

	memset(&epg, 0, sizeof(epg));

	i2b_buf(2, caid, epg.caid);
	i2b_buf(4, provider, epg.provid);

	epg.emmlen=len;
	memcpy(epg.emm, buffer, epg.emmlen);

	do_emm(dvbapi_client, &epg);
}

void dvbapi_read_priority(void) {
	FILE *fp;
	char token[128], str1[128];
	char type;
	int32_t i, ret, count=0;

	const char *cs_prio="oscam.dvbapi";

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_prio);
	fp=fopen(token, "r");

	if (!fp) {
		cs_debug_mask(D_DVBAPI, "ERROR: Can't open priority file %s", token);
		return;
	}

	if (dvbapi_priority) {
		cs_debug_mask(D_DVBAPI, "reread priority file %s", cs_prio);
		struct s_dvbapi_priority *o, *p;
		for (p = dvbapi_priority; p != NULL; p = o) {
			o = p->next;
			free(p);
		}
		dvbapi_priority = NULL;
	}

	while (fgets(token, sizeof(token), fp)) {
		// Ignore comments and empty lines
		if (token[0]=='#' || token[0]=='/' || token[0]=='\n' || token[0]=='\r' || token[0]=='\0')
			continue;
		if (strlen(token)>100) continue;

		memset(str1, 0, 128);

		for (i=0; i<(int)strlen(token) && token[i]==' '; i++);
		if (i  == (int)strlen(token) - 1) //empty line or all spaces
			continue;

		for (i=0;i<(int)strlen(token);i++) {
			if ((token[i]==':' || token[i]==' ') && token[i+1]==':') { 	// if "::" or " :"
				memmove(token+i+2, token+i+1, strlen(token)-i+1); //insert extra position
				token[i+1]='0';		//and fill it with NULL
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

		if (ret<1 || (type != 'p' && type != 'i' && type != 'm' && type != 'd' && type != 's' && type != 'l' && type != 'j' && type != 'a' && type != 'x')) {
			//fprintf(stderr, "Warning: line containing %s in %s not recognized, ignoring line\n", token, cs_prio);
			//fprintf would issue the warning to the command line, which is more consistent with other config warnings
			//however it takes OSCam a long time (>4 seconds) to reach this part of the program, so the warnings are reaching tty rather late
			//which leads to confusion. So send the warnings to log file instead
			cs_debug_mask(D_DVBAPI, "WARN: line containing %s in %s not recognized, ignoring line\n", token, cs_prio);
			continue;
		}

		struct s_dvbapi_priority *entry;
		if (!cs_malloc(&entry, sizeof(struct s_dvbapi_priority))) {
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
		ret = sscanf(str1, "%4x:%6x:%33[^:]:%4x:%4x", &caid, &provid, c_srvid, &ecmpid, &chid);
		if (ret < 1) {
			cs_debug_mask(D_DVBAPI, "Error in oscam.dvbapi: ret=%d | %c: %04X %06X %s %04X %04X",
						ret, type, caid, provid, c_srvid, ecmpid, chid);
			continue; // skip this entry!
		}
		else {
			cs_debug_mask(D_DVBAPI, "Parsing rule: ret=%d | %c: %04X %06X %s %04X %04X",
						ret, type, caid, provid, c_srvid, ecmpid, chid);
		}
			
		entry->caid=caid;
		entry->provid=provid;
		entry->ecmpid=ecmpid;
		entry->chid=chid;

		uint32_t delay=0, force=0, mapcaid=0, mapprovid=0, mapecmpid=0;
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
			case 'a':
			case 'j':
				sscanf(str1+64, "%4x:%6x:%4x", &mapcaid, &mapprovid, &mapecmpid);
				entry->mapcaid=mapcaid;
				entry->mapprovid=mapprovid;
				entry->mapecmpid=mapecmpid;
				break;
		}

		if (c_srvid[0]=='=') {
			struct s_srvid *this;

			for (i=0;i<16;i++)
			for (this = cfg.srvid[i]; this; this = this->next) {
				if (strcmp(this->prov, c_srvid+1)==0) {
					struct s_dvbapi_priority *entry2;
					if (!cs_malloc(&entry2,sizeof(struct s_dvbapi_priority)))
						continue;
					memcpy(entry2, entry, sizeof(struct s_dvbapi_priority));

					entry2->srvid=this->srvid;

					cs_debug_mask(D_DVBAPI, "prio srvid: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X %04X | prio %d | delay %d",
						ret, entry2->type, entry2->caid, entry2->provid, entry2->srvid, entry2->ecmpid, entry2->chid, entry2->mapcaid, entry2->mapprovid, entry2->mapecmpid, entry2->force, entry2->delay);

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

		cs_debug_mask(D_DVBAPI, "prio: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X %04X | prio %d | delay %d",
			ret, entry->type, entry->caid, entry->provid, entry->srvid, entry->ecmpid, entry->chid, entry->mapcaid, entry->mapprovid, entry->mapecmpid, entry->force, entry->delay);

		if (!dvbapi_priority) {
			dvbapi_priority=entry;
		} else {
 			struct s_dvbapi_priority *p;
			for (p = dvbapi_priority; p->next != NULL; p = p->next);
			p->next = entry;
		}
	}

	cs_debug_mask(D_DVBAPI, "Read %d entries from %s", count, cs_prio);

	fclose(fp);
	return;
}

struct s_dvbapi_priority *dvbapi_check_prio_match_emmpid(int32_t demux_id, uint16_t caid, uint32_t provid, char type) {
	struct s_dvbapi_priority *p;
	int32_t i;

	uint16_t ecm_pid=0;
	for (i=0; i<demux[demux_id].ECMpidcount; i++) {
		if ((demux[demux_id].ECMpids[i].CAID==caid) && (demux[demux_id].ECMpids[i].PROVID==provid)) {
			ecm_pid=demux[demux_id].ECMpids[i].ECM_PID;
			break;
		}
	}

	if (!ecm_pid)
		return NULL;

	for (p=dvbapi_priority, i=0; p != NULL; p=p->next, i++) {
		if (p->type != type) continue;

		if (p->caid 	&& p->caid 	!= caid)	continue;
		if (p->provid && p->provid 	!= provid)	continue;
		if (p->ecmpid	&& p->ecmpid 	!= ecm_pid)	continue;
		if (p->srvid	&& p->srvid 	!= demux[demux_id].program_number)	continue;

		if (p->type == 'i' && p->chid) continue;

		return p;
	}
	return NULL;

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

int32_t chk_valid_btun(ECM_REQUEST *er, uint16_t caidto)
{
	int32_t i;
	struct s_client *cl = cur_client();
	TUNTAB *ttab;
	ttab = &cl->ttab;

	for (i = 0; i<ttab->n; i++) {
		if ((er->caid==ttab->bt_caidfrom[i]) &&
				((caidto==ttab->bt_caidto[i])) &&
				((er->srvid==ttab->bt_srvid[i]) || (ttab->bt_srvid[i])==0xFFFF)) {
			return 1;
		}
	}
#ifdef WITH_LB
	if (cfg.lb_auto_betatunnel && lb_valid_btun(er, caidto))
		return 1;

#endif
	return 0;
}

void dvbapi_resort_ecmpids(int32_t demux_index) {
	int32_t n, cache=0, prio=1, highest_prio=0, matching_done=0;
	uint16_t btun_caid=0;

	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		demux[demux_index].ECMpids[n].status=0;
		demux[demux_index].ECMpids[n].checked=0;
	}

	demux[demux_index].max_status=0;
	demux[demux_index].tries = 0;
	demux[demux_index].curindex = 0;
	demux[demux_index].pidindex = -1;

	if (cfg.dvbapi_requestmode == 1) {
		int32_t found=-1;
		for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
			if (find_channel_cache(demux_index, n, 0)) {
				found = n;
				break;
			}
		}
		if (found != -1) { //Found in cache
			for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
				if (n != found)
					demux[demux_index].ECMpids[n].status = -1;
				else
					demux[demux_index].ECMpids[n].status = 1;
			}
			demux[demux_index].max_status = 1;
			return;
		}
	} else {
		//prioritize CAIDs which already decoded same caid:provid
		for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
			if (find_channel_cache(demux_index, n, 1)) {
				cache=1; //found cache entry
				demux[demux_index].ECMpids[n].status = prio;
				cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (found caid/provid in cache - weight: %d)", n,
						demux[demux_index].ECMpids[n].CAID,demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, 
						demux[demux_index].ECMpids[n].status);
			}
		}

		//prioritize CAIDs which already decoded same caid:provid:srvid
		for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
			if (find_channel_cache(demux_index, n, 0)) {
				cache=2; //found cache entry with higher priority
				demux[demux_index].ECMpids[n].status = prio*2;
				cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (found caid/provid/srvid in cache - weight: %d)", n,
						demux[demux_index].ECMpids[n].CAID,demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, 
						demux[demux_index].ECMpids[n].status);
			}
		}
	}

	//prioritize & ignore according to oscam.dvbapi and cfg.preferlocalcards
	if (dvbapi_priority) {
		struct s_reader *rdr;
		ECM_REQUEST *er;
		if (!cs_malloc(&er, sizeof(ECM_REQUEST)))
			return;

		int32_t add_prio=0; // make sure that p: values overrule cache
		if (cache==1)
			add_prio = prio;
		else if (cache==2)
			add_prio = prio*2;

		int32_t p_order = demux[demux_index].ECMpidcount; // reverse order! makes sure that user defined p: values are in the right order

		highest_prio = (prio * demux[demux_index].ECMpidcount) + p_order;

		struct s_dvbapi_priority *p;
		for (p = dvbapi_priority; p != NULL; p = p->next) {
			if (p->type != 'p' && p->type != 'i')
				continue;
			for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
				if (!cache && demux[demux_index].ECMpids[n].status != 0)
					continue;
				else if (cache==1 && (demux[demux_index].ECMpids[n].status < 0 || demux[demux_index].ECMpids[n].status > prio))
					continue;
				else if (cache==2 && (demux[demux_index].ECMpids[n].status < 0 || demux[demux_index].ECMpids[n].status > prio*2))
					continue;

				er->caid = er->ocaid = demux[demux_index].ECMpids[n].CAID;
				er->prid = demux[demux_index].ECMpids[n].PROVID;
				er->pid = demux[demux_index].ECMpids[n].ECM_PID;
				er->srvid = demux[demux_index].program_number;
				er->client = cur_client();

				btun_caid = get_betatunnel_caid_to(er->caid);
				if (p->type == 'p' && btun_caid) {
					if (chk_valid_btun(er, btun_caid))
						er->caid = btun_caid;
				}

				if (p->caid && p->caid != er->caid)
					continue;
				if (p->provid && p->provid != er->prid)
					continue;
				if (p->ecmpid && p->ecmpid != er->pid)
					continue;
				if (p->srvid && p->srvid != er->srvid)
					continue;
				
				if (p->type == 'i') { // check if ignored by dvbapi
					if (p->chid)
						continue;
					demux[demux_index].ECMpids[n].status = -1;
					cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X (file)", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,demux[demux_index].ECMpids[n].ECM_PID);
					continue;
				}

				if (p->type == 'p') {
					if (demux[demux_index].ECMpids[n].status == -1) //skip ignores
						continue;

					matching_done = 1;

					for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
						if (cfg.preferlocalcards
								&& !is_network_reader(rdr)
								&& rdr->card_status == CARD_INSERTED) { // cfg.preferlocalcards = 1 local reader
							if (matching_reader(er, rdr, 0)) {
								if (cache==2 && demux[demux_index].ECMpids[n].status==1)
									demux[demux_index].ECMpids[n].status++;
								else if (cache && !demux[demux_index].ECMpids[n].status)
									demux[demux_index].ECMpids[n].status += add_prio;
								demux[demux_index].ECMpids[n].status += (prio * demux[demux_index].ECMpidcount) + (p_order--); //priority*ECMpidcount should overrule network reader
								cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (localrdr: %s weight: %d)", n, demux[demux_index].ECMpids[n].CAID,
										demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, rdr->label, demux[demux_index].ECMpids[n].status);
								break;
							} else {
								if (!rdr->next) // no match so ignore it!
									demux[demux_index].ECMpids[n].status = -1;
							}
						} else { // cfg.preferlocalcards = 0 or cfg.preferlocalcards = 1 and no local reader
							if (matching_reader(er, rdr, 0)) {
								if (cache==2 && demux[demux_index].ECMpids[n].status==1)
									demux[demux_index].ECMpids[n].status++;
								else if (cache && !demux[demux_index].ECMpids[n].status)
									demux[demux_index].ECMpids[n].status += add_prio;
								demux[demux_index].ECMpids[n].status += prio + (p_order--);
								cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (rdr: %s weight: %d)", n, demux[demux_index].ECMpids[n].CAID,
									demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, rdr->label, demux[demux_index].ECMpids[n].status);
								break;
							} else {
								if (!rdr->next) // no match so ignore it!
									demux[demux_index].ECMpids[n].status = -1;
							}
						}
					}
					if (demux[demux_index].ECMpids[n].status == -1)
						cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X (no matching reader)", n, demux[demux_index].ECMpids[n].CAID, 
						demux[demux_index].ECMpids[n].PROVID,demux[demux_index].ECMpids[n].ECM_PID);
				}
			}
		}
		free(er);
	} 
	
	 if (!dvbapi_priority || !matching_done) { //works if there is no oscam.dvbapi or if there is oscam.dvbapi but not p rules in it
		struct s_reader *rdr;
		ECM_REQUEST *er;
		if (!cs_malloc(&er, sizeof(ECM_REQUEST)))
			return;

		highest_prio = prio*2;

		for (n=0; n<demux[demux_index].ECMpidcount; n++) {
			if (demux[demux_index].ECMpids[n].status == -1) //skip ignores
				continue;

			matching_done=1;

			er->caid = er->ocaid = demux[demux_index].ECMpids[n].CAID;
			er->prid = demux[demux_index].ECMpids[n].PROVID;
			er->pid = demux[demux_index].ECMpids[n].ECM_PID;
			er->srvid = demux[demux_index].program_number;
			er->client = cur_client();

			btun_caid = get_betatunnel_caid_to(er->caid);
			if (btun_caid) {
				if (chk_valid_btun(er, btun_caid))
					er->caid = btun_caid;
			}

			for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
				if (cfg.preferlocalcards 
						&& !is_network_reader(rdr) 
						&& rdr->card_status==CARD_INSERTED) { // cfg.preferlocalcards = 1 local reader
					if (matching_reader(er, rdr, 0)) {
						demux[demux_index].ECMpids[n].status += prio*2;
						cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (localrdr: %s weight: %d)", n, demux[demux_index].ECMpids[n].CAID,
								demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, rdr->label, demux[demux_index].ECMpids[n].status);
						break;
					} else {
						if (!rdr->next) // no match so ignore it!
							demux[demux_index].ECMpids[n].status = -1;
					}
				} else { // cfg.preferlocalcards = 0 or cfg.preferlocalcards = 1 and no local reader
					if (matching_reader(er, rdr, 0)) {
						demux[demux_index].ECMpids[n].status += prio;
						cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (rdr: %s weight: %d)", n, demux[demux_index].ECMpids[n].CAID,
								demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, rdr->label, demux[demux_index].ECMpids[n].status);
						break;
					} else {
						if (!rdr->next) // no match so ignore it!
							demux[demux_index].ECMpids[n].status = -1;
					}
				}
			}
			if (demux[demux_index].ECMpids[n].status == -1)
				cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X (no matching reader)", n, demux[demux_index].ECMpids[n].CAID,
				demux[demux_index].ECMpids[n].PROVID,demux[demux_index].ECMpids[n].ECM_PID);
		}
		free(er);
	}

	if (cache==1)
		highest_prio += prio;
	else if (cache==2)
		highest_prio += prio*2;

	highest_prio++;

	for (n=demux[demux_index].ECMpidcount; n>-1; n--) { //maintain pid prio order of the pmt.
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
					cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X (service %s) pos %d", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, sidtab->label, nr);
				}
				if ((cfg.dvbapi_sidtabok&((SIDTABBITS)1<<nr)) && (chk_srvid_match(&er, sidtab))) {
					demux[demux_index].ECMpids[n].status = highest_prio++; //priority
					cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (service: %s position: %d)", n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, sidtab->label, demux[demux_index].ECMpids[n].status);
				}
			}
		}
	}

#ifdef WITH_COOLAPI
	// driver sometimes reports error if too many emm filter 
	// but adding more ecm filter is no problem
	// ... so ifdef here instead of limiting MAX_FILTER
	demux[demux_index].max_emm_filter = 14;
#else
	if (cfg.dvbapi_requestmode == 1) {
		uint16_t ecm_filter_needed=0;
		for (n=0; n<demux[demux_index].ECMpidcount; n++) {
			if (demux[demux_index].ECMpids[n].status > -1)
				ecm_filter_needed++;
		}
		if (MAX_FILTER-ecm_filter_needed<=0)
			demux[demux_index].max_emm_filter = 0;
		else
			demux[demux_index].max_emm_filter = MAX_FILTER-ecm_filter_needed;
	} else {
		demux[demux_index].max_emm_filter = MAX_FILTER-1;
	}
#endif

	demux[demux_index].max_status = highest_prio;
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

		cs_debug_mask(D_DVBAPI, "[pmt] type: %02x length: %d", buffer[j], descriptor_length);

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
				descriptor_ca_provider = (buffer[j+7] << 8| (buffer[j+8]));

			if (descriptor_ca_system_id >> 8 == 0x4A && descriptor_length == 0x05)
				descriptor_ca_provider = buffer[j+6];

			dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider);
		}
	}

	//Apply mapping:
	if (dvbapi_priority) {
		struct s_dvbapi_priority *mapentry;
		for (j = 0; (int32_t)j < demux[demux_id].ECMpidcount; j++) {
			mapentry = dvbapi_check_prio_match(demux_id, j, 'm');
			if (mapentry) {
				cs_debug_mask(D_DVBAPI,"mapping ECM from %04X:%06X to %04X:%06X",
						demux[demux_id].ECMpids[j].CAID, demux[demux_id].ECMpids[j].PROVID,
						mapentry->mapcaid, mapentry->mapprovid);
				demux[demux_id].ECMpids[j].CAID = mapentry->mapcaid;
				demux[demux_id].ECMpids[j].PROVID = mapentry->mapprovid;
			}
		}
	}
}

void request_cw(struct s_client *client, ECM_REQUEST *er)
{
#ifdef WITH_DEBUG
	char buf[ECM_FMT_LEN];
	format_ecm(er, buf, ECM_FMT_LEN);
	cs_debug_mask(D_DVBAPI, "dvbapi request cw for %s", buf);
#endif
	get_cw(client, er);
}

void dvbapi_try_next_caid(int32_t demux_id) {
	int32_t num=-1, n, j;
	if (cfg.dvbapi_decodeforever && demux[demux_id].tries > 2){
		dvbapi_resort_ecmpids(demux_id);
		cs_sleepms(150);
		dvbapi_start_descrambling(demux_id);
		return;
	}
		
	if (demux[demux_id].tries > 2) {
		cs_log("ERROR: Can't decode channel");
		dvbapi_stop_filter(demux_id, TYPE_ECM);
		return;
	}

	//values for first run (status > 0)
	int32_t start=1;
	int32_t end=demux[demux_id].max_status;

	while (num==-1) {
		for (j = end; j >= start && num == -1; j--) { //largest status first!
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
		cs_debug_mask(D_DVBAPI,"try pids again #%d", demux[demux_id].tries);
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

	if (cfg.dvbapi_requestmode != 1){
		dvbapi_stop_filter(demux_id, TYPE_ECM);
    }

	cs_debug_mask(D_DVBAPI,"[TRY PID %d] CAID: %04X PROVID: %06X CA_PID: %04X", num, demux[demux_id].ECMpids[num].CAID, demux[demux_id].ECMpids[num].PROVID, demux[demux_id].ECMpids[num].ECM_PID);
#if defined WITH_AZBOX || defined WITH_MCA
	openxcas_provid = demux[demux_id].ECMpids[num].PROVID;
	openxcas_caid = demux[demux_id].ECMpids[num].CAID;
	openxcas_ecm_pid = demux[demux_id].ECMpids[num].ECM_PID;
#endif
	demux[demux_id].curindex=num;

	demux[demux_id].ECMpids[num].checked=1;

	//BISS or FAKE CAID
	//ecm stream pid is fake, so send out one fake ecm request
	if (demux[demux_id].ECMpids[num].CAID == 0xFFFF || (demux[demux_id].ECMpids[num].CAID >> 8) == 0x26) {
		ECM_REQUEST *er;
		if (!(er=get_ecmtask()))
			return;

		er->srvid = demux[demux_id].program_number;
		er->caid  = demux[demux_id].ECMpids[num].CAID;
		er->pid   = demux[demux_id].ECMpids[num].ECM_PID;
		er->prid  = demux[demux_id].ECMpids[num].PROVID;

		er->ecmlen=5;
		er->ecm[1] = 0x00;
		er->ecm[2] = 0x02;
		i2b_buf(2, er->srvid, er->ecm+3);

		for (j=0, n=5; j<demux[demux_id].STREAMpidcount; j++, n+=2) {
			i2b_buf(2, demux[demux_id].STREAMpids[j], er->ecm+n);
			er->ecm[2] += 2;
			er->ecmlen += 2;
		}

		request_cw(dvbapi_client, er);

		if (cfg.dvbapi_requestmode == 1)
			dvbapi_try_next_caid(demux_id);

		return;
	}

	if (cfg.dvbapi_requestmode == 1) {
		dvbapi_start_filter(demux_id, num, demux[demux_id].ECMpids[num].ECM_PID, demux[demux_id].ECMpids[num].CAID, 0x80, 0xF0, 3000, TYPE_ECM, 3);
		dvbapi_try_next_caid(demux_id);
	} else {
		dvbapi_start_filter(demux_id, num, demux[demux_id].ECMpids[num].ECM_PID, demux[demux_id].ECMpids[num].CAID, 0x80, 0xF0, 3000, TYPE_ECM, 0);
	}
}

static void getDemuxOptions(int32_t demux_id, unsigned char *buffer, uint16_t *ca_mask, uint16_t *demux_index, uint16_t *adapter_index){
#ifdef WITH_MCA
	*ca_mask=0x03, *demux_index=0x01, *adapter_index=0x00;
#else
	*ca_mask=0x01, *demux_index=0x00, *adapter_index=0x00;
#endif

	if (buffer[17]==0x82 && buffer[18]==0x02) {
		//enigma2
		*ca_mask = buffer[19];
		*demux_index = buffer[20];
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_IPBOX_PMT) {
		*ca_mask = demux_id + 1;
		*demux_index = demux_id;
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_QBOXHD && buffer[17]==0x82 && buffer[18]==0x03) {
		//ca_mask = buffer[19];     // with STONE 1.0.4 always 0x01
		*demux_index = buffer[20];   // with STONE 1.0.4 always 0x00
		*adapter_index = buffer[21]; // with STONE 1.0.4 adapter index can be 0,1,2
		*ca_mask = (1 << *adapter_index); // use adapter_index as ca_mask (used as index for ca_fd[] array)
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_PC && buffer[7]==0x82 && buffer[8]==0x02) {
		*demux_index = buffer[9];	// it is always 0 but you never know
		*adapter_index = buffer[10];	// adapter index can be 0,1,2
		*ca_mask = (1 << *adapter_index);	// use adapter_index as ca_mask (used as index for ca_fd[] array)
	}
}

int32_t dvbapi_parse_capmt(unsigned char *buffer, uint32_t length, int32_t connfd, char *pmtfile) {
	uint32_t i;
	int32_t demux_id=-1;
	uint16_t ca_mask, demux_index, adapter_index;

#ifdef WITH_COOLAPI
	int32_t ca_pmt_list_management = 0x03;
#else
	int32_t ca_pmt_list_management = buffer[0];
#endif
	uint32_t program_number = (buffer[1] << 8) | buffer[2];
	uint32_t program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	cs_ddump_mask(D_DVBAPI, buffer, length, "capmt:");

	for (i = 0; i < MAX_DEMUX; i++) {
#ifdef WITH_COOLAPI
		if (connfd>0 && demux[i].program_number==program_number) {
#else
		if (connfd>0 && demux[i].socket_fd == connfd) {
#endif
			//PMT Update
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
		}
	}

	if (demux_id==-1)
		for (demux_id=0; demux_id<MAX_DEMUX && demux[demux_id].program_number>0; demux_id++);

	if (demux_id>=MAX_DEMUX) {
		cs_log("ERROR: No free id (MAX_DEMUX)");
		return -1;
	}

	getDemuxOptions(demux_id, buffer, &ca_mask, &demux_index, &adapter_index);

	if (buffer[7]==0x81 && buffer[8]==0x08) {
		// parse private descriptor as used by enigma (4 bytes namespace, 2 tsid, 2 onid)
		demux[demux_id].enigma_namespace=(buffer[9] << 24 | buffer[10] << 16 | buffer[11] << 8 | buffer[12]);
		demux[demux_id].tsid=(buffer[13] << 8 | buffer[14]);
		demux[demux_id].onid=(buffer[15] << 8 | buffer[16]);
	} else {
		demux[demux_id].enigma_namespace=0;
		demux[demux_id].tsid=0;
		demux[demux_id].onid=0;
	}


	demux[demux_id].program_number=program_number;
	demux[demux_id].demux_index=demux_index;
	demux[demux_id].adapter_index=adapter_index;
	demux[demux_id].ca_mask=ca_mask;
	demux[demux_id].socket_fd=connfd;
	demux[demux_id].rdr=NULL;
	demux[demux_id].pidindex=-1;

	cs_debug_mask(D_DVBAPI, "id: %2d demux_index: %2d ca_mask: %02x program_info_length: %3d ca_pmt_list_management %02x",
			demux_id, demux[demux_id].demux_index, demux[demux_id].ca_mask, program_info_length, ca_pmt_list_management);

	if (pmtfile)
		cs_strncpy(demux[demux_id].pmt_file, pmtfile, sizeof(demux[demux_id].pmt_file));

	if (program_info_length > 1 && program_info_length < length)
		dvbapi_parse_descriptor(demux_id, program_info_length-1, buffer+7);

	uint32_t es_info_length=0;
	struct s_dvbapi_priority *addentry;
	for (i = program_info_length + 6; i < length; i += es_info_length + 5) {
		int32_t stream_type = buffer[i];
		uint16_t elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug_mask(D_DVBAPI, "[pmt] stream_type: %02x pid: %04x length: %d", stream_type, elementary_pid, es_info_length);

		if (demux[demux_id].STREAMpidcount >= ECM_PIDS)
			break;

		demux[demux_id].STREAMpids[demux[demux_id].STREAMpidcount++]=elementary_pid;

		if (es_info_length != 0 && es_info_length < length) {
			dvbapi_parse_descriptor(demux_id, es_info_length, buffer+i+5);
		} else {
			for (addentry=dvbapi_priority; addentry != NULL; addentry=addentry->next) {
				if (addentry->type != 'a') continue;
				if (addentry->ecmpid && addentry->ecmpid 	!= elementary_pid) continue;
				if (addentry->srvid 	!= demux[demux_id].program_number) continue;
				cs_debug_mask(D_DVBAPI,"[pmt] Add Fake FFFF:%06x:%04x for unencrypted stream on srvid %04X", addentry->mapprovid, addentry->mapecmpid, demux[demux_id].program_number);
				dvbapi_add_ecmpid(demux_id, 0xFFFF, addentry->mapecmpid, addentry->mapprovid);
				break;
			}
		}
	}
	cs_log("Found %d ECMpids and %d STREAMpids in PMT", demux[demux_id].ECMpidcount, demux[demux_id].STREAMpidcount);
	
	char channame[32];
	get_servicename(dvbapi_client, demux[demux_id].program_number, demux[demux_id].ECMpidcount>0 ? demux[demux_id].ECMpids[0].CAID : 0, channame);
	cs_log("New program number: %04X (%s) [pmt_list_management %d]", program_number, channame, ca_pmt_list_management);
	
	struct s_dvbapi_priority *xtraentry;
	int32_t j, k, l, m, xtra_demux_id;
	for (xtraentry=dvbapi_priority; xtraentry != NULL; xtraentry=xtraentry->next) {
		if (xtraentry->type != 'x') continue;
		for(j = 0; j <= demux[demux_id].ECMpidcount; ++j){
			if (xtraentry->caid	&& xtraentry->caid 	!= demux[demux_id].ECMpids[j].CAID)	continue;
			if (xtraentry->provid	&& xtraentry->provid 	!= demux[demux_id].ECMpids[j].PROVID) continue;
			if (xtraentry->ecmpid	&& xtraentry->ecmpid 	!= demux[demux_id].ECMpids[j].ECM_PID)	continue;
			if (xtraentry->srvid	&& xtraentry->srvid 	!= demux[demux_id].program_number) continue;
			cs_log("[pmt] Mapping %04X:%06X:%04X:%04X to xtra demuxer/ca-devices", xtraentry->caid, xtraentry->provid, xtraentry->ecmpid, xtraentry->srvid);
			for (xtra_demux_id=0; xtra_demux_id<MAX_DEMUX && demux[xtra_demux_id].program_number>0; xtra_demux_id++);
			if (xtra_demux_id>=MAX_DEMUX) {
				cs_log("Found no free demux device for xtra streams.");
				continue;
			}
			
			getDemuxOptions(xtra_demux_id, buffer, &ca_mask, &demux_index, &adapter_index);
						
			// copy to new demuxer
			demux[xtra_demux_id].ECMpids[0] = demux[demux_id].ECMpids[j];
			demux[xtra_demux_id].ECMpidcount = 1;
			demux[xtra_demux_id].STREAMpidcount = 0;		
			demux[xtra_demux_id].program_number=demux[demux_id].program_number;
			demux[xtra_demux_id].demux_index=demux_index;
			demux[xtra_demux_id].adapter_index=adapter_index;
			demux[xtra_demux_id].ca_mask=ca_mask;
			demux[xtra_demux_id].socket_fd=connfd;
			demux[xtra_demux_id].rdr=NULL;
			demux[xtra_demux_id].pidindex=-1;
			
			//add streams to xtra demux
			for(k = 0; k < demux[demux_id].STREAMpidcount; ++k){
				if(!demux[demux_id].ECMpids[j].streams || demux[demux_id].ECMpids[j].streams & (1 << k)){
					demux[xtra_demux_id].ECMpids[0].streams |= (1 << demux[xtra_demux_id].STREAMpidcount);
					demux[xtra_demux_id].STREAMpids[demux[xtra_demux_id].STREAMpidcount] = demux[demux_id].STREAMpids[k];
					++demux[xtra_demux_id].STREAMpidcount;
					
					//shift stream associations in normal demux because we will remove the stream entirely
					for(l = 0; l < demux[demux_id].ECMpidcount; ++l){
						for(m = k; m < demux[demux_id].STREAMpidcount-1; ++m){
							if(demux[demux_id].ECMpids[l].streams & (1 << (m+1))){
								demux[demux_id].ECMpids[l].streams |= (1 << m);
							} else {
								demux[demux_id].ECMpids[l].streams &= ~(1 << m);
							}
						}
					}
					// remove stream association from normal demux device
					for(l = k; l < demux[demux_id].STREAMpidcount-1; ++l){
						demux[demux_id].STREAMpids[l] = demux[demux_id].STREAMpids[l+1];
					}
					--demux[demux_id].STREAMpidcount;
					--k;
				}
			}
			
			//remove ecmpid from normal demuxer
			for(k = j; k < demux[demux_id].ECMpidcount; ++k){
				demux[demux_id].ECMpids[k] = demux[demux_id].ECMpids[k+1];
			}
			--demux[demux_id].ECMpidcount;			
			--j;
			if(demux[xtra_demux_id].STREAMpidcount > 0){
				dvbapi_start_descrambling(xtra_demux_id);
				dvbapi_try_next_caid(xtra_demux_id);
			} else {
				cs_log("[pmt] Found no streams for xtra demuxer. Not starting additional decoding on it.");
			}
			if(demux[demux_id].STREAMpidcount < 1){
				cs_log("[pmt] Found no streams for normal demuxer. Not starting additional decoding on it.");
				return xtra_demux_id;
			}
		}
	}

#if defined WITH_AZBOX || defined WITH_MCA
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
		dvbapi_client->last=time((time_t*)0);
	}

	return demux_id;
}


void dvbapi_handlesockmsg (unsigned char *buffer, uint32_t len, int32_t connfd) {
	uint32_t val=0, size=0, i, k;

	//cs_dump(buffer, len, "handlesockmsg:");
	for (k = 0; k < len; k += 3 + size + val) {
		if (buffer[0+k] != 0x9F || buffer[1+k] != 0x80) {
			cs_debug_mask(D_DVBAPI,"unknown socket command: %02x", buffer[0+k]);
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
				cs_debug_mask(D_DVBAPI,"handlesockmsg() unknown command");
				cs_dump(buffer, len, "unknown command:");
				break;
		}
	}
}

int32_t dvbapi_init_listenfd(void) {
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
	if (bind(listenfd, (struct sockaddr_un *) &servaddr, clilen) < 0)
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

	for (ptr1=strtok_r(caidasc, ",", &saveptr1); (ptr1); ptr1=strtok_r(NULL, ",", &saveptr1)) {
		uint32_t caid, prov;
		if( (ptr3=strchr(trim(ptr1), ':')) )
			*ptr3++='\0';
		else
			ptr3="";

		if (((caid=a2i(ptr1, 2))|(prov=a2i(ptr3, 3)))) {
			struct s_dvbapi_priority *entry;
			if (!cs_malloc(&entry, sizeof(struct s_dvbapi_priority)))
				return;
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

void event_handler(int32_t UNUSED(signal)) {
	struct stat pmt_info;
	char dest[1024];
	DIR *dirp;
	struct dirent entry, *dp = NULL;
	int32_t i, pmt_fd;
	uchar mbuf[1024];

	if (dvbapi_client != cur_client()) return;

	pthread_mutex_lock(&event_handler_lock);

	if (cfg.dvbapi_boxtype == BOXTYPE_PC)
		pausecam = 0;
	else {
		int32_t standby_fd = open(STANDBY_FILE, O_RDONLY);
		pausecam = (standby_fd > 0) ? 1 : 0;
		if (standby_fd) close(standby_fd);
	}

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
					cs_log("Stopping demux for pmt file %s", dest);
				 	dvbapi_stop_descrambling(i);
				}

				close(pmt_fd);
				continue;
			} else {
				cs_log("Stopping demux for pmt file %s", dest);
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
		cs_debug_mask(D_DVBAPI,"opendir failed (errno=%d %s)", errno, strerror(errno));
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	while (!cs_readdir_r(dirp, &entry, &dp)) {
		if (!dp) break;

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

		cs_debug_mask(D_DVBAPI,"found pmt file %s", dest);
		cs_sleepms(100);

		uint32_t len = read(pmt_fd,mbuf,sizeof(mbuf));
		close(pmt_fd);

		if (len < 1) {
			cs_debug_mask(D_DVBAPI,"pmt file %s have invalid len!", dest);
			continue;
		}

		int32_t pmt_id;
#ifdef QBOXHD
		uint32_t j1,j2;
		// QboxHD pmt.tmp is the full capmt written as a string of hex values
		// pmt.tmp must be longer than 3 bytes (6 hex chars) and even length
		if ((len<6) || ((len%2) != 0) || ((len/2)>sizeof(dest))) {
			cs_debug_mask(D_DVBAPI,"error parsing QboxHD pmt.tmp, incorrect length");
			continue;
		}

		for(j2=0,j1=0;j2<len;j2+=2,j1++) {
			if (sscanf((char*)mbuf+j2, "%02X", (unsigned int*)dest+j1) != 1) {
				cs_debug_mask(D_DVBAPI,"error parsing QboxHD pmt.tmp, data not valid in position %d",j2);
				pthread_mutex_unlock(&event_handler_lock);
				return;
			}
		}

		cs_ddump_mask(D_DVBAPI, (unsigned char *)dest, len/2, "QboxHD pmt.tmp:");

		pmt_id = dvbapi_parse_capmt((unsigned char *)dest+4, (len/2)-4, -1, dp->d_name);
#else
		if (len>sizeof(dest)) {
			cs_debug_mask(D_DVBAPI,"event_handler() dest buffer is to small for pmt data!");
			continue;
		}
		cs_ddump_mask(D_DVBAPI, mbuf,len,"pmt:");

		dest[0] = 0x03;
		dest[1] = mbuf[3];
		dest[2] = mbuf[4];

		i2b_buf(2, (((mbuf[10] & 0x0F) << 8) | mbuf[11])+1, (uchar*)dest+4);
		dest[6] = 0;

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

	if (cfg.dvbapi_au>0) // start emm filter!
		dvbapi_start_emm_filter(demux_id);
	
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
				cs_debug_mask(D_DVBAPI,"Found %d IRDETO ECM CHIDs", buffer[5]+1);
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

		if (!provid)
			provid = chk_provid(buffer, caid);

		if (provid != curpid->PROVID)
			curpid->PROVID = provid;
			
		ECM_REQUEST *er;
		if (!(er=get_ecmtask()))
			return;

		er->srvid = demux[demux_id].program_number;

		er->tsid = demux[demux_id].tsid;
		er->onid = demux[demux_id].onid;
		er->ens = demux[demux_id].enigma_namespace;

		er->caid  = caid;
		er->pid   = curpid->ECM_PID;
		er->prid  = provid;
		er->chid  = chid;
		er->ecmlen= len;
		memcpy(er->ecm, buffer, er->ecmlen);

		request_cw(dvbapi_client, er);

		if (demux[demux_id].demux_fd[filter_num].count==1) {
			cs_debug_mask(D_DVBAPI, "auto disable filter #%d", filter_num);
			dvbapi_stop_filternum(demux_id, filter_num);
		}
		if (demux[demux_id].demux_fd[filter_num].count>1) {
			demux[demux_id].demux_fd[filter_num].count--;
		}
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

	//emm filter iteration
	if (!ll_emm_active_filter)
		ll_emm_active_filter = ll_create("ll_emm_active_filter");

	if (!ll_emm_inactive_filter)
		ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter");

	if (!ll_emm_pending_filter)
		ll_emm_pending_filter = ll_create("ll_emm_pending_filter");

	uint32_t filter_count = ll_count(ll_emm_active_filter)+ll_count(ll_emm_inactive_filter);
	if (ll_count(ll_emm_inactive_filter) > 0 && filter_count > demux[demux_id].max_emm_filter) {
		int32_t filter_queue = ll_count(ll_emm_inactive_filter);
		int32_t stopped=0, started=0;
		time_t now = time((time_t *) 0);
		S_EMM_FILTER *filter_item;
		LL_ITER itr;
		itr = ll_iter_create(ll_emm_active_filter);
		while ((filter_item=ll_iter_next(&itr))) {
			if (!ll_count(ll_emm_inactive_filter) || (started == filter_queue))
				break;
			if (abs(now-filter_item->time_started) > 45) {
					struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match_emmpid(filter_item->demux_id, filter_item->caid, 
																						filter_item->provid, 'p');
					if (!forceentry || (forceentry && !forceentry->force)) {
					cs_debug_mask(D_DVBAPI,"[EMM Filter] removing emm filter %i num %i on demux index %i", 
										filter_item->count, filter_item->num, filter_item->demux_id);
					dvbapi_stop_filternum(filter_item->demux_id, filter_item->num);
					ll_iter_remove_data(&itr);
					add_emmfilter_to_list(filter_item->demux_id, filter_item->filter, filter_item->caid, 
											filter_item->provid, filter_item->pid, filter_item->count, -1, 0);
					stopped++;
				}
			}
			if (stopped>started) {
				S_EMM_FILTER *filter_item2;
				LL_ITER itr2 = ll_iter_create(ll_emm_inactive_filter);
				while ((filter_item2=ll_iter_next(&itr2))) {
						cs_ddump_mask(D_DVBAPI, filter_item2->filter, 32, "[EMM Filter] starting emm filter %i, pid: 0x%04X on demux index %i",
											filter_item2->count, filter_item2->pid, filter_item2->demux_id);
						dvbapi_set_filter(filter_item2->demux_id, selected_api, filter_item2->pid, filter_item2->caid, 
											filter_item2->provid, filter_item2->filter, filter_item2->filter+16, 0,
											demux[filter_item2->demux_id].pidindex, filter_item2->count, TYPE_EMM, 1);
						ll_iter_remove_data(&itr2);
						started++;
						break;	
				}
			}
		}
		itr = ll_iter_create(ll_emm_pending_filter);
		while ((filter_item=ll_iter_next(&itr))) {
			add_emmfilter_to_list(filter_item->demux_id, filter_item->filter, filter_item->caid, 
									filter_item->provid, filter_item->pid, filter_item->count, 0, 0);
			ll_iter_remove_data(&itr);
		}
	}
}

static void * dvbapi_main_local(void *cli) {
#ifdef WITH_AZBOX
	return azbox_main_thread(cli);
#endif
#ifdef WITH_MCA
	return mca_main_thread(cli);
#endif

	struct s_client * client = (struct s_client *) cli;
	client->thread=pthread_self();
	pthread_setspecific(getclient, cli);

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
	for (account = cfg.account; account; account=account->next) {
		if ((ok = streq(cfg.dvbapi_usr, account->usr)))
			break;
	}
	cs_auth_client(client, ok ? account : (struct s_auth *)(-1), "dvbapi");

	memset(demux, 0, sizeof(struct demux_s) * MAX_DEMUX);
	memset(ca_fd, 0, sizeof(ca_fd));

	dvbapi_read_priority();
	dvbapi_detect_api();

	if (selected_box == -1 || selected_api==-1) {
		cs_log("ERROR: Could not detect DVBAPI version.");
		return NULL;
	}

	if (cfg.dvbapi_pmtmode == 1)
		disable_pmt_files=1;

	int32_t listenfd = -1;
	if (cfg.dvbapi_boxtype != BOXTYPE_IPBOX_PMT && cfg.dvbapi_pmtmode != 2 && cfg.dvbapi_pmtmode != 5) {
		listenfd = dvbapi_init_listenfd();
		if (listenfd < 1) {
			cs_log("ERROR: Could not init camd.socket.");
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
		int32_t ret = pthread_create(&event_thread, NULL, dvbapi_event_thread, (void*) dvbapi_client);
		if(ret){
			cs_log("ERROR: Can't create dvbapi event thread (errno=%d %s)", ret, strerror(ret));
			return NULL;
		} else
			pthread_detach(event_thread);
	}


	pfd2[0].fd = listenfd;
	pfd2[0].events = (POLLIN | POLLPRI);
	type[0]=1;
#ifdef WITH_COOLAPI
	system("pzapit -rz");
#endif
	while (1) {
		pfdcount = (listenfd > -1) ? 1 : 0;

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
			}
			if (pfd2[i].revents & (POLLIN | POLLPRI)) {
				if (type[i]==1) {
					if (pfd2[i].fd==listenfd) {
						clilen = sizeof(servaddr);
						connfd = accept(listenfd, (struct sockaddr_un *)&servaddr, (socklen_t *)&clilen);
						cs_debug_mask(D_DVBAPI, "new socket connection fd: %d", connfd);

						disable_pmt_files=1;

						if (connfd <= 0) {
							cs_debug_mask(D_DVBAPI,"accept() returns error on fd event %d (errno=%d %s)", pfd2[i].revents, errno, strerror(errno));
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
	return NULL;
}

void dvbapi_write_cw(int32_t demux_id, uchar *cw, int32_t idx) {
	int32_t n;
	int8_t cwEmpty = 0;
	unsigned char nullcw[8];
	memset(nullcw, 0, 8);
	ca_descr_t ca_descr;
	memset(&ca_descr,0,sizeof(ca_descr));
	if(memcmp(demux[demux_id].lastcw[0],nullcw,8)==0 && memcmp(demux[demux_id].lastcw[1],nullcw,8)==0) cwEmpty = 1;		// to make sure that both cws get written on constantcw

	for (n=0;n<2;n++) {
		char lastcw[9*3];
		char newcw[9*3];
		cs_hexdump(0, demux[demux_id].lastcw[n], 8, lastcw, sizeof(lastcw));
		cs_hexdump(0, cw+(n*8), 8, newcw, sizeof(newcw));
		if (((memcmp(cw+(n*8),demux[demux_id].lastcw[0],8)!=0 && memcmp(cw+(n*8),demux[demux_id].lastcw[1],8)!=0) || cwEmpty) && memcmp(cw+(n*8),nullcw,8)!=0) { // check if already delivered and new cw part is valid!
			ca_descr.index = idx;
			ca_descr.parity = n;
			cs_debug_mask(D_DVBAPI,"writing %s part (%s) of controlword, replacing expired (%s)",(n == 1?"odd":"even"), newcw, lastcw);
			memcpy(demux[demux_id].lastcw[n],cw+(n*8),8);
			memcpy(ca_descr.cw,cw+(n*8),8);
#ifdef WITH_COOLAPI
			cs_debug_mask(D_DVBAPI, "write cw%d index: %d (ca_mask %d)", n, ca_descr.index, demux[demux_id].ca_mask);
			coolapi_write_cw(demux[demux_id].ca_mask, demux[demux_id].STREAMpids, demux[demux_id].STREAMpidcount, &ca_descr);
#else
			int32_t i;
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {
					cs_debug_mask(D_DVBAPI, "write cw%d index: %d (ca%d)", n, ca_descr.index, i);
					if (ca_fd[i]<=0) {
						if (cfg.dvbapi_boxtype == BOXTYPE_PC)
							ca_fd[i]=dvbapi_open_netdevice(1, i, demux[demux_id].adapter_index);
						else
							ca_fd[i]=dvbapi_open_device(1, i, demux[demux_id].adapter_index);
						if (ca_fd[i]<=0)
							return;
					}

					if (cfg.dvbapi_boxtype == BOXTYPE_PC) {
						// preparing packet
						int32_t request = CA_SET_DESCR;
						unsigned char packet[sizeof(request) + sizeof(ca_descr)];
						memcpy(&packet, &request, sizeof(request));
						memcpy(&packet[sizeof(request)], &ca_descr, sizeof(ca_descr));

						// sending data
						send(ca_fd[i], &packet, sizeof(packet), 0);
					} else {
						if (ioctl(ca_fd[i], CA_SET_DESCR, &ca_descr) < 0)
							cs_log("ERROR: ioctl(CA_SET_DESCR): %s", strerror(errno));
					}
				}
			}
#endif
		}
	}
}

void delayer(ECM_REQUEST *er)
{
  if (cfg.dvbapi_delayer <= 0) return;

  struct timeb tpe;
  cs_ftime(&tpe);
  int32_t t = 1000 * (tpe.time-er->tps.time) + tpe.millitm-er->tps.millitm;
  if (t < cfg.dvbapi_delayer) {
    cs_debug_mask(D_DVBAPI, "delayer: t=%dms, cfg=%dms -> delay=%dms", t, cfg.dvbapi_delayer, cfg.dvbapi_delayer-t);
    cs_sleepms(cfg.dvbapi_delayer-t);
  }
}

void dvbapi_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
#ifdef WITH_AZBOX
	azbox_send_dcw(client, er);
	return;
#endif
#ifdef WITH_MCA
	mca_send_dcw(client, er);
	return;
#endif
    
	int32_t i,j;

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].program_number==er->srvid) {
			demux[i].rdr=er->selected_reader;

			for (j=0; j<demux[i].ECMpidcount; j++)
				if ((demux[i].ECMpids[j].CAID == er->caid || demux[i].ECMpids[j].CAID == er->ocaid) && demux[i].ECMpids[j].ECM_PID == er->pid && demux[i].ECMpids[j].PROVID == er->prid)
						break;
			if (j==demux[i].ECMpidcount) continue;

			if (er->rc < E_NOTFOUND && cfg.dvbapi_requestmode==0 && (demux[i].pidindex==-1) && er->caid!=0) {
							edit_channel_cache(i, j, 1);
			                dvbapi_start_descrambling(i);
			}

			if (er->rc < E_NOTFOUND && cfg.dvbapi_requestmode==1 && (demux[i].pidindex==-1) && er->caid!=0 && demux[i].ECMpids[j].checked != 2) { //FOUND

                                        int32_t num_pids=0, last_idx=j;

                                        int32_t t;
                                        for (t=0;t<demux[i].ECMpidcount;t++) {

                                                //check this FOUND for higher status:
                                                if (t!=j && demux[i].ECMpids[j].status >= demux[i].ECMpids[t].status) { //mark index t as low status
                                                        demux[i].ECMpids[t].checked = 2;
                                                }
                                                if (demux[i].ECMpids[t].checked != 2) {
                                                        num_pids++;
                                                        last_idx=t;
                                                }
                                        }

                                                int32_t o;
                                                for (o = 0; o < MAX_FILTER; o++) {
                                                        if (demux[i].demux_fd[o].fd > 0) { //TESTME: ocaid for betatunnel added!
                                                                if ((demux[i].demux_fd[o].pid == er->pid) && ((demux[i].demux_fd[o].caid == demux[i].ECMpids[last_idx].CAID ) || (demux[i].demux_fd[o].caid == er->ocaid)))
                                                                        demux[i].demux_fd[o].count = 0; //activate last_idx
                                                                      else
                                                                        dvbapi_stop_filternum(i, o);
                                                        }
                                                }
                                                edit_channel_cache(i, j, 1);

                                                demux[i].curindex = j;
                                                dvbapi_start_descrambling(i);
                            }
                                        if (demux[i].pidindex != -1 && demux[i].curindex != j) {
                                                demux[i].curindex = j;
                                                //I hope this trick works for all: adjust the index to write the right cw:
                                                demux[i].ECMpids[j].index = demux[i].ECMpids[demux[i].pidindex].index;
                                                dvbapi_start_descrambling(i);
                                        }
			if (er->rc >= E_NOTFOUND) {
				edit_channel_cache(i, j, 0);
				if ((er->caid >> 8) == 0x06 && demux[i].ECMpids[j].irdeto_chids < (((0xFFFF<<(demux[i].ECMpids[j].irdeto_numchids)) ^ 0xFFFF) & 0xFFFF)) {
					demux[i].ECMpids[j].irdeto_curchid++;
					demux[i].ECMpids[j].table=0;
					cs_debug_mask(D_DVBAPI,"trying irdeto chid index: %d", demux[i].ECMpids[j].irdeto_curchid);
					return;
				}
				demux[i].ECMpids[j].irdeto_chids = 0;
				demux[i].ECMpids[j].irdeto_curchid = 0;
				demux[i].ECMpids[j].irdeto_cycle = 0;
				int8_t last_checked = demux[i].ECMpids[j].checked;
				demux[i].ECMpids[j].checked = 2;

				if (demux[i].pidindex==-1) {
					if (cfg.dvbapi_requestmode == 1)
						return;

					struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(i, demux[i].curindex, 'p');
					if (forceentry && forceentry->force)
							dvbapi_start_descrambling(i);
					else
						dvbapi_try_next_caid(i);
				} else {
					struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(i, demux[i].curindex, 'p');
					if (!forceentry || (forceentry && !forceentry->force)) {
						demux[i].curindex = 0; 
						demux[i].pidindex = -1;
						dvbapi_try_next_caid(i);
					}
					else if (cfg.dvbapi_requestmode == 1) {
						int32_t t, num_pids;
						for (num_pids = 0, t = 0; t < demux[i].ECMpidcount;t++) {
							if (demux[i].ECMpids[t].checked != 2)
								num_pids++;
						}
						cs_debug_mask(D_DVBAPI, "request restarting num_pids=%d last_checked=%d", num_pids, last_checked);

						if (!num_pids && last_checked == 1) { // we had rc=E_FOUND, but now we get a NOT_FOUND? Try all caids again:
							dvbapi_resort_ecmpids(i);
							dvbapi_try_next_caid(i);
						}
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

			delayer(er);

			switch (selected_api) {
#ifdef WITH_STAPI
				case STAPI:
					stapi_write_cw(i, er->cw, demux[i].STREAMpids, demux[i].STREAMpidcount, demux[i].pmt_file);
					break;
#endif
				default:
					if (cfg.dvbapi_boxtype == BOXTYPE_NEUMO) {
						int32_t idx=0;
						sscanf(demux[i].pmt_file, "pmt%3d.tmp", &idx);
						dvbapi_write_cw(i, er->cw, idx);
						break;
					}
					dvbapi_write_cw(i, er->cw, demux[i].ECMpids[j].index-1);
					break;
			}

			// reset idle-Time
			client->last=time((time_t*)0);

			FILE *ecmtxt;
			ecmtxt = fopen(ECMINFO_FILE, "w");
			if(ecmtxt != NULL && er->rc < E_NOTFOUND) {
				char tmp[25];
				fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
				switch (er->rc) {
					case 0: 
						if (er->selected_reader) {
							fprintf(ecmtxt, "reader: %s\n", er->selected_reader->label);
							if (is_cascading_reader(er->selected_reader))
								fprintf(ecmtxt, "from: %s\n", er->selected_reader->device);
							else
								fprintf(ecmtxt, "from: local\n");
						fprintf(ecmtxt, "protocol: %s\n", reader_get_type_desc(er->selected_reader, 1));
#ifdef MODULE_CCCAM
						fprintf(ecmtxt, "hops: %d\n", er->selected_reader->cc_currenthops);
#endif
						}
						break;

					case 1:	
						fprintf(ecmtxt, "reader: Cache\n");
						fprintf(ecmtxt, "from: cache1\n");
						fprintf(ecmtxt, "protocol: none\n");
						break;

					case 2:	
						fprintf(ecmtxt, "reader: Cache\n");
						fprintf(ecmtxt, "from: cache2\n");
						fprintf(ecmtxt, "protocol: none\n");
						break;

					case 3:	
						fprintf(ecmtxt, "reader: Cache\n");
						fprintf(ecmtxt, "from: cache3\n");
						fprintf(ecmtxt, "protocol: none\n");
						break;
				}
				fprintf(ecmtxt, "ecm time: %.3f\n", (float) client->cwlastresptime/1000);
				fprintf(ecmtxt, "cw0: %s\n", cs_hexdump(1,demux[i].lastcw[0],8, tmp, sizeof(tmp)));
				fprintf(ecmtxt, "cw1: %s\n", cs_hexdump(1,demux[i].lastcw[1],8, tmp, sizeof(tmp)));
				fclose(ecmtxt);
				ecmtxt = NULL;
			}
			if (ecmtxt) {
				fclose(ecmtxt);
				ecmtxt = NULL;
			}

		}
	}
}

static void * dvbapi_handler(struct s_client * cl, uchar* UNUSED(mbuf), int32_t len) {
	//cs_log("dvbapi loaded fd=%d", idx);
	if (cfg.dvbapi_enabled == 1) {
		cl = create_client(get_null_ip());
		cl->ctyp = len;
		cl->typ='c';
		int32_t ret = pthread_create(&cl->thread, NULL, dvbapi_main_local, (void*) cl);
		if(ret){
			cs_log("ERROR: Can't create dvbapi handler thread (errno=%d %s)", ret, strerror(ret));
			return NULL;
		} else
			pthread_detach(cl->thread);
	}

	return NULL;
}

/*
 *	protocol structure
 */

void module_dvbapi(struct s_module *ph)
{
	ph->desc="dvbapi";
	ph->type=MOD_CONN_SERIAL;
	ph->listenertype = LIS_DVBAPI;
	ph->multi=1;
	ph->s_handler=dvbapi_handler;
	ph->send_dcw=dvbapi_send_dcw;
}
#endif // HAVE_DVBAPI
