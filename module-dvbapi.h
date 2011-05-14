#ifdef HAVE_DVBAPI

#ifndef MODULEDVBAPI_H_
#define MODULEDVBAPI_H_


#include <sys/un.h>
#include <dirent.h>

#define TYPE_ECM 1
#define TYPE_EMM 2

//api
#define DVBAPI_3	0
#define DVBAPI_1	1
#define STAPI		2
#define COOLAPI		3

#define TMPDIR	"/tmp/"
#define STANDBY_FILE	"/tmp/.pauseoscam"
#define ECMINFO_FILE	"/tmp/ecm.info"

#ifdef COOL
#define MAX_DEMUX 3
#else
#define MAX_DEMUX 5
#endif
#define MAX_CAID 50
#define ECM_PIDS 30
#define MAX_FILTER 10

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define BOX_COUNT 6

struct box_devices
{
	char *path;
	char *ca_device;
	char *demux_device;
	char *cam_socket_path;
};

struct s_ecmpids
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t ECM_PID;
	uint16_t EMM_PID;
	int32_t irdeto_numchids;
	int32_t irdeto_curchid;
	int32_t irdeto_chid;
	int32_t checked;
	int32_t status;
	unsigned char table;
	int32_t index;
	uint32_t streams;
};

typedef struct filter_s
{
	uint32_t fd; //FilterHandle
	int32_t pidindex;
	int32_t pid;
	uint16_t type;
	int32_t count;
#ifdef WITH_STAPI
	int32_t NumSlots;
	uint32_t	SlotHandle[10];
	uint32_t  	BufferHandle[10];
#endif
} FILTERTYPE;

struct s_emmpids
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t PID;
	uint8_t type;
};

#ifdef WITH_STAPI
struct STDEVICE
{
	char name[20];
	uint32_t 	SessionHandle;
	uint32_t	SignalHandle;
	pthread_t thread;
	struct filter_s demux_fd[MAX_DEMUX][MAX_FILTER];
};

struct read_thread_param
{
	int32_t id;
	struct s_client *cli;
};

#define BUFFLEN	1024
#define PROCDIR	"/proc/stpti4_core/"
#define PTINUM 10
#define SLOTNUM 20

pthread_mutex_t filter_lock;

struct STDEVICE dev_list[PTINUM];
#endif

typedef struct demux_s
{
	int32_t demux_index;
	FILTERTYPE demux_fd[MAX_FILTER];
	int32_t ca_mask;
	int32_t adapter_index;
	int32_t socket_fd;
	int32_t ECMpidcount;
	struct s_ecmpids ECMpids[ECM_PIDS];
	int32_t EMMpidcount;
	struct s_emmpids EMMpids[ECM_PIDS];
	int32_t STREAMpidcount;
	uint16_t STREAMpids[ECM_PIDS];
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
#ifdef WITH_STAPI
	uint32_t DescramblerHandle[PTINUM];
	int32_t desc_pidcount;
	uint32_t slot_assc[PTINUM][SLOTNUM];
#endif
} DEMUXTYPE;

struct s_dvbapi_priority
{
	char type; // p or i
	uint16_t caid;
	uint32_t provid;
	uint16_t srvid;
	uint16_t chid;
	uint16_t ecmpid;
	uint16_t mapcaid;
	uint32_t mapprovid;
	int32_t delay;
	int32_t force;
#ifdef WITH_STAPI
	char devname[30];
	char pmtfile[30];
	int32_t disablefilter;
#endif
	struct s_dvbapi_priority *next;
};


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
//------------------------------------------------------------------


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
	uint32_t index;
	uint32_t parity;	/* 0 == even, 1 == odd */
	unsigned char cw[8];
} ca_descr_t;

typedef struct ca_pid {
	uint32_t pid;
	int32_t index;		/* -1 == disable*/
} ca_pid_t;

#define DMX_START		_IO('o', 41)
#define DMX_STOP		_IO('o', 42)
#define DMX_SET_FILTER	_IOW('o', 43, struct dmx_sct_filter_params)

#define CA_SET_DESCR		_IOW('o', 134, ca_descr_t)
#define CA_SET_PID		_IOW('o', 135, ca_pid_t)
// --------------------------------------------------------------------

#ifdef AZBOX
#include "openxcas/openxcas_api.h"
#include "openxcas/openxcas_message.h"

int32_t openxcas_provid, openxcas_seq, openxcas_filter_idx, openxcas_stream_id, openxcas_cipher_idx, openxcas_busy;
unsigned char openxcas_cw[16];
uint16_t openxcas_sid, openxcas_caid, openxcas_ecm_pid, openxcas_video_pid, openxcas_audio_pid, openxcas_data_pid;

void azbox_openxcas_ecm_callback(int32_t stream_id, uint32_t sequence, int32_t cipher_index, uint32_t caid, unsigned char *ecm_data, int32_t l, uint16_t pid);
void azbox_openxcas_ex_callback(int32_t stream_id, uint32_t seq, int32_t idx, uint32_t pid, unsigned char *ecm_data, int32_t l);
void azbox_send_dcw(struct s_client *client, ECM_REQUEST *er);
void * azbox_main(void * cli);
#endif

#ifdef COOL
int32_t coolapi_set_filter (int32_t fd, int32_t num, int32_t pid, byte * flt, byte * mask);
int32_t coolapi_remove_filter (int32_t fd, int32_t num);
int32_t coolapi_open_device (int32_t demux_index, int32_t demux_id);
int32_t coolapi_close_device(int32_t fd);
int32_t coolapi_write_cw(int32_t mask, uint16_t *STREAMpids, int32_t count, ca_descr_t * ca_descr);
int32_t coolapi_set_pid (int32_t demux_id, int32_t num, int32_t index, int32_t pid);
void coolapi_close_all();
void dvbapi_write_cw(int32_t demux_id, uchar *cw, int32_t index);
#endif

#ifdef WITH_STAPI
static int32_t stapi_open();
static int32_t stapi_set_filter(int32_t demux_id, uint16_t pid, uchar *filter, uchar *mask, int32_t num, char *pmtfile);
static int32_t stapi_remove_filter(int32_t demux_id, int32_t num, char *pmtfile);
static int32_t stapi_set_pid(int32_t demux_id, int32_t num, int32_t index, uint16_t pid, char *pmtfile);
static int32_t stapi_write_cw(int32_t demux_id, uchar *cw, uint16_t *, int32_t, char *pmtfile);
static int32_t stapi_do_set_filter(int32_t demux_id, FILTERTYPE *filter, uint16_t *pids, int32_t pidcount, uchar *filt, uchar *mask, int32_t dev_id);
static int32_t stapi_do_remove_filter(int32_t demux_id, FILTERTYPE *filter, int32_t dev_id);
static void *stapi_read_thread(void *);

uint32_t oscam_stapi_Capability(char *name);
char *oscam_stapi_LibVersion(void);
uint32_t oscam_stapi_Open(char *name, uint32_t *sessionhandle);
uint32_t oscam_stapi_SignalAllocate(uint32_t sessionhandle, uint32_t *signalhandle);
uint32_t oscam_stapi_FilterAllocate(uint32_t sessionhandle, uint32_t *filterhandle);
uint32_t oscam_stapi_SlotInit(uint32_t sessionhandle, uint32_t signalhandle, uint32_t *bufferhandle, uint32_t *slothandle, uint16_t pid);
uint32_t oscam_stapi_FilterSet(uint32_t filterhandle, uchar *filt, uchar *mask);
uint32_t oscam_stapi_FilterAssociate(uint32_t filterhandle, uint32_t slothandle);
uint32_t oscam_stapi_SlotDeallocate(uint32_t slothandle);
uint32_t oscam_stapi_BufferDeallocate(uint32_t bufferhandle);
uint32_t oscam_stapi_FilterDeallocate(uint32_t filterhandle);
uint32_t oscam_stapi_Close(uint32_t sessionhandle);
uint32_t oscam_stapi_CheckVersion();
uint32_t oscam_stapi_DescramblerAssociate(uint32_t deschandle, uint32_t slot);
uint32_t oscam_stapi_DescramblerDisassociate(uint32_t deschandle, uint32_t slot);
uint32_t oscam_stapi_DescramblerAllocate(uint32_t sessionhandle, uint32_t *deschandle);
uint32_t oscam_stapi_DescramblerDeallocate(uint32_t deschandle);
uint32_t oscam_stapi_DescramblerSet(uint32_t deschandle, int32_t parity, uchar *cw);
uint32_t oscam_stapi_SignalWaitBuffer(uint32_t signalhandle, uint32_t *qbuffer, int32_t timeout);
uint32_t oscam_stapi_BufferReadSection(uint32_t bufferhandle, uint32_t *filterlist, int32_t maxfilter, uint32_t *filtercount, int32_t *crc, uchar *buf, int32_t bufsize, uint32_t *size);
uint32_t oscam_stapi_SignalAbort(uint32_t signalhandle);
uint32_t oscam_stapi_PidQuery(char *name, uint16_t pid);
uint32_t oscam_stapi_BufferFlush(uint32_t bufferhandle);
uint32_t oscam_stapi_SlotClearPid(uint32_t slot);
#endif

void dvbapi_stop_descrambling(int);
void dvbapi_process_input(int32_t demux_id, int32_t filter_num, uchar *buffer, int32_t len);
int32_t dvbapi_open_device(int32_t, int32_t, int);
int32_t dvbapi_stop_filternum(int32_t demux_index, int32_t num);
int32_t dvbapi_stop_filter(int32_t demux_index, int32_t type);
struct s_dvbapi_priority *dvbapi_check_prio_match(int32_t demux_id, int32_t pidindex, char type);

#ifdef WITH_STAPI
	#define cs_log(x...)	cs_log("stapi: "x)
	#ifdef WITH_DEBUG
		#define cs_debug_mask(x,y...)	cs_debug_mask(x,"stapi: "y)
	#endif
#else
	#define cs_log(x...)	cs_log("dvbapi: "x)
	#ifdef WITH_DEBUG
		#define cs_debug_mask(x,y...)	cs_debug_mask(x,"dvbapi: "y)
	#endif
#endif

#endif // MODULEDVBAPI_H_
#endif // WITH_DVBAPI
