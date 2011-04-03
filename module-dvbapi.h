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
#define ECM_PIDS 20
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
	unsigned short CAID;
	unsigned long PROVID;
	unsigned short ECM_PID;
	unsigned short EMM_PID;
	int irdeto_numchids;
	int irdeto_curchid;
	int irdeto_chid;
	int checked;
	int status;
	unsigned char table;
	int index;
	unsigned char slen;
	char stream[8];
};

typedef struct filter_s
{
	uint fd; //FilterHandle
	int pidindex;
	int pid;
	ushort type;
	int count;
#ifdef WITH_STAPI
	int NumSlots;
	uint	SlotHandle[10];
	uint  	BufferHandle[10];
#endif
} FILTERTYPE;

struct s_emmpids
{
	ushort CAID;
	ulong PROVID;
	ushort PID;
	uint8 type;
};

#ifdef WITH_STAPI
struct STDEVICE
{
	char name[20];
	uint 	SessionHandle;
	uint	SignalHandle;
	pthread_t thread;
	struct filter_s demux_fd[MAX_DEMUX][MAX_FILTER];
};

struct read_thread_param
{
	int id;
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
	int demux_index;
	FILTERTYPE demux_fd[MAX_FILTER];
	int ca_mask;
	int adapter_index;
	int socket_fd;
	int ECMpidcount;
	struct s_ecmpids ECMpids[ECM_PIDS];
	int EMMpidcount;
	struct s_emmpids EMMpids[ECM_PIDS];
	int STREAMpidcount;
	unsigned short STREAMpids[ECM_PIDS];
	int pidindex;
	int curindex;
	int tries;
	int max_status;
	unsigned short program_number;
	unsigned char lastcw[2][8];
	int emm_filter;
	uchar hexserial[8];
	struct s_reader *rdr;
	char pmt_file[30];
	int pmt_time;
#ifdef WITH_STAPI
	uint DescramblerHandle[PTINUM];
	int desc_pidcount;
	uint slot_assc[PTINUM][SLOTNUM];
#endif
} DEMUXTYPE;

struct s_dvbapi_priority
{
	char type; // p or i
	ushort caid;
	ulong provid;
	ushort srvid;
	ushort chid;
	ushort ecmpid;
	ushort mapcaid;
	ulong mapprovid;
	int delay;
	int force;
#ifdef WITH_STAPI
	char devname[30];
	char pmtfile[30];
	int disablefilter;
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
	unsigned int index;
	unsigned int parity;	/* 0 == even, 1 == odd */
	unsigned char cw[8];
} ca_descr_t;

typedef struct ca_pid {
	unsigned int pid;
	int index;		/* -1 == disable*/
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

int openxcas_provid, openxcas_seq, openxcas_filter_idx, openxcas_stream_id, openxcas_cipher_idx, openxcas_busy;
unsigned char openxcas_cw[16];
unsigned short openxcas_sid, openxcas_caid, openxcas_ecm_pid, openxcas_video_pid, openxcas_audio_pid, openxcas_data_pid;

void azbox_openxcas_ecm_callback(int stream_id, unsigned int sequence, int cipher_index, unsigned int caid, unsigned char *ecm_data, int l, unsigned short pid);
void azbox_openxcas_ex_callback(int stream_id, unsigned int seq, int idx, unsigned int pid, unsigned char *ecm_data, int l);
void azbox_send_dcw(struct s_client *client, ECM_REQUEST *er);
void * azbox_main(void * cli);
#endif

#ifdef COOL
int coolapi_set_filter (int fd, int num, int pid, byte * flt, byte * mask);
int coolapi_remove_filter (int fd, int num);
int coolapi_open_device (int demux_index, int demux_id);
int coolapi_close_device(int fd);
int coolapi_write_cw(int mask, unsigned short *STREAMpids, int count, ca_descr_t * ca_descr);
int coolapi_set_pid (int demux_id, int num, int index, int pid);
void coolapi_close_all();
void dvbapi_write_cw(int demux_id, uchar *cw, int index);
#endif

#ifdef WITH_STAPI
static int stapi_open();
static int stapi_set_filter(int demux_id, ushort pid, uchar *filter, uchar *mask, int num, char *pmtfile);
static int stapi_remove_filter(int demux_id, int num, char *pmtfile);
static int stapi_set_pid(int demux_id, int num, int index, ushort pid, char *pmtfile);
static int stapi_write_cw(int demux_id, uchar *cw, ushort *, int, char *pmtfile);
static int stapi_do_set_filter(int demux_id, FILTERTYPE *filter, ushort *pids, int pidcount, uchar *filt, uchar *mask, int dev_id);
static int stapi_do_remove_filter(int demux_id, FILTERTYPE *filter, int dev_id);
static void *stapi_read_thread(void *);

uint oscam_stapi_Capability(char *name);
char *oscam_stapi_LibVersion(void);
uint oscam_stapi_Open(char *name, uint *sessionhandle);
uint oscam_stapi_SignalAllocate(uint sessionhandle, uint *signalhandle);
uint oscam_stapi_FilterAllocate(uint sessionhandle, uint *filterhandle);
uint oscam_stapi_SlotInit(uint sessionhandle, uint signalhandle, uint *bufferhandle, uint *slothandle, ushort pid);
uint oscam_stapi_FilterSet(uint filterhandle, uchar *filt, uchar *mask);
uint oscam_stapi_FilterAssociate(uint filterhandle, uint slothandle);
uint oscam_stapi_SlotDeallocate(uint slothandle);
uint oscam_stapi_BufferDeallocate(uint bufferhandle);
uint oscam_stapi_FilterDeallocate(uint filterhandle);
uint oscam_stapi_Close(uint sessionhandle);
uint oscam_stapi_CheckVersion();
uint oscam_stapi_DescramblerAssociate(uint deschandle, uint slot);
uint oscam_stapi_DescramblerDisassociate(uint deschandle, uint slot);
uint oscam_stapi_DescramblerAllocate(uint sessionhandle, uint *deschandle);
uint oscam_stapi_DescramblerDeallocate(uint deschandle);
uint oscam_stapi_DescramblerSet(uint deschandle, int parity, uchar *cw);
uint oscam_stapi_SignalWaitBuffer(uint signalhandle, uint *qbuffer, int timeout);
uint oscam_stapi_BufferReadSection(uint bufferhandle, uint *filterlist, int maxfilter, uint *filtercount, int *crc, uchar *buf, int bufsize, uint *size);
uint oscam_stapi_SignalAbort(uint signalhandle);
uint oscam_stapi_PidQuery(char *name, ushort pid);
uint oscam_stapi_BufferFlush(uint bufferhandle);
uint oscam_stapi_SlotClearPid(uint slot);
#endif

void dvbapi_stop_descrambling(int);
void dvbapi_process_input(int demux_id, int filter_num, uchar *buffer, int len);
int dvbapi_open_device(int, int, int);
int dvbapi_stop_filternum(int demux_index, int num);
int dvbapi_stop_filter(int demux_index, int type);
struct s_dvbapi_priority *dvbapi_check_prio_match(int demux_id, int pidindex, char type);

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
