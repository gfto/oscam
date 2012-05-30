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

#define PORT		9000

#define TMPDIR	"/tmp/"
#define STANDBY_FILE	"/tmp/.pauseoscam"
#define ECMINFO_FILE	"/tmp/ecm.info"

#define MAX_DEMUX 16
#define MAX_CAID 50
#define ECM_PIDS 30
#define MAX_FILTER 24

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
	int8_t api;
};

struct s_ecmpids
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t ECM_PID;
	uint16_t EMM_PID;
	int8_t irdeto_numchids;
	int8_t irdeto_curchid;
	int32_t irdeto_chids;
	int32_t irdeto_cycle;
	int8_t checked;
	int8_t status;
	unsigned char table;
	int8_t index;
	uint32_t streams;
};

typedef struct filter_s
{
	uint32_t fd; //FilterHandle
	int32_t pidindex;
	int32_t pid;
	uint16_t caid;
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

#define PTINUM 10
#define SLOTNUM 20

typedef struct demux_s
{
	int8_t demux_index;
	FILTERTYPE demux_fd[MAX_FILTER];
	int32_t ca_mask;
	int8_t adapter_index;
	int32_t socket_fd;
	int8_t ECMpidcount;
	struct s_ecmpids ECMpids[ECM_PIDS];
	int8_t EMMpidcount;
	struct s_emmpids EMMpids[ECM_PIDS];
	int8_t STREAMpidcount;
	uint16_t STREAMpids[ECM_PIDS];
	int16_t pidindex;
	int16_t curindex;
	int8_t tries;
	int8_t max_status;
	uint16_t program_number;
	unsigned char lastcw[2][8];
	int8_t emm_filter;
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
	int16_t delay;
	int8_t force;
#ifdef WITH_STAPI
	char devname[30];
	char pmtfile[30];
	int8_t disablefilter;
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

void dvbapi_stop_descrambling(int);
void dvbapi_process_input(int32_t demux_id, int32_t filter_num, uchar *buffer, int32_t len);
int32_t dvbapi_open_device(int32_t, int32_t, int);
int32_t dvbapi_stop_filternum(int32_t demux_index, int32_t num);
int32_t dvbapi_stop_filter(int32_t demux_index, int32_t type);
struct s_dvbapi_priority *dvbapi_check_prio_match(int32_t demux_id, int32_t pidindex, char type);
void dvbapi_send_dcw(struct s_client *client, ECM_REQUEST *er);
void dvbapi_write_cw(int32_t demux_id, uchar *cw, int32_t index);
int32_t dvbapi_parse_capmt(unsigned char *buffer, uint32_t length, int32_t connfd, char *pmtfile);
void request_cw(struct s_client *dvbapi_client, ECM_REQUEST *er);
void dvbapi_try_next_caid(int32_t demux_id);

#undef cs_log
#define cs_log(txt, x...)	cs_log_int(0, 1, NULL, 0, "dvbapi: "txt, ##x)
#ifdef WITH_DEBUG
	#undef cs_debug_mask
	#define cs_debug_mask(x,txt,y...)	cs_log_int(x, 1, NULL, 0, "dvbapi: "txt, ##y)
#endif

#endif // MODULEDVBAPI_H_
#endif // WITH_DVBAPI
