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

#define TMPDIR	"/tmp/"
#define STANDBY_FILE	"/tmp/.pauseoscam"
#define ECMINFO_FILE	"/tmp/ecm.info"

#define MAX_DEMUX 5
#define MAX_CAID 50
#define ECM_PIDS 20
#define MAX_FILTER 10

#ifndef FALSE
#define FALSE 0
#endif

#define BOX_COUNT 4

struct box_devices
{
	char ca_device_path[32];
	char demux_device_path[32];
	char cam_socket_path[32];
};

typedef struct ECMPIDS
{
	unsigned short CAID;
	unsigned long PROVID;
	unsigned short ECM_PID;
	unsigned short EMM_PID;
	int checked;
	int status;
	unsigned char table;
} ECMPIDSTYPE;

typedef struct filter_s
{
	uint fd; //FilterHandle
	int pidindex;
	int pid;
	ushort type;
	int count;
#ifdef WITH_STAPI
	uint	SlotHandle;
	uint  	BufferHandle;
#endif
} FILTERTYPE;

typedef struct demux_s
{
	unsigned short demux_index;
	FILTERTYPE demux_fd[MAX_FILTER];
	unsigned short cadev_index;
	int ca_fd;
	int socket_fd;
	unsigned short ECMpidcount;
	ECMPIDSTYPE ECMpids[ECM_PIDS];
	int pidindex;
	int tries;
	int max_status;
	unsigned short program_number;
	unsigned short STREAMpidcount;
	unsigned short STREAMpids[ECM_PIDS];
	unsigned char lastcw[2][8];
	int emm_filter;
	uchar hexserial[8];
	struct s_reader *rdr;
	char pmt_file[50];
	int pmt_time;
#ifdef WITH_STAPI
	uint STREAMhandle[ECM_PIDS];
#endif
} DEMUXTYPE;


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

#ifdef WITH_STAPI
void *stapi_read_thread(void *);
void stapi_off(int);
int stapi_write_cw(int demux_id, uchar *cw);
int stapi_get_device(int demux_id, int pid);
int stapi_open();
int stapi_set_filter(int demux_id, ushort pid, uchar *filter, uchar *mask, int num);
int stapi_remove_filter(int demux_id, int num);
int stapi_set_pid(int demux_id, int num, int index);
int stapi_write_cw(int demux_id, uchar *cw);
#endif

void dvbapi_stop_descrambling(int);
void dvbapi_process_input(int demux_id, int filter_num, uchar *buffer, int len);
int dvbapi_open_device(int, int);
int dvbapi_stop_filternum(int demux_index, int num);
int dvbapi_stop_filter(int demux_index, int type);

#ifdef WITH_STAPI
  #define cs_log(x...)	cs_log("stapi: "x) 
  #define cs_debug(x...)	cs_debug("stapi: "x) 
#else
  #define cs_log(x...)	cs_log("dvbapi: "x) 
  #define cs_debug(x...)	cs_debug("dvbapi: "x) 
#endif

#endif // MODULEDVBAPI_H_
#endif // WITH_DVBAPI
