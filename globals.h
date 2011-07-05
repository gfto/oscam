#define _GNU_SOURCE //needed for PTHREAD_MUTEX_RECURSIVE on some plattforms and maybe other things; do not remove
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <time.h>
#include <sys/timeb.h>
#include <limits.h>
#include <pwd.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include "module-datastruct-llist.h"

//for reader-nagra variables in s_reader:
#include "cscrypt/idea.h"

#include "oscam-config.h"

#ifndef USE_CMAKE
#  include "oscam-ostype.h"
#endif
#include "oscam-types.h"
#include "cscrypt/cscrypt.h"

#ifdef HAVE_PCSC
  #ifdef OS_CYGWIN32
    #define __reserved
    #define __nullnullterminated
    #include <specstrings.h>
    #include "cygwin/WinSCard.h"
  #else
    #include <PCSC/pcsclite.h>
    #ifdef OS_MACOSX
        #include <PCSC/wintypes.h>
    #else
        #include <PCSC/reader.h>
    #endif
  #endif
#endif

#if defined(LIBUSB)
#ifdef __FreeBSD__
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif
#include "csctapi/smartreader_types.h"
#endif

/* ===========================
 *         macros
 * =========================== */
// Prevent use of unsafe functions (doesn't work for MacOSX)
#ifndef OS_MACOSX
#define strcpy(a,b) UNSAFE_STRCPY_USE_CS_STRNCPY_INSTEAD()
#define sprintf(a,...) UNSAFE_SPRINTF_USE_SNPRINTF_INSTEAD()
#define strtok(a,b,c) UNSAFE_STRTOK_USE_STRTOK_R_INSTEAD()
#endif

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#ifdef WITH_DEBUG
# define call(arg) \
	if (arg) { \
		cs_debug_mask(D_TRACE, "ERROR, function call %s returns error.",#arg); \
	}
# define D_USE(x) x
#else
# define call(arg) arg
# if defined(__GNUC__)
#  define D_USE(x) D_USE_ ## x __attribute__((unused))
# elif defined(__LCLINT__)
#  define D_USE(x) /*@debug use only@*/ x
# else
#  define D_USE(x) x
# endif
#endif

//checking if (X) free(X) unneccessary since freeing a null pointer doesnt do anything
#define NULLFREE(X) {if (X) {void *tmpX=X; X=NULL; free(tmpX); }}

#ifdef WITH_DEBUG
#define tmp_dbg(X) char tmp_dbg[X]
#else
#define tmp_dbg(X)
#endif
/* ===========================
 *         constants
 * =========================== */
#ifndef CS_GLOBALS
#define CS_GLOBALS
#define CS_VERSION    "1.00-dynamic_svn"
#ifndef CS_SVN_VERSION
#	define CS_SVN_VERSION "test"
#endif
#ifndef CS_CONFDIR
#define CS_CONFDIR    "/usr/local/etc"
#endif
#ifndef CS_LOGFILE
#define CS_LOGFILE    "/var/log/oscam.log"
#endif
#define CS_QLEN       128 // size of request queue
#define CS_MAXCAIDTAB 32  // max. caid-defs/user
#define CS_MAXTUNTAB  20  // max. betatunnel mappings
#define CS_MAXPROV    32
#define CS_MAXPORTS   32  // max server ports
#define CS_MAXFILTERS   16
#define CS_MAX_CAIDVALUETAB 16

#define CS_ECMSTORESIZE   16  // use MD5()
#define CS_EMMSTORESIZE   16  // use MD5()
#define CS_CLIENT_TIMEOUT 5000
#define CS_CLIENT_MAXIDLE 120
#define CS_BIND_TIMEOUT   120
#define CS_DELAY          0
#define CS_ECM_RINGBUFFER_MAX 20 // max size for ECM last responsetimes ringbuffer

#define CS_CACHE_TIMEOUT  60
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 64000
#endif
#define PTHREAD_STACK_SIZE PTHREAD_STACK_MIN+32768

#ifdef  CS_EMBEDDED
#define CS_MAXPENDING   16
#else
#define CS_MAXPENDING   32
#endif

#define CS_EMMCACHESIZE  64 //nr of EMMs that each client will cache; cache is per client, so memory-expensive...
#define MSGLOGSIZE 64	//size of string buffer for a ecm to return messages

#define D_TRACE     1 // Generate very detailed error/trace messages per routine
#define D_ATR       2 // Debug ATR parsing, dump of ecm, cw
#define D_READER    4 // Debug Reader/Proxy Process
#define D_CLIENT    8 // Debug Client Process
#define D_IFD       16  // Debug IFD+protocol
#define D_DEVICE    32  // Debug Reader I/O
#define D_EMM				64  // Dumps EMM
#define D_DVBAPI		128 // Debug DVBAPI
#define D_ALL_DUMP  255 // dumps all

#define R_DB2COM1   0x1 // Reader Dbox2 @ com1
#define R_DB2COM2   0x2 // Reader Dbox2 @ com1
#define R_SC8in1    0x3 // Reader Sc8in1 or MCR
#define R_MP35      0x4 // AD-Teknik Multiprogrammer 3.5 and 3.6 (only usb tested)
#define R_MOUSE     0x5 // Reader smartcard mouse
/////////////////// phoenix readers which need baudrate setting and timings need to be guarded by OSCam: BEFORE R_MOUSE
#define R_INTERNAL  0x6 // Reader smartcard intern
/////////////////// internal readers (Dreambox, Coolstream, IPBox) are all R_INTERNAL, they are determined compile-time
/////////////////// readers that do not reed baudrate setting and timings are guarded by reader itself (large buffer built in): AFTER R_SMART
#define R_SMART     0x7 // Smartreader+
#define R_PCSC      0x8 // PCSC
/////////////////// proxy readers after R_CS378X
#define R_CAMD35    0x20  // Reader cascading camd 3.5x
#define R_CAMD33    0x21  // Reader cascading camd 3.3x
#define R_NEWCAMD   0x22  // Reader cascading newcamd
#define R_RADEGAST  0x23  // Reader cascading radegast
#define R_CS378X    0x24  // Reader cascading camd 3.5x TCP
#define R_CONSTCW   0x25  // Reader for Constant CW
/////////////////// peer to peer proxy readers after R_CCCAM
#define R_GBOX      0x30  // Reader cascading gbox
#define R_CCCAM     0x35  // Reader cascading cccam
#define R_SERIAL    0x80  // Reader serial
#define R_IS_NETWORK    0x60
#define R_IS_CASCADING  0xE0

//ECM rc codes, reader only:
#define E_RDR_NOTFOUND          0
#define E_RDR_FOUND             1
//ECM rc codes:
#define E_FOUND			0
#define E_CACHE1		1
#define E_CACHE2		2
#define E_EMU				3
///////above is all found
#define E_NOTFOUND	4  //for selection of found, use < E_NOTFOUND
#define E_TIMEOUT		5
#define E_SLEEPING	6
#define E_FAKE			7
#define E_INVALID		8
#define E_CORRUPT		9
#define E_NOCARD		10
#define E_EXPDATE		11
#define	E_DISABLED	12
#define	E_STOPPED		13 //for selection of error, use <= E_STOPPED and exclude selection of found
///////above is all notfound, some error or problem
#define E_99				99 //this code is undocumented
#define E_UNHANDLED	100 //for selection of unhandled, use >= E_UNHANDLED

#define CS_MAX_MOD 20
#define MOD_CONN_TCP    1
#define MOD_CONN_UDP    2
#define MOD_CONN_NET    3
#define MOD_CONN_SERIAL 4
#define MOD_NO_CONN	8

#define MOD_CARDSYSTEM  16
#define MOD_ADDON       32

#ifdef HAVE_DVBAPI
#define BOXTYPE_DREAMBOX	1
#define BOXTYPE_DUCKBOX	2
#define BOXTYPE_UFS910	3
#define BOXTYPE_DBOX2	4
#define BOXTYPE_IPBOX	5
#define BOXTYPE_IPBOX_PMT	6
#define BOXTYPE_DM7000	7
#define BOXTYPE_QBOXHD	8
#define BOXTYPE_COOLSTREAM	9
#define BOXTYPE_NEUMO	10
#define BOXTYPES		10
extern const char *boxdesc[];
#endif

#define EMM_UNIQUE 1
#define EMM_SHARED 2
#define EMM_GLOBAL 4
#define EMM_UNKNOWN 8

//EMM types:
#define UNKNOWN 0
#define UNIQUE	1
#define SHARED	2
#define GLOBAL	3

#ifdef CS_CORE
char *PIP_ID_TXT[] = { "ECM", "EMM", "CIN", "KCL", "UDP", NULL  };
char *RDR_CD_TXT[] = { "cd", "dsr", "cts", "ring", "none",
#ifdef USE_GPIO
                       "gpio1", "gpio2", "gpio3", "gpio4", "gpio5", "gpio6", "gpio7", //felix: changed so that gpio can be used
#endif
                       NULL };
#else
extern char *PIP_ID_TXT[];
extern char *RDR_CD_TXT[];
#endif

#define PIP_ID_ECM    0
#define PIP_ID_EMM    1
#define PIP_ID_CIN    2  // CARD_INFO
#define PIP_ID_UDP    3
#define PIP_ID_MAX    PIP_ID_UDP
#define PIP_ID_ERR    (-1)
#define PIP_ID_NUL    (-2)

#define cdiff *c_start

#define NCD_AUTO    0
#define NCD_524     1
#define NCD_525     2

// moved from reader-common.h
#define UNKNOWN        0
#define CARD_NEED_INIT 1
#define CARD_INSERTED  2
#define CARD_FAILURE   3
#define NO_CARD        4

// moved from stats
#define DEFAULT_REOPEN_SECONDS 900
#define DEFAULT_MIN_ECM_COUNT 5
#define DEFAULT_MAX_ECM_COUNT 500
#define DEFAULT_NBEST 1
#define DEFAULT_NFB 1
#define DEFAULT_RETRYLIMIT 800
#define DEFAULT_LB_MODE 0
#define DEFAULT_LB_STAT_CLEANUP 336
#define DEFAULT_LB_USE_LOCKING 0
#define DEFAULT_LB_REOPEN_MODE 0
#define DEFAULT_UPDATEINTERVAL 240
#define DEFAULT_LB_AUTO_BETATUNNEL 1

enum {E1_GLOBAL=0, E1_USER, E1_READER, E1_SERVER, E1_LSERVER};
enum {E2_GLOBAL=0, E2_GROUP, E2_CAID, E2_IDENT, E2_CLASS, E2_CHID, E2_QUEUE,
      E2_EA_LEN, E2_F0_LEN, E2_OFFLINE, E2_SID,
      E2_CCCAM_NOCARD=0x27, E2_CCCAM_NOK1=0x28, E2_CCCAM_NOK2=0x29, E2_CCCAM_LOOP=0x30,
      E2_WRONG_CHKSUM};

#define CTA_RES_LEN 512

#ifdef CS_LED
#define  LED1A 		0
#define  LED1B 		1
#define  LED2 		2
#define  LED3 		3
#define  LED_OFF	0
#define  LED_ON		1
#define  LED_BLINK_ON 	2
#define  LED_BLINK_OFF 	3
#define  LED_DEFAULT 	10
extern void cs_switch_led(int32_t led, int32_t action);
#endif

#ifdef QBOXHD_LED
#define QBOXHD_LED_DEVICE               "/dev/sw0"
#define QBOXHD_SET_LED_ALL_PANEL_COLOR	_IO(0xBC, 13)    // payload = 3byte [H][S][V]
#define QBOXHD_LED_COLOR_RED        359  // only H value, S and V values are always == 99
#define QBOXHD_LED_COLOR_GREEN      120
#define QBOXHD_LED_COLOR_BLUE       230
#define QBOXHD_LED_COLOR_YELLOW     55
#define QBOXHD_LED_COLOR_MAGENTA    290

#define QBOXHDMINI_LED_DEVICE       "/dev/lpc_0"
#define	QBOXHDMINI_IOSET_RGB        _IOWR('L', 6, qboxhdmini_led_color_struct)
#define QBOXHDMINI_LED_COLOR_RED     0x1F0000               // 3 bytes RGB , 5 bit used for each color
#define QBOXHDMINI_LED_COLOR_GREEN   0x001F00
#define QBOXHDMINI_LED_COLOR_BLUE    0x00001F
#define QBOXHDMINI_LED_COLOR_YELLOW  0x1F1F00
#define QBOXHDMINI_LED_COLOR_MAGENTA 0x1F001F

#define QBOXHD_LED_COLOR_OFF        -1   // all colors H,S,V and/or R,G,B == 0,0,0

#define QBOXHD_LED_BLINK_FAST       100  // blink milliseconds
#define QBOXHD_LED_BLINK_MEDIUM     200
#define QBOXHD_LED_BLINK_SLOW       400

#endif //QBOXHD_LED

#define MAX_ATR_LEN 33         // max. ATR length
#define MAX_HIST    15         // max. number of historical characters

#define MAX_SIDBITS 64         // max services
#define SIDTABBITS uint64_t      // 64bit type for services, if a system does not support this type,
                               // please use a define and define it as uint32_t / MAX_SIDBITS 32

#define BAN_UNKNOWN 1			//failban mask for anonymous/ unknown contact
#define BAN_DISABLED 2			//failban mask for disabled user
#define BAN_SLEEPING 4			//failban mask for sleeping user
#define BAN_DUPLICATE 8			//failban mask for duplicate user

#define ACTION_READER_IDLE		1
#define ACTION_READER_REMOTE	2
#define ACTION_READER_REMOTELOG	3
#define ACTION_READER_RESET		4
#define ACTION_READER_ECM_REQUEST	5
#define ACTION_READER_EMM		6
#define ACTION_READER_CARDINFO	7
#define ACTION_READER_INIT		8

#define ACTION_CLIENT_TCP_CONNECT	21
#define ACTION_CLIENT_UDP		22
#define ACTION_CLIENT_TCP		23
#define ACTION_CLIENT_ECM_ANSWER	24
#define ACTION_CLIENT_KILL		25
#define ACTION_CLIENT_INIT		26

#define AVAIL_CHECK_CONNECTED 0
#define AVAIL_CHECK_LOADBALANCE 1

#define LB_MAX_STAT_TIME 10

/* ===========================
 *      global structures
 * =========================== */
typedef struct cs_mutexlock {
    int				read_lock;
    int				write_lock;
    time_t			lastlock;
    int				timeout;
    char			*name;
} CS_MUTEX_LOCK;

typedef struct s_caidvaluetab {
	uint16_t		n;
	uint16_t		caid[CS_MAX_CAIDVALUETAB];
	uint16_t		value[CS_MAX_CAIDVALUETAB];
} CAIDVALUETAB;

typedef struct s_classtab {
	uchar			an;
	uchar			bn;
	uchar			aclass[31];
	uchar			bclass[31];
} CLASSTAB;

typedef struct s_caidtab {
	uint16_t		caid[CS_MAXCAIDTAB];
	uint16_t		mask[CS_MAXCAIDTAB];
	uint16_t		cmap[CS_MAXCAIDTAB];
} CAIDTAB;

typedef struct s_tuntab {
	uint16_t		n;
	uint16_t		bt_caidfrom[CS_MAXTUNTAB];
	uint16_t		bt_caidto[CS_MAXTUNTAB];
	uint16_t		bt_srvid[CS_MAXTUNTAB];
} TUNTAB;

typedef struct s_sidtab {
	char			label[64];
	uint16_t		num_caid;
	uint16_t		num_provid;
	uint16_t		num_srvid;
	uint16_t		*caid;
	uint32_t		*provid;
	uint16_t		*srvid;
	struct s_sidtab	*next;
} SIDTAB;

typedef struct s_filter {
	uint16_t		caid;
	uchar			nprids;
	uint32_t		prids[CS_MAXPROV];
} FILTER;

typedef struct s_ftab {
	int32_t			nfilts;
	FILTER			filts[CS_MAXFILTERS];
} FTAB;

typedef struct s_port {
	int32_t			fd;
	int32_t			s_port;
	int32_t			ncd_key_is_set;    //0 or 1
	uchar			ncd_key[16];
	FTAB			ftab;
} PORT;

typedef struct s_ptab {
	int32_t			nports;
	PORT			ports[CS_MAXPORTS];
} PTAB;

typedef struct aes_entry {
    uint16_t		keyid;
    uint16_t		caid;
    uint32_t		ident;
    uchar			plainkey[16];
    AES_KEY			key;
    struct aes_entry	*next;
} AES_ENTRY;

struct s_ecm {
	uchar			ecmd5[CS_ECMSTORESIZE];
	uchar			cw[16];
	uint16_t		caid;
	uint64_t		grp;
	struct s_reader	*reader;
	int32_t  		rc;
	time_t 			time;
};

struct s_emm {
	uchar			emmd5[CS_EMMSTORESIZE];
	uchar			type;
	int32_t			count;
};

typedef struct v_ban {					// failban listmember
	int32_t 		v_count;
	uint32_t 		v_ip;
	time_t 			v_time;
} V_BAN;

typedef struct s_entitlement {			// contains entitlement Info
	uint16_t		id;					// the element ID
	uint32_t		type;				// enumerator for tier,chid whatever
										// 0="", 1="Package", 2="PPV-Event", 3="chid", 4="tier"
	uint16_t		caid;				// the caid of element
	uint32_t		provid;				// the provid of element
	uint16_t		class;				// the class needed for some systems
	time_t			start;				// startdate
	time_t			end;				// enddate
} S_ENTITLEMENT;

struct s_client ;
struct ecm_request_t ;
struct emm_packet_t ;

struct s_module {
	int8_t			active;
	int8_t			multi;
	int8_t			type;
	int8_t			watchdog;
	char 			desc[16];
	char 			*logtxt;
	//int32_t  		s_port;
	in_addr_t		s_ip;
	void			*(*s_handler)(struct s_client *, uchar *, int);
	void			(*s_init)(struct s_client *);
	int32_t		(*recv)(struct s_client *, uchar *, int32_t);
	void			(*send_dcw)(struct s_client*, struct ecm_request_t *);
	void			(*cleanup)(struct s_client*);
	int8_t			c_multi;
	int32_t			(*c_recv_chk)(struct s_client*, uchar *, int32_t *, uchar *, int32_t);
	int32_t			(*c_init)(struct s_client*);
	int32_t			(*c_send_ecm)(struct s_client *, struct ecm_request_t *, uchar *);
	int32_t			(*c_send_emm)(struct emm_packet_t *);
	int32_t			(*c_init_log)(void);
	int32_t			(*c_recv_log)(uint16_t *, uint32_t *, uint16_t *);
	int32_t			(*c_available)(struct s_reader *, int32_t); 	//Schlocke: available check for load-balancing,
										// params:
										// rdr (reader to check)
										// int32_t checktype (0=return connected, 1=return loadbalance-avail) return int
	void 			(*c_idle)(void);	// Schlocke: called when reader is idle
	void 			(*c_card_info)(void);	// Schlocke: request card infos
	int32_t  		c_port;
	PTAB 			*ptab;
	int32_t 		num;
};

struct s_ATR ;

struct s_cardreader
{
	int8_t			active;
	char			desc[16];
	int32_t			(*reader_init)(struct s_reader*);
	int32_t			(*get_status)(struct s_reader*, int*);
	int32_t			(*activate)(struct s_reader*, struct s_ATR *);
	int32_t			(*transmit)(struct s_reader*, unsigned char *sent, uint32_t size);
	int32_t			(*receive)(struct s_reader*, unsigned char *data, uint32_t size);
	int32_t			(*close)(struct s_reader*);
	int32_t			(*set_parity)(struct s_reader*, uchar parity);
	int32_t			(*write_settings)(struct s_reader*,
										uint32_t ETU,
										uint32_t EGT,
										unsigned char P,
										unsigned char I,
										uint16_t Fi,
										unsigned char Di,
										unsigned char Ni);
	int32_t			(*set_protocol)(struct s_reader*,
										unsigned char * params,
										uint32_t *length,
										uint32_t len_request);
	int32_t			(*set_baudrate)(struct s_reader*,
										uint32_t baud); //set only for readers which need baudrate setting and timings need to be guarded by OSCam
	int32_t			typ; 				// fixme: workaround, remove when all old code is converted

	int8_t			max_clock_speed; 	// 1 for reader->typ > R_MOUSE
	int8_t			need_inverse; 		// 0 = reader does inversing; 1 = inversing done by oscam
	//io_serial config
	int8_t			flush;
	int8_t			read_written; 		// 1 = written bytes has to read from device
};

struct s_cardsystem {
	int8_t 			active;
	char 			*desc;
	int32_t  		(*card_init)();
	int32_t  		(*card_info)();
	int32_t  		(*do_ecm)();
	int32_t  		(*do_emm)();
	void 			(*post_process)();
	int32_t  		(*get_emm_type)();
	void 			(*get_emm_filter)();
	uchar 			caids[2];
};

#ifdef IRDETO_GUESSING
struct s_irdeto_quess {
	int32_t			b47;
	uint16_t		caid;
	uint16_t		sid;
	struct s_irdeto_quess *next;
};
#endif

typedef struct ecm_request_t {
	uchar			ecm[512];
	uchar			cw[16];
	uchar			ecmd5[CS_ECMSTORESIZE];
	int16_t			l;
	uint16_t		caid;
	uint16_t		ocaid; 				//original caid, used for betatunneling
	uint16_t		srvid;
	uint16_t		chid;
	uint16_t		pid;
	uint16_t		idx;
	uint32_t		prid;
	struct s_reader	*selected_reader;
	LLIST			*matching_rdr;		//list of matching readers
	LL_NODE			*fallback;			// in *matching_rdr, at position "fallback" the first fallback reader is in the list
	struct s_client	*client;			//contains pointer to 'c' client while running in 'r' client
	int32_t			cpti;				// client pending table index
	int32_t			stage;				// processing stage in server module
	int32_t			level;				// send-level in client module
	int32_t			rc;
	uchar			rcEx;
	struct timeb	tps;				// incoming time stamp
	uchar			locals_done;
	int32_t			btun; 				// mark er as betatunneled
	int32_t			reader_avail; 		// count of available readers
	int32_t			reader_count; 		// count of contacted readers

#ifdef CS_WITH_DOUBLECHECK
	int32_t			checked;
	uchar			cw_checked[16];
#endif

#ifdef MODULE_CCCAM
	struct s_reader *origin_reader;
	void 			*origin_card; 		// CCcam preferred card!
#endif

	void 			*src_data;
	struct s_ecm 	*ecmcacheptr;		// Pointer to ecm-cw-rc-cache!
	char 			msglog[MSGLOGSIZE];
} ECM_REQUEST;

#ifdef CS_ANTICASC
struct s_acasc_shm {
	uint16_t 		ac_count : 15;
	uint16_t 		ac_deny  : 1;
};

struct s_acasc {
	uint16_t 		stat[10];
	uchar  			idx;			// current active index in stat[]
};
#endif

#ifdef WEBIF
struct s_cwresponse {
	int32_t			duration;
	time_t			timestamp;
	int32_t			rc;
};
#endif

struct s_client {
	int8_t			init_done;
	pthread_mutex_t	thread_lock;
	int8_t			thread_active;
	int8_t			kill;
	LLIST			*joblist;
	in_addr_t		ip;
	in_port_t		port;
	time_t			login;
	time_t			last;
	time_t			lastswitch;
	time_t			lastemm;
	time_t			lastecm;
	time_t			expirationdate;
	int32_t			allowedtimeframe[2];
	int8_t			c35_suppresscmd08;
	uint8_t			c35_sleepsend;
	int8_t			ncd_keepalive;
	int8_t			disabled;
	uint64_t		grp;
	int8_t			crypted;
	int8_t			dup;
	LLIST			*aureader_list;
	int8_t			autoau;
	int8_t			monlvl;
	CAIDTAB			ctab;
	TUNTAB			ttab;
	SIDTABBITS		sidtabok; 			// positiv services
	SIDTABBITS		sidtabno; 			// negative services
	int8_t			typ;        		// first s_client is type s=starting (master) thread; type r = physical reader, type p = proxy reader both always have 1 s_reader struct allocated; type c = client (user logging in into oscam) type m = monitor type h = http server a = anticascader
	int8_t			ctyp;
	uint16_t		last_srvid;
	uint16_t		last_caid;
	struct s_srvid 	*last_srvidptr;
	int32_t			tosleep;
	struct s_auth 	*account;
	int32_t			udp_fd;
	int32_t			fd_m2c;				// master writes to this fd
	int32_t			fd_m2c_c;			// client reads from this fd
	uint16_t		pipecnt;
	CS_MUTEX_LOCK 	pipelock;
	struct sockaddr_in udp_sa;
	int8_t			log;
	int32_t			logcounter;
	int32_t			cwfound;     		// count found ECMs per client
	int32_t			cwcache;     		// count ECMs from cache1/2 per client
	int32_t			cwnot;       		// count not found ECMs per client
	int32_t			cwtun;       		// count betatunneled ECMs per client
	int32_t			cwignored;   		// count ignored  ECMs per client
	int32_t			cwtout;      		// count timeouted ECMs per client
	int32_t			cwlastresptime; 	//last Responsetime (ms)
	int32_t			emmok;       		// count EMM ok
	int32_t			emmnok;	     		// count EMM nok
	int8_t			pending;     		// number of ECMs pending

#ifdef WEBIF
	struct s_cwresponse cwlastresptimes[CS_ECM_RINGBUFFER_MAX]; //ringbuffer for last 20 times
	int32_t			cwlastresptimes_last; // ringbuffer pointer
	int8_t			wihidden;			// hidden in webinterface status
	char      		lastreader[64];		// last cw got from this reader
#endif

	uchar			ucrc[4];    		// needed by monitor and used by camd35
	uint32_t		pcrc;        		// pwd crc
	AES_KEY			aeskey;      		// encryption key needed by monitor and used by camd33, camd35
	AES_KEY			aeskey_decrypt;		// decryption key needed by monitor and used by camd33, camd35
	uint16_t		ncd_msgid;
	char 			ncd_client_id[5];
	uchar			ncd_skey[16];

#ifdef MODULE_CCCAM
	void			*cc;
#endif

#ifdef MODULE_GBOX
	void			*gbox;
#endif

	int32_t			port_idx;    		// index in server ptab
	int32_t			ncd_server;			// newcamd server

#ifdef CS_ANTICASC
	uint16_t		ac_limit;
	struct s_acasc_shm acasc;
#endif

	FTAB			fchid;
	FTAB			ftab;				// user [caid] and ident filter
	CLASSTAB		cltab;

	int32_t 		pfd;				// Primary FD, must be closed on exit
	struct s_reader *reader;			// points to s_reader when cl->typ='r'

	ECM_REQUEST 	*ecmtask;
	struct s_emm 	*emmcache;

	pthread_t		thread;
	pthread_mutex_t	**mutexstore;
	uint16_t 		mutexstore_alloc;
	uint16_t 		mutexstore_used;

#ifdef WITH_MUTEXDEBUG
	char 			**mutexstore_file;
	uint16_t 		*mutexstore_line;
#endif

	struct s_serial_client	*serialdata;

	//reader common
	int32_t 		last_idx;
	uint16_t 		idx;
	int8_t 			rotate;

	uchar			*req;

	int8_t 			ncd_proto;

	//camd35
	uchar 			upwd[64];
	int8_t 			is_udp;
	int8_t 			stopped;
	uint16_t 		lastcaid;
	uint16_t 		lastsrvid;
	int32_t 		lastpid;
	time_t 			emm_last;
	int8_t 			disable_counter;
	uchar 			lastserial[8];

	//monitor
	int8_t 			auth;

	//oscam.c
	struct timeval	tv;

	//failban value set bitwise - compared with BAN_
	int32_t 		failban;
	int8_t 			cleaned;
	struct s_client	*next; 				//make client a linked list
};

struct geo_cache {						//for viaccess var in s_reader:
	uint32_t 		provid;
	uchar 			geo[256];
	uchar 			geo_len;
	int32_t 		number_ecm;
};

struct s_CmdTabEntry {					// for videoguard in s_reader
	unsigned char 	cla;
	unsigned char 	cmd;
	unsigned char 	len;
	unsigned char 	mode;
};

struct s_CmdTab {
	unsigned char 	index;
	unsigned char 	size;
	unsigned char 	Nentries;
	unsigned char 	dummy;
	struct s_CmdTabEntry e[1];
};

struct s_ecmWhitelist {
	uint16_t 					caid;
	struct s_ecmWhitelistIdent 	*idents;
	struct s_ecmWhitelist 		*next;
};

struct s_ecmWhitelistIdent {
	uint32_t 					ident;
	struct s_ecmWhitelistLen 	*lengths;
	struct s_ecmWhitelistIdent 	*next;
};

struct s_ecmWhitelistLen {
	int16_t 					len;
	struct s_ecmWhitelistLen 	*next;
};

//ratelimit
struct ecmrl {
	uint16_t        srvid;
	time_t			last;
};
#define MAXECMRATELIMIT	20

struct s_reader  						//contains device info, reader info and card info
{
	uint32_t		auprovid; 			// AU only for this provid
	int8_t			audisabled; 		// exclude reader from auto AU
	int8_t			smargopatch;
	struct s_client *client; 			// pointer to 'r'client this reader is running in
	LLIST 			*ll_entitlements;	// entitlements
	int8_t       	enable;
	int8_t       	available; 			// Schlocke: New flag for loadbalancing. Only reader if reader supports ph.c_available function
	int8_t       	dropbadcws;			// Schlocke: 1=drops cw if checksum is wrong. 0=fix checksum (default)
	int8_t       	fd_error;
	uint64_t    	grp;
	int8_t       	fallback;
	int32_t       	typ;
	char      		label[64];
#ifdef WEBIF
	char     		description[64];
#endif
	char      		device[128];
	void      		*spec_dev; 			// pointer to structure that contains specific device data
	uint16_t    	slot;   			// in case of multiple slots like sc8in1; first slot = 1
	int32_t       	handle;   			// device handle
	int32_t       	fdmc;     			// device handle for multicam
#ifdef WITH_STAPI
	uint32_t 		stsmart_handle; 	// device handle for stsmart driver
#endif
	char      		pcsc_name[128];
	int8_t       	pcsc_has_card;
	int32_t       	detect;
	int32_t       	mhz;      			// actual clock rate of reader in 10khz steps
	int32_t	    	cardmhz;			// standard clock speed your card should have in 10khz steps; normally 357 but for Irdeto cards 600
	int32_t      	r_port;
	char      		r_usr[64];
	char      		r_pwd[64];
	char      		l_pwd[64];
	int32_t       	l_port;
	int32_t       	log_port;
	CAIDTAB   		ctab;
	uint32_t     	boxid;
	int8_t       	nagra_read; 		// read nagra ncmed records: 0 disabled (default), 1 read all records, 2 read valid records only
	uchar	    	nagra_boxkey[16]; 	// n3 boxkey 8byte  or tiger idea key 16byte
	char      		country_code[3]; 	// irdeto country code.
	int8_t       	force_irdeto;
	uchar     		rsa_mod[120]; 		// rsa modulus for nagra cards.
	uchar     		atr[64];
	int32_t			atrlen;
	SIDTABBITS    	sidtabok;			// positiv services
	SIDTABBITS    	sidtabno;			// negative services
	uchar     		hexserial[8];
	int32_t       	nprov;
	uchar     		prid[CS_MAXPROV][8];
	uchar     		availkeys[CS_MAXPROV][16];  // viaccess; misused in seca, if availkeys[PROV][0]=0 then expired, 1 then valid.
	uchar     		sa[CS_MAXPROV][4];  // viaccess & seca
	uint16_t    	acs;    			// irdeto
	uint16_t    	caid;
	uint16_t  		b_nano;
	uint16_t  		s_nano;
	int32_t       	blockemm;
	char      		*emmfile;
	char      		pincode[5];
	int32_t			ucpk_valid;
	int8_t       	logemm;
	int8_t			cachemm;
	int16_t			rewritemm;
	int8_t			card_status;
	int8_t			deprecated; 		//if 0 ATR obeyed, if 1 default speed (9600) is chosen; for devices that cannot switch baudrate
	struct s_module ph;
	struct s_cardreader crdr;
	struct s_cardsystem csystem;
	uchar     		ncd_key[16];
	uchar     		ncd_skey[16];
	int8_t       	ncd_disable_server_filt;
	uint16_t    	ncd_msgid;
	int8_t       	ncd_proto;
#ifdef MODULE_CCCAM
	char      		cc_version[7];  	// cccam version
	char      		cc_build[7];    	// cccam build number
	int8_t       	cc_maxhop;      	// cccam max distance
	int8_t       	cc_mindown;     	// cccam min downhops
	int8_t       	cc_currenthops; 	// number of hops for CCCam
	int8_t       	cc_want_emu; 		// Schlocke: Client want to have EMUs, 0 - NO; 1 - YES
	uint32_t    	cc_id;
	int8_t       	cc_keepalive;
	int8_t			cc_hop; 			// For non-cccam reader: hop for virtual cards
#endif
	int8_t     		tcp_connected;
	int32_t       	tcp_ito;      		// inactivity timeout
	int32_t       	tcp_rto;      		// reconnect timeout
	struct timeb	tcp_block_connect_till; //time tcp connect ist blocked
	int32_t       	tcp_block_delay; 	//incrementing block time
	time_t    		last_g;      		// get (if last_s-last_g>tcp_rto - reconnect )
	time_t    		last_s;       		// send
	uint8_t   		show_cls;     		// number of classes subscription showed on kill -31
	FTAB      		fchid;
	FTAB      		ftab;
	CLASSTAB  		cltab;
	struct s_ecmWhitelist *ecmWhitelist;
	char      		*init_history;
	int32_t       	init_history_pos;
	int32_t       	brk_pos;
	int32_t       	msg_idx;
#ifdef WEBIF
	int32_t			emmwritten[4]; 		// count written EMM
	int32_t			emmskipped[4]; 		// count skipped EMM
	int32_t			emmerror[4];		// count error EMM
	int32_t			emmblocked[4];		// count blocked EMM
	int32_t			lbvalue;			// loadbalance Value
#endif
#ifdef HAVE_PCSC
	SCARDCONTEXT 	hContext;
	SCARDHANDLE 	hCard;
	DWORD 			dwActiveProtocol;
#endif
#ifdef LIBUSB
	uint8_t  		device_endpoint; 	// usb endpoint for Infinity USB Smart in smartreader mode.
	struct s_sr_config *sr_config;
#endif
#ifdef AZBOX
	int32_t			mode;
#endif
	////variables from icc_async.h start
	int32_t 		convention; 		// Convention of this ICC
	unsigned char 	protocol_type; 		// Type of protocol
	uint16_t 		BWT,CWT; 			// (for overclocking uncorrected) block waiting time, character waiting time, in ETU
	uint32_t 		current_baudrate; 	// (for overclocking uncorrected) baudrate to prevent unnecessary conversions from/to termios structure
	uint32_t 		read_timeout; 		// Max timeout (ms) to receive characters
	uint32_t 		block_delay; 		// Delay (ms) after starting to transmit
	uint32_t 		char_delay; 		// Delay (ms) after transmiting each sucesive char
	////variables from io_serial.h
	int32_t 		written; 			// keep score of how much bytes are written to serial port, since they are echoed back they have to be read
	////variables from protocol_t1.h
	uint16_t 		ifsc;  				// Information field size for the ICC
	unsigned char  	ns;              	// Send sequence number
	////variables from reader-dre.c
	unsigned char 	provider;
	////variables from reader-nagra.c
 	IDEA_KEY_SCHEDULE ksSession;
 	int8_t 			is_pure_nagra;
 	int8_t 			is_tiger;
 	int8_t 			is_n3_na;
 	int8_t 			has_dt08;
 	int8_t 			swapCW;
 	uint8_t 		ExpiryDate[2];
 	uint8_t 		ActivationDate[2];
 	unsigned char 	rom[15];
 	unsigned char 	plainDT08RSA[64];
 	unsigned char 	IdeaCamKey[16];
 	unsigned char 	irdId[4];
 	unsigned char 	sessi[16];
 	unsigned char 	signature[8];
 	unsigned char 	cam_state[3];
	////variables from reader-irdeto.c
	int32_t acs57; // A flag for the ACS57 ITA DVB-T
	////variables from reader-cryptoworks.c
	BIGNUM 			exp;
	BIGNUM 			ucpk;
	////variables from reader-viaccess.c
	struct geo_cache last_geo;
#ifdef MODULE_CCCAM
	int32_t 		cc_reshare;
#endif
#ifdef WITH_LB
	int32_t 		lb_weight;     		//loadbalance weight factor, if unset, weight=100. The higher the value, the higher the usage-possibility
	int32_t 		lb_usagelevel; 		//usagelevel for loadbalancer
	int32_t 		lb_usagelevel_ecmcount;
	time_t 			lb_usagelevel_time; //time for counting ecms, this creates usagelevel
	struct timeb 	lb_last; 			//time for oldest reader
	LLIST 			*lb_stat; 			//loadbalancer reader statistics
#endif

	AES_ENTRY		*aes_list;			// multi AES linked list
 	// variables from reader-videoguard*
 	int8_t			ndsversion; 		// 0 auto (default), 1 NDS1, 12 NDS1+, 2 NDS2
 	const char 		*card_desc;
 	int32_t			card_baseyear;
 	int32_t			card_tierstart;
 	int32_t			card_system_version;
 	struct s_CmdTab *cmd_table;
 	uint16_t		cardkeys[3][32];
 	unsigned char	stateD3A[16];
 	AES_KEY			ekey;
 	AES_KEY			astrokey;
	//ratelimit
	int32_t			ratelimitecm;
	int32_t			ratelimitseconds;
	struct ecmrl    rlecmh[MAXECMRATELIMIT];
	int8_t			fix_9993;
	struct s_reader *next;
};

#ifdef CS_ANTICASC
struct s_cpmap
{
	uint16_t		caid;
	uint32_t		provid;
	uint16_t		sid;
	uint16_t		chid;
	uint16_t		dwtime;
	struct s_cpmap	*next;
};
#endif

struct s_auth
{
	char			usr[64];
	char			pwd[64];
#ifdef WEBIF
	char			description[64];
#endif
	int8_t			uniq;
	LLIST			*aureader_list;
	int8_t			autoau;
	int8_t			monlvl;
	uint64_t		grp;
	int32_t			tosleep;
	CAIDTAB			ctab;
	SIDTABBITS		sidtabok;			// positiv services
	SIDTABBITS		sidtabno;			// negative services
	FTAB			fchid;
	FTAB			ftab;				// user [caid] and ident filter
	CLASSTAB		cltab;
	TUNTAB			ttab;
#ifdef CS_ANTICASC
	int32_t			ac_users;			// 0 - unlimited
	uchar			ac_penalty;			// 0 - log, >0 - fake dw
	struct s_acasc	ac_stat;
#endif
	in_addr_t		dynip;
	uchar			dyndns[64];
	time_t			expirationdate;
	time_t			firstlogin;
	int32_t			allowedtimeframe[2];
	int8_t			c35_suppresscmd08;
	uint8_t			c35_sleepsend;
	int8_t			ncd_keepalive;
	int32_t			cccmaxhops;
	int32_t			cccreshare;
	int8_t			cccignorereshare;
	int8_t			cccstealth;
	int8_t			disabled;
	int32_t			failban;

	int32_t			cwfound;
	int32_t			cwcache;
	int32_t			cwnot;
	int32_t			cwtun;
	int32_t			cwignored;
	int32_t			cwtout;
	int32_t			emmok;
	int32_t			emmnok;
	struct s_auth	*next;
};

struct s_srvid
{
	uint16_t   		srvid;
	int8_t     		ncaid;
	uint16_t   		caid[10];
	char    		*data;
	char    		*prov;
	char    		*name;
	char    		*type;
	char    		*desc;
	struct s_srvid	*next;
};

struct s_tierid
{
	uint16_t    	tierid;
	int8_t    	 	ncaid;
	uint16_t   		caid[10];
	char    		name[33];
	struct s_tierid *next;
};

//Todo #ifdef CCCAM
struct s_provid
{
	uint16_t		caid;
	uint32_t		provid;
	char			prov[33];
	char			sat[33];
	char			lang[33];
	struct			s_provid *next;
};

struct s_ip
{
	in_addr_t 		ip[2];
	struct s_ip 	*next;
};

struct s_config
{
	int32_t			nice;
	uint32_t		netprio;
	uint32_t		ctimeout;
	uint32_t		ftimeout;
	uint32_t		cmaxidle;
	int32_t			ulparent;
	uint32_t		delay;
	int32_t			bindwait;
	int32_t			tosleep;
	in_addr_t		srvip;
	char			*usrfile;
	char			*cwlogdir;
	char			*emmlogdir;
	char			*logfile;
	char			*mailfile;
	uint8_t			logtostdout;
	uint8_t 		logtosyslog;
	uint32_t		loghistorysize;
	int8_t			disablelog;
	int8_t			disablemail;
	int8_t			disableuserfile;
	int8_t			usrfileflag;
	struct s_auth 	*account;
	struct s_srvid 	*srvid[16];
	struct s_tierid *tierid;
	//Todo #ifdef CCCAM
	struct s_provid *provid;
	struct s_sidtab *sidtab;
	int32_t			mon_port;
	in_addr_t		mon_srvip;
	struct s_ip 	*mon_allowed;
	int32_t			mon_aulow;
	int32_t			mon_hideclient_to;
	int32_t			mon_level;
	int32_t			mon_appendchaninfo;
#ifdef WEBIF
	int32_t			http_port;
	char			http_user[65];
	char			http_pwd[65];
	char			http_css[128];
	char			http_jscript[128];
	char			http_tpl[128];
	char			http_script[128];
	int32_t			http_refresh;
	int8_t			http_hide_idle_clients;
	struct s_ip 	*http_allowed;
	int8_t			http_readonly;
	in_addr_t		http_dynip;
	uchar			http_dyndns[64];
	int8_t			http_use_ssl;
	char			http_cert[128];
	char			http_help_lang[3];
#endif
	int8_t			http_full_cfg;
	int32_t			failbantime;
	int32_t			failbancount;
	LLIST 			*v_list; //failban list
	int32_t			c33_port;
	in_addr_t		c33_srvip;
	uchar			c33_key[16];
	int32_t			c33_crypted;
	int32_t			c33_passive;
	struct s_ip 	*c33_plain;
	int32_t			c35_port;
	in_addr_t		c35_srvip;
	int8_t			c35_suppresscmd08;
	int8_t			c35_tcp_suppresscmd08;
	int8_t			c35_udp_suppresscmd08;
	PTAB			c35_tcp_ptab;
	in_addr_t		c35_tcp_srvip;
	PTAB			ncd_ptab;
	in_addr_t		ncd_srvip;
	uchar			ncd_key[16];
	int32_t			ncd_keepalive;
	int8_t			ncd_mgclient;
	struct s_ip 	*ncd_allowed;
	int32_t			rad_port;
	in_addr_t		rad_srvip;
#ifdef MODULE_CCCAM
	uint16_t		cc_port[CS_MAXPORTS];
	int8_t			cc_reshare;
	int8_t			cc_ignore_reshare;
	int32_t			cc_update_interval;
	in_addr_t		cc_srvip;
	char			cc_version[7];
	int8_t			cc_minimize_cards;
	int8_t			cc_keep_connected;
	int8_t			cc_stealth;
	int8_t			cc_reshare_services;
	int8_t     		cc_forward_origin_card;
	int8_t			cc_use_fixed_nodeid;
	uint8_t			cc_fixed_nodeid[8];
#endif
	char			gbox_hostname[128];
	char			gbox_key[9];
	char			gbox_gsms_path[200];
	int32_t			gbox_port;
	struct s_ip 	*rad_allowed;
	char			rad_usr[32];
	char			ser_device[512];
	uint32_t		srtimeout;  // SerialReaderTimeount in millisec
	int32_t			max_log_size;
	int8_t			waitforcards;
	int32_t			waitforcards_extra_delay;
	int8_t			preferlocalcards;
	int8_t			saveinithistory;
	int32_t     	reader_restart_seconds; //schlocke: reader restart auf x seconds, disable = 0
	int8_t			dropdups; //drop duplicate logins


//Loadbalancer-Config:
#ifdef WITH_LB
	int32_t     lb_mode; //schlocke: reader loadbalancing mode
	int32_t     lb_save; //schlocke: load/save statistics to file, save every x ecms
	int32_t		lb_nbest_readers; // count of best readers
	int32_t		lb_nfb_readers; // count of fallback readers
	int32_t		lb_min_ecmcount; // minimal ecm count to evaluate lbvalues
	int32_t     lb_max_ecmcount; // maximum ecm count before reseting lbvalues
	int32_t     lb_reopen_seconds; //time between retrying failed readers/caids/prov/srv
	int32_t	lb_retrylimit; //reopen only happens if reader response time > retrylimit
	CAIDVALUETAB lb_retrylimittab;
	CAIDVALUETAB lb_nbest_readers_tab; //like nbest_readers, but for special caids
	CAIDTAB lb_noproviderforcaid; //do not store loadbalancer stats with providers for this caid
	char	*lb_savepath; //path where the stat file is save. Empty=default=/tmp/.oscam/stat
	int32_t	lb_stat_cleanup; //duration in hours for cleaning old statistics
	int32_t lb_use_locking; //use a mutex lock while searching for readers (get_cw())
	int32_t lb_reopen_mode; //reopen readers mode
	int32_t lb_max_readers; //limit the amount of readers during learning
	int32_t lb_auto_betatunnel; //automatic selection of betatunnel convertion based on learned data
#endif
	int32_t resolve_gethostbyname;

#ifdef CS_WITH_DOUBLECHECK
	int8_t double_check; //schlocke: Double checks each ecm+dcw from two (or more) readers
#endif

#ifdef IRDETO_GUESSING
	struct s_irdeto_quess *itab[0xff];
#endif

#ifdef HAVE_DVBAPI
	int8_t		dvbapi_enabled;
	int8_t		dvbapi_au;
	char		dvbapi_usr[64];
	int8_t		dvbapi_boxtype;
	int8_t		dvbapi_pmtmode;
	int8_t		dvbapi_requestmode;
	SIDTABBITS    dvbapi_sidtabok;	// positiv services
	SIDTABBITS    dvbapi_sidtabno;	// negative services
#endif

#ifdef CS_ANTICASC
	char		ac_enabled;
	int32_t		ac_users;       // num of users for account (0 - default)
	int32_t		ac_stime;       // time to collect AC statistics (3 min - default)
	int32_t		ac_samples;     // qty of samples
	int32_t		ac_penalty;     // 0 - write to log
	int32_t		ac_fakedelay;   // 100-1000 ms
	int32_t		ac_denysamples;
	char		ac_logfile[128];
	struct		s_cpmap *cpmap;
#endif

#ifdef QBOXHD_LED
    int8_t disableqboxhdled; // disable qboxhd led , default = 0
#endif

#ifdef LCDSUPPORT
    char		*lcd_output_path;
    int32_t		lcd_hide_idle;
    int32_t		lcd_write_intervall;
#endif
};

struct s_clientinit
{
	void *(*handler)(struct s_client*);
	struct s_client * client;
};

struct s_data {
	int action;
	struct s_reader *rdr;
	struct s_client *cl;
	void *ptr;
	uint16_t len;
};

typedef struct reader_stat_t
{
  int32_t           rc;
  uint16_t        caid;
  uint32_t         prid;
  uint16_t        srvid;
  int16_t			ecmlen;

  time_t        last_received;

  int32_t           ecm_count;
  int32_t           time_avg;
  int32_t           time_stat[LB_MAX_STAT_TIME];
  int32_t           time_idx;

  int32_t			fail_factor;
} READER_STAT;

typedef struct emm_packet_t
{
  uchar emm[258];
  uchar l;
  uchar caid[2];
  uchar provid[4];
  uchar hexserial[8];					 //contains hexserial or SA of EMM
  uchar type;
  struct s_client *client;
} EMM_PACKET;

#ifdef QBOXHD_LED
typedef struct {
	uint16_t H;  // range 0-359
	unsigned char S;   // range 0-99
	unsigned char V;   // range 0-99
} qboxhd_led_color_struct;
typedef struct {
	unsigned char red;  // first 5 bit used (&0x1F)
	unsigned char green; // first 5 bit used (&0x1F)
	unsigned char blue; // first 5 bit used (&0x1F)
} qboxhdmini_led_color_struct;
#endif


/* ===========================
 *      global variables
 * =========================== */
extern char cs_tmpdir[200];
extern pthread_key_t getclient;
extern struct s_client *first_client;
extern struct s_reader *first_active_reader; //points to list of _active_ readers (enable = 1, deleted = 0)
extern LLIST *configured_readers;
extern int32_t cs_dblevel;
extern uint16_t len4caid[256];
extern struct s_config cfg;
extern char cs_confdir[];
extern char *loghist, *loghistptr;
extern struct s_module ph[CS_MAX_MOD];
extern struct s_cardsystem cardsystem[CS_MAX_MOD];
extern struct s_cardreader cardreader[CS_MAX_MOD];
extern CS_MUTEX_LOCK gethostbyname_lock;
#if defined(LIBUSB)
extern pthread_mutex_t sr_lock;
#endif

extern pid_t server_pid; // PID of server - set while startup

/* ===========================
 *      global functions
 * =========================== */
#include "global-functions.h"

#endif
