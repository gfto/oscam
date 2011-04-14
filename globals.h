#define _GNU_SOURCE //prevents "implicit" warning for asprintf
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

// Prevent use of unsafe functions (doesn't work for MacOSX)
#ifndef OS_MACOSX
#define strcpy(a,b) UNSAFE_STRCPY_USE_CS_STRNCPY_INSTEAD()
#define sprintf(a,...) UNSAFE_SPRINTF_USE_SNPRINTF_INSTEAD()
#endif

#ifndef CS_GLOBALS
#define CS_GLOBALS
#define CS_VERSION    "1.00-unstable_svn"
#ifndef CS_SVN_VERSION
#	define CS_SVN_VERSION "test"
#endif

#include "oscam-config.h"

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
		return ERROR; \
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

// DM500 and Dbox2 have toolchains which don't match their plattform. Therefore pthread_cleanup_push can't be used (binaries compile but only work on DM 7020)
#if defined(TUXBOX) && defined(PPC)
#define NO_PTHREAD_CLEANUP_PUSH
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
#define CS_MAXLOGHIST     30
#define CS_LOGHISTSIZE    193 // 32+128+33: username + logline + channelname
#define CS_ECM_RINGBUFFER_MAX 20 // max size for ECM last responsetimes ringbuffer

#define CS_CACHE_TIMEOUT  60
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 64000
#endif

#ifdef  CS_EMBEDDED
#define CS_MAXPENDING   16
#define PTHREAD_STACK_SIZE PTHREAD_STACK_MIN+8000
#else
#define CS_MAXPENDING   32
#define PTHREAD_STACK_SIZE PTHREAD_STACK_MIN+10000
#endif

#define CS_EMMCACHESIZE  64 //nr of EMMs that each client will cache; cache is per client, so memory-expensive...

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
#define PIP_ID_KCL    3  // Schlocke: Kill all Clients (no param)
#define PIP_ID_UDP    4
#define PIP_ID_MAX    PIP_ID_UDP


#define PIP_ID_ERR    (-1)
#define PIP_ID_DIR    (-2)
#define PIP_ID_NUL    (-3)

#define cdiff *c_start

#define NCD_AUTO    0
#define NCD_524     1
#define NCD_525     2

// moved from reader-common.h
#define UNKNOWN        0
#define NO_CARD        4
#define CARD_NEED_INIT 1
#define CARD_INSERTED  2
#define CARD_FAILURE   3

// moved from stats
#define DEFAULT_REOPEN_SECONDS 900
#define DEFAULT_MIN_ECM_COUNT 5
#define DEFAULT_MAX_ECM_COUNT 500
#define DEFAULT_NBEST 1
#define DEFAULT_NFB 1
#define DEFAULT_RETRYLIMIT 800
#define DEFAULT_LB_STAT_CLEANUP 336
#define DEFAULT_LB_USE_LOCKING 0
#define DEFAULT_LB_REOPEN_MODE 0
#define DEFAULT_UPDATEINTERVAL 240

enum {E1_GLOBAL=0, E1_USER, E1_READER, E1_SERVER, E1_LSERVER};
enum {E2_GLOBAL=0, E2_GROUP, E2_CAID, E2_IDENT, E2_CLASS, E2_CHID, E2_QUEUE,
      E2_EA_LEN, E2_F0_LEN, E2_OFFLINE, E2_SID, 
      E2_CCCAM_NOCARD=0x27, E2_CCCAM_NOK1=0x28, E2_CCCAM_NOK2=0x29, E2_CCCAM_LOOP=0x30};

pid_t server_pid; //alno: PID of server - set while startup

// constants
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

extern void qboxhd_led_blink(int32_t color, int32_t duration);

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

//checking if (X) free(X) unneccessary since freeing a null pointer doesnt do anything
#define NULLFREE(X) {if (X) {void *tmpX=X; X=NULL; free(tmpX); }}

typedef struct s_caidvaluetab
{
  uint16_t n;
  uint16_t caid[CS_MAX_CAIDVALUETAB];
  uint16_t value[CS_MAX_CAIDVALUETAB];
} CAIDVALUETAB;

typedef struct s_classtab
{
  uchar an;
  uchar bn;
  uchar aclass[31];
  uchar bclass[31];
} CLASSTAB;

typedef struct s_caidtab
{
  uint16_t caid[CS_MAXCAIDTAB];
  uint16_t mask[CS_MAXCAIDTAB];
  uint16_t cmap[CS_MAXCAIDTAB];
} CAIDTAB;

typedef struct s_tuntab
{
  uint16_t bt_caidfrom[CS_MAXTUNTAB];
  uint16_t bt_caidto[CS_MAXTUNTAB];
  uint16_t bt_srvid[CS_MAXTUNTAB];
} TUNTAB;

typedef struct s_sidtab
{
  char     label[64];
  uint16_t   num_caid;
  uint16_t   num_provid;
  uint16_t   num_srvid;
  uint16_t   *caid;
  uint32_t   *provid;
  uint16_t   *srvid;
  struct   s_sidtab *next;
} SIDTAB;


typedef struct s_filter
{
  uint16_t caid;
  uchar  nprids;
  uint32_t  prids[CS_MAXPROV];
} FILTER;

typedef struct s_ftab
{
  int32_t    nfilts;
  FILTER filts[CS_MAXFILTERS];
} FTAB;

typedef struct s_port
{
  int32_t    fd;
  int32_t    s_port;
  int32_t    ncd_key_is_set;    //0 or 1
  uchar  ncd_key[16];
  FTAB   ftab;
} PORT;

typedef struct s_ptab
{
  int32_t    nports;
  PORT   ports[CS_MAXPORTS];
} PTAB;

typedef struct aes_entry {
    uint16_t      keyid;
    uint16_t      caid;
    uint32_t      ident;
    uchar		plainkey[16];
    AES_KEY     key;
    struct aes_entry   *next;
} AES_ENTRY;

struct s_ecm
{
  uchar  	ecmd5[CS_ECMSTORESIZE];
  uchar  	cw[16];
  uint16_t 	caid;
  uint64_t  	grp;
  struct s_reader *reader;
  int32_t  rc;
  time_t time;
};

struct s_emm
{
  uchar emmd5[CS_EMMSTORESIZE];
  uchar type;
  int32_t   count;
};

// failban listmember
typedef struct v_ban {
	int32_t v_count;
	uint32_t v_ip;
	time_t v_time;
} V_BAN;

#define AVAIL_CHECK_CONNECTED 0
#define AVAIL_CHECK_LOADBALANCE 1

struct s_client ;
struct ecm_request_t ;
struct emm_packet_t ;

struct s_module
{
  int32_t  active;
  int32_t  multi;
  int32_t  type;
  int32_t  watchdog;
  char desc[16];
  char *logtxt;
  //int32_t  s_port;
  in_addr_t s_ip;
  void *(*s_handler)();
  int32_t  (*recv)(struct s_client *, uchar *, int32_t);
  void (*send_dcw)(struct s_client*, struct ecm_request_t *);
  void (*cleanup)(struct s_client*);
  int32_t  c_multi;
  int32_t  (*c_recv_chk)(struct s_client*, uchar *, int32_t *, uchar *, int32_t);
  int32_t  (*c_init)(struct s_client*);
  int32_t  (*c_send_ecm)(struct s_client *, struct ecm_request_t *, uchar *);
  int32_t  (*c_send_emm)(struct emm_packet_t *);
  int32_t  (*c_init_log)(void);
  int32_t  (*c_recv_log)(uint16_t *, uint32_t *, uint16_t *);
  int32_t  (*c_available)(struct s_reader *, int32_t); 	//Schlocke: available check for load-balancing,
                         //params:
                         //rdr (reader to check)
                         //int32_t checktype (0=return connected, 1=return loadbalance-avail) return int
  void (*c_idle)(void);      //Schlocke: called when reader is idle
  void (*c_card_info)(void); //Schlocke: request card infos
  int32_t  c_port;
  PTAB *ptab;
  int32_t num;
};

struct s_ATR ;

struct s_cardreader
{
	int32_t	active;
	char	desc[16];
	int32_t	(*reader_init)(struct s_reader*);
	int32_t	(*get_status)(struct s_reader*, int*);
	int32_t	(*activate)(struct s_reader*, struct s_ATR *);
	int32_t	(*transmit)(struct s_reader*, unsigned char *sent, uint32_t size);
	int32_t	(*receive)(struct s_reader*, unsigned char *data, uint32_t size);
	int32_t	(*close)(struct s_reader*);
	int32_t	(*set_parity)(struct s_reader*, uchar parity);
	int32_t	(*write_settings)(struct s_reader*, uint32_t ETU, uint32_t EGT, unsigned char P, unsigned char I, uint16_t Fi, unsigned char Di, unsigned char Ni);
	int32_t	(*set_protocol)(struct s_reader*, unsigned char * params, uint32_t *length, uint32_t len_request);
	int32_t	(*set_baudrate)(struct s_reader*, uint32_t baud); //set only for readers which need baudrate setting and timings need to be guarded by OSCam
	int32_t	typ; //fixme: workaround, remove when all old code is converted

	int32_t	max_clock_speed; // 1 for reader->typ > R_MOUSE
	int32_t	need_inverse; //0 = reader does inversing; 1 = inversing done by oscam
	//io_serial config
	int32_t	flush;
	int32_t	read_written; // 1 = written bytes has to read from device
};

struct s_cardsystem
{
	int32_t active;
	char *desc;
	int32_t  (*card_init)();
	int32_t  (*card_info)();
	int32_t  (*do_ecm)();
	int32_t  (*do_emm)();
	void (*post_process)();
	int32_t  (*get_emm_type)();
	void (*get_emm_filter)();
	uchar caids[2];
};

#ifdef IRDETO_GUESSING
struct s_irdeto_quess
{
  int32_t    b47;
  uint16_t caid;
  uint16_t sid;
  struct s_irdeto_quess *next;
};
#endif

#define MSGLOGSIZE 64
typedef struct ecm_request_t
{
  uchar         ecm[256];
  uchar         cw[16];
  uchar         ecmd5[CS_ECMSTORESIZE];
//  uchar         l;
  int16_t         l;
  uint16_t        caid;
  uint16_t        ocaid; //original caid, used for betatunneling
  uint16_t        srvid;
  uint16_t        chid;
  uint16_t        pid;
  uint16_t        idx;
  uint32_t         prid;
  struct s_reader *selected_reader;
  LLIST         *matching_rdr; //list of matching readers
  LL_NODE       *fallback; // in *matching_rdr, at position "fallback" the first fallback reader is in the list
  struct s_client *client; //contains pointer to 'c' client while running in 'r' client
  int32_t           cpti;   // client pending table index
  int32_t           stage;    // processing stage in server module
  int32_t           level;    // send-level in client module
  int32_t           rc;
  uchar         rcEx;
  struct timeb  tps;    // incoming time stamp
  uchar         locals_done;
  int32_t		btun; // mark er as betatunneled
  int32_t		reader_avail; //count of available readers
  int32_t           reader_count; //count of contacted readers

#ifdef CS_WITH_DOUBLECHECK
  int32_t		checked;
  uchar		cw_checked[16];
#endif

  struct s_reader *origin_reader;
  void * origin_card; //CCcam preferred card!
  
  struct s_ecm *ecmcacheptr; //Pointer to ecm-cw-rc-cache!

  char msglog[MSGLOGSIZE];
} ECM_REQUEST;

#ifdef CS_ANTICASC
struct s_acasc_shm {
  uint16_t ac_count : 15;
  uint16_t ac_deny  : 1;
};

struct s_acasc {
  uint16_t stat[10];
  uchar  idx;    // current active index in stat[]
};
#endif

struct s_client
{
  in_addr_t	ip;
  in_port_t	port;
  time_t	login;
  time_t	last;
  time_t	lastswitch;
  time_t	lastemm;
  time_t	lastecm;
  time_t	expirationdate;
  int32_t		allowedtimeframe[2];
  int32_t		c35_suppresscmd08;
  int32_t		c35_sleepsend;
  int32_t		ncd_keepalive;
  int32_t		disabled;
  uint64_t	grp;
  int32_t		crypted;
  int32_t		dup;
  LLIST	*aureader_list;
  int32_t		autoau;
  int32_t		monlvl;
  CAIDTAB	ctab;
  TUNTAB	ttab;
  SIDTABBITS	sidtabok; // positiv services
  SIDTABBITS	sidtabno; // negative services
  int32_t		typ;        // first s_client is type s=starting (master) thread; type r = physical reader, type p = proxy reader both always have 1 s_reader struct allocated; type c = client (user logging in into oscam) type m = monitor type h = http server a = anticascader
  int32_t		ctyp;
  int32_t		stat;
  int32_t		last_srvid;
  int32_t		last_caid;
  int32_t		tosleep;
  struct s_auth *account;
  int32_t		udp_fd;
  int32_t		fd_m2c; //master writes to this fd
  int32_t		fd_m2c_c; //client reads from this fd
  struct	sockaddr_in udp_sa;
  int32_t		log;
  int32_t		logcounter;
  int32_t		cwfound;     // count found ECMs per client
  int32_t		cwcache;     // count ECMs from cache1/2 per client
  int32_t		cwnot;       // count not found ECMs per client
  int32_t		cwtun;       // count betatunneled ECMs per client
  int32_t		cwignored;   // count ignored  ECMs per client
  int32_t		cwtout;      // count timeouted ECMs per client
  int32_t		cwlastresptime; //last Responsetime (ms)
  int32_t		cwlastresptimes[CS_ECM_RINGBUFFER_MAX]; //ringbuffer for last 20 times
  int32_t		cwlastresptimes_last; // ringbuffer pointer
  int32_t		emmok;       // count EMM ok
  int32_t		emmnok;	     // count EMM nok
#ifdef WEBIF
  int32_t		wihidden;	// hidden in webinterface status
  char      lastreader[64]; // last cw got from this reader
#endif
  uchar		ucrc[4];    // needed by monitor and used by camd35
  uint32_t		pcrc;        // pwd crc
  AES_KEY	aeskey;      // encryption key needed by monitor and used by camd33, camd35
  AES_KEY	aeskey_decrypt;      // decryption key needed by monitor and used by camd33, camd35
  uint16_t	ncd_msgid;
  char 		ncd_client_id[5];
  uchar		ncd_skey[16];
  void		*cc;
  void		*gbox;
  int32_t		port_idx;    // index in server ptab
  int32_t		ncd_server;  // newcamd server
#ifdef CS_ANTICASC
  uint16_t	ac_limit;
  struct	s_acasc_shm acasc;
#endif
  FTAB		fchid;
  FTAB		ftab;        // user [caid] and ident filter
  CLASSTAB	cltab;


  int32_t pfd;      // Primary FD, must be closed on exit
  struct s_reader *reader; //points to s_reader when cl->typ='r'

  ECM_REQUEST *ecmtask;
  struct s_emm *emmcache;

  pthread_t thread;
  
  struct s_serial_client *serialdata;

  //reader common
  int32_t last_idx;
  uint16_t idx;
  int32_t rotate;

  uchar	*req;

  int32_t       ncd_proto;

  //camd35
  uchar upwd[64];
  int32_t is_udp;
  int32_t stopped;
  int32_t lastcaid;
  int32_t lastsrvid;
  int32_t lastpid;
  time_t emm_last;
  int32_t disable_counter;
  uchar lastserial[8];

  //cccam
  int32_t g_flag;
  int32_t cc_use_rc4;

  //monitor
  int32_t auth;

  //cs_hexdump buffer
  uchar dump[520];
  
  //an iterator to be used across OSCam; threadspecific
  LL_ITER it;
  int32_t itused;

  //oscam.c
  struct timeval tv;

  //failban value set bitwise - compared with BAN_
  int32_t failban;
  int32_t cleaned;
  struct s_client *next; //make client a linked list
};


//for viaccess var in s_reader:
struct geo_cache
{
	uint32_t provid;
	uchar geo[256];
	uchar geo_len;
	int32_t number_ecm;
};
// for videoguard in s_reader
struct s_CmdTabEntry {
  unsigned char cla;
  unsigned char cmd;
  unsigned char len;
  unsigned char mode;
};

struct s_CmdTab {
  unsigned char index;
  unsigned char size;
  unsigned char Nentries;
  unsigned char dummy;
  struct s_CmdTabEntry e[1];
};
//ratelimit
struct ecmrl {
	uint16_t        srvid;
	time_t	last;
};
#define MAXECMRATELIMIT	20

struct s_reader  //contains device info, reader info and card info
{
  uint32_t		auprovid; // AU only for this provid
  int32_t		audisabled; // exclude reader from auto AU
  int32_t		smargopatch;
  struct s_client * client; //pointer to 'r'client this reader is running in
  int32_t       enable;
  int32_t       available; //Schlocke: New flag for loadbalancing. Only reader if reader supports ph.c_available function
  int32_t       fd_error;
  int32_t       fd;
  uint64_t    grp;
  int32_t       fallback;
  int32_t       typ;
  char      label[64];
  char      device[128];
  void      *spec_dev;  //pointer to structure that contains specific device data
  uint16_t    slot;   //in case of multiple slots like sc8in1; first slot = 1
  int32_t       handle;   //device handle
  int32_t       fdmc;     //device handle for multicam
#ifdef WITH_STAPI
  uint32_t stsmart_handle; //device handle for stsmart driver
#endif
  char      pcsc_name[128];
  int32_t       pcsc_has_card;
  int32_t       detect;
  int32_t       mhz;      //actual clock rate of reader in 10khz steps
  int32_t	    cardmhz;	    //standard clock speed your card should have in 10khz steps; normally 357 but for Irdeto cards 600
  int32_t       r_port;
  char      r_usr[64];
  char      r_pwd[64];
  char      l_pwd[64];
  int32_t       r_crypted;
  int32_t       l_port;
  int32_t       log_port;
  CAIDTAB   ctab;
  uint32_t     boxid;
  int32_t       nagra_read; // read nagra ncmed records: 0 disabled (default), 1 read all records, 2 read valid records only
  uchar	    nagra_boxkey[16]; //n3 boxkey 8byte  or tiger idea key 16byte
  char      country_code[3]; // irdeto country code.
  int32_t       force_irdeto;
  uchar     rsa_mod[120]; //rsa modulus for nagra cards.
  uchar     atr[64];
  int32_t		atrlen;
  SIDTABBITS    sidtabok;	// positiv services
  SIDTABBITS    sidtabno;	// negative services
  uchar     hexserial[8];
  int32_t       nprov;
  uchar     prid[CS_MAXPROV][8];
  uchar     availkeys[CS_MAXPROV][16];  // viaccess; misused in seca, if availkeys[PROV][0]=0 then expired, 1 then valid.
  uchar     sa[CS_MAXPROV][4];    // viaccess & seca
  uint16_t    acs;    // irdeto
  uint16_t    caid;
  uint16_t  b_nano;
  uint16_t  s_nano;
  int32_t       blockemm;
  char      * emmfile;
  char      pincode[5];
  int32_t		ucpk_valid;
  int32_t       logemm;
  int32_t       cachemm;
  int32_t       rewritemm;
  int32_t       card_status;
  int32_t       deprecated; //if 0 ATR obeyed, if 1 default speed (9600) is chosen; for devices that cannot switch baudrate
  struct    s_module ph;
  struct    s_cardreader crdr;
  struct    s_cardsystem csystem;
  uchar     ncd_key[16];
  uchar     ncd_skey[16];
  int32_t       ncd_disable_server_filt;
  uint16_t    ncd_msgid;
  int32_t       ncd_proto;
  char      cc_version[7];  // cccam version
  char      cc_build[7];    // cccam build number
  int32_t       cc_maxhop;      // cccam max distance
  int32_t       cc_mindown;     // cccam min downhops
  int32_t       cc_currenthops; // number of hops for CCCam
  int32_t       cc_want_emu; //Schlocke: Client want to have EMUs, 0 - NO; 1 - YES
  uint32_t    cc_id;
  int32_t       cc_keepalive;
  uchar     tcp_connected;
  int32_t       tcp_ito;      // inactivity timeout
  int32_t       tcp_rto;      // reconnect timeout
  struct timeb	tcp_block_connect_till; //time tcp connect ist blocked
  int32_t       tcp_block_delay; //incrementing block time
  time_t    last_g;       // get (if last_s-last_g>tcp_rto - reconnect )
  time_t    last_s;       // send
  uchar     show_cls;     // number of classes subscription showed on kill -31
  FTAB      fchid;
  FTAB      ftab;
  CLASSTAB  cltab;
  char      *init_history;
  int32_t       init_history_pos;
  int32_t       brk_pos;
  int32_t       msg_idx;
#ifdef WEBIF
  int32_t		emmwritten[4]; //count written EMM
  int32_t		emmskipped[4]; //count skipped EMM
  int32_t		emmerror[4];	//count error EMM
  int32_t		emmblocked[4];	//count blocked EMM
  int32_t		lbvalue;		//loadbalance Value
#endif
#ifdef HAVE_PCSC
  SCARDCONTEXT hContext;
  SCARDHANDLE hCard;
  DWORD dwActiveProtocol;
#endif
#ifdef LIBUSB
  uint8_t  device_endpoint; // usb endpoint32_t for Infinity USB Smart in smartreader mode.
  struct s_sr_config *sr_config;
#endif
#ifdef AZBOX
  int32_t mode;
#endif
	////variables from icc_async.h start
	int32_t convention; //Convention of this ICC
	unsigned char protocol_type; // Type of protocol
	uint16_t BWT,CWT; // (for overclocking uncorrected) block waiting time, character waiting time, in ETU
	uint32_t current_baudrate; // (for overclocking uncorrected) baudrate to prevent unnecessary conversions from/to termios structure
	uint32_t read_timeout; // Max timeout (ms) to receive characters
	uint32_t block_delay; // Delay (ms) after starting to transmit
	uint32_t char_delay; // Delay (ms) after transmiting each sucesive char
	////variables from io_serial.h
	int32_t written; //keep score of how much bytes are written to serial port, since they are echoed back they have to be read
	////variables from protocol_t1.h
	uint16_t ifsc;  /* Information field size for the ICC */
	unsigned char  ns;              /* Send sequence number */
	////variables from reader-dre.c
	unsigned char provider;
	////variables from reader-nagra.c
        IDEA_KEY_SCHEDULE ksSession;
 	int32_t is_pure_nagra;
 	int32_t is_tiger;
 	int32_t is_n3_na;
 	int32_t has_dt08;
 	int32_t swapCW;
        uint8_t ExpiryDate[2];
        uint8_t ActivationDate[2];
 	unsigned char rom[15];
 	unsigned char plainDT08RSA[64];
 	unsigned char IdeaCamKey[16];
 	unsigned char irdId[4];
 	unsigned char sessi[16];
 	unsigned char signature[8];
 	unsigned char cam_state[3];
	////variables from reader-irdeto.c
	int32_t acs57; // A flag for the ACS57 ITA DVB-T
	////variables from reader-cryptoworks.c
	BIGNUM exp;
	BIGNUM ucpk;
	////variables from reader-viaccess.c
	struct geo_cache last_geo;
	int32_t cc_reshare;
	int32_t lb_weight;     //loadbalance weight factor, if unset, weight=100. The higher the value, the higher the usage-possibility
	int32_t lb_usagelevel; //usagelevel for loadbalancer
	int32_t lb_usagelevel_ecmcount;
	time_t lb_usagelevel_time; //time for counting ecms, this creates usagelevel
	struct timeb lb_last; //time for oldest reader
	LLIST *lb_stat; //loadbalancer reader statistics
	// multi AES linked list
	AES_ENTRY *aes_list;
        // variables from reader-videoguard*
        int32_t ndsversion; // 0 auto (default), 1 NDS1, 12 NDS1+, 2 NDS2
        const char * card_desc;
        int32_t  card_baseyear;
        int32_t  card_tierstart;
        int32_t  card_system_version;
        struct s_CmdTab *cmd_table;
        uint16_t cardkeys[3][32];
        unsigned char stateD3A[16];
        AES_KEY       ekey;
        AES_KEY       astrokey;
	//ratelimit
	int32_t ratelimitecm;
	int32_t ratelimitseconds;
	struct ecmrl    rlecmh[MAXECMRATELIMIT];
	int32_t fix_9993;
	struct s_reader *next;
};

#ifdef CS_ANTICASC
struct s_cpmap
{
  uint16_t caid;
  uint32_t  provid;
  uint16_t sid;
  uint16_t chid;
  uint16_t dwtime;
  struct s_cpmap *next;
};
#endif

struct s_auth
{
  char     usr[64];
  char     pwd[64];
#ifdef WEBIF
  char     description[64];
#endif
  int32_t      uniq;
  LLIST    *aureader_list;
  int32_t      autoau;
  int32_t      monlvl;
  uint64_t   grp;
  int32_t      tosleep;
  CAIDTAB  ctab;
  SIDTABBITS   sidtabok;  // positiv services
  SIDTABBITS   sidtabno;  // negative services
  FTAB     fchid;
  FTAB     ftab;       // user [caid] and ident filter
  CLASSTAB cltab;
  TUNTAB   ttab;
#ifdef CS_ANTICASC
  int32_t		ac_users;   // 0 - unlimited
  uchar		ac_penalty; // 0 - log, >0 - fake dw
  struct s_acasc ac_stat;
#endif
  in_addr_t dynip;
  uchar     dyndns[64];
  time_t    expirationdate;
  time_t    firstlogin;
  int32_t		allowedtimeframe[2];
  int32_t       c35_suppresscmd08;
  int32_t       c35_sleepsend;
  int32_t       ncd_keepalive;
  int32_t       cccmaxhops;
  int32_t       cccreshare;
  int32_t       cccignorereshare;
  int32_t		cccstealth;
  int32_t       disabled;
  int32_t 		failban;
  
  int32_t		cwfound;
  int32_t		cwcache;
  int32_t		cwnot;
  int32_t		cwtun;
  int32_t 		cwignored;
  int32_t		cwtout;
  int32_t		emmok;
  int32_t		emmnok;
                                                                                                                             
  struct   s_auth *next;
};

struct s_srvid
{
  int32_t     srvid;
  int32_t     ncaid;
  int32_t     caid[10];
  char    *data;
  char    *prov;
  char    *name;
  char    *type;
  char    *desc;
  struct  s_srvid *next;
};

struct s_tierid
{
  int32_t     tierid;
  int32_t     ncaid;
  int32_t     caid[10];
  char    name[33];
  struct  s_tierid *next;
};

//Todo #ifdef CCCAM
struct s_provid
{
	int32_t		caid;
	uint32_t	provid;
	char	prov[33];
	char	sat[33];
	char	lang[33];
	struct	s_provid *next;
};

struct s_ip
{
  in_addr_t ip[2];
  struct s_ip *next;
};

struct s_config
{
	int32_t		nice;
	uint32_t		netprio;
	uint32_t		ctimeout;
	uint32_t		ftimeout;
	uint32_t		cmaxidle;
	int32_t		ulparent;
	uint32_t		delay;
	int32_t		bindwait;
	int32_t		tosleep;
	in_addr_t	srvip;
	char		*usrfile;
	char		*cwlogdir;
	char		*logfile;
	uint8_t	logtostdout;
	uint8_t logtosyslog;
	int32_t		disablelog;
	int32_t		disableuserfile;
	int32_t		usrfileflag;
	struct s_auth 	*account;
	struct s_srvid 	*srvid;
        struct s_tierid *tierid;
	//Todo #ifdef CCCAM
	struct s_provid *provid;
	struct s_sidtab *sidtab;
	int32_t		mon_port;
	in_addr_t	mon_srvip;
	struct s_ip 	*mon_allowed;
	int32_t		mon_aulow;
	int32_t		mon_hideclient_to;
	int32_t		mon_level;
	int32_t		mon_appendchaninfo;
#ifdef WEBIF
	int32_t			http_port;
	char		http_user[65];
	char		http_pwd[65];
	char		http_css[128];
	char		http_jscript[128];
	char		http_tpl[128];
	char		http_script[128];
	int32_t			http_refresh;
	int32_t			http_hide_idle_clients;
	struct s_ip *http_allowed;
	int32_t			http_readonly;
	in_addr_t	http_dynip;
	uchar		http_dyndns[64];
	int32_t			http_use_ssl;
	char		http_cert[128];
	char		http_help_lang[3];
	int			http_enhancedstatus_cccam;
#endif
	int32_t			http_full_cfg;
	int32_t			failbantime;
	int32_t			failbancount;
	LLIST 		*v_list; //failban list
	int32_t		c33_port;
	in_addr_t	c33_srvip;
	uchar		c33_key[16];
	int32_t		c33_crypted;
	int32_t		c33_passive;
	struct s_ip 	*c33_plain;
	int32_t		c35_port;
	in_addr_t	c35_srvip;
	int32_t		c35_suppresscmd08;
	int32_t		c35_tcp_suppresscmd08;
	int32_t		c35_udp_suppresscmd08;
	PTAB		c35_tcp_ptab;
	in_addr_t	c35_tcp_srvip;
	PTAB		ncd_ptab;
	in_addr_t	ncd_srvip;
	uchar		ncd_key[16];
	int32_t		ncd_keepalive;
	int32_t		ncd_mgclient;
	struct s_ip 	*ncd_allowed;
	PTAB		cc_ptab;
	int32_t		rad_port;
	in_addr_t	rad_srvip;
	int32_t		cc_port;
	int32_t		cc_reshare;
	int32_t		cc_ignore_reshare;
	int32_t		cc_update_interval;
	in_addr_t	cc_srvip;
	char		cc_version[7];
	int32_t             cc_minimize_cards;
	int32_t             cc_keep_connected;
	int32_t		cc_stealth;
	int32_t		cc_reshare_services;
	int32_t     cc_forward_origin_card;
	char	gbox_hostname[128];
	char	gbox_key[9];
	char	gbox_gsms_path[200];
	int32_t		gbox_port;
	struct s_ip *rad_allowed;
	char		rad_usr[32];
	char		ser_device[512];
	uint32_t		srtimeout;  // SerialReaderTimeount in millisec
	int32_t		max_log_size;
	int32_t		waitforcards;
	int32_t		waitforcards_extra_delay;
	int32_t		preferlocalcards;
	int32_t		saveinithistory;
	int32_t     reader_restart_seconds; //schlocke: reader restart auf x seconds, disable = 0
	int32_t		dropdups; //drop duplicate logins


//Loadbalancer-Config:
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
	
	int32_t             resolve_gethostbyname;

#ifdef CS_WITH_DOUBLECHECK
        int32_t             double_check; //schlocke: Double checks each ecm+dcw from two (or more) readers
#endif

#ifdef IRDETO_GUESSING
	struct s_irdeto_quess *itab[0xff];
#endif

#ifdef HAVE_DVBAPI
	int32_t		dvbapi_enabled;
	int32_t		dvbapi_au;
	char		dvbapi_usr[64];
	int32_t		dvbapi_boxtype;
	int32_t		dvbapi_pmtmode;
	int32_t		dvbapi_requestmode;
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
    int32_t disableqboxhdled; // disable qboxhd led , default = 0
#endif
};

struct s_clientinit
{
	void *(*handler)(struct s_client*);
	struct s_client * client;
};

//Loadbalance constants:
#define LB_NONE 0
#define LB_FASTEST_READER_FIRST 1
#define LB_OLDEST_READER_FIRST 2
#define LB_LOWEST_USAGELEVEL 3
#define LB_LOG_ONLY 10

#define LB_MAX_STAT_TIME 20

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

  int32_t           request_count;
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

//EMM types:
#define UNKNOWN 0
#define UNIQUE	1
#define SHARED	2
#define GLOBAL	3

// oscam-simples
extern char *remote_txt(void);
extern char *trim(char *);
extern char *strtolower(char *);
extern int32_t gethexval(char);
extern int32_t cs_atob(uchar *, char *, int);
extern uint32_t cs_atoi(char *, int, int);
extern int32_t byte_atob(char *);
extern int32_t word_atob(char *);
extern int32_t dyn_word_atob(char *asc);
extern int32_t key_atob_l(char *, uchar *, int);
extern char *key_btoa(char *, uchar *);
extern char *cs_hexdump(int, const uchar *, int);
extern in_addr_t cs_inet_order(in_addr_t);
extern char *cs_inet_ntoa(in_addr_t);
extern in_addr_t cs_inet_addr(char *txt);
extern uint32_t b2i(int, uchar *);
extern uint64_t b2ll(int, uchar *);
extern uchar *i2b(int, uint32_t);
extern uchar *i2b_cl(int32_t n, uint32_t i, struct s_client *cl);
extern uchar *i2b_buf(int32_t n, uint32_t i, uchar *b);
  
extern uint32_t a2i(char *, int);
extern int32_t boundary(int, int);
extern void cs_ftime(struct timeb *);
extern void cs_sleepms(uint32_t);
extern void cs_sleepus(uint32_t);
extern int32_t bytes_available(int);
extern void cs_setpriority(int);
extern struct s_auth *find_user(char *);
extern int32_t check_filled(uchar *value, int32_t length);
extern void *cs_malloc(void *result, size_t size, int32_t quiterror);
extern void *cs_realloc(void *result, size_t size, int32_t quiterror);
#ifdef WEBIF
extern char to_hex(char code);
extern void char_to_hex(const unsigned char* p_array, uint32_t p_array_len, unsigned char *result);
extern void create_rand_str(char *dst, int32_t size);
#endif
extern void uint64ToBitchar(uint64_t value, int32_t size, char *result);
extern int32_t file_exists(const char * filename);
extern void clear_sip(struct s_ip **sip);
extern void clear_ptab(struct s_ptab *ptab);
extern void clear_ftab(struct s_ftab *ftab);
void clear_caidtab(struct s_caidtab *ctab);
void clear_tuntab(struct s_tuntab *ttab);
extern int32_t file_copy(char *srcfile, char *destfile);
extern int32_t safe_overwrite_with_bak(char *destfile, char *tmpfile, char *bakfile, int32_t forceBakOverWrite);
extern void fprintf_conf(FILE *f, int32_t varnameWidth, const char *varname, const char *fmtstring, ...);
extern void cs_strncpy(char * destination, const char * source, size_t num);
extern char *get_servicename(int32_t srvid, int32_t caid);
extern char *get_tiername(int32_t tierid, int32_t caid);
extern char *get_provider(int32_t caid, uint32_t provid);
extern void make_non_blocking(int32_t fd);
extern uchar fast_rnd(void);
extern void init_rnd(void);
extern int32_t hexserialset(struct s_reader *rdr);
extern char *monitor_get_proto(struct s_client *);
extern char *reader_get_type_desc(struct s_reader * rdr, int32_t extended);
extern char *get_ncd_client_name(char *client_id);
extern char *strnew(char *str);
extern void hexserial_to_newcamd(uchar *source, uchar *dest, uint16_t caid);
extern void newcamd_to_hexserial(uchar *source, uchar *dest, uint16_t caid);
extern int32_t check_ip(struct s_ip *ip, in_addr_t n);

extern pthread_key_t getclient;
extern struct s_client * cur_client(void);
extern struct s_client *first_client;
extern struct s_reader *first_active_reader; //points to list of _active_ readers (enable = 1, deleted = 0)
extern LLIST *configured_readers;

// oscam variables

extern int32_t cs_dblevel, loghistidx;

extern uint16_t len4caid[256];

extern struct card_struct *Cards;
//extern struct idstore_struct *idstore;
extern uint32_t *IgnoreList;

extern struct s_config cfg;
extern char cs_confdir[];
extern char loghist[CS_MAXLOGHIST*CS_LOGHISTSIZE];
extern struct s_module ph[CS_MAX_MOD];
extern struct s_cardsystem cardsystem[CS_MAX_MOD];
extern struct s_cardreader cardreader[CS_MAX_MOD];
//extern ECM_REQUEST *ecmtask;

#ifdef CS_ANTICASC
extern FILE *fpa;
#endif
extern pthread_mutex_t gethostbyname_lock;

// oscam
#ifdef WEBIF
extern void cs_exit_oscam();
extern void cs_restart_oscam();
extern int32_t cs_get_restartmode();
extern void start_thread(void * startroutine, char * nameroutine);

//reset stats for webif:
extern void clear_account_stats(struct s_auth *account);
extern void clear_all_account_stats();
extern void clear_system_stats();
                              
#endif
extern void cs_reload_config();
extern int32_t recv_from_udpipe(uchar *);
extern char* username(struct s_client *);
extern struct s_client * get_client_by_tid(uint32_t);
extern int32_t chk_bcaid(ECM_REQUEST *, CAIDTAB *);
extern void cs_exit(int32_t sig);
extern int32_t comp_timeb(struct timeb *tpa, struct timeb *tpb);
extern struct s_client * create_client(in_addr_t);
extern int32_t cs_auth_client(struct s_client *, struct s_auth *, const char*);
extern void cs_disconnect_client(struct s_client *);
extern int32_t check_cwcache2(ECM_REQUEST *, uint64_t grp);
extern int32_t write_to_pipe(int, int, uchar *, int);
extern int32_t read_from_pipe(int, uchar **, int);
extern int32_t write_ecm_answer(struct s_reader *, ECM_REQUEST *);
extern void log_emm_request(struct s_reader *);
extern uint32_t chk_provid(uchar *, uint16_t);
#ifdef IRDETO_GUESSING
extern void guess_irdeto(ECM_REQUEST *);
#endif
extern void get_cw(struct s_client *, ECM_REQUEST *);
extern void do_emm(struct s_client *, EMM_PACKET *);
extern ECM_REQUEST *get_ecmtask(void);
extern void request_cw(ECM_REQUEST *, int, int);
extern int32_t send_dcw(struct s_client *, ECM_REQUEST *);
extern int32_t process_input(uchar *, int, int);
extern int32_t has_srvid(struct s_client *cl, ECM_REQUEST *er);
extern int32_t chk_srvid(struct s_client *, ECM_REQUEST *);
extern int32_t chk_srvid_match(ECM_REQUEST *, SIDTAB *);
extern int32_t chk_sfilter(ECM_REQUEST *, PTAB*);
extern int32_t chk_ufilters(ECM_REQUEST *);
extern int32_t chk_rsfilter(struct s_reader * reader, ECM_REQUEST *);
extern int32_t matching_reader(ECM_REQUEST *, struct s_reader *);
extern int32_t emm_reader_match(struct s_reader *reader, uint16_t caid, uint32_t provid);
extern void set_signal_handler(int32_t , int32_t , void (*));
extern void cs_log_config(void);
extern void cs_waitforcardinit(void);
extern void cs_reinit_clients(struct s_auth *new_accounts);
extern int32_t process_client_pipe(struct s_client *cl, uchar *buf, int32_t l);
extern void update_reader_config(uchar *ptr);
extern int32_t chk_ctab(uint16_t caid, CAIDTAB *ctab);
extern int32_t chk_srvid_by_caid_prov(struct s_client *, uint16_t caid, uint32_t provid);
extern void nullclose(int32_t *fd);
extern void *clientthread_init(void * init);
extern void cleanup_thread(void *var);
extern void kill_thread(struct s_client *cl);
extern int32_t get_threadnum(struct s_client *client);
extern void cs_add_violation(uint32_t ip);

extern void cs_card_info(void);
extern void cs_debug_level(void);

#ifdef CS_ANTICASC
extern void init_ac(void);
extern void ac_init_stat();
extern void ac_clear();
extern void ac_done_stat();
extern int32_t  ac_init_log();
extern void ac_do_stat(void);
extern void ac_init_client(struct s_client *, struct s_auth *);
extern void ac_chk(struct s_client *,ECM_REQUEST*, int);
#endif

// oscam-config
extern int32_t  init_config(void);
extern int32_t  init_free_userdb(struct s_auth *auth);
extern struct s_auth *init_userdb();
extern int32_t  init_readerdb(void);
extern int32_t  init_sidtab(void);
extern void free_sidtab(struct s_sidtab *sidtab);
extern void init_free_sidtab();
extern int32_t  init_srvid(void);
extern int32_t  init_tierid(void);
extern int32_t  search_boxkey(uint16_t, char *);
extern void init_len4caid(void);
#ifdef IRDETO_GUESSING
extern int32_t  init_irdeto_guess_tab(void);
#endif
extern void chk_caidtab(char *caidasc, CAIDTAB *ctab);
extern void chk_tuntab(char *tunasc, TUNTAB *ttab);
extern void chk_services(char *labels, SIDTABBITS *sidok, SIDTABBITS *sidno);
extern void chk_ftab(char *zFilterAsc, FTAB *ftab, const char *zType, const char *zName, const char *zFiltName);
extern void chk_cltab(char *classasc, CLASSTAB *clstab);
extern void chk_iprange(char *value, struct s_ip **base);
extern void chk_port_tab(char *portasc, PTAB *ptab);
#ifdef CS_ANTICASC
extern void chk_t_ac(char *token, char *value);
#endif
extern void chk_t_camd33(char *token, char *value);
extern void chk_t_camd35(char *token, char *value);
extern void chk_t_camd35_tcp(char *token, char *value);
extern void chk_t_newcamd(char *token, char *value);
extern void chk_t_radegast(char *token, char *value);
extern void chk_t_serial(char *token, char *value);
extern void chk_t_gbox(char *token, char *value);
extern void chk_t_cccam(char *token, char *value);
extern void chk_t_global(const char *token, char *value);
extern void chk_t_monitor(char *token, char *value);
extern void chk_reader(char *token, char *value, struct s_reader *rdr);

#ifdef HAVE_DVBAPI
extern void chk_t_dvbapi(char *token, char *value);
void dvbapi_chk_caidtab(char *caidasc, char type);
void dvbapi_read_priority();
#endif

#ifdef WEBIF
extern void chk_t_webif(char *token, char *value);
#endif

extern void cs_accounts_chk(void);
extern void chk_account(const char *token, char *value, struct s_auth *account);
extern void chk_sidtab(char *token, char *value, struct s_sidtab *sidtab);
extern int32_t write_services();
extern int32_t write_userdb(struct s_auth *authptr);
extern int32_t write_config();
extern int32_t write_server();
extern void write_versionfile();
extern char *mk_t_caidtab(CAIDTAB *ctab);
extern char *mk_t_caidvaluetab(CAIDVALUETAB *tab);
extern char *mk_t_tuntab(TUNTAB *ttab);
extern char *mk_t_group(uint64_t grp);
extern char *mk_t_ftab(FTAB *ftab);
extern char *mk_t_camd35tcp_port();
extern char *mk_t_aeskeys(struct s_reader *rdr);
extern char *mk_t_newcamd_port();
extern char *mk_t_aureader(struct s_auth *account);
extern char *mk_t_nano(struct s_reader *rdr, uchar flag);
extern char *mk_t_service( uint64_t sidtabok, uint64_t sidtabno);
extern char *mk_t_logfile();
extern char *mk_t_iprange(struct s_ip *range);
extern void free_mk_t(char *value);

//Todo #ifdef CCCAM
extern int32_t init_provid();
extern char * get_tmp_dir();
extern void init_share();
extern void done_share();

// oscam-reader
extern int32_t logfd;
extern int32_t reader_cmd2icc(struct s_reader * reader, const uchar *buf, const int32_t l, uchar *response, uint16_t *response_length);
extern int32_t card_write(struct s_reader * reader, const uchar *, const uchar *, uchar *, uint16_t *);
extern int32_t check_sct_len(const unsigned char *data, int32_t off);
extern void cs_ri_brk(struct s_reader * reader, int);
extern void cs_ri_log(struct s_reader * reader, char *,...);
extern void * start_cardreader(void *);
extern void reader_card_info(struct s_reader * reader);
extern int32_t hostResolve(struct s_reader * reader);
extern int32_t network_tcp_connection_open();
extern void network_tcp_connection_close(struct s_client *, int);
extern int32_t casc_recv_timer(struct s_reader * reader, uchar *buf, int32_t l, int32_t msec);
extern void clear_reader_pipe(struct s_reader * reader);
extern void block_connect(struct s_reader *rdr);
extern int32_t is_connect_blocked(struct s_reader *rdr);
            
// oscam-log
extern int32_t  cs_init_log();
extern int32_t cs_open_logfiles();
extern void cs_write_log(char *);
extern void cs_log(const char *,...);
#ifdef WITH_DEBUG
extern void cs_debug_mask(uint16_t, const char *,...);
extern void cs_ddump_mask(uint16_t, const uchar *, int, char *, ...);
#else
#define nop() asm volatile("nop")
#define cs_debug(...) nop()
#define cs_debug_mask(...) nop()
#define cs_ddump(...) nop()
#define cs_ddump_mask(...) nop()
#endif
extern void cs_close_log(void);
extern int32_t  cs_init_statistics();
extern void cs_dump(const uchar *, int, char *, ...);

// oscam-aes
extern void aes_set_key(char *);
extern void add_aes_entry(struct s_reader *rdr, uint16_t caid, uint32_t ident, int32_t keyid, uchar *aesKey);
extern void aes_encrypt_idx(struct s_client *, uchar *, int);
extern void aes_decrypt(uchar *, int);
extern int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid,int32_t keyid, uchar *buf, int32_t n);
extern int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid,int32_t keyid);
extern void parse_aes_keys(struct s_reader *rdr,char *value);
extern void aes_clear_entries(struct s_reader *rdr);

#define aes_encrypt(b, n) aes_encrypt_idx(cur_client(), b, n)

// reader-common
extern int32_t reader_device_init(struct s_reader * reader);
extern int32_t reader_checkhealth(struct s_reader * reader);
extern void reader_post_process(struct s_reader * reader);
extern int32_t reader_ecm(struct s_reader * reader, ECM_REQUEST *);
extern int32_t reader_emm(struct s_reader * reader, EMM_PACKET *);
int32_t reader_get_emm_type(EMM_PACKET *ep, struct s_reader * reader);
struct s_cardsystem *get_cardsystem_by_caid(uint16_t caid);
extern void reader_device_close(struct s_reader * reader);

//module-stat
extern void init_stat();
extern int32_t get_best_reader(ECM_REQUEST *er);
extern void clear_reader_stat(struct s_reader *reader);
extern void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int32_t ecm_time, int32_t rc);
extern void load_stat_from_file();
extern void save_stat_to_file(int);
extern void clear_all_stat();
extern void housekeeping_stat(int32_t force);

#ifdef HAVE_PCSC
// reader-pcsc
extern void pcsc_close(struct s_reader *pcsc_reader);
#endif

void reader_nagra();
void reader_irdeto();
void reader_cryptoworks();
void reader_viaccess();
void reader_conax();
void reader_seca();
void reader_videoguard1();
void reader_videoguard2();
void reader_videoguard12();
void reader_dre();
void reader_tongfang();

void cardreader_mouse(struct s_cardreader *crdr);
void cardreader_smargo(struct s_cardreader *crdr);
#ifdef WITH_STAPI
void cardreader_stapi(struct s_cardreader *crdr);
#endif

// protocol modules
extern int32_t  monitor_send_idx(struct s_client *, char *);
extern void module_monitor(struct s_module *);
extern void module_camd35(struct s_module *);
extern void module_camd35_tcp(struct s_module *);
extern void module_camd33(struct s_module *);
extern void module_newcamd(struct s_module *);
extern void module_radegast(struct s_module *);
extern void module_oscam_ser(struct s_module *);
extern void module_cccam(struct s_module *);
extern void module_gbox(struct s_module *);
extern void module_constcw(struct s_module *);
extern struct timeval *chk_pending(struct timeb tp_ctimeout);
#ifdef HAVE_DVBAPI
extern void module_dvbapi(struct s_module *);
#endif

#ifdef WEBIF
// oscam-http
extern void http_srv();
#endif

// oscam-garbage
#ifdef WITH_DEBUG
extern void add_garbage_debug(void *data, char *file, int32_t line);
#define add_garbage(x)	add_garbage_debug(x,__FILE__, __LINE__)
#else
extern void add_garbage(void *data);
#endif
extern void start_garbage_collector(int);
extern void stop_garbage_collector();

#endif  // CS_GLOBALS
