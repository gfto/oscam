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

#ifndef CS_GLOBALS
#define CS_GLOBALS
#define CS_VERSION    "1.00-unstable_svn"
#ifndef CS_SVN_VERSION
#	define CS_SVN_VERSION "test"
#endif

#if defined(__GNUC__)  && !defined(__arm__)
#  define GCC_PACK __attribute__((packed))
#else
#  define GCC_PACK
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

#ifdef CS_WITH_GBOX
#define CS_MAXCARDS       4096
#define CS_MAXIGNORE      1024
#define CS_MAXLOCALS      16
#endif

#define CS_ECMSTORESIZE   16  // use MD5()
#define CS_EMMSTORESIZE   16  // use MD5()
#define CS_CLIENT_TIMEOUT 5000
#define CS_CLIENT_MAXIDLE 120
#define CS_BIND_TIMEOUT   120
#define CS_DELAY          0
#define CS_MAXLOGHIST     30
#define CS_LOGHISTSIZE    193 // 32+128+33: username + logline + channelname
#define CS_MAXREADERCAID  16

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
#ifdef CS_WITH_GBOX
#define R_GBOX      0x30  // Reader cascading gbox
#endif
#define R_CCCAM     0x35  // Reader cascading cccam
#define R_SERIAL    0x80  // Reader serial
#define R_IS_NETWORK    0x60
#define R_IS_CASCADING  0xE0

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

enum {E1_GLOBAL=0, E1_USER, E1_READER, E1_SERVER, E1_LSERVER};
enum {E2_GLOBAL=0, E2_GROUP, E2_CAID, E2_IDENT, E2_CLASS, E2_CHID, E2_QUEUE,
      E2_EA_LEN, E2_F0_LEN, E2_OFFLINE, E2_SID};

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;
typedef long long int64;

int server_pid; //alno: PID of server - set while startup

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
extern void cs_switch_led(int led, int action);
#endif

#ifdef QBOXHD_LED
typedef struct {
	unsigned short H;  // range 0-359
	unsigned char S;   // range 0-99
	unsigned char V;   // range 0-99
} qboxhd_led_color_struct;
typedef struct {
	unsigned char red;  // first 5 bit used (&0x1F)
	unsigned char green; // first 5 bit used (&0x1F)
	unsigned char blue; // first 5 bit used (&0x1F)
} qboxhdmini_led_color_struct;

extern void qboxhd_led_blink(int color, int duration);

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
#define SIDTABBITS uint64      // 64bit type for services, if a system does not support this type,
                               // please use a define and define it as uint32 / MAX_SIDBITS 32

#define BAN_UNKNOWN 1			//failban mask for anonymous/ unknown contact
#define BAN_DISABLED 2			//failban mask for disabled user
#define BAN_SLEEPING 4			//failban mask for sleeping user
#define BAN_DUPLICATE 8			//failban mask for duplicate user

//checking if (X) free(X) unneccessary since freeing a null pointer doesnt do anything
#define NULLFREE(X) {if (X) {void *tmpX=X; X=NULL; free(tmpX); }}

typedef struct s_classtab
{
  uchar an;
  uchar bn;
  uchar aclass[31];
  uchar bclass[31];
} GCC_PACK CLASSTAB;

typedef struct s_caidtab
{
  ushort caid[CS_MAXCAIDTAB];
  ushort mask[CS_MAXCAIDTAB];
  ushort cmap[CS_MAXCAIDTAB];
} GCC_PACK CAIDTAB;

typedef struct s_tuntab
{
  ushort bt_caidfrom[CS_MAXTUNTAB];
  ushort bt_caidto[CS_MAXTUNTAB];
  ushort bt_srvid[CS_MAXTUNTAB];
} GCC_PACK TUNTAB;

typedef struct s_sidtab
{
  char     label[64];
  ushort   num_caid;
  ushort   num_provid;
  ushort   num_srvid;
  ushort   *caid;
  ulong    *provid;
  ushort   *srvid;
  struct   s_sidtab *next;
} GCC_PACK SIDTAB;


typedef struct s_filter
{
  ushort caid;
  uchar  nprids;
  ulong  prids[CS_MAXPROV];
} GCC_PACK FILTER;

typedef struct s_ftab
{
  int    nfilts;
  FILTER filts[CS_MAXFILTERS];
} GCC_PACK FTAB;

typedef struct s_port
{
  int    fd;
  int    s_port;
  int    ncd_key_is_set;    //0 or 1
  uchar  ncd_key[16];
  FTAB   ftab;
} GCC_PACK PORT;

typedef struct s_ptab
{
  int    nports;
  PORT   ports[CS_MAXPORTS];
} GCC_PACK PTAB;

typedef struct aes_entry {
    ushort      keyid;
    ushort      caid;
    uint32      ident;
    uchar		plainkey[16];
    AES_KEY     key;
    struct aes_entry   *next;
} AES_ENTRY;

struct s_ecm
{
  uchar  	ecmd5[CS_ECMSTORESIZE];
  uchar  	cw[16];
  ushort 	caid;
  uint64  	grp;
  struct s_reader *reader;
  struct s_ecm *next;
  //int level;
};

struct s_emm
{
  uchar emmd5[CS_EMMSTORESIZE];
  uchar type;
  int   count;
};

// failban listmember
typedef struct v_ban {
	int v_count;
	uint v_ip;
	time_t v_time;
} GCC_PACK V_BAN;

#define AVAIL_CHECK_CONNECTED 0
#define AVAIL_CHECK_LOADBALANCE 1

struct s_client ;
struct ecm_request_t ;
struct emm_packet_t ;

struct s_module
{
  //int  fd;
  int  multi;
  int  type;
  int  watchdog;
  char desc[16];
  char *logtxt;
  //int  s_port;
  in_addr_t s_ip;
  void *(*s_handler)();
  int  (*recv)(struct s_client *, uchar *, int);
  void (*send_dcw)(struct s_client*, struct ecm_request_t *);
  void (*cleanup)(struct s_client*);
  int  c_multi;
  int  (*c_recv_chk)(struct s_client*, uchar *, int *, uchar *, int);
  int  (*c_init)(struct s_client*);
  int  (*c_send_ecm)(struct s_client *, struct ecm_request_t *, uchar *);
  int  (*c_send_emm)(struct emm_packet_t *);
  int  (*c_init_log)(void);
  int  (*c_recv_log)(ushort *, ulong *, ushort *);
  int  (*c_available)(struct s_reader *, int); 	//Schlocke: available check for load-balancing,
                         //params:
                         //rdr (reader to check)
                         //int checktype (0=return connected, 1=return loadbalance-avail) return int
  void (*c_idle)(void);      //Schlocke: called when reader is idle
  void (*c_card_info)(void); //Schlocke: request card infos
  int  c_port;
  PTAB *ptab;
  int num;
};

struct s_ATR ;

struct s_cardreader
{
	int	active;
	char	desc[16];
	int	(*reader_init)(struct s_reader*);
	int	(*get_status)(struct s_reader*, int*);
	int	(*activate)(struct s_reader*, struct s_ATR *);
	int	(*transmit)(struct s_reader*, unsigned char *sent, unsigned int size);
	int	(*receive)(struct s_reader*, unsigned char *data, unsigned int size);
	int	(*close)(struct s_reader*);
	int	(*set_parity)(struct s_reader*, uchar parity);
	int	(*write_settings)(struct s_reader*, unsigned long ETU, unsigned long EGT, unsigned char P, unsigned char I);
	int	(*set_protocol)(struct s_reader*, unsigned char * params, unsigned *length, uint len_request);
	int	(*set_baudrate)(struct s_reader*, ulong baud); //set only for readers which need baudrate setting and timings need to be guarded by OSCam
	int	flush;
};

struct s_cardsystem
{
	char *desc;
	int  (*card_init)();
	int  (*card_info)();
	int  (*do_ecm)();
	int  (*do_emm)();
	void (*post_process)();
	int  (*get_emm_type)();
	void (*get_emm_filter)();
	uchar caids[2];
};

#ifdef IRDETO_GUESSING
struct s_irdeto_quess
{
  int    b47;
  ushort caid;
  ushort sid;
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
  short         l;
  ushort        caid;
  ushort        ocaid;
  ushort        srvid;
  ushort        chid;
  ushort        pid;
  ushort        idx;
  ulong         prid;
  struct s_reader *selected_reader;
  int           rdr_count;
  uint8         *matching_rdr;
  LLIST         *matching_rdr2; //list of matching readers, should replace *matching_rdr
  LLIST         *matching_rdr2_fallback; //list of matching fallback readers; can be possible replaced by a pointer into the matching_rdr list, from which point on the readers will all be fallback
  struct s_client *client; //contains pointer to 'c' client while running in 'r' client
  int           cpti;   // client pending table index
  int           stage;    // processing stage in server module
  int           level;    // send-level in client module
  int           rc;
  uchar         rcEx;
  struct timeb  tps;    // incoming time stamp
  uchar         locals_done;
  int		btun; // mark er as betatunneled
  int		reader_avail; //count of available readers
  int           reader_count; //count of contacted readers

#ifdef CS_WITH_DOUBLECHECK
  int		checked;
  uchar		cw_checked[16];
  struct s_reader *origin_reader;
#endif

#ifdef CS_WITH_GBOX
  ushort	gbxCWFrom;
  ushort	gbxFrom;
  ushort	gbxTo;
  uchar		gbxForward[16];
  int		gbxRidx;
#endif
  char msglog[MSGLOGSIZE];

} GCC_PACK      ECM_REQUEST;

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
  int		allowedtimeframe[2];
  int		c35_suppresscmd08;
  int		c35_sleepsend;
  int		ncd_keepalive;
  int		disabled;
  uint64	grp;
  int		crypted;
  int		dup;
  struct s_reader *aureader; //the reader that needs EMMs from this client
  int		autoau;
  int		monlvl;
  CAIDTAB	ctab;
  TUNTAB	ttab;
  SIDTABBITS	sidtabok; // positiv services
  SIDTABBITS	sidtabno; // negative services
  int		typ;        // first s_client is type s=starting (master) thread; type r = physical reader, type p = proxy reader both always have 1 s_reader struct allocated; type c = client (user logging in into oscam) type m = monitor type h = http server a = anticascader
  int		ctyp;
  int		stat;
  int		last_srvid;
  int		last_caid;
  int		tosleep;
  struct s_auth *account;
  int		udp_fd;
  int		fd_m2c; //master writes to this fd
  int		fd_m2c_c; //client reads from this fd
  struct	sockaddr_in udp_sa;
  int		log;
  int		logcounter;
  int		cwfound;     // count found ECMs per client
  int		cwcache;     // count ECMs from cache1/2 per client
  int		cwnot;       // count not found ECMs per client
  int		cwtun;       // count betatunneled ECMs per client
  int		cwignored;   // count ignored  ECMs per client
  int		cwtout;      // count timeouted ECMs per client
  int		cwlastresptime; //last Responsetime (ms)
  int		emmok;       // count EMM ok
  int		emmnok;	     // count EMM nok
#ifdef WEBIF
  int		wihidden;	// hidden in webinterface status
  char      lastreader[64]; // last cw got from this reader
#endif
  uchar		ucrc[4];    // needed by monitor and used by camd35
  ulong		pcrc;        // pwd crc
  AES_KEY	aeskey;      // encryption key needed by monitor and used by camd33, camd35
  AES_KEY	aeskey_decrypt;      // decryption key needed by monitor and used by camd33, camd35
  ushort	ncd_msgid;
  char 		ncd_client_id[5];
  uchar		ncd_skey[16];
  void		*cc;
  int		port_idx;    // index in server ptab
  int		ncd_server;  // newcamd server
#ifdef CS_ANTICASC
  ushort	ac_idx;
  ushort	ac_limit;
  uchar		ac_penalty;
#endif
  FTAB		fchid;
  FTAB		ftab;        // user [caid] and ident filter
  CLASSTAB	cltab;


  int pfd;      // Primary FD, must be closed on exit
  struct s_reader *reader; //points to s_reader when cl->typ='r'

  ECM_REQUEST *ecmtask;
  struct s_emm *emmcache;

  pthread_t thread;
  
  struct s_serial_client *serialdata;

  //reader common
  int last_idx;
  ushort idx;
  int rotate;

  uchar	*req;

  //camd33
  uchar	camdbug[256];

  int       ncd_proto;

  //camd35
  uchar upwd[64];
  int is_udp;
  int stopped;
  int lastcaid;
  int lastsrvid;
  int lastpid;
  time_t emm_last;
  int disable_counter;
  uchar lastserial[8];

  //cccam
  int g_flag;
  int cc_use_rc4;

  //monitor
  int auth;

  //cs_hexdump buffer
  uchar dump[520];

  //oscam.c
  struct timeval tv;

  //failban value set bitwise - compared with BAN_
  int failban;
  struct s_client *next; //make client a linked list
};


//for viaccess var in s_reader:
struct geo_cache
{
	ulong provid;
	uchar geo[256];
	uchar geo_len;
	int number_ecm;
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
	ushort        srvid;
	time_t	last;
};
#define MAXECMRATELIMIT	20

struct s_reader  //contains device info, reader info and card info
{
  ulong		auprovid; // AU only for this provid
  int		audisabled; // exclude reader from auto AU
  int 		deleted; // if this flag is set the reader is not shown in webif and becomes not writte to oscam.server
  int		smargopatch;
  struct s_client * client; //pointer to 'r'client this reader is running in
  int       enable;
  int       available; //Schlocke: New flag for loadbalancing. Only reader if reader supports ph.c_available function
  int       fd_error;
  int       fd;
  uint64    grp;
  int       fallback;
  int       typ;
  int       card_system;
  char      label[64];
  char      device[128];
  ushort    slot;   //in case of multiple slots like sc8in1; first slot = 1
  int       handle;   //device handle
  int       fdmc;     //device handle for multicam
#ifdef WITH_STAPI
  unsigned int stsmart_handle; //device handle for stsmart driver
#endif
  char      pcsc_name[128];
  int       pcsc_has_card;
  int       detect;
  int       mhz;      //actual clock rate of reader in 10khz steps
  int	    cardmhz;	    //standard clock speed your card should have in 10khz steps; normally 357 but for Irdeto cards 600
  int       r_port;
  char      r_usr[64];
  char      r_pwd[64];
  int       r_crypted;
  int       l_port;
  int       log_port;
  CAIDTAB   ctab;
  ulong     boxid;
  int       nagra_read; // read nagra ncmed records: 0 disabled (default), 1 read all records, 2 read valid records only
  uchar	    nagra_boxkey[16]; //n3 boxkey 8byte  or tiger idea key 16byte
  char      country_code[3]; // irdeto country code.
  int       force_irdeto;
  uchar     rsa_mod[120]; //rsa modulus for nagra cards.
  uchar     atr[64];
  int		atrlen;
  SIDTABBITS    sidtabok;	// positiv services
  SIDTABBITS    sidtabno;	// negative services
  uchar     hexserial[8];
  int       nprov;
  uchar     prid[CS_MAXPROV][8];
  uchar     availkeys[CS_MAXPROV][16];  // viaccess; misused in seca, if availkeys[PROV][0]=0 then expired, 1 then valid.
  uchar     sa[CS_MAXPROV][4];    // viaccess & seca
  ushort    acs;    // irdeto
  ushort    caid[CS_MAXREADERCAID];
  uchar     b_nano[256];
  int       blockemm_unknown; //block EMMs that have unknown type
  int       blockemm_u;				//blcok Unique EMMs
  int       blockemm_s;				//block Shared EMMS
  int       blockemm_g;				//block Global EMMs
  char      * emmfile;
  char      pincode[5];
  int		ucpk_valid;
  int       logemm;
  int       cachemm;
  int       rewritemm;
  int       card_status;
  int       deprecated; //if 0 ATR obeyed, if 1 default speed (9600) is chosen; for devices that cannot switch baudrate
  struct    s_module ph;
  struct    s_cardreader crdr;
  uchar     ncd_key[16];
  uchar     ncd_skey[16];
  int       ncd_disable_server_filt;
  ushort    ncd_msgid;
  int       ncd_proto;
  char      cc_version[7];  // cccam version
  char      cc_build[7];    // cccam build number
  int       cc_maxhop;      // cccam max distance
  int       cc_currenthops; // number of hops for CCCam
  int       cc_want_emu; //Schlocke: Client want to have EMUs, 0 - NO; 1 - YES
  uint32    cc_id;
  int       cc_keepalive;
  uchar     tcp_connected;
  int       tcp_ito;      // inactivity timeout
  int       tcp_rto;      // reconnect timeout
  struct timeb	tcp_block_connect_till; //time tcp connect ist blocked
  int       tcp_block_delay; //incrementing block time
  time_t    last_g;       // get (if last_s-last_g>tcp_rto - reconnect )
  time_t    last_s;       // send
  uchar     show_cls;     // number of classes subscription showed on kill -31
  FTAB      fchid;
  FTAB      ftab;
  CLASSTAB  cltab;
#ifdef CS_WITH_GBOX
  uchar     gbox_pwd[4];
  uchar     gbox_timecode[7];
  int       gbox_online;
  uchar     gbox_vers;
  uchar     gbox_prem;
  int       gbox_fd;
  struct timeb  gbox_lasthello;   // incoming time stamp
#endif

  int       init_history_pos;
  int       brk_pos;
  int       msg_idx;
#ifdef WEBIF
  int		emmwritten[4]; //count written EMM
  int		emmskipped[4]; //count skipped EMM
  int		emmerror[4];	//count error EMM
  int		emmblocked[4];	//count blocked EMM
  int		lbvalue;		//loadbalance Value
#endif
#ifdef HAVE_PCSC
  SCARDCONTEXT hContext;
  SCARDHANDLE hCard;
  DWORD dwActiveProtocol;
#endif
#ifdef LIBUSB
  uint8_t  device_endpoint; // usb endpoint for Infinity USB Smart in smartreader mode.
  struct s_sr_config *sr_config;
#endif
#ifdef AZBOX
  int mode;
#endif
	////variables from icc_async.h start
	int convention; //Convention of this ICC
	unsigned char protocol_type; // Type of protocol
	unsigned short BWT,CWT; // (for overclocking uncorrected) block waiting time, character waiting time, in ETU
	unsigned long current_baudrate; // (for overclocking uncorrected) baudrate to prevent unnecessary conversions from/to termios structure
	unsigned int read_timeout; // Max timeout (ms) to receive characters
	unsigned int block_delay; // Delay (ms) after starting to transmit
	unsigned int char_delay; // Delay (ms) after transmiting each sucesive char
	////variables from io_serial.h
	int written; //keep score of how much bytes are written to serial port, since they are echoed back they have to be read
	////variables from protocol_t1.h
	unsigned short ifsc;  /* Information field size for the ICC */
	unsigned char  ns;              /* Send sequence number */
	////variables from reader-dre.c
	unsigned char provider;
	////variables from reader-nagra.c
        IDEA_KEY_SCHEDULE ksSession;
 	int is_pure_nagra;
 	int is_tiger;
 	int is_n3_na;
 	int has_dt08;
 	int swapCW;
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
	int acs57; // A flag for the ACS57 ITA DVB-T
	////variables from reader-cryptoworks.c
	BIGNUM exp;
	BIGNUM ucpk;
	////variables from reader-viaccess.c
	struct geo_cache last_geo;
	int cc_reshare;
	int lb_weight;     //loadbalance weight factor, if unset, weight=100. The higher the value, the higher the usage-possibility
	int lb_usagelevel; //usagelevel for loadbalancer
	int lb_usagelevel_ecmcount;
	time_t lb_usagelevel_time; //time for counting ecms, this creates usagelevel
	struct timeb lb_last; //time for oldest reader
	LLIST *lb_stat; //loadbalancer reader statistics
	// multi AES linked list
	AES_ENTRY *aes_list;
        // variables from reader-videoguard*
        int ndsversion; // 0 auto (default), 1 NDS1, 12 NDS1+, 2 NDS2
        const char * card_desc;
        int  card_baseyear;
        int  card_tierstart;
        int  card_system_version;
        struct s_CmdTab *cmd_table;
        unsigned short cardkeys[3][32];
        unsigned char stateD3A[16];
        AES_KEY       ekey;
        AES_KEY       astrokey;
	//ratelimit
	int ratelimitecm;
	int ratelimitseconds;
	struct ecmrl    rlecmh[MAXECMRATELIMIT];
	struct s_reader *next;
};

#ifdef CS_ANTICASC

struct s_acasc_shm {
  ushort ac_count : 15;
  ushort ac_deny  : 1;
};

struct s_acasc {
  ushort stat[10];
  uchar  idx;    // current active index in stat[]
};

struct s_cpmap
{
  ushort caid;
  ulong  provid;
  ushort sid;
  ushort chid;
  ushort dwtime;
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
  int      uniq;
  struct s_reader *aureader;
  int      autoau;
  int      monlvl;
  uint64   grp;
  int      tosleep;
  CAIDTAB  ctab;
  SIDTABBITS   sidtabok;  // positiv services
  SIDTABBITS   sidtabno;  // negative services
  FTAB     fchid;
  FTAB     ftab;       // user [caid] and ident filter
  CLASSTAB cltab;
  TUNTAB   ttab;
#ifdef CS_ANTICASC
  int      ac_idx;
  int      ac_users;   // 0 - unlimited
  uchar    ac_penalty; // 0 - log, >0 - fake dw
#endif
  in_addr_t dynip;
  uchar     dyndns[64];
  time_t    expirationdate;
  int		allowedtimeframe[2];
  int       c35_suppresscmd08;
  int       c35_sleepsend;
  int       ncd_keepalive;
  int       cccmaxhops;
  int       cccreshare;
  int       disabled;
  int 		failban;
  
  int		cwfound;
  int		cwcache;
  int		cwnot;
  int		cwtun;
  int 		cwignored;
  int		cwtout;
  int		emmok;
  int		emmnok;
                                                                                                                             
  struct   s_auth *next;
};

struct s_srvid
{
  int     srvid;
  int     ncaid;
  int     caid[10];
  char    prov[33];
  char    name[33];
  char    type[33];
  char    desc[33];
  struct  s_srvid *next;
};

struct s_tierid
{
  int     tierid;
  int     ncaid;
  int     caid[10];
  char    name[33];
  struct  s_tierid *next;
};

//Todo #ifdef CCCAM
struct s_provid
{
	int		caid;
	ulong	provid;
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
	int		nice;
	ulong		netprio;
	ulong		ctimeout;
	ulong		ftimeout;
	ulong		cmaxidle;
	int		ulparent;
	ulong		delay;
	int		bindwait;
	int		tosleep;
	in_addr_t	srvip;
	char		*usrfile;
	char		*cwlogdir;
	char		*logfile;
	uint8	logtostdout;
	uint8 logtosyslog;
	int		disablelog;
	int		disableuserfile;
	int		usrfileflag;
	struct s_auth 	*account;
	struct s_srvid 	*srvid;
        struct s_tierid *tierid;
	//Todo #ifdef CCCAM
	struct s_provid *provid;
	struct s_sidtab *sidtab;
	int		mon_port;
	in_addr_t	mon_srvip;
	struct s_ip 	*mon_allowed;
	int		mon_aulow;
	int		mon_hideclient_to;
	int		mon_level;
	int		mon_appendchaninfo;
#ifdef WEBIF
	int			http_port;
	char		http_user[65];
	char		http_pwd[65];
	char		http_css[128];
	char		http_jscript[128];
	char		http_tpl[128];
	char		http_script[128];
	int			http_refresh;
	int			http_hide_idle_clients;
	struct s_ip *http_allowed;
	int			http_readonly;
	in_addr_t	http_dynip;
	uchar		http_dyndns[64];
	int			http_use_ssl;
	char		http_cert[128];
#endif
	int			http_full_cfg;
	int			failbantime;
	int			failbancount;
	LLIST 		*v_list; //failban list
	int		c33_port;
	in_addr_t	c33_srvip;
	uchar		c33_key[16];
	int		c33_crypted;
	int		c33_passive;
	struct s_ip 	*c33_plain;
	int		c35_port;
	in_addr_t	c35_srvip;
	int		c35_suppresscmd08;
	PTAB		c35_tcp_ptab;
	in_addr_t	c35_tcp_srvip;
	PTAB		ncd_ptab;
	in_addr_t	ncd_srvip;
	uchar		ncd_key[16];
	int		ncd_keepalive;
	int		ncd_mgclient;
	struct s_ip 	*ncd_allowed;
	PTAB		cc_ptab;
	int		rad_port;
	in_addr_t	rad_srvip;
	int		cc_port;
	int		cc_reshare;
	int		cc_ignore_reshare;
	int		cc_update_interval;
	in_addr_t	cc_srvip;
	char		cc_version[7];
	int             cc_minimize_cards;
	int             cc_keep_connected;
	int		cc_stealth;
	int		cc_reshare_services;
	struct s_ip *rad_allowed;
	char		rad_usr[32];
	char		ser_device[512];
	ulong		srtimeout;  // SerialReaderTimeount in millisec
	int		max_log_size;
	int		waitforcards;
	int		preferlocalcards;
	int		saveinithistory;
	int     reader_restart_seconds; //schlocke: reader restart auf x seconds, disable = 0

//Loadbalancer-Config:
	int     lb_mode; //schlocke: reader loadbalancing mode
	int     lb_save; //schlocke: load/save statistics to file, save every x ecms
	int		lb_nbest_readers; // count of best readers
	int		lb_nfb_readers; // count of fallback readers
	int		lb_min_ecmcount; // minimal ecm count to evaluate lbvalues
	int     lb_max_ecmcount; // maximum ecm count before reseting lbvalues
	int     lb_reopen_seconds; //time between retrying failed readers/caids/prov/srv
	int	lb_retrylimit; //reopen only happens if reader response time > retrylimit
	char	*lb_savepath; //path where the stat file is save. Empty=default=/tmp/.oscam/stat
	int	lb_stat_cleanup; //duration in hours for cleaning old statistics
	
	int             resolve_gethostbyname;

#ifdef CS_WITH_DOUBLECHECK
        int             double_check; //schlocke: Double checks each ecm+dcw from two (or more) readers
#endif

#ifdef CS_WITH_GBOX
	uchar		gbox_pwd[8];
	uchar		ignorefile[128];
	uchar		cardfile[128];
	uchar		gbxShareOnl[128];
	int		maxdist;
	int		num_locals;
	unsigned long 	locals[CS_MAXLOCALS];
#endif

#ifdef IRDETO_GUESSING
	struct s_irdeto_quess *itab[0xff];
#endif

#ifdef HAVE_DVBAPI
	int		dvbapi_enabled;
	int		dvbapi_au;
	char		dvbapi_usr[64];
	int		dvbapi_boxtype;
	int		dvbapi_pmtmode;
	int		dvbapi_requestmode;
	SIDTABBITS    dvbapi_sidtabok;	// positiv services
	SIDTABBITS    dvbapi_sidtabno;	// negative services
#endif

#ifdef CS_ANTICASC
	char		ac_enabled;
	int		ac_users;       // num of users for account (0 - default)
	int		ac_stime;       // time to collect AC statistics (3 min - default)
	int		ac_samples;     // qty of samples
	int		ac_penalty;     // 0 - write to log
	int		ac_fakedelay;   // 100-1000 ms
	int		ac_denysamples;
	char		ac_logfile[128];
	struct		s_cpmap *cpmap;
#endif

#ifdef QBOXHD_LED
    int disableqboxhdled; // disable qboxhd led , default = 0
#endif
};

//Loadbalance constants:
#define LB_NONE 0
#define LB_FASTEST_READER_FIRST 1
#define LB_OLDEST_READER_FIRST 2
#define LB_LOWEST_USAGELEVEL 3
#define LB_MAX_STAT_TIME 20

typedef struct reader_stat_t
{
  int           rc;
  ushort        caid;
  ulong         prid;
  ushort        srvid;

  time_t        last_received;

  int           ecm_count;
  int           time_avg;
  int           time_stat[LB_MAX_STAT_TIME];
  int           time_idx;

  int           request_count;
} GCC_PACK      READER_STAT;

typedef struct emm_packet_t
{
  uchar emm[258];
  uchar l;
  uchar caid[2];
  uchar provid[4];
  uchar hexserial[8];					 //contains hexserial or SA of EMM
  uchar type;
  struct s_client *client;
} GCC_PACK EMM_PACKET;

//EMM types:
#define UNKNOWN 0
#define UNIQUE	1
#define SHARED	2
#define GLOBAL	3

// oscam-simples
extern char *remote_txt(void);
extern char *trim(char *);
extern char *strtolower(char *);
extern int gethexval(char);
extern int cs_atob(uchar *, char *, int);
extern ulong cs_atoi(char *, int, int);
extern int byte_atob(char *);
extern long word_atob(char *);
extern long dyn_word_atob(char *asc);
extern int key_atob_l(char *, uchar *, int);
extern char *key_btoa(char *, uchar *);
extern char *cs_hexdump(int, const uchar *, int);
extern in_addr_t cs_inet_order(in_addr_t);
extern char *cs_inet_ntoa(in_addr_t);
extern in_addr_t cs_inet_addr(char *txt);
extern ulong b2i(int, uchar *);
extern ullong b2ll(int, uchar *);
extern uchar *i2b(int, ulong);
extern ulong a2i(char *, int);
extern int boundary(int, int);
extern void cs_ftime(struct timeb *);
extern void cs_sleepms(unsigned int);
extern void cs_sleepus(unsigned int);
extern int bytes_available(int);
extern void cs_setpriority(int);
extern struct s_auth *find_user(char *);
extern int check_filled(uchar *value, int length);
extern void *cs_malloc(void *result, size_t size, int quiterror);
extern void *cs_realloc(void *result, size_t size, int quiterror);
#ifdef WEBIF
extern char to_hex(char code);
extern void char_to_hex(const unsigned char* p_array, unsigned int p_array_len, unsigned char *result);
extern void create_rand_str(char *dst, int size);
#endif
extern void uint64ToBitchar(uint64 value, int size, char *result);
extern int file_exists(const char * filename);
extern void clear_sip(struct s_ip **sip);
extern void clear_ptab(struct s_ptab *ptab);
extern void clear_ftab(struct s_ftab *ftab);
void clear_caidtab(struct s_caidtab *ctab);
void clear_tuntab(struct s_tuntab *ttab);
extern int safe_overwrite_with_bak(char *destfile, char *tmpfile, char *bakfile, int forceBakOverWrite);
extern void fprintf_conf(FILE *f, int varnameWidth, const char *varname, const char *fmtstring, ...);
extern void cs_strncpy(char * destination, const char * source, size_t num);
extern char *get_servicename(int srvid, int caid);
extern char *get_tiername(int tierid, int caid);
extern char *get_provider(int caid, ulong provid);
extern void make_non_blocking(int fd);
extern uchar fast_rnd(void);
extern void init_rnd(void);
extern int hexserialset(struct s_reader *rdr);
extern char *monitor_get_proto(struct s_client *);
extern char *reader_get_type_desc(struct s_reader * rdr, int extended);
extern char *get_ncd_client_name(char *client_id);
extern char *strnew(char *str);

extern pthread_key_t getclient;
extern struct s_client * cur_client(void);
extern struct s_client *first_client;
extern struct s_reader *first_reader;

// oscam variables

extern int cs_dblevel, loghistidx;

extern ushort len4caid[256];

extern struct card_struct *Cards;
//extern struct idstore_struct *idstore;
extern unsigned long *IgnoreList;

extern struct s_config *cfg;
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
extern int cs_get_restartmode();

//reset stats for webif:
extern void clear_account_stats(struct s_auth *account);
extern void clear_all_account_stats();
extern void clear_system_stats();
                              
#endif
extern int recv_from_udpipe(uchar *);
extern char* username(struct s_client *);
extern struct s_client * get_client_by_tid(unsigned long);
extern int chk_bcaid(ECM_REQUEST *, CAIDTAB *);
extern void cs_exit(int sig);
extern int comp_timeb(struct timeb *tpa, struct timeb *tpb);
extern struct s_client * create_client(in_addr_t);
extern int cs_auth_client(struct s_client *, struct s_auth *, const char*);
extern void cs_disconnect_client(struct s_client *);
extern int check_cwcache2(ECM_REQUEST *, uint64);
extern int write_to_pipe(int, int, uchar *, int);
extern int read_from_pipe(int, uchar **, int);
extern int write_ecm_answer(struct s_reader *, ECM_REQUEST *);
extern void log_emm_request(struct s_reader *);
extern ulong chk_provid(uchar *, ushort);
#ifdef IRDETO_GUESSING
extern void guess_irdeto(ECM_REQUEST *);
#endif
extern void get_cw(struct s_client *, ECM_REQUEST *);
extern void do_emm(struct s_client *, EMM_PACKET *);
extern ECM_REQUEST *get_ecmtask(void);
extern void request_cw(ECM_REQUEST *, int, int);
extern int send_dcw(struct s_client *, ECM_REQUEST *);
extern int process_input(uchar *, int, int);
extern int has_srvid(struct s_client *cl, ECM_REQUEST *er);
extern int chk_srvid(struct s_client *, ECM_REQUEST *);
extern int chk_srvid_match(ECM_REQUEST *, SIDTAB *);
extern int chk_sfilter(ECM_REQUEST *, PTAB*);
extern int chk_ufilters(ECM_REQUEST *);
extern int chk_rsfilter(struct s_reader * reader, ECM_REQUEST *);
extern int matching_reader(ECM_REQUEST *, struct s_reader *);
extern void set_signal_handler(int , int , void (*));
extern void cs_log_config(void);
extern void cs_waitforcardinit(void);
extern void cs_reinit_clients(struct s_auth *new_accounts);
extern int process_client_pipe(struct s_client *cl, uchar *buf, int l);
extern void update_reader_config(uchar *ptr);
extern int chk_ctab(ushort caid, CAIDTAB *ctab);
extern int chk_srvid_by_caid_prov(struct s_client *, ushort caid, ulong provid);
extern void nullclose(int *fd);
extern void kill_thread(struct s_client *cl);
extern int get_threadnum(struct s_client *client);
extern int get_ridx(struct s_reader *reader);
extern void cs_add_violation(uint ip);

extern void cs_card_info(void);
extern void cs_debug_level(void);

#ifdef CS_ANTICASC
extern void init_ac(void);
extern void ac_init_stat();
extern void ac_clear();
extern void ac_done_stat();
extern int  ac_init_log();
extern void ac_do_stat(void);
extern void ac_init_client(struct s_auth *);
extern void ac_chk(ECM_REQUEST*, int);
#endif

// oscam-config
extern int  init_config(void);
extern int  init_free_userdb(struct s_auth *auth);
extern struct s_auth *init_userdb();
extern int  init_readerdb(void);
extern int  init_sidtab(void);
extern int  init_srvid(void);
extern int  init_tierid(void);
extern int  search_boxkey(ushort, char *);
extern void init_len4caid(void);
#ifdef IRDETO_GUESSING
extern int  init_irdeto_guess_tab(void);
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
#ifdef CS_WITH_GBOX
extern void chk_t_gbox(char *token, char *value);
#endif
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
extern int write_services();
extern int write_userdb(struct s_auth *authptr);
extern int write_config();
extern int write_server();
extern void write_versionfile();
extern char *mk_t_caidtab(CAIDTAB *ctab);
extern char *mk_t_tuntab(TUNTAB *ttab);
extern char *mk_t_group(uint64 grp);
extern char *mk_t_ftab(FTAB *ftab);
extern char *mk_t_camd35tcp_port();
extern char *mk_t_aeskeys(struct s_reader *rdr);
extern char *mk_t_newcamd_port();
extern char *mk_t_nano(struct s_reader *rdr, uchar flag);
extern char *mk_t_service( uint64 sidtabok, uint64 sidtabno);
extern char *mk_t_logfile();

//Todo #ifdef CCCAM
extern int init_provid();
extern char * get_tmp_dir();

// oscam-reader
extern int logfd;
extern int reader_cmd2icc(struct s_reader * reader, const uchar *buf, const int l, uchar *response, ushort *response_length);
extern int card_write(struct s_reader * reader, const uchar *, const uchar *, uchar *, ushort *);
extern int check_sct_len(const unsigned char *data, int off);
extern void cs_ri_brk(struct s_reader * reader, int);
extern void cs_ri_log(struct s_reader * reader, char *,...);
extern void * start_cardreader(void *);
extern void reader_card_info(struct s_reader * reader);
extern int hostResolve(struct s_reader * reader);
extern int network_tcp_connection_open();
extern void network_tcp_connection_close(struct s_client *, int);
extern int casc_recv_timer(struct s_reader * reader, uchar *buf, int l, int msec);
extern void clear_reader_pipe(struct s_reader * reader);
extern void block_connect(struct s_reader *rdr);
extern int is_connect_blocked(struct s_reader *rdr);
            
// oscam-log
extern int  cs_init_log();
extern void cs_write_log(char *);
extern void cs_log(const char *,...);
#ifdef WITH_DEBUG
extern void cs_debug_mask(unsigned short, const char *,...);
extern void cs_ddump_mask(unsigned short, const uchar *, int, char *, ...);
#else
#define nop() asm volatile("nop")
#define cs_debug(...) nop()
#define cs_debug_mask(...) nop()
#define cs_ddump(...) nop()
#define cs_ddump_mask(...) nop()
#endif
extern void cs_close_log(void);
extern int  cs_init_statistics();
extern void cs_dump(const uchar *, int, char *, ...);

// oscam-aes
extern void aes_set_key(char *);
extern void add_aes_entry(struct s_reader *rdr, ushort caid, uint32 ident, int keyid, uchar *aesKey);
extern void aes_encrypt_idx(struct s_client *, uchar *, int);
extern void aes_decrypt(uchar *, int);
extern int aes_decrypt_from_list(AES_ENTRY *list, ushort caid, uint32 provid,int keyid, uchar *buf, int n);
extern int aes_present(AES_ENTRY *list, ushort caid, uint32 provid,int keyid);
extern void parse_aes_keys(struct s_reader *rdr,char *value);
extern void aes_clear_entries(struct s_reader *rdr);

#define aes_encrypt(b, n) aes_encrypt_idx(cur_client(), b, n)

// reader-common
extern int reader_device_init(struct s_reader * reader);
extern int reader_checkhealth(struct s_reader * reader);
extern void reader_post_process(struct s_reader * reader);
extern int reader_ecm(struct s_reader * reader, ECM_REQUEST *);
extern int reader_emm(struct s_reader * reader, EMM_PACKET *);
int reader_get_emm_type(EMM_PACKET *ep, struct s_reader * reader);
void get_emm_filter(struct s_reader * rdr, uchar *filter);
int get_cardsystem(ushort caid);
extern int check_emm_cardsystem(struct s_reader * rdr, EMM_PACKET *ep);
extern void reader_device_close(struct s_reader * reader);

//module-stat
extern void init_stat();
extern int get_best_reader(ECM_REQUEST *er);
extern void clear_reader_stat(struct s_reader *reader);
extern void add_stat(struct s_reader *rdr, ECM_REQUEST *er, int ecm_time, int rc);
extern void load_stat_from_file();
extern void save_stat_to_file();
extern void clear_all_stat();
extern void housekeeping_stat(int force);

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
#ifdef WITH_STAPI
void cardreader_stapi(struct s_cardreader *crdr);
#endif

// protocol modules
extern int  monitor_send_idx(struct s_client *, char *);
extern void module_monitor(struct s_module *);
extern void module_camd35(struct s_module *);
extern void module_camd35_tcp(struct s_module *);
extern void module_camd33(struct s_module *);
extern void module_newcamd(struct s_module *);
extern void module_radegast(struct s_module *);
extern void module_oscam_ser(struct s_module *);
extern void module_cccam(struct s_module *);
extern void module_constcw(struct s_module *);
extern struct timeval *chk_pending(struct timeb tp_ctimeout);
#ifdef CS_WITH_GBOX
extern void module_gbox(struct s_module *);
#endif
#ifdef HAVE_DVBAPI
extern void module_dvbapi(struct s_module *);
#endif

#ifdef WEBIF
// oscam-http
extern void http_srv();
#endif

// oscam-garbage
extern void add_garbage(void *data);
extern void start_garbage_collector();

#endif  // CS_GLOBALS
