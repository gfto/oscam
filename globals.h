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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include <pthread.h>

//for reader-nagra variables in s_reader: 
#include "cscrypt/idea.h" 

#ifndef CS_GLOBALS
#define CS_GLOBALS
#define CS_VERSION    "0.99.4svn"
#ifndef CS_SVN_VERSION
#	define CS_SVN_VERSION "test"
#endif

#if defined(__GNUC__)
#  define GCC_PACK __attribute__((packed))
#else
#  define GCC_PACK
#endif

#define call(arg) \
	if (arg) { \
		cs_debug_mask(D_TRACE, "ERROR, function call %s returns error.",#arg); \
		return ERROR; \
	}

#include "oscam-config.h"
#ifndef USE_CMAKE
#  include "oscam-ostype.h"
#endif
#include "oscam-types.h"
#include "cscrypt/cscrypt.h"

#ifdef HAVE_PCSC 
  #ifdef OS_CYGWIN32
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
#include <libusb-1.0/libusb.h>
#include "csctapi/smartreader_types.h"
#endif

#ifndef CS_CONFDIR
#define CS_CONFDIR    "/usr/local/etc"
#endif
#ifndef CS_MMAPFILE
#define CS_MMAPFILE   "/tmp/oscam.mem"
#endif
#ifndef CS_LOGFILE
#define CS_LOGFILE    "/var/log/oscam.log"
#endif
#define CS_QLEN       128 // size of request queue
#define CS_MAXQLEN    128 // size of request queue for cardreader
#define CS_MAXCAIDTAB 32  // max. caid-defs/user
#define CS_MAXTUNTAB  16  // max. betatunnel mappings
#define CS_MAXPROV    32
#define CS_MAXPORTS   32  // max server ports
#define CS_MAXFILTERS   16

#define CS_MAXCARDS       4096
#define CS_MAXIGNORE      1024
#define CS_MAXLOCALS      16
#define CS_ECMSTORESIZE   16  // use MD5()
#define CS_EMMSTORESIZE   270
#define CS_CLIENT_TIMEOUT 5000
#define CS_CLIENT_MAXIDLE 120
#define CS_BIND_TIMEOUT   120
#define CS_DELAY          0
#define CS_RESOLVE_DELAY  30
#define CS_MAXLOGHIST     30
#define CS_LOGHISTSIZE    193 // 32+128+33: username + logline + channelname
#define CS_MAXREADERCAID  16

#ifdef  CS_EMBEDDED
#define CS_MAXPID   32
#define CS_MAXREADER    (CS_MAXPID>>1)
#define CS_MAXPENDING   CS_MAXPID
#define CS_ECMCACHESIZE   CS_MAXPID
#define CS_EMMCACHESIZE   (CS_MAXPID<<1)
#else
#define CS_MAXPID   512
#define CS_MAXREADER    (CS_MAXPID>>2)
#define CS_MAXPENDING   (CS_MAXPID<<1)
#define CS_ECMCACHESIZE   CS_MAXPID
#define CS_EMMCACHESIZE   (CS_MAXPID<<1)
#define CS_RDR_INIT_HIST
#endif

#define D_TRACE     1 // Generate very detailed error/trace messages per routine
#define D_ATR       2 // Debug ATR parsing, dump of ecm, cw
#define D_READER    4 // Debug Reader/Proxy Process
#define D_CLIENT    8 // Debug Client Process
#define D_IFD       16  // Debug IFD+protocol
#define D_DEVICE    32  // Debug Reader I/O
#define D_EMM				64  // Dumps EMM
#define D_FUT				128 // Reserved for future use
#define D_ALL_DUMP  255 // dumps all

#define R_DB2COM1		0x1 // Reader Dbox2 @ com1
#define R_DB2COM2		0x2 // Reader Dbox2 @ com1
#define R_SC8in1    0x3 // Reader smartcard mouse
#define R_MOUSE     0x4 // Reader smartcard mouse
/////////////////// phoenix readers which need baudrate setting and timings need to be guarded by OSCam: BEFORE R_MOUSE
#define R_INTERNAL  0x5 // Reader smartcard intern
/////////////////// internal readers (Dreambox, Coolstream, IPBox) are all R_INTERNAL, they are determined compile-time
/////////////////// readers that do not reed baudrate setting and timings are guarded by reader itself (large buffer built in): AFTER R_SMART
#define R_SMART     0x6 // Smartreader+
#define R_PCSC 			0x7 // PCSC
/////////////////// proxy readers after R_CS378X
#define R_CAMD35    0x10  // Reader cascading camd 3.5x
#define R_CAMD33    0x11  // Reader cascading camd 3.3x
#define R_NEWCAMD   0x12  // Reader cascading newcamd
#define R_RADEGAST  0x13  // Reader cascading radegast
#define R_CS378X    0x14  // Reader cascading camd 3.5x TCP
#define R_CONSTCW   0x15  // Reader for Constant CW
/////////////////// peer to peer proxy readers after R_CCCAM
#ifdef CS_WITH_GBOX
#define R_GBOX      0x20  // Reader cascading gbox
#endif
#define R_CCCAM     0x25  // Reader cascading cccam
#define R_SERIAL    0x80  // Reader serial
#define R_IS_NETWORK    0x70
#define R_IS_CASCADING  0xF0


#define CS_MAX_MOD 12
#define MOD_CONN_TCP    1
#define MOD_CONN_UDP    2
#define MOD_CONN_NET    3
#define MOD_CONN_SERIAL 4
#define MOD_NO_CONN	8

#ifdef HAVE_DVBAPI
#define BOXTYPE_DREAMBOX	1
#define BOXTYPE_DUCKBOX	2
#define BOXTYPE_UFS910	3
#define BOXTYPE_DBOX2	4
#define BOXTYPE_IPBOX	5
#define BOXTYPE_IPBOX_PMT	6 
#define BOXTYPES		6
extern char *boxdesc[];
#endif

#ifdef CS_CORE
char *PIP_ID_TXT[] = { "ECM", "EMM", "LOG", "CIN", "HUP", "RST", "KCL", "STA", "BES", NULL  };
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
#define PIP_ID_LOG    2
#define PIP_ID_CIN    3  // CARD_INFO
#define PIP_ID_HUP    4
#define PIP_ID_RST    5  // Schlocke: Restart Reader, CCcam for example (param: ridx)
#define PIP_ID_KCL    6  // Schlocke: Kill all Clients (no param)
#define PIP_ID_STA    7  // Schlocke: Add statistic (param: ADD_READER_STAT)
#define PIP_ID_BES    8  // Schlocke: Get best reader (param ECM_REQUEST, return to client with data int ridx)

#define PIP_ID_DCW    9
#define PIP_ID_MAX    PIP_ID_BES


#define PIP_ID_ERR    (-1)
#define PIP_ID_DIR    (-2)
#define PIP_ID_NUL    (-3)

#define cdiff *c_start

#define NCD_AUTO    0
#define NCD_524     1
#define NCD_525     2

#define CS_ANTICASC

// moved from reader-common.h
#define NO_CARD        0
#define CARD_NEED_INIT 1
#define CARD_INSERTED  2
#define CARD_FAILURE   3

enum {E1_GLOBAL=0, E1_USER, E1_READER, E1_SERVER, E1_LSERVER};
enum {E2_GLOBAL=0, E2_GROUP, E2_CAID, E2_IDENT, E2_CLASS, E2_CHID, E2_QUEUE,
      E2_EA_LEN, E2_F0_LEN, E2_OFFLINE, E2_SID};

//typedef unsigned char uchar;
//typedef unsigned long ulong;

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long long uint64;

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
  char     label[33];
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
  FTAB   ftab;
} GCC_PACK PORT;

typedef struct s_ptab
{
  int    nports;
  PORT   ports[CS_MAXPORTS];
} GCC_PACK PTAB;

#if defined(LIBUSB)
typedef struct  {
    int F;
    float D;
    int fs;
    int N;
    int T;
    int inv;
    int parity;
    int irdeto;
    int running;
	libusb_device *usb_dev;
	libusb_device_handle *usb_dev_handle;
    enum smartreader_chip_type type;
    int in_ep;  // 0x01
    int out_ep; // 0x82
    int index;
    /** usb read timeout */
    int usb_read_timeout;
    /** usb write timeout */
    int usb_write_timeout;
    unsigned int writebuffer_chunksize;
    unsigned char bitbang_enabled;
    int baudrate;
    int interface;   // 0 or 1 
    /** maximum packet size. Needed for filtering modem status bytes every n packets. */
    unsigned int max_packet_size;
    unsigned char g_read_buffer[4096];
    unsigned int g_read_buffer_size;
    pthread_mutex_t g_read_mutex;
    pthread_mutex_t g_usb_mutex;
    pthread_t rt;
    unsigned char modem_status;
} SR_CONFIG;
#endif

typedef struct aes_entry {
    ushort      keyid;
    ushort      caid;
    uint32      ident;
    AES_KEY     key;
    struct aes_entry   *next;
} AES_ENTRY;

struct s_ecm
{
  uchar  ecmd5[CS_ECMSTORESIZE];
  uchar  cw[16];
  ushort caid;
  ulong  grp;
  //int level;
};

struct s_emm
{
  uchar emm[CS_EMMSTORESIZE];
  uchar type;
  int   count;
};

#define AVAIL_CHECK_CONNECTED 0
#define AVAIL_CHECK_LOADBALANCE 1

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
  void (*s_handler)();
  int  (*recv)();
  void (*send_dcw)();
  void (*cleanup)();
  int  c_multi;
  int  (*c_recv_chk)();
  int  (*c_init)();
  int  (*c_send_ecm)();
  int  (*c_send_emm)();
  int  (*c_init_log)();
  int  (*c_recv_log)();
  int  (*c_available)(); //Schlocke: available check for load-balancing, 
                         //params: 
                         //int ridx (reader to check)
                         //int checktype (0=return connected, 1=return loadbalance-avail) return int
  void (*c_idle)(); //Schlocke: called when reader is idle
  int  c_port;
  PTAB *ptab;
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

struct s_client
{
  pid_t		pid;
  in_addr_t	ip;
  in_port_t	port;
  time_t	login;
  time_t	last;
  time_t	lastswitch;
  time_t	lastemm;
  time_t	lastecm;
  time_t	expirationdate;
  int		c35_suppresscmd08;
  int		c35_sleepsend;
  int		ncd_keepalive;
  int		disabled;
  ulong		grp;
  int		crypted;
  int		dup;
  int		au;
  int		autoau;
  int		monlvl;
  int		dbglvl;
  CAIDTAB	ctab;
  TUNTAB	ttab;
  ulong		sidtabok; // positiv services
  ulong		sidtabno; // negative services
  int		typ;
  int		ctyp;
  int		stat;
  int		ufd;
  int		last_srvid;
  int		last_caid;
  int		tosleep;
  char		usr[32];
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
#endif
  uchar		ucrc[4];    // needed by monitor and used by camd35
  ulong		pcrc;        // pwd crc
  AES_KEY	aeskey;      // needed by monitor and used by camd33, camd35
  ushort	ncd_msgid;
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
};

//for viaccess var in s_reader:
struct geo_cache
{
	ulong provid;
	uchar geo[256];
	uchar geo_len;
};

struct s_reader  //contains device info, reader info and card info
{
  ulong		auprovid; // AU only for this provid
  int		audisabled; // exclude reader from auto AU
  int 		deleted; // if this flag is set the reader is not shown in webif and becomes not writte to oscam.server
  int		smargopatch;
  int		pid;
  int       cs_idx;
  int       ridx; //FIXME reader[ridx] reader has to know what number it is, should be replaced by storing pointer to reader instead of array index
  int       enable;
  int       available; //Schlocke: New flag for loadbalancing. Only reader if reader supports ph.c_available function
  int       fd_error;
  int       fd;
  ulong     grp;
  int       fallback;
  int       typ;
  int       card_system;
  char      label[32];
  char      device[128];
  ushort    slot;   //in case of multiple slots like sc8in1; first slot = 1
  int       handle;   //device handle
#ifdef ST_LINUX
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
  uchar	    nagra_boxkey[16]; //n3 boxkey 8byte  or tiger idea key 16byte
  int       has_rsa;
  int       force_irdeto;
  uchar     aes_key[16];
  uchar     rsa_mod[120]; //rsa modulus for nagra cards.
  uchar     atr[64];
  int		atrlen;
  ulong     sidtabok;	// positiv services
  ulong     sidtabno;	// negative services
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
  int       cachecm;
  int       rewritemm;
  int       card_status;
  int       deprecated; //if 0 ATR obeyed, if 1 default speed (9600) is chosen; for devices that cannot switch baudrate
  struct    s_module ph;
  uchar     ncd_key[16];
  uchar     ncd_skey[16];
  int       ncd_disable_server_filt;
  ushort    ncd_msgid;
  int       ncd_proto;
  char      cc_version[7];  // cccam version
  char      cc_build[5];    // cccam build number
  int       cc_maxhop;      // cccam max distance
  int       cc_currenthops; // number of hops for CCCam
  void      *cc;            // ptr to cccam internal data struct
  int       cc_disable_retry_ecm; //Schlocke
  int       cc_disable_auto_block; //Schlocke
  int       cc_force_resend_ecm;   //Schlocke
  int       cc_want_emu; //Schlocke: Client want to have EMUs, 0 - NO; 1 - YES
  uint      cc_id;
  uchar     tcp_connected;
  int       tcp_ito;      // inactivity timeout
  int       tcp_rto;      // reconnect timeout
  time_t    last_g;       // get (if last_s-last_g>tcp_rto - reconnect )
  time_t    last_s;       // send
  uchar     show_cls;     // number of classes subscription showed on kill -31
  int       maxqlen;      // max queue length
  int       qlen;         // current queue length
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
#ifdef CS_RDR_INIT_HIST
  uchar     init_history[4096];
#endif
  int       init_history_pos;
  int       msg_idx;
#ifdef WEBIF
  int		emmwritten[4]; //count written EMM
  int		emmskipped[4]; //count skipped EMM
  int		emmerror[4];	//count error EMM
  int		emmblocked[4];	//count blocked EMM
#endif
#ifdef HAVE_PCSC
  SCARDCONTEXT hContext;
  SCARDHANDLE hCard;
  DWORD dwActiveProtocol;
#endif
#ifdef LIBUSB
  SR_CONFIG *sr_config;
#endif
	////variables from icc_async.h start
	int convention; //Convention of this ICC
	unsigned char protocol_type; // Type of protocol
	unsigned short BWT,CWT; // (for overclocking uncorrected) block waiting time, character waiting time, in ETU
	unsigned long current_baudrate; // (for overclocking uncorrected) baudrate to prevent unnecessary conversions from/to termios structure
	unsigned int read_timeout; // Max timeout (ms) to receive characters
	unsigned int block_delay; // Delay (ms) after starting to transmit
	unsigned int char_delay; // Delay (ms) after transmiting each sucesive char
	////variables from io_serial.h start
	int written; //keep score of how much bytes are written to serial port, since they are echoed back they have to be read
	////variables from reader-dre.c 
	unsigned char provider;
	////variables from reader-nagra.c 
        IDEA_KEY_SCHEDULE ksSession; 
 	int is_pure_nagra; 
 	int is_tiger; 
 	int has_dt08; 
 	int swapCW; 
 	unsigned char rom[15]; 
 	unsigned char plainDT08RSA[64]; 
 	unsigned char IdeaCamKey[16]; 
 	unsigned char irdId[4]; 
 	unsigned char sessi[16]; 
 	unsigned char signature[8]; 
 	unsigned char cam_state[3]; 
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
	time_t lb_last; //time for oldest reader
	// multi AES linked list
	AES_ENTRY *aes_list;
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
  char     usr[33];
  char     pwd[33];
  int      uniq;
  int      au;
  int      autoau;
  int      monlvl;
  ulong    grp;
  int      tosleep;
  CAIDTAB  ctab;
  ulong    sidtabok;  // positiv services
  ulong    sidtabno;  // negative services
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
  int       c35_suppresscmd08;
  int       c35_sleepsend;
  int       ncd_keepalive;
  int       cccmaxhops;
  int       cccreshare;
  int       disabled;
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
	int		debuglvl;
	ulong		netprio;
	ulong		ctimeout;
	ulong		ftimeout;
	ulong		cmaxidle;
	int		ulparent;
	ulong		delay;
	int		bindwait;
	int		resolvedelay;
	int		clientdyndns;
	int		tosleep;
	in_addr_t	srvip;
	char		*pidfile;
	char		*usrfile;
	char		*cwlogdir;
	char		*logfile;
	int		disablelog;
	int		disableuserfile;
	int		usrfileflag;
	struct s_auth 	*account;
	struct s_srvid 	*srvid;
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
	char		http_tpl[128];
	char		http_script[128];
	int			http_refresh;
	int			http_hide_idle_clients;
	struct 	s_ip *http_allowed;
	int			http_readonly;
	in_addr_t	http_dynip;
	uchar		http_dyndns[64];
#endif
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
	in_addr_t	cc_srvip;
	uchar		cc_version[7];
	struct s_ip *rad_allowed;
	char		rad_usr[32];
	char		ser_device[512];
	ulong		srtimeout;  // SerialReaderTimeount in millisec
	int		max_log_size;
	int		waitforcards;
	int		preferlocalcards;
	int		saveinithistory;
	int     reader_restart_seconds; //schlocke: reader restart auf x seconds, disable = 0
	int     reader_auto_loadbalance; //schlocke: reader loadbalancing disable = 0 enable = 1
	int     reader_auto_loadbalance_save; //schlocke: load/save statistics to file, save every x ecms

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
	char		dvbapi_usr[33];
	int		dvbapi_boxtype;
	int		dvbapi_pmtmode;
	CAIDTAB	dvbapi_prioritytab;
	CAIDTAB	dvbapi_ignoretab;
	CAIDTAB	dvbapi_delaytab;
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
	//  struct s_reader reader[];
};

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
  int           reader[CS_MAXREADER];
  int           cidx;   // client index
  int           cpti;   // client pending table index
  int           stage;    // processing stage in server module
  int           level;    // send-level in client module
  int           rc;
  uchar         rcEx;
  struct timeb  tps;    // incoming time stamp
  uchar         locals_done;
  int		btun; // mark er as betatunneled

#ifdef CS_WITH_GBOX
  ushort	gbxCWFrom;
  ushort	gbxFrom;
  ushort	gbxTo;
  uchar		gbxForward[16];
  int		gbxRidx;
#endif

} GCC_PACK      ECM_REQUEST;

//Loadbalance constants:
#define LB_NONE 0
#define LB_FASTEST_READER_FIRST 1
#define LB_OLDEST_READER_FIRST 2
#define LB_LOWEST_USAGELEVEL 3

#define MAX_STAT_TIME 20
#define MIN_ECM_COUNT 5
#define MAX_ECM_COUNT 500

 
typedef struct add_reader_stat_t
{
  int           ridx;
  int           time;
  int           rc;
  
  ushort        caid;
  ulong         prid;
  ushort        srvid;
} GCC_PACK      ADD_READER_STAT;

typedef struct reader_stat_t
{
  int           rc;
  ushort        caid;
  ulong         prid;
  ushort        srvid;

  int           ecm_count;  
  int           time_avg;
  int           time_stat[MAX_STAT_TIME];
  int           time_idx;
} GCC_PACK      READER_STAT;

typedef struct get_reader_stat_t 
{
  ushort        caid;
  ulong         prid;
  ushort        srvid;
  int           cidx;
  int           reader_avail[CS_MAXREADER];
  uchar         ecmd5[CS_ECMSTORESIZE];
} GCC_PACK      GET_READER_STAT;

typedef struct emm_packet_t
{
  uchar emm[258];
  uchar l;
  uchar caid[2];
  uchar provid[4];
  uchar hexserial[8];					 //contains hexserial or SA of EMM
  uchar type;
  int   cidx;
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
extern int key_atob(char *, uchar *);
extern int key_atob14(char *, uchar *);
extern int key_atob_l(char *, uchar *, int);
extern char *key_btoa(char *, uchar *);
extern char *cs_hexdump(int, uchar *, int);
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
#ifdef WEBIF
extern int x2i(int i);
extern void urldecode(char *s);
extern char to_hex(char code);
extern char *urlencode(char *str);
extern char *char_to_hex(const unsigned char* p_array, unsigned int p_array_len, char hex2ascii[256][2]);
extern void create_rand_str(char *dst, int size);
#endif
extern void long2bitchar(long value, char *result);
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
extern char *get_provider(int caid, ulong provid);
extern void make_non_blocking(int fd);

// oscam variables
extern int pfd, fd_c2m, cs_idx, *c_start, cs_ptyp, cs_dblevel;
extern int *logidx, *loghistidx, *log_fd;
extern int is_server, *mcl;
extern uchar mbuf[1024];
extern ushort len4caid[256];
extern pid_t master_pid;
extern struct s_ecm *ecmcache;
extern struct s_client *client;

extern struct card_struct *Cards;
extern struct idstore_struct *idstore;
extern unsigned long *IgnoreList;

extern struct s_config *cfg;
extern char cs_confdir[], *loghist;
extern struct s_module ph[CS_MAX_MOD];
extern ECM_REQUEST *ecmtask;
#ifdef CS_ANTICASC
extern struct s_acasc_shm *acasc;
extern FILE *fpa;
extern int use_ac_log;
#endif
extern pthread_mutex_t gethostbyname_lock; //gethostbyname ist NOT threadsafe! So we need a mutex-lock!

// oscam
extern int recv_from_udpipe(uchar *);
extern char* username(int);
extern int idx_from_pid(pid_t);
extern int chk_bcaid(ECM_REQUEST *, CAIDTAB *);
extern void cs_exit(int sig);
extern int cs_fork(in_addr_t, in_port_t);
extern void wait4master(void);
extern int cs_auth_client(struct s_auth *, char*);
extern void cs_disconnect_client(void);
extern int check_ecmcache1(ECM_REQUEST *, ulong);
extern int check_ecmcache2(ECM_REQUEST *, ulong);
extern void store_logentry(char *);
extern int write_to_pipe(int, int, uchar *, int);
extern int read_from_pipe(int, uchar **, int);
extern int write_ecm_request(int, ECM_REQUEST *);
extern int write_ecm_answer(struct s_reader *, int, ECM_REQUEST *);
extern void log_emm_request(int);
extern ulong chk_provid(uchar *, ushort);
extern void guess_cardsystem(ECM_REQUEST *);
#ifdef IRDETO_GUESSING
extern void guess_irdeto(ECM_REQUEST *); 
#endif
extern void get_cw(ECM_REQUEST *);
extern void do_emm(EMM_PACKET *);
extern ECM_REQUEST *get_ecmtask(void);
extern void request_cw(ECM_REQUEST *, int, int);
extern int send_dcw(ECM_REQUEST *);
extern int process_input(uchar *, int, int);
extern int chk_srvid(ECM_REQUEST *, int);
extern int chk_srvid_match(ECM_REQUEST *, SIDTAB *);
extern int chk_sfilter(ECM_REQUEST *, PTAB*);
extern int chk_ufilters(ECM_REQUEST *);
extern int chk_rfilter(ECM_REQUEST *, struct s_reader *);
extern int chk_rsfilter(struct s_reader * reader, ECM_REQUEST *, int);
extern int chk_avail_reader(ECM_REQUEST *, struct s_reader *);
extern int matching_reader(ECM_REQUEST *, struct s_reader *);
extern void set_signal_handler(int , int , void (*)(int));
extern void cs_log_config(void);
extern void cs_waitforcardinit(void);
extern void cs_reinit_clients(void);
extern void chk_dcw(int fd);
extern void update_reader_config(uchar *ptr);

#ifdef CS_ANTICASC
//extern void start_anticascader(void);
extern void init_ac(void);
extern void ac_init_stat();
extern int  ac_init_log(char*);
extern void ac_do_stat(void);
extern void ac_init_client(struct s_auth *);
extern void ac_chk(ECM_REQUEST*, int);
#endif

// oscam-nano
extern int chk_class(ECM_REQUEST *, CLASSTAB*, const char*, const char*);

// oscam-config
extern int  init_config(void);
extern int  init_userdb(struct s_auth **authptr_org);
extern int  init_readerdb(void);
extern int  init_sidtab(void);
extern int  init_srvid(void);
extern int  search_boxkey(ushort, char *);
extern void init_len4caid(void);
#ifdef IRDETO_GUESSING
extern int  init_irdeto_guess_tab(void); 
#endif
extern void chk_caidtab(char *caidasc, CAIDTAB *ctab);
extern void chk_tuntab(char *tunasc, TUNTAB *ttab);
extern void chk_services(char *labels, ulong *sidok, ulong *sidno);
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
extern void chk_t_global(char *token, char *value);
extern void chk_t_monitor(char *token, char *value);
extern void chk_reader(char *token, char *value, struct s_reader *rdr);

#ifdef HAVE_DVBAPI
extern void chk_t_dvbapi(char *token, char *value);
void dvbapi_chk_caidtab(char *caidasc, CAIDTAB *ctab);
#endif

#ifdef WEBIF
extern void chk_t_webif(char *token, char *value);
#endif

extern void chk_account(char *token, char *value, struct s_auth *account);
extern void chk_sidtab(char *token, char *value, struct s_sidtab *sidtab);
extern int write_services();
extern int write_userdb(struct s_auth *authptr);
extern int write_config();
extern int write_server();
extern char *mk_t_caidtab(CAIDTAB *ctab);
extern char *mk_t_tuntab(TUNTAB *ttab);
extern char *mk_t_group(ulong *grp);
extern char *mk_t_ftab(FTAB *ftab);
//Todo #ifdef CCCAM
extern int init_provid();
extern char * get_tmp_dir();

// oscam-reader
extern int ridx, logfd;
extern int reader_cmd2icc(struct s_reader * reader, uchar *buf, int l, uchar *response, ushort *response_length);
extern int card_write(struct s_reader * reader, uchar *, uchar *, uchar *, ushort *);
extern int check_sct_len(const unsigned char *data, int off);
extern void cs_ri_brk(struct s_reader * reader, int);
extern void cs_ri_log(struct s_reader * reader, char *,...);
extern void * start_cardreader(void *);
extern void reader_card_info(struct s_reader * reader);
extern int hostResolve();
extern int network_tcp_connection_open();
extern void network_tcp_connection_close(struct s_reader * reader, int);

// oscam-log
extern int  cs_init_log(char *);
extern void cs_write_log(char *);
extern void cs_log(char *,...);
extern void cs_debug(char *,...);
extern void cs_debug_nolf(char *,...);
extern void cs_debug_mask(unsigned short, char *,...);
extern void cs_ddump(uchar *, int, char *, ...);
extern void cs_ddump_mask(unsigned short, uchar *, int, char *, ...);
extern void cs_close_log(void);
extern int  cs_init_statistics(char *);
extern void cs_statistics(int);
extern void cs_dump(uchar *, int, char *, ...);

// oscam-aes
extern void aes_set_key(char *);
extern void aes_encrypt_idx(int, uchar *, int);
extern void aes_decrypt(uchar *, int);
extern int aes_decrypt_from_list(AES_ENTRY *list, ushort caid, uint32 provid,int keyid, uchar *buf, int n);
extern int aes_present(AES_ENTRY *list, ushort caid, uint32 provid,int keyid);
extern void parse_aes_keys(struct s_reader *rdr,char *value);
extern void aes_clear_entries(struct s_reader *rdr);

#define aes_encrypt(b, n) aes_encrypt_idx(cs_idx, b, n)

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

//module-stat
extern void init_stat();
extern void add_reader_stat(ADD_READER_STAT *add_stat);
extern int get_best_reader(GET_READER_STAT *grs, int *result);

#ifdef HAVE_PCSC
// reader-pcsc
extern int pcsc_reader_do_api(struct s_reader *pcsc_reader, uchar *buf, uchar *cta_res, ushort *cta_lr,int l);
extern int pcsc_activate_card(struct s_reader *pcsc_reader, uchar *atr, ushort *atr_size);
extern int pcsc_check_card_inserted(struct s_reader *pcsc_reader);
extern int pcsc_reader_init(struct s_reader *pcsc_reader, char *device);
#endif

// protocol modules
extern int  monitor_send_idx(int, char *);
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
#ifdef WITH_STAPI
extern void module_stapi(struct s_module *);
#endif


// module-monitor
extern char *monitor_get_proto(int idx);
extern int cs_idx2ridx(int idx);

#ifdef WEBIF
// oscam-http
extern void http_srv();
#endif

#ifdef ST_LINUX
extern void Fortis_STSMART_Close();
extern void Fortis_STPTI_Close();
#endif

#endif  // CS_GLOBALS
