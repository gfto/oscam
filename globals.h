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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include <pthread.h>

#ifndef CS_GLOBALS
#define CS_GLOBALS
#define CS_VERSION		"0.99.3svn"

#if defined(__GNUC__)
#  define GCC_PACK __attribute__((packed))
#else
#  define GCC_PACK
#endif

#include "oscam-config.h"
#include "oscam-ostype.h"
#include "oscam-types.h"
#include "cscrypt/cscrypt.h"

#ifndef CS_CONFDIR
#define CS_CONFDIR 		"/usr/local/etc"
#endif
#ifndef CS_MMAPFILE
#define CS_MMAPFILE 		"/tmp/mcps.mem"
#endif
#ifndef CS_LOGFILE
#define CS_LOGFILE		"/var/log/mcps.log"
#endif
#define CS_QLEN			128	// size of request queue
#define CS_MAXQLEN		128	// size of request queue for cardreader
#define CS_MAXCAIDTAB		32	// max. caid-defs/user
#define CS_MAXTUNTAB        4   // max. betatunnel mappings
#define CS_MAXPROV		32
#define CS_MAXPORTS		32	// max server ports
#define CS_MAXFILTERS		16

#define CS_MAXCARDS		4096
#define CS_MAXIGNORE	1024
#define CS_MAXLOCALS    16
#define CS_ECMSTORESIZE		16	// use MD5()
#define CS_EMMSTORESIZE		270
#define CS_CLIENT_TIMEOUT	5
#define CS_CLIENT_MAXIDLE	120
#define CS_BIND_TIMEOUT		120
#define CS_DELAY		0
#define CS_RESOLVE_DELAY	30
#define CS_MAXLOGHIST		30
#define CS_LOGHISTSIZE		160	// 32+128: username + logline

#ifdef OLD_DEFS
#ifdef  CS_EMBEDDED
#define CS_MAXPENDING		32
#define CS_ECMCACHESIZE		32
#define CS_EMMCACHESIZE		64
#define CS_MAXPID		32
#define CS_MAXREADER		8
#else
#define CS_MAXPENDING		128
#define CS_ECMCACHESIZE		128
#define CS_EMMCACHESIZE		256
#define CS_MAXPID		128
#define CS_MAXREADER		64
#endif
#endif

#ifdef  CS_EMBEDDED
#define CS_MAXPID		32
#define CS_MAXREADER		(CS_MAXPID>>1)
#define CS_MAXPENDING		CS_MAXPID
#define CS_ECMCACHESIZE		CS_MAXPID
#define CS_EMMCACHESIZE		(CS_MAXPID<<1)
#else
#define CS_MAXPID		512
#define CS_MAXREADER		(CS_MAXPID>>2)
#define CS_MAXPENDING		(CS_MAXPID<<1)
#define CS_ECMCACHESIZE		CS_MAXPID
#define CS_EMMCACHESIZE		(CS_MAXPID<<1)
#define CS_RDR_INIT_HIST
#endif

#define D_DUMP			1	// Debug Dumps
#define D_MASTER		2	// Debug Master Process
#define D_READER		4	// Debug Reader/Proxy Process
#define D_CLIENT		8	// Debug Client Process
#define D_DEVICE		16	// Debug Reader I/O
#define D_WATCHDOG		32	// Debug Watchdog
#define D_ALL_DUMP		63

#define R_MOUSE			0x1	// Reader smartcard mouse
#define R_INTERN		0x2	// Reader smartcard intern
#define R_SMART		0x5	// Smartreader+
#define R_CAMD35		0x10	// Reader cascading camd 3.5x
#define R_CAMD33		0x11	// Reader cascading camd 3.3x
#define R_NEWCAMD		0x12	// Reader cascading newcamd
#define R_RADEGAST		0x13	// Reader cascading radegast
#define R_CS378X		0x14	// Reader cascading camd 3.5x TCP
#define R_GBOX		0x20	// Reader cascading gbox
#define R_SERIAL		0x80	// Reader serial
#define R_IS_NETWORK		0x70
#define R_IS_CASCADING		0xF0

#define CS_MAX_MOD 8
#define MOD_CONN_TCP		1
#define MOD_CONN_UDP		2
#define MOD_CONN_NET		3
#define MOD_CONN_SERIAL		4

#ifdef CS_CORE
char *PIP_ID_TXT[] = { "ECM", "EMM", "LOG", "CIN", "HUP", NULL };
char *RDR_CD_TXT[] = { "cd", "dsr", "cts", "ring", "none",
#ifdef USE_GPIO
                       "gpio2", "gpio3", "gpio4", "gpio5", "gpio6", "gpio7",
#endif
                       NULL };
#else
extern char *PIP_ID_TXT[];
extern char *RDR_CD_TXT[];
#endif

#define	PIP_ID_ECM		0
#define	PIP_ID_EMM		1
#define	PIP_ID_LOG		2
#define PIP_ID_CIN		3  // CARD_INFO
#define PIP_ID_HUP		4
#define	PIP_ID_MAX		PIP_ID_HUP
#define	PIP_ID_DCW		5

#define	PIP_ID_ERR		(-1)
#define	PIP_ID_DIR		(-2)
#define	PIP_ID_NUL		(-3)

#define cdiff *c_start

#define NCD_AUTO		0
#define NCD_524			1
#define NCD_525			2

#define CS_ANTICASC

enum {E1_GLOBAL=0, E1_USER, E1_READER, E1_SERVER, E1_LSERVER};
enum {E2_GLOBAL=0, E2_GROUP, E2_CAID, E2_IDENT, E2_CLASS, E2_CHID, E2_QUEUE,
      E2_EA_LEN, E2_F0_LEN, E2_OFFLINE, E2_SID};

//typedef unsigned char uchar;
//typedef unsigned long ulong;

typedef struct s_classtab
{
  uchar an;
  uchar bn;
  uchar aclass[31];
  uchar bclass[31];
} GCC_PACK CLASSTAB;

typedef	struct s_caidtab
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

typedef	struct s_port
{
  int    fd;
  int    s_port;
  FTAB   ftab;
} GCC_PACK PORT;

typedef	struct s_ptab
{
  int    nports;
  PORT   ports[CS_MAXPORTS];
} GCC_PACK PTAB;

struct s_ecm
{
  uchar  ecmd5[CS_ECMSTORESIZE];
  uchar  cw[16];
  ushort caid;
  ulong  prid;
  ulong  grp;
//  int	level;
};

struct s_emm
{
  uchar emm[CS_EMMSTORESIZE];
  uchar type;
  int   count;
};

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
  int  c_multi;
  int  (*c_recv_chk)();
  int  (*c_init)();
  int  (*c_send_ecm)();
  int  (*c_init_log)();
  int  (*c_recv_log)();
  int  c_port;
  PTAB *ptab;
};

struct s_irdeto_quess
{
  int    b47;
  ushort caid;
  ushort sid;
  struct s_irdeto_quess *next;
};

struct s_client
{
  pid_t     pid;
  in_addr_t ip;
  in_port_t port;
  time_t    login;
  time_t    last;
  time_t    lastswitch;
  time_t    lastemm;
  time_t    lastecm;
  ulong     grp;
  int       crypted;
  int       dup;
  int       au;
  int       monlvl;
  int       dbglvl;
  CAIDTAB   ctab;
  TUNTAB    ttab;
  ulong     sidtabok;	// positiv services
  ulong     sidtabno;	// negative services
  int       typ;
  int       ctyp;
  int       stat;
  int       ufd;
  int       last_srvid;
  int       last_caid;
  int       tosleep;
  char      usr[32];
  int       udp_fd;
  int       fd_m2c;
  struct    sockaddr_in udp_sa;
  int       log;
  int       logcounter;
  int       cwfound;
  int       cwcache;
  int       cwnot;
  uchar     ucrc[4];		 // needed by monitor and used by camd35
  ulong     pcrc;        // pwd crc
  AES_KEY   aeskey;		   // needed by monitor and used by camd33, camd35
  ushort    ncd_msgid;
  uchar     ncd_skey[16];
  int       port_idx;    // index in server ptab
  int       ncd_server;  // newcamd server?
#ifdef CS_ANTICASC
  ushort    ac_idx;
  ushort    ac_limit;
  uchar     ac_penalty;
#endif
  FTAB      fchid;
  FTAB      ftab;        // user [caid] and ident filter
  CLASSTAB  cltab;
};

struct s_reader
{
  int       cs_idx;
  int       fd;
  ulong     grp;
  int       fallback;
  int       typ;
  int       card_system;
  char      label[32];
  char      device[128];
  int       detect;
  int       mhz;
  int       custom_speed;
  int       r_port;
  char      r_usr[64];
  char      r_pwd[64];
  int       r_crypted;
  int       l_port;
  int       log_port;
  CAIDTAB   ctab;
  ulong     sidtabok;	// positiv services
  ulong     sidtabno;	// negative services
  uchar     hexserial[8];
  int       nprov;
  uchar     prid[CS_MAXPROV][8];
  uchar     availkeys[CS_MAXPROV][16];	// viaccess; misused in seca, if availkeys[PROV][0]=0 then expired, 1 then valid.
  uchar     sa[CS_MAXPROV][4];		// viaccess & seca
  ushort    acs;		// irdeto
  ushort    caid[16];
  uchar     b_nano[256];
  char      pincode[5];
  int       logemm;
  int       cachemm;
  int       rewritemm;
  int       online;
  struct    s_module ph;
  uchar     ncd_key[16];
  uchar     ncd_skey[16];
  int       ncd_disable_server_filt;
  ushort    ncd_msgid;
  int       ncd_proto;
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
  uchar     gbox_pwd[4];
  uchar     gbox_timecode[7];
  int       gbox_online;
  uchar     gbox_vers;
  uchar     gbox_prem;
  int       gbox_fd;
  struct timeb  gbox_lasthello;		// incoming time stamp
#ifdef CS_RDR_INIT_HIST
  uchar     init_history[1024];
  int       init_history_pos;
#endif
};

#ifdef CS_ANTICASC

struct s_acasc_shm {
  ushort count : 15;
  ushort deny  : 1;
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
  int      monlvl;
  ulong    grp;
  int      tosleep;
  CAIDTAB  ctab;
  ulong    sidtabok;	// positiv services
  ulong    sidtabno;	// negative services
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
  struct   s_auth *next;
};

struct s_srvid
{
  int  srvid;
  char name[33];
  struct s_srvid *next;
};

struct s_ip
{
  in_addr_t ip[2];
  struct s_ip *next;
};

struct s_config
{
  int       nice;
  ulong     netprio;
  int       ctimeout;
  int       ftimeout;
  int       cmaxidle;
  int	    ulparent;
  ulong     delay;
  int       bindwait;
  int       resolvedelay;
  int       tosleep;
  in_addr_t srvip;
  char      pidfile[128];
  char      usrfile[128];
  struct s_auth *account;
  struct s_srvid *srvid;
  struct s_sidtab *sidtab;
  int       mon_port;
  in_addr_t mon_srvip;
  struct s_ip *mon_allowed;
  int       mon_aulow;
  int       mon_hideclient_to;
  int       mon_level;
  int       c33_port;
  in_addr_t c33_srvip;
  uchar     c33_key[16];
  int       c33_crypted;
  int       c33_passive;
  struct s_ip *c33_plain;
  int       c35_port;
  in_addr_t c35_srvip;
  PTAB      c35_tcp_ptab;
  in_addr_t c35_tcp_srvip;
  PTAB      ncd_ptab;
  in_addr_t ncd_srvip;
  uchar     ncd_key[16];
  int       rad_port;
  in_addr_t rad_srvip;
  struct s_ip *rad_allowed;
  char      rad_usr[32];
  char      ser_device[512];
  int       srtimeout;  // SerialReaderTimeount in millisec
  int       max_log_size;
  int       show_ecm_dw;
  uchar      gbox_pwd[8];
  uchar		ignorefile[512];
  uchar     cardfile[512];
  uchar     gbxShareOnl[512];
  int 		maxdist;
  int       num_locals;
  unsigned long locals[CS_MAXLOCALS];
  //struct s_irdeto_quess *itab[0xff];
#ifdef CS_ANTICASC
  char      ac_enabled;
  int       ac_users;       // num of users for account (0 - default)
  int       ac_stime;       // time to collect AC statistics (3 min - default)
  int       ac_samples;     // qty of samples
  int       ac_penalty;     // 0 - write to log
  int       ac_fakedelay;   // 100-1000 ms
  int       ac_denysamples; 
  char      ac_logfile[128];
  struct s_cpmap *cpmap;
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
  int           cidx;		// client index
  int           cpti;		// client pending table index
  int           stage;		// processing stage in server module
  int           level;		// send-level in client module
  int           rc;
  uchar         rcEx;
  struct timeb  tps;		// incoming time stamp
  ushort		gbxCWFrom;
  ushort 		gbxFrom;
  ushort		gbxTo;
  
  uchar     	gbxForward[16];
  int			gbxRidx;
} GCC_PACK      ECM_REQUEST;

typedef struct emm_packet_t
{
  uchar emm[258];
  uchar l;
  uchar caid[2];
  uchar provid[4];
  uchar hexserial[8];
  uchar type;
  int   cidx;
} GCC_PACK EMM_PACKET;

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
extern int key_atob4(char *, uchar *);
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
extern void cs_sleepms(int);
extern int bytes_available(int);
extern void cs_setpriority(int);
extern struct s_auth *find_user(char *);

// oscam variables
extern int pfd, rfd, fd_c2m, fd_m2c, cs_idx, *c_start, cs_ptyp, cs_dblevel, cs_hw;
extern int *logidx, *loghistidx, *log_fd;
extern int is_server, *mcl;
extern uchar mbuf[1024];
extern ushort len4caid[256];
extern pid_t master_pid;
extern struct s_ecm *ecmcache;
extern struct s_client *client;
extern struct s_reader *reader;

extern struct card_struct *Cards;
extern struct idstore_struct *idstore;
extern unsigned long *IgnoreList;

extern struct s_config *cfg;
extern char cs_confdir[], *loghist;
extern EMM_PACKET epg;
extern struct s_module ph[CS_MAX_MOD];
extern ECM_REQUEST *ecmtask;
extern char logfile[256];
#ifdef CS_ANTICASC
extern struct s_acasc_shm *acasc;
extern FILE *fpa;
extern int use_ac_log;
#endif


// oscam
extern char *cs_platform(char *);
extern int recv_from_udpipe(uchar *, int);
extern char* username(int);
extern int idx_from_pid(pid_t);
extern int chk_bcaid(ECM_REQUEST *, CAIDTAB *);
extern void cs_exit(int sig);
extern int cs_fork(in_addr_t, in_port_t);
extern void wait4master(void);
extern int cs_auth_client(struct s_auth *, char*);
extern void cs_disconnect_client(void);
extern int check_ecmcache(ECM_REQUEST *, ulong);
extern int write_to_pipe(int, int, uchar *, int);
extern int read_from_pipe(int, uchar **, int);
extern int write_ecm_request(int, ECM_REQUEST *);
extern int write_ecm_answer(int, ECM_REQUEST *);
extern void log_emm_request(int);
extern ulong chk_provid(uchar *, ushort);
extern void guess_cardsystem(ECM_REQUEST *);
extern void guess_irdeto(ECM_REQUEST *);
extern void get_cw(ECM_REQUEST *);
extern void do_emm(EMM_PACKET *);
extern ECM_REQUEST *get_ecmtask(void);
extern void request_cw(ECM_REQUEST *, int);
extern int send_dcw(ECM_REQUEST *);
extern int process_input(uchar *, int, int);
extern int chk_srvid(ECM_REQUEST *, int);
extern int chk_sfilter(ECM_REQUEST *, PTAB*);
extern int chk_ufilters(ECM_REQUEST *);
extern int chk_rfilter(ECM_REQUEST *, struct s_reader *);
extern int chk_rsfilter(ECM_REQUEST *, int);
extern int chk_avail_reader(ECM_REQUEST *, struct s_reader *);
extern void set_signal_handler(int , int , void (*)(int));
extern void cs_log_config(void);

#ifdef CS_ANTICASC
//extern void start_anticascader(void);
extern void init_ac(void);
extern void ac_init_stat(int);
extern int  ac_init_log(char*);
extern void ac_do_stat(void);
extern void ac_init_client(struct s_auth *);
extern void ac_chk(ECM_REQUEST*, int);
#endif

// oscam-nano
extern int chk_class(ECM_REQUEST *, CLASSTAB*, const char*, const char*);

// oscam-config
extern int  init_config(void);
extern int  init_userdb(void);
extern int  init_readerdb(void);
extern int  init_sidtab(void);
extern int  init_srvid(void);
extern int  search_boxkey(ushort, ulong, char *);
extern void init_len4caid(void);
extern int  init_irdeto_guess_tab(void);

// oscam-reader
extern int ridx, logfd;
extern void cs_ri_brk(int);
extern void cs_ri_log(char *,...);
extern void start_cardreader(void);
extern void reader_card_info(void);

// oscam-log
extern int  cs_init_log(char *);
extern void cs_log(char *,...);
extern void cs_debug(char *,...);
extern void cs_ddump(uchar *, int, char *, ...);
extern void cs_close_log(void);
extern int  cs_init_statistics(char *);
extern void cs_statistics(int);
extern void cs_dump(uchar *, int, char *, ...);

// oscam-aes
extern void aes_set_key(char *);
extern void aes_encrypt_idx(int, uchar *, int);
extern void aes_decrypt(uchar *, int);
#define aes_encrypt(b, n) aes_encrypt_idx(cs_idx, b, n)

// reader-common
extern int reader_device_init(char *, int);
extern int reader_checkhealth(void);
extern int reader_ecm(ECM_REQUEST *);
extern int reader_emm(EMM_PACKET *);

// reader-irdeto
extern int irdeto_card_init(uchar *, int);
extern int irdeto_do_ecm(ECM_REQUEST *);
extern int irdeto_do_emm(EMM_PACKET *);
extern int irdeto_card_info(void);

// reader-viaccess
extern int viaccess_card_init(uchar *, int);
extern int viaccess_do_ecm(ECM_REQUEST *);
extern int viaccess_do_emm(EMM_PACKET *);
extern int viaccess_card_info(void);

// reader-videoguard
extern int videoguard_card_init(uchar *, int);
extern int videoguard_do_ecm(ECM_REQUEST *);
extern int videoguard_do_emm(EMM_PACKET *);
extern int videoguard_card_info(void);

// reader-cryptoworks
extern int cryptoworks_card_init(uchar *, int);
extern int cryptoworks_do_ecm(ECM_REQUEST *);
extern int cryptoworks_do_emm(EMM_PACKET *);
extern int cryptoworks_card_info(void);

// reader-seca
extern int seca_card_init(uchar *, int);
extern int seca_do_ecm(ECM_REQUEST *);
extern int seca_do_emm(EMM_PACKET *);
extern int seca_card_info(void);
 
// protocol modules
extern int  monitor_send_idx(int, char *);
extern void module_monitor(struct s_module *);
extern void module_camd35(struct s_module *);
extern void module_camd35_tcp(struct s_module *);
extern void module_camd33(struct s_module *);
extern void module_newcamd(struct s_module *);
extern void module_radegast(struct s_module *);
extern void module_oscam_ser(struct s_module *);
extern void module_gbox(struct s_module *);
extern struct timeval *chk_pending(struct timeb tp_ctimeout);
#endif	// CS_GLOBALS
