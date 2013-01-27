#include "globals.h"
#include <getopt.h>

#include "csctapi/cardreaders.h"
#include "modules.h"
#include "readers.h"

#include "extapi/coolapi.h"
#include "module-anticasc.h"
#include "module-cacheex.h"
#include "module-cccam.h"
#include "module-dvbapi-azbox.h"
#include "module-dvbapi-mca.h"
#include "module-ird-guess.h"
#include "module-lcd.h"
#include "module-led.h"
#include "module-stat.h"
#include "module-webif.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-failban.h"
#include "oscam-files.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "reader-common.h"

static void chk_dcw(struct s_client *cl, struct s_ecm_answer *ea);

/*****************************************************************************
        Globals
*****************************************************************************/
char *RDR_CD_TXT[] = {
	"cd", "dsr", "cts", "ring", "none",
	"gpio1", "gpio2", "gpio3", "gpio4", "gpio5", "gpio6", "gpio7",
	NULL
};

char *entitlement_type[] = {"", "package", "PPV-Event", "chid", "tier", "class", "PBM", "admin" };

const char *syslog_ident = "oscam";
char *oscam_pidfile = NULL;
char default_pidfile[64];

int32_t exit_oscam=0;
struct s_module modules[CS_MAX_MOD];
struct s_cardsystem cardsystems[CS_MAX_MOD];
struct s_cardreader cardreaders[CS_MAX_MOD];

struct s_client * first_client = NULL; //Pointer to clients list, first client is master
struct s_client * first_client_hashed[CS_CLIENT_HASHBUCKETS];  // Alternative hashed client list
struct s_reader * first_active_reader = NULL; //list of active readers (enable=1 deleted = 0)
LLIST * configured_readers = NULL; //list of all (configured) readers

uint16_t  len4caid[256];    // table for guessing caid (by len)
char  cs_confdir[128]=CS_CONFDIR;
uint16_t cs_dblevel=0;   // Debug Level
int32_t thread_pipe[2] = {0, 0};
int8_t cs_restart_mode=1; //Restartmode: 0=off, no restart fork, 1=(default)restart fork, restart by webif, 2=like=1, but also restart on segfaults
uint8_t cs_http_use_utf8 = 0;
int8_t cs_capture_SEGV=0;
int8_t cs_dump_stack=0;
uint16_t cs_waittime = 60;
char  cs_tmpdir[200]={0x00};
pid_t server_pid=0;
CS_MUTEX_LOCK system_lock;
CS_MUTEX_LOCK config_lock;
CS_MUTEX_LOCK gethostbyname_lock;
CS_MUTEX_LOCK clientlist_lock;
CS_MUTEX_LOCK readerlist_lock;
CS_MUTEX_LOCK fakeuser_lock;
CS_MUTEX_LOCK ecmcache_lock;
CS_MUTEX_LOCK readdir_lock;
CS_MUTEX_LOCK hitcache_lock;
pthread_key_t getclient;
static int32_t bg;
static int32_t gbdb;
static int32_t max_pending = 32;

struct s_client *timecheck_client;

//Cache for  ecms, cws and rcs:
struct ecm_request_t	*ecmcwcache = NULL;
uint32_t ecmcwcache_size = 0;

struct  s_config  cfg;

int log_remove_sensitive = 1;

char    *prog_name = NULL;
char    *processUsername = NULL;
#if defined(WEBIF) || defined(MODULE_MONITOR)
char    *loghist = NULL;     // ptr of log-history
char    *loghistptr = NULL;
#endif

/*****************************************************************************
        Statics
*****************************************************************************/
#define _check(CONFIG_VAR, text) \
	do { \
		if (config_##CONFIG_VAR()) \
			printf(" %s", text); \
	} while(0)

/* Prints usage information and information about the built-in modules. */
static void show_usage(void)
{
	printf("%s",
"  ___  ____   ___\n"
" / _ \\/ ___| / __|__ _ _ __ ___\n"
"| | | \\___ \\| |  / _` | '_ ` _ \\\n"
"| |_| |___) | |_| (_| | | | | | |\n"
" \\___/|____/ \\___\\__,_|_| |_| |_|\n\n");
	printf("OSCam cardserver v%s, build r%s (%s)\n", CS_VERSION, CS_SVN_VERSION, CS_TARGET);
	printf("Copyright (C) 2009-2013 OSCam developers.\n");
	printf("This program is distributed under GPLv3.\n");
	printf("OSCam is based on Streamboard mp-cardserver v0.9d written by dukat\n");
	printf("Visit http://www.streamboard.tv/oscam/ for more details.\n\n");

	printf(" Features   :");
	_check(WEBIF, "webif");
	_check(TOUCH, "touch");
	_check(MODULE_MONITOR, "monitor");
	_check(WITH_SSL, "ssl");
	if (!config_WITH_STAPI())
		_check(HAVE_DVBAPI, "dvbapi");
	else
		_check(WITH_STAPI, "dvbapi_stapi");
	_check(IRDETO_GUESSING, "irdeto-guessing");
	_check(CS_ANTICASC, "anticascading");
	_check(WITH_DEBUG, "debug");
	_check(WITH_LB, "loadbalancing");
	_check(LCDSUPPORT, "lcd");
	_check(LEDSUPPORT, "led");
	printf("\n");

	printf(" Protocols  :");
	_check(MODULE_CAMD33, "camd33");
	_check(MODULE_CAMD35, "camd35_udp");
	_check(MODULE_CAMD35_TCP, "camd35_tcp");
	_check(MODULE_NEWCAMD, "newcamd");
	_check(MODULE_CCCAM, "cccam");
	_check(MODULE_CCCSHARE, "cccam_share");
	_check(MODULE_PANDORA, "pandora");
	_check(MODULE_GHTTP, "ghttp");
	_check(CS_CACHEEX, "cache-exchange");
	_check(MODULE_GBOX, "gbox");
	_check(MODULE_RADEGAST, "radegast");
	_check(MODULE_SERIAL, "serial");
	_check(MODULE_CONSTCW, "constcw");
	printf("\n");

	printf(" Readers    :");
	_check(READER_NAGRA, "nagra");
	_check(READER_IRDETO, "irdeto");
	_check(READER_CONAX, "conax");
	_check(READER_CRYPTOWORKS, "cryptoworks");
	_check(READER_SECA, "seca");
	_check(READER_VIACCESS, "viaccess");
	_check(READER_VIDEOGUARD, "videoguard");
	_check(READER_DRE, "dre");
	_check(READER_TONGFANG, "tongfang");
	_check(READER_BULCRYPT, "bulcrypt");
	printf("\n");

	printf(" CardReaders:");
	_check(CARDREADER_PHOENIX, "phoenix");
	_check(CARDREADER_INTERNAL_AZBOX, "internal_azbox");
	_check(CARDREADER_INTERNAL_COOLAPI, "internal_coolapi");
	_check(CARDREADER_INTERNAL_SCI, "internal_sci");
	_check(CARDREADER_SC8IN1, "sc8in1");
	_check(CARDREADER_MP35, "mp35");
	_check(CARDREADER_SMARGO, "smargo");
	_check(CARDREADER_PCSC, "pcsc");
	_check(CARDREADER_SMART, "smartreader");
	_check(CARDREADER_DB2COM, "db2com");
	_check(CARDREADER_STAPI, "stapi");
	printf("\n");
	printf(" ConfigDir  : %s\n", CS_CONFDIR);
	printf("\n");
	printf(" Usage: oscam [parameters]\n");
	printf("\n Directories:\n");
	printf(" -c, --config-dir <dir>  | Read configuration files from <dir>.\n");
	printf("                         . Default: %s\n", CS_CONFDIR);
	printf(" -t, --temp-dir <dir>    | Set temporary directory to <dir>.\n");
#if defined(__CYGWIN__)
	printf("                         . Default: (OS-TMP)\n");
#else
	printf("                         . Default: /tmp/.oscam\n");
#endif
	printf("\n Startup:\n");
	printf(" -b, --daemon            | Start in the background as daemon.\n");
	printf(" -B, --pidfile <pidfile> | Create pidfile when starting.\n");
	if (config_WEBIF()) {
	printf(" -r, --restart <level>   | Set restart level:\n");
	printf("                         .   0 - Restart disabled (exit on restart request).\n");
	printf("                         .   1 - WebIf restart is active (default).\n");
	printf("                         .   2 - Like 1, but also restart on segfaults.\n");
	}
	printf(" -w, --wait <secs>       | Set how much seconds to wait at startup for the\n");
	printf("                         . system clock to be set correctly. Default: 60\n");
	printf("\n Logging:\n");
	printf(" -I, --syslog-ident <ident> | Set syslog ident. Default: oscam\n");
	printf(" -S, --show-sensitive    | Do not filter sensitive info (card serials, boxids)\n");
	printf("                         . from the logs.\n");
	printf(" -d, --debug <level>     | Set debug level mask used for logging:\n");
	printf("                         .     0 - No extra debugging (default).\n");
	printf("                         .     1 - Detailed error messages.\n");
	printf("                         .     2 - ATR parsing info, ECM, EMM and CW dumps.\n");
	printf("                         .     4 - Traffic from/to the reader.\n");
	printf("                         .     8 - Traffic from/to the clients.\n");
	printf("                         .    16 - Traffic to the reader-device on IFD layer.\n");
	printf("                         .    32 - Traffic to the reader-device on I/O layer.\n");
	printf("                         .    64 - EMM logging.\n");
	printf("                         .   128 - DVBAPI logging.\n");
	printf("                         .   256 - Loadbalancer logging.\n");
	printf("                         .   512 - CACHEEX logging.\n");
	printf("                         .  1024 - Client ECM logging.\n");
	printf("                         . 65535 - Debug all.\n");
	printf("\n Settings:\n");
	printf(" -p, --pending-ecm <num> | Set the maximum number of pending ECM packets.\n");
	printf("                         . Default: 32 Max: 255\n");
	if (config_WEBIF()) {
	printf(" -u, --utf8              | Enable WebIf support for UTF-8 charset.\n");
	}
	printf("\n Debug parameters:\n");
	printf(" -a, --crash-dump        | Write oscam.crash file on segfault. This option\n");
	printf("                         . needs GDB to be installed and OSCam executable to\n");
	printf("                         . contain the debug information (run oscam-XXXX.debug)\n");
	printf(" -s, --capture-segfaults | Capture segmentation faults.\n");
	printf(" -g, --gcollect <mode>   | Garbage collector debug mode:\n");
	printf("                         .   1 - Immediate free.\n");
	printf("                         .   2 - Check for double frees.\n");
	printf("\n Information:\n");
	printf(" -h, --help              | Show command line help text.\n");
	printf(" -V, --build-info        | Show OSCam binary configuration and version.\n");
}
#undef _check

/* Keep the options sorted */
static const char short_options[] = "aB:bc:d:g:hI:p:r:Sst:uVw:";

/* Keep the options sorted by short option */
static const struct option long_options[] = {
	{ "crash-dump",			no_argument,       NULL, 'a' },
	{ "pidfile",			required_argument, NULL, 'B' },
	{ "daemon",				no_argument,       NULL, 'b' },
	{ "config-dir",			required_argument, NULL, 'c' },
	{ "debug",				required_argument, NULL, 'd' },
	{ "gcollect",			required_argument, NULL, 'g' },
	{ "help",				no_argument,       NULL, 'h' },
	{ "syslog-ident",		required_argument, NULL, 'I' },
	{ "pending-ecm",		required_argument, NULL, 'p' },
	{ "restart",			required_argument, NULL, 'r' },
	{ "show-sensitive",		no_argument,       NULL, 'S' },
	{ "capture-segfaults",	no_argument,       NULL, 's' },
	{ "temp-dir",			required_argument, NULL, 't' },
	{ "utf8",				no_argument,       NULL, 'u' },
	{ "build-info",			no_argument,       NULL, 'V' },
	{ "wait",				required_argument, NULL, 'w' },
	{ 0, 0, 0, 0 }
};

static void write_versionfile(bool use_stdout);

static void parse_cmdline_params(int argc, char **argv) {
	int i;
	while ((i = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF) {
		if (i == '?')
			fprintf(stderr, "ERROR: Unknown command line parameter: %s\n", argv[optind - 1]);
		switch(i) {
		case 'a': // --crash-dump
			cs_dump_stack = 1;
			break;
		case 'B': // --pidfile
			oscam_pidfile = optarg;
			break;
		case 'b': // --daemon
			bg = 1;
			break;
		case 'c': // --config-dir
			cs_strncpy(cs_confdir, optarg, sizeof(cs_confdir));
			break;
		case 'd': // --debug
			cs_dblevel = atoi(optarg);
			break;
		case 'g': // --gcollect
			gbdb = atoi(optarg);
			break;
		case 'h': // --help
			show_usage();
			exit(EXIT_SUCCESS);
			break;
		case 'I': // --syslog-ident
			syslog_ident = optarg;
			break;
		case 'p': // --pending-ecm
			max_pending = atoi(optarg) <= 0 ? 32 : MIN(atoi(optarg), 255);
			break;
		case 'r': // --restart
			if (config_WEBIF()) {
				cs_restart_mode = atoi(optarg);
			}
			break;
		case 'S': // --show-sensitive
			log_remove_sensitive = !log_remove_sensitive;
			break;
		case 's': // --capture-segfaults
			cs_capture_SEGV = 1;
			break;
		case 't': { // --temp-dir
			mkdir(optarg, S_IRWXU);
			int j = open(optarg, O_RDONLY);
			if (j >= 0) {
				close(j);
				cs_strncpy(cs_tmpdir, optarg, sizeof(cs_tmpdir));
			} else {
				printf("WARNING: Temp dir does not exist. Using default value.\n");
			}
			break;
		}
		case 'u': // --utf8
			if (config_WEBIF()) {
				cs_http_use_utf8 = 1;
				printf("WARNING: Web interface UTF-8 mode enabled. Carefully read documentation as bugs may arise.\n");
			}
			break;
		case 'V': // --build-info
			write_versionfile(true);
			exit(EXIT_SUCCESS);
			break;
		case 'w': // --wait
			cs_waittime = strtoul(optarg, NULL, 10);
			break;
		}
	}
}

#define write_conf(CONFIG_VAR, text) \
	fprintf(fp, "%-30s %s\n", text ":", config_##CONFIG_VAR() ? "yes" : "no")

#define write_readerconf(CONFIG_VAR, text) \
	fprintf(fp, "%-30s %s\n", text ":", config_##CONFIG_VAR() ? "yes" : "no - no EMM support!")

#define write_cardreaderconf(CONFIG_VAR, text) \
	fprintf(fp, "%s%-19s %s\n", "cardreader_", text ":", config_##CONFIG_VAR() ? "yes" : "no")

static void write_versionfile(bool use_stdout) {
	FILE *fp = stdout;
	if (!use_stdout) {
		char targetfile[256];
		snprintf(targetfile, sizeof(targetfile) - 1, "%s%s", get_tmp_dir(), "/oscam.version");
		targetfile[sizeof(targetfile) - 1] = 0;
		fp = fopen(targetfile, "w");
		if (!fp) {
			cs_log("Cannot open %s (errno=%d %s)", targetfile, errno, strerror(errno));
			return;
		}
		struct tm st;
		time_t now = time(NULL);
		localtime_r(&now, &st);

		fprintf(fp, "Unix starttime: %ld\n", (long)now);
		fprintf(fp, "Starttime:      %02d.%02d.%04d %02d:%02d:%02d\n",
			st.tm_mday, st.tm_mon + 1, st.tm_year + 1900,
			st.tm_hour, st.tm_min, st.tm_sec);
	}

	fprintf(fp, "Version:        oscam-%s-r%s\n", CS_VERSION, CS_SVN_VERSION);

	fprintf(fp, "\n");
	write_conf(WEBIF, "Web interface support");
	write_conf(TOUCH, "Touch interface support");
	write_conf(WITH_SSL, "SSL support");
	write_conf(HAVE_DVBAPI, "DVB API support");
	if (config_HAVE_DVBAPI()) {
		write_conf(WITH_AZBOX, "DVB API with AZBOX support");
		write_conf(WITH_MCA, "DVB API with MCA support");
		write_conf(WITH_COOLAPI, "DVB API with COOLAPI support");
		write_conf(WITH_STAPI, "DVB API with STAPI support");
	}
	write_conf(CS_ANTICASC, "Anti-cascading support");
	write_conf(IRDETO_GUESSING, "Irdeto guessing");
	write_conf(WITH_DEBUG, "Debug mode");
	write_conf(MODULE_MONITOR, "Monitor");
	write_conf(WITH_LB, "Loadbalancing support");
	write_conf(LCDSUPPORT, "LCD support");
	write_conf(LEDSUPPORT, "LED support");
	write_conf(IPV6SUPPORT, "IPv6 support");
	write_conf(CS_CACHEEX, "Cache exchange support");

	fprintf(fp, "\n");
	write_conf(MODULE_CAMD33, "camd 3.3x");
	write_conf(MODULE_CAMD35, "camd 3.5 UDP");
	write_conf(MODULE_CAMD35_TCP, "camd 3.5 TCP");
	write_conf(MODULE_NEWCAMD, "newcamd");
	write_conf(MODULE_CCCAM, "CCcam");
	write_conf(MODULE_CCCSHARE, "CCcam share");
	write_conf(MODULE_PANDORA, "Pandora");
	write_conf(MODULE_GHTTP, "ghttp");
	write_conf(MODULE_GBOX, "gbox");
	write_conf(MODULE_RADEGAST, "radegast");
	write_conf(MODULE_SERIAL, "serial");
	write_conf(MODULE_CONSTCW, "constant CW");

	fprintf(fp, "\n");
	write_conf(WITH_CARDREADER, "Reader support");
	if (config_WITH_CARDREADER()) {
		fprintf(fp, "\n");
		write_readerconf(READER_NAGRA, "Nagra");
		write_readerconf(READER_IRDETO, "Irdeto");
		write_readerconf(READER_CONAX, "Conax");
		write_readerconf(READER_CRYPTOWORKS, "Cryptoworks");
		write_readerconf(READER_SECA, "Seca");
		write_readerconf(READER_VIACCESS, "Viaccess");
		write_readerconf(READER_VIDEOGUARD, "NDS Videoguard");
		write_readerconf(READER_DRE, "DRE Crypt");
		write_readerconf(READER_TONGFANG, "TONGFANG");
		write_readerconf(READER_BULCRYPT, "Bulcrypt");
		fprintf(fp, "\n");
		write_cardreaderconf(CARDREADER_PHOENIX, "phoenix");
		write_cardreaderconf(CARDREADER_INTERNAL_AZBOX, "internal_azbox");
		write_cardreaderconf(CARDREADER_INTERNAL_COOLAPI, "internal_coolapi");
		write_cardreaderconf(CARDREADER_INTERNAL_SCI, "internal_sci");
		write_cardreaderconf(CARDREADER_SC8IN1, "sc8in1");
		write_cardreaderconf(CARDREADER_MP35, "mp35");
		write_cardreaderconf(CARDREADER_SMARGO, "smargo");
		write_cardreaderconf(CARDREADER_PCSC, "pcsc");
		write_cardreaderconf(CARDREADER_SMART, "smartreader");
		write_cardreaderconf(CARDREADER_DB2COM, "db2com");
		write_cardreaderconf(CARDREADER_STAPI, "stapi");
	} else {
		write_readerconf(WITH_CARDREADER, "Reader Support");
	}
	if (!use_stdout)
		fclose(fp);
}
#undef write_conf
#undef write_readerconf
#undef write_cardreaderconf

#ifdef NEED_DAEMON
// The compat function is not called daemon() because this may cause problems.
static int32_t do_daemon(int32_t nochdir, int32_t noclose)
{
  int32_t fd;

  switch (fork())
  {
    case -1: return (-1);
    case 0:  break;
    default: _exit(0);
  }

  if (setsid()==(-1))
    return(-1);

  if (!nochdir)
    (void)chdir("/");

  if (!noclose && (fd=open("/dev/null", O_RDWR, 0)) != -1)
  {
    (void)dup2(fd, STDIN_FILENO);
    (void)dup2(fd, STDOUT_FILENO);
    (void)dup2(fd, STDERR_FILENO);
    if (fd>2)
      (void)close(fd);
  }
  return(0);
}
#else
#define do_daemon daemon
#endif

int32_t recv_from_udpipe(uchar *buf)
{
  uint16_t n;
  if (buf[0]!='U')
  {
    cs_log("INTERNAL PIPE-ERROR");
    cs_exit(1);
  }
  memcpy(&n, buf+1, 2);

  memmove(buf, buf+3, n);

  return n;
}

static struct s_client * idx_from_ip(IN_ADDR_T ip, in_port_t port)
{
  struct s_client *cl;
  for (cl=first_client; cl ; cl=cl->next)
    if (!cl->kill && (IP_EQUAL(cl->ip, ip)) && (cl->port==port) && ((cl->typ=='c') || (cl->typ=='m')))
      return cl;
  return NULL;
}

int32_t chk_bcaid(ECM_REQUEST *er, CAIDTAB *ctab)
{
  int32_t caid;
  if ((caid=chk_caid(er->caid, ctab))<0)
    return(0);
  er->caid=caid;
  return(1);
}

void cs_accounts_chk(void)
{
	struct s_auth *account1,*account2;
  struct s_auth *new_accounts = init_userdb();
  cs_writelock(&config_lock);
  struct s_auth *old_accounts = cfg.account;  
  for (account1=cfg.account; account1; account1=account1->next) {
    for (account2=new_accounts; account2; account2=account2->next) {
      if (!strcmp(account1->usr, account2->usr)) {
        account2->cwfound = account1->cwfound;
        account2->cwcache = account1->cwcache;
        account2->cwnot = account1->cwnot;
        account2->cwtun = account1->cwtun;
        account2->cwignored  = account1->cwignored;
        account2->cwtout = account1->cwtout;
        account2->emmok = account1->emmok;
        account2->emmnok = account1->emmnok;
        account2->firstlogin = account1->firstlogin;
        ac_copy_vars(account1, account2);
      }
    }
  }
  cs_reinit_clients(new_accounts);
  cfg.account = new_accounts;
  init_free_userdb(old_accounts);
  ac_clear();
  cs_writeunlock(&config_lock);
}

static void remove_ecm_from_reader(ECM_REQUEST *ecm) {
	int32_t i;

	struct s_ecm_answer *ea = ecm->matching_rdr;
	while (ea) {
	    if ((ea->status & REQUEST_SENT) && !(ea->status & REQUEST_ANSWERED)) {
	      //we found a outstanding reader, clean it:
        struct s_reader *rdr = ea->reader;
        if (rdr){
        	struct s_client *cl = rdr->client;
        	if(cl) {
        		ECM_REQUEST *ecmtask = cl->ecmtask;
        		if(ecmtask){
	            for (i = 0; i < cfg.max_pending; ++i) {
	            	if (ecmtask[i].parent == ecm) {
	            		ecmtask[i].parent = NULL;
	            		ecmtask[i].client = NULL;
	            		cacheex_set_csp_lastnode(&ecmtask[i]);
	            	}
	            }
	          }
          }
        }
	    }
	    ea = ea->next;
	}

}

void free_ecm(ECM_REQUEST *ecm) {
	struct s_ecm_answer *ea, *nxt;

	cacheex_free_csp_lastnodes(ecm);

	//remove this ecm from reader queue to avoid segfault on very late answers (when ecm is already disposed)
	//first check for outstanding answers:
	remove_ecm_from_reader(ecm);

    //free matching_rdr list:
	ea = ecm->matching_rdr;
	ecm->matching_rdr = NULL;
	while (ea) {
		nxt = ea->next;
		add_garbage(ea);
		ea = nxt;
	}
	add_garbage(ecm);
}


/**
 * free() data from job queue. Only releases data with len != 0
 **/
static void free_data(struct s_data *data)
{
    if (data) {
        if (data->len && data->ptr) {
            free(data->ptr);
        }
	free(data);
    }
}

static void cleanup_ecmtasks(struct s_client *cl)
{
	ECM_REQUEST *ecm;
	struct s_ecm_answer *ea_list, *ea_prev;

	if (cl->ecmtask) {
		int32_t i;
		for (i = 0; i < cfg.max_pending; i++) {
			ecm = &cl->ecmtask[i];
			ecm->matching_rdr=NULL;
			ecm->client = NULL;
		}
		add_garbage(cl->ecmtask);
		cl->ecmtask = NULL;
	}

	if (cl->cascadeusers) {
		ll_destroy_data(cl->cascadeusers);
		cl->cascadeusers = NULL;
	}

	//remove this clients ecm from queue. because of cache, just null the client:
	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		if (ecm->client == cl) {
			ecm->client = NULL;
			cacheex_set_cacheex_src(ecm, cl);
			//if cl is a reader, remove from matching_rdr:
			for(ea_list = ecm->matching_rdr, ea_prev=NULL; ea_list; ea_prev = ea_list, ea_list = ea_list->next) {
				if (ea_list->reader->client == cl) {
					if (ea_prev)
						ea_prev->next = ea_list->next;
					else
						ecm->matching_rdr = ea_list->next;
					add_garbage(ea_list);
				}
			}

			//if cl is a client, remove ecm from reader queue:
		
			remove_ecm_from_reader(ecm);
		}
	}
	cs_readunlock(&ecmcache_lock);

	//remove client from rdr ecm-queue:
	cs_readlock(&readerlist_lock);
	struct s_reader *rdr = first_active_reader;
	while (rdr) {
		if (rdr->client && rdr->client->ecmtask) {
			int i;
			for (i = 0; i < cfg.max_pending; i++) {
				ecm = &rdr->client->ecmtask[i];
				if (ecm->client == cl) {
					ecm->client = NULL;
					ecm->parent = NULL;
				}
			}
		}
		rdr=rdr->next;
	}
	cs_readunlock(&readerlist_lock);
}

/**
 * removes a reader from ecm cache queue - data
 **/
void remove_reader_from_ecm(struct s_reader *rdr)
{
        ECM_REQUEST *ecm;
        struct s_ecm_answer *ea_list, *ea_prev;

	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		for(ea_list = ecm->matching_rdr, ea_prev=NULL; ea_list; ea_prev = ea_list, ea_list = ea_list->next) {
			if (ea_list->reader == rdr) {
				if (ea_prev)
					ea_prev->next = ea_list->next;
				else
					ecm->matching_rdr = ea_list->next;
				add_garbage(ea_list);
			}
		}
	}
	cs_readunlock(&ecmcache_lock);
}

void cleanup_thread(void *var)
{
	struct s_client *cl = var;
	if(!cl) return;
	struct s_reader *rdr = cl->reader;

	// Remove client from client list. kill_thread also removes this client, so here just if client exits itself...
	struct s_client *prev, *cl2;
	cs_writelock(&clientlist_lock);
	cl->kill = 1;
	for (prev=first_client, cl2=first_client->next; prev->next != NULL; prev=prev->next, cl2=cl2->next)
		if (cl == cl2)
			break;
	if (cl == cl2)
		prev->next = cl2->next; //remove client from list
	int32_t bucket = (uintptr_t)cl/16 % CS_CLIENT_HASHBUCKETS;
	//remove client from hashed list
	if(first_client_hashed[bucket] == cl){
		first_client_hashed[bucket] = cl->nexthashed;
	} else {
		for (prev=first_client_hashed[bucket], cl2=first_client_hashed[bucket]->nexthashed; prev->nexthashed != NULL; prev=prev->nexthashed, cl2=cl2->nexthashed)
			if (cl == cl2)
				break;
		if (cl == cl2)
			prev->nexthashed = cl2->nexthashed;
	}
	cs_writeunlock(&clientlist_lock);

	// Clean reader. The cleaned structures should be only used by the reader thread, so we should be save without waiting
	if (rdr){
	        remove_reader_from_ecm(rdr);

		remove_reader_from_active(rdr);
		if(rdr->ph.cleanup)
			rdr->ph.cleanup(cl);
		if (cl->typ == 'r')
			cardreader_close(rdr);
		if (cl->typ == 'p')
			network_tcp_connection_close(rdr, "cleanup");
		cl->reader = NULL;
	}

	// Clean client specific data
	if(cl->typ == 'c'){
		cs_statistics(cl);
		cl->last_caid = 0xFFFF;
		cl->last_srvid = 0xFFFF;
		cs_statistics(cl);

		cs_sleepms(500); //just wait a bit that really really nobody is accessing client data

		if(modules[cl->ctyp].cleanup)
			modules[cl->ctyp].cleanup(cl);
	}

	// Close network socket if not already cleaned by previous cleanup functions
	if(cl->pfd)
		close(cl->pfd);

	// Clean all remaining structures

	pthread_mutex_trylock(&cl->thread_lock);

	//cleanup job list
	LL_ITER it = ll_iter_create(cl->joblist);
	struct s_data *data;
	while ((data=ll_iter_next(&it)))
            free_data(data);
	ll_destroy(cl->joblist);
	cl->joblist = NULL;
	cl->account = NULL;
	pthread_mutex_unlock(&cl->thread_lock);
	pthread_mutex_destroy(&cl->thread_lock);

	cleanup_ecmtasks(cl);
	add_garbage(cl->emmcache);
#ifdef MODULE_CCCAM
	add_garbage(cl->cc);
#endif
#ifdef MODULE_SERIAL
	add_garbage(cl->serialdata);
#endif
	add_garbage(cl);
}

static void cs_cleanup(void)
{
	stat_finish();

	cccam_done_share();

	kill_all_clients();

	//cleanup readers:
	struct s_client *cl;
	struct s_reader *rdr;
	for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
		cl = rdr->client;
		if(cl){
			rdr_log(rdr, "Killing reader");
			kill_thread(cl);
			// Stop MCR reader display thread
			if (cl->typ == 'r' && cl->reader && cl->reader->typ == R_SC8in1
					&& cl->reader->sc8in1_config && cl->reader->sc8in1_config->display_running) {
				cl->reader->sc8in1_config->display_running = 0;
			}
		}
	}
	first_active_reader = NULL;

	init_free_userdb(cfg.account);
	cfg.account = NULL;
	init_free_sidtab();

	if (oscam_pidfile)
		unlink(oscam_pidfile);

	config_free();

	cs_close_log();
}

/*
 * flags: 1 = restart, 2 = don't modify if SIG_IGN, may be combined
 */
void set_signal_handler(int32_t sig, int32_t flags, void (*sighandler))
{
#ifdef CS_SIGBSD
  if ((signal(sig, sighandler)==SIG_IGN) && (flags & 2))
  {
    signal(sig, SIG_IGN);
    siginterrupt(sig, 0);
  }
  else
    siginterrupt(sig, (flags & 1) ? 0 : 1);
#else
  struct sigaction sa;
  sigaction(sig, (struct sigaction *) 0, &sa);
  if (!((flags & 2) && (sa.sa_handler==SIG_IGN)))
  {
    sigemptyset(&sa.sa_mask);
    sa.sa_flags=(flags & 1) ? SA_RESTART : 0;
    sa.sa_handler=sighandler;
    sigaction(sig, &sa, (struct sigaction *) 0);
  }
#endif
}

static void cs_master_alarm(void)
{
  cs_log("PANIC: master deadlock!");
  fprintf(stderr, "PANIC: master deadlock!");
  fflush(stderr);
}

static void cs_sigpipe(void)
{
	if (cs_dblevel & D_ALL_DUMP)
		cs_log("Got sigpipe signal -> captured");
}

static void cs_dummy(void) {
	return;
}

/* Switch debuglevel forward one step (called when receiving SIGUSR1). */
void cs_debug_level(void) {
	switch (cs_dblevel) {
		case 0:
			cs_dblevel = 1;
			break;
		case 128:
			cs_dblevel = 255;
			break;
		case 255:
			cs_dblevel = 0;
			break;
		default:
			cs_dblevel <<= 1;
	}

	cs_log("debug_level=%d", cs_dblevel);
}

void cs_card_info(void)
{
	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		if( cl->typ=='r' && cl->reader )
			add_job(cl, ACTION_READER_CARDINFO, NULL, 0);
}

/**
 * write stacktrace to oscam.crash. file is always appended
 * Usage:
 * 1. compile oscam with debug parameters (Makefile: DS_OPTS="-ggdb")
 * 2. you need gdb installed and working on the local machine
 * 3. start oscam with parameter: -a
 */
void cs_dumpstack(int32_t sig)
{
	FILE *fp = fopen("oscam.crash", "a+");

	time_t timep;
	char buf[200];

	time(&timep);
	cs_ctime_r(&timep, buf);

	fprintf(stderr, "crashed with signal %d on %swriting oscam.crash\n", sig, buf);

	fprintf(fp, "%sOSCam cardserver v%s, build r%s (%s)\n", buf, CS_VERSION, CS_SVN_VERSION, CS_TARGET);
	fprintf(fp, "FATAL: Signal %d: %s Fault. Logged StackTrace:\n\n", sig, (sig == SIGSEGV) ? "Segmentation" : ((sig == SIGBUS) ? "Bus" : "Unknown"));
	fclose(fp);

	FILE *cmd = fopen("/tmp/gdbcmd", "w");
	fputs("bt\n", cmd);
	fputs("thread apply all bt\n", cmd);
	fclose(cmd);

	snprintf(buf, sizeof(buf)-1, "gdb %s %d -batch -x /tmp/gdbcmd >> oscam.crash", prog_name, getpid());
	if(system(buf) == -1)
		fprintf(stderr, "Fatal error on trying to start gdb process.");

	exit(-1);
}


/**
 * called by signal SIGHUP
 *
 * reloads configs:
 *  - useraccounts (oscam.user)
 *  - services ids (oscam.srvid)
 *  - tier ids     (oscam.tiers)
 *  Also clears anticascading stats.
 **/
void cs_reload_config(void)
{
		cs_accounts_chk();
		init_srvid();
		init_tierid();
		ac_init_stat();
}

/* Sets signal handlers to ignore for early startup of OSCam because for example log
   could cause SIGPIPE errors and the normal signal handlers can't be used at this point. */
static void init_signal_pre(void)
{
		set_signal_handler(SIGPIPE , 1, SIG_IGN);
		set_signal_handler(SIGWINCH, 1, SIG_IGN);
		set_signal_handler(SIGALRM , 1, SIG_IGN);
		set_signal_handler(SIGHUP  , 1, SIG_IGN);
}

/* Sets the signal handlers.*/
static void init_signal(int8_t isDaemon)
{
		set_signal_handler(SIGINT, 3, cs_exit);
		//set_signal_handler(SIGKILL, 3, cs_exit);
#if defined(__APPLE__)
		set_signal_handler(SIGEMT, 3, cs_exit);
#else
		//set_signal_handler(SIGPOLL, 3, cs_exit);
#endif
		//set_signal_handler(SIGPROF, 3, cs_exit);
		set_signal_handler(SIGTERM, 3, cs_exit);
		//set_signal_handler(SIGVTALRM, 3, cs_exit);

		set_signal_handler(SIGWINCH, 1, SIG_IGN);
		//  set_signal_handler(SIGPIPE , 0, SIG_IGN);
		set_signal_handler(SIGPIPE , 0, cs_sigpipe);
		//  set_signal_handler(SIGALRM , 0, cs_alarm);
		set_signal_handler(SIGALRM , 0, cs_master_alarm);
		// set_signal_handler(SIGCHLD , 1, cs_child_chk);
		set_signal_handler(SIGHUP  , 1, isDaemon?cs_dummy:cs_reload_config);
		//set_signal_handler(SIGHUP , 1, cs_sighup);
		set_signal_handler(SIGUSR1, 1, isDaemon?cs_dummy:cs_debug_level);
		set_signal_handler(SIGUSR2, 1, isDaemon?cs_dummy:cs_card_info);
		set_signal_handler(OSCAM_SIGNAL_WAKEUP, 0, isDaemon?cs_dummy:cs_dummy);

		if(!isDaemon){
			if (cs_capture_SEGV) {
				set_signal_handler(SIGSEGV, 1, cs_exit);
				set_signal_handler(SIGBUS, 1, cs_exit);
			}
			else if (cs_dump_stack) {
				set_signal_handler(SIGSEGV, 1, cs_dumpstack);
				set_signal_handler(SIGBUS, 1, cs_dumpstack);
			}

			cs_log("signal handling initialized (type=%s)",
#ifdef CS_SIGBSD
			"bsd"
#else
			"sysv"
#endif
			);
		}
	return;
}

void cs_exit(int32_t sig)
{
	if (cs_dump_stack && (sig == SIGSEGV || sig == SIGBUS))
		cs_dumpstack(sig);

	set_signal_handler(SIGCHLD, 1, SIG_IGN);
	set_signal_handler(SIGHUP , 1, SIG_IGN);
	set_signal_handler(SIGPIPE, 1, SIG_IGN);

	if (sig==SIGALRM) {
		cs_debug_mask(D_TRACE, "thread %8lX: SIGALRM, skipping", (unsigned long)pthread_self());
		return;
	}

  if (sig && (sig!=SIGQUIT))
    cs_log("thread %8lX exit with signal %d", (unsigned long)pthread_self(), sig);

  struct s_client *cl = cur_client();
  if (!cl)
  	return;

	if (cl->typ == 'h' || cl->typ == 's') {
		led_status_stopping();
		led_stop();
		lcd_thread_stop();

#if !defined(__CYGWIN__)
	char targetfile[256];
		snprintf(targetfile, 255, "%s%s", get_tmp_dir(), "/oscam.version");
		if (unlink(targetfile) < 0)
			cs_log("cannot remove oscam version file %s (errno=%d %s)", targetfile, errno, strerror(errno));
#endif
		coolapi_close_all();
  }

	// this is very important - do not remove
	if (cl->typ != 's') {
		cs_debug_mask(D_TRACE, "thread %8lX ended!", (unsigned long)pthread_self());

		cleanup_thread(cl);

		//Restore signals before exiting thread
		set_signal_handler(SIGPIPE , 0, cs_sigpipe);
		set_signal_handler(SIGHUP  , 1, cs_reload_config);

		pthread_exit(NULL);
		return;
	}

	cs_log("cardserver down");

	cs_cleanup();

	if (!exit_oscam)
	  exit_oscam = sig?sig:1;

	if (sig == SIGINT)
		exit(sig);
}

/* Checks if the date of the system is correct and waits if necessary. */
static void init_check(void){
	char *ptr = __DATE__;
	int32_t month, year = atoi(ptr + strlen(ptr) - 4), day = atoi(ptr + 4);
	if(day > 0 && day < 32 && year > 2010 && year < 9999){
		struct tm timeinfo;
		char months[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
		for(month = 0; month < 12; ++month){
			if(!strncmp(ptr, months[month], 3)) break;
		}
		if(month > 11) month = 0;
		memset(&timeinfo, 0, sizeof(timeinfo));
		timeinfo.tm_mday = day;
		timeinfo.tm_mon = month;
		timeinfo.tm_year = year - 1900;
		time_t builddate = mktime(&timeinfo) - 86400;
	  int32_t i = 0;
	  while(time((time_t*)0) < builddate){
	  	if(i == 0) cs_log("The current system time is smaller than the build date (%s). Waiting up to %d seconds for time to correct", ptr, cs_waittime);
	  	cs_sleepms(1000);
	  	++i;
	  	if(i > cs_waittime){
	  		cs_log("Waiting was not successful. OSCam will be started but is UNSUPPORTED this way. Do not report any errors with this version.");
				break;
	  	}
	  }
	  // adjust login time of first client
	  if(i > 0) first_client->login=time((time_t *)0);
	}
}

static int32_t start_listener(struct s_module *ph, int32_t port_idx)
{
  int32_t ov=1, timeout, is_udp, i;
  char ptxt[2][32];
  struct SOCKADDR sad;     /* structure to hold server's address */
  socklen_t sad_len;
  cs_log("Starting listener %d", port_idx);

  ptxt[0][0]=ptxt[1][0]='\0';
  if (!ph->ptab->ports[port_idx].s_port)
  {
    cs_log("%s: disabled", ph->desc);
    return(0);
  }
  is_udp=(ph->type==MOD_CONN_UDP);

  memset((char  *)&sad,0,sizeof(sad)); /* clear sockaddr structure   */
#ifdef IPV6SUPPORT
  SIN_GET_FAMILY(sad) = AF_INET6;            /* set family to Internet     */
  SIN_GET_ADDR(sad) = in6addr_any;
  sad_len = sizeof(struct sockaddr_in6);
#else
  sad.sin_family = AF_INET;            /* set family to Internet     */
  sad_len = sizeof(struct sockaddr);
  if (!ph->s_ip)
    ph->s_ip=cfg.srvip;
  if (ph->s_ip)
  {
    sad.sin_addr.s_addr=ph->s_ip;
    snprintf(ptxt[0], sizeof(ptxt[0]), ", ip=%s", inet_ntoa(sad.sin_addr));
  }
  else
    sad.sin_addr.s_addr=INADDR_ANY;
#endif
  timeout=cfg.bindwait;
  //ph->fd=0;
  ph->ptab->ports[port_idx].fd = 0;

  if (ph->ptab->ports[port_idx].s_port > 0)   /* test for illegal value    */
    SIN_GET_PORT(sad) = htons((uint16_t)ph->ptab->ports[port_idx].s_port);
  else
  {
    cs_log("%s: Bad port %d", ph->desc, ph->ptab->ports[port_idx].s_port);
    return(0);
  }

  int s_domain = PF_INET;
#ifdef IPV6SUPPORT
  s_domain = PF_INET6;
#endif
  int s_type   = is_udp ? SOCK_DGRAM : SOCK_STREAM;
  int s_proto  = is_udp ? IPPROTO_UDP : IPPROTO_TCP;

  if ((ph->ptab->ports[port_idx].fd = socket(s_domain, s_type, s_proto)) < 0)
  {
    cs_log("%s: Cannot create socket (errno=%d: %s)", ph->desc, errno, strerror(errno));
#ifdef IPV6SUPPORT
    cs_log("%s: Trying fallback to IPv4", ph->desc);
    s_domain = PF_INET;
    if ((ph->ptab->ports[port_idx].fd = socket(s_domain, s_type, s_proto)) < 0)
    {
      cs_log("%s: Cannot create socket (errno=%d: %s)", ph->desc, errno, strerror(errno));
      return(0);
    }
#else
    return(0);
#endif
  }

#ifdef IPV6SUPPORT
// azbox toolchain do not have this define
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 26
#endif
  // set the server socket option to listen on IPv4 and IPv6 simultaneously
  int val = 0;
  if (setsockopt(ph->ptab->ports[port_idx].fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&val, sizeof(val))<0)
  {
    cs_log("%s: setsockopt(IPV6_V6ONLY) failed (errno=%d: %s)", ph->desc, errno, strerror(errno));
  }
#endif

  ov=1;
  if (setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_REUSEADDR, (void *)&ov, sizeof(ov))<0)
  {
    cs_log("%s: setsockopt failed (errno=%d: %s)", ph->desc, errno, strerror(errno));
    close(ph->ptab->ports[port_idx].fd);
    return(ph->ptab->ports[port_idx].fd=0);
  }

#ifdef SO_REUSEPORT
  setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_REUSEPORT, (void *)&ov, sizeof(ov));
#endif

  if (set_socket_priority(ph->ptab->ports[port_idx].fd, cfg.netprio) > -1)
      snprintf(ptxt[1], sizeof(ptxt[1]), ", prio=%d", cfg.netprio);

  if( !is_udp )
  {
    int32_t keep_alive = 1;
    setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_KEEPALIVE,
               (void *)&keep_alive, sizeof(keep_alive));
  }

  while (timeout--)
  {
    if (bind(ph->ptab->ports[port_idx].fd, (struct sockaddr *)&sad, sad_len) < 0)
    {
      if (timeout)
      {
        cs_log("%s: Bind request failed (%s), waiting another %d seconds",
               ph->desc, strerror(errno), timeout);
        cs_sleepms(1000);
      }
      else
      {
        cs_log("%s: Bind request failed (%s), giving up", ph->desc, strerror(errno));
        close(ph->ptab->ports[port_idx].fd);
        return(ph->ptab->ports[port_idx].fd=0);
      }
    }
    else timeout=0;
  }

  if (!is_udp)
    if (listen(ph->ptab->ports[port_idx].fd, CS_QLEN)<0)
    {
      cs_log("%s: Cannot start listen mode (errno=%d: %s)", ph->desc, errno, strerror(errno));
      close(ph->ptab->ports[port_idx].fd);
      return(ph->ptab->ports[port_idx].fd=0);
    }

	cs_log("%s: initialized (fd=%d, port=%d%s%s%s)",
         ph->desc, ph->ptab->ports[port_idx].fd,
         ph->ptab->ports[port_idx].s_port,
         ptxt[0], ptxt[1], ph->logtxt ? ph->logtxt : "");

	for( i=0; i<ph->ptab->ports[port_idx].ftab.nfilts; i++ ) {
		int32_t j, pos=0;
		char buf[30 + (8*ph->ptab->ports[port_idx].ftab.filts[i].nprids)];
		pos += snprintf(buf, sizeof(buf), "-> CAID: %04X PROVID: ", ph->ptab->ports[port_idx].ftab.filts[i].caid );

		for( j=0; j<ph->ptab->ports[port_idx].ftab.filts[i].nprids; j++ )
			pos += snprintf(buf+pos, sizeof(buf)-pos, "%06X, ", ph->ptab->ports[port_idx].ftab.filts[i].prids[j]);

		if(pos>2 && j>0)
			buf[pos-2] = '\0';

		cs_log("%s", buf);
	}

	return(ph->ptab->ports[port_idx].fd);
}

/* Starts a thread named nameroutine with the start function startroutine. */
void start_thread(void * startroutine, char * nameroutine) {
	pthread_t temp;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	cs_log("starting thread %s", nameroutine);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	cs_writelock(&system_lock);
	int32_t ret = pthread_create(&temp, &attr, startroutine, NULL);
	if (ret)
		cs_log("ERROR: can't create %s thread (errno=%d %s)", nameroutine, ret, strerror(ret));
	else {
		cs_log("%s thread started", nameroutine);
		pthread_detach(temp);
	}
	pthread_attr_destroy(&attr);
	cs_writeunlock(&system_lock);
}

/* Allows to kill another thread specified through the client cl with locking.
  If the own thread has to be cancelled, cs_exit or cs_disconnect_client has to be used. */
void kill_thread(struct s_client *cl) {
	if (!cl || cl->kill) return;
	if (cl == cur_client()) {
		cs_log("Trying to kill myself, exiting.");
		cs_exit(0);
	}
	add_job(cl, ACTION_CLIENT_KILL, NULL, 0); //add kill job, ...
	cl->kill=1;                               //then set kill flag!
}

/* Removes a reader from the list of active readers so that no ecms can be requested anymore. */
void remove_reader_from_active(struct s_reader *rdr) {
	struct s_reader *rdr2, *prv = NULL;
	//rdr_log(rdr, "CHECK: REMOVE READER FROM ACTIVE");
	cs_writelock(&readerlist_lock);
	for (rdr2=first_active_reader; rdr2 ; prv=rdr2, rdr2=rdr2->next) {
		if (rdr2==rdr) {
			if (prv) prv->next = rdr2->next;
			else first_active_reader = rdr2->next;
			break;
		}
	}
	rdr->next = NULL;
	rdr->active=0;
	cs_writeunlock(&readerlist_lock);
}

/* Adds a reader to the list of active readers so that it can serve ecms. */
void add_reader_to_active(struct s_reader *rdr) {
	struct s_reader *rdr2, *rdr_prv=NULL, *rdr_tmp=NULL;
	int8_t at_first = 1;

	if (rdr->next)
		remove_reader_from_active(rdr);

	//rdr_log(rdr, "CHECK: ADD READER TO ACTIVE");
	cs_writelock(&readerlist_lock);
	cs_writelock(&clientlist_lock);

	//search configured position:
	LL_ITER it = ll_iter_create(configured_readers);
	while ((rdr2=ll_iter_next(&it))) {
		if(rdr2==rdr) break;
		if (rdr2->client && rdr2->enable) {
			rdr_prv = rdr2;
			at_first = 0;
		}
	}

	//insert at configured position:
	if (first_active_reader) {
		if (at_first) {
			rdr->next = first_active_reader;
			first_active_reader = rdr;

			//resort client list:
			struct s_client *prev, *cl;
			for (prev = first_client, cl = first_client->next;
					prev->next != NULL; prev = prev->next, cl = cl->next)
				if (rdr->client == cl)
					break;

			if (cl && rdr->client == cl) {
				prev->next = cl->next; //remove client from list
				cl->next = first_client->next;
				first_client->next = cl;
			}
		}
		else
		{
			for (rdr2=first_active_reader; rdr2->next && rdr2 != rdr_prv ; rdr2=rdr2->next) ; //search last element
			rdr_prv = rdr2;
			rdr_tmp = rdr2->next;
			rdr2->next = rdr;
			rdr->next = rdr_tmp;

			//resort client list:
			struct s_client *prev, *cl;
			for (prev = first_client, cl = first_client->next;
					prev->next != NULL; prev = prev->next, cl = cl->next)
				if (rdr->client == cl)
					break;
			if (cl && rdr->client == cl) {
				prev->next = cl->next; //remove client from list
				cl->next = rdr_prv->client->next;
				rdr_prv->client->next = cl;
			}
		}

	} else first_active_reader = rdr;
	rdr->active=1;
	cs_writeunlock(&clientlist_lock);
	cs_writeunlock(&readerlist_lock);
}

/* Starts or restarts a cardreader without locking. If restart=1, the existing thread is killed before restarting,
   if restart=0 the cardreader is only started. */
static int32_t restart_cardreader_int(struct s_reader *rdr, int32_t restart) {
	struct s_client *cl = rdr->client;
	if (restart){
		remove_reader_from_active(rdr);		//remove from list
		kill_thread(cl); //kill old thread
		cs_sleepms(500);
	}

	while (restart && is_valid_client(cl)) {
		//If we quick disable+enable a reader (webif), remove_reader_from_active is called from
		//cleanup. this could happen AFTER reader is restarted, so oscam crashes or reader is hidden
		//rdr_log(rdr, "CHECK: WAITING FOR CLEANUP");
		cs_sleepms(500);
	}

	rdr->client = NULL;
	rdr->tcp_connected = 0;
	rdr->card_status = UNKNOWN;
	rdr->tcp_block_delay = 100;
	cs_ftime(&rdr->tcp_block_connect_till);

	if (rdr->device[0] && is_cascading_reader(rdr)) {
		if (!rdr->ph.num) {
			rdr_log(rdr, "Protocol Support missing. (typ=%d)", rdr->typ);
			return 0;
		}
		rdr_debug_mask(rdr, D_TRACE, "protocol: %s", rdr->ph.desc);
	}

	if (!rdr->enable)
		return 0;

	if (rdr->device[0]) {
		if (restart) {
			rdr_log(rdr, "Restarting reader");
		}
		cl = create_client(first_client->ip);
		if (cl == NULL) return 0;
		cl->reader=rdr;
		rdr_log(rdr, "creating thread for device %s", rdr->device);

		cl->sidtabok=rdr->sidtabok;
		cl->sidtabno=rdr->sidtabno;
		cl->grp = rdr->grp;

		rdr->client=cl;

		cl->typ='r';
		//client[i].ctyp=99;

		add_job(cl, ACTION_READER_INIT, NULL, 0);
		add_reader_to_active(rdr);

		return 1;
	}
	return 0;
}

/* Starts or restarts a cardreader with locking. If restart=1, the existing thread is killed before restarting,
   if restart=0 the cardreader is only started. */
int32_t restart_cardreader(struct s_reader *rdr, int32_t restart) {
	cs_writelock(&system_lock);
	int32_t result = restart_cardreader_int(rdr, restart);
	cs_writeunlock(&system_lock);
	return result;
}

static void init_cardreader(void) {

	cs_debug_mask(D_TRACE, "cardreader: Initializing");
	cs_writelock(&system_lock);
	struct s_reader *rdr;

	cardreader_init_locks();

	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) {
		if (rdr->enable) {
			restart_cardreader_int(rdr, 0);
		}
	}

	load_stat_from_file();
	cs_writeunlock(&system_lock);
}

/**
 * get ecm from ecmcache
 **/
struct ecm_request_t *check_cwcache(ECM_REQUEST *er, struct s_client *cl)
{
	time_t now = time(NULL);
	//time_t timeout = now-(time_t)(cfg.ctimeout/1000)-CS_CACHE_TIMEOUT;
	time_t timeout = now-cfg.max_cache_time;
	struct ecm_request_t *ecm;
	uint64_t grp = cl?cl->grp:0;
#ifdef CS_CACHEEX
	// precalculate for better performance
	uint8_t ecmd5chk = checkECMD5(er);
	bool hasMatchAlias = cacheex_is_match_alias(cl, er);
#endif
	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		if (ecm->tps.time < timeout) {
			ecm = NULL;
			break;
		}
		if (ecm->ecmcacheptr)
			continue;

		if ((grp && ecm->grp && !(grp & ecm->grp)))
			continue;

#ifdef CS_CACHEEX
		if (!hasMatchAlias || !cacheex_match_alias(cl, er, ecm)) {
			//CWs from csp/cacheex have no ecms, csp ecmd5 is invalid, cacheex has ecmd5
			if (ecmd5chk && checkECMD5(ecm)){
				if (memcmp(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
					continue; // no match
			} else if (ecm->csp_hash != er->csp_hash) //fallback for csp only
				continue; // no match
		}
#else
		if (memcmp(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
				continue; // no match
#endif

		if (er->caid != ecm->caid && ecm->rc >= E_NOTFOUND && !is_betatunnel_caid(er->caid))
			continue; //CW for the cached ECM wasn't found but now the client asks on a different caid so give it another try
				
		if (ecm->rc != E_99){
			cs_readunlock(&ecmcache_lock);
			return ecm;
		}
	}
	cs_readunlock(&ecmcache_lock);
	return NULL; // nothing found so return null
}

/*
 * write_ecm_request():
 */
static int32_t write_ecm_request(struct s_reader *rdr, ECM_REQUEST *er)
{
	add_job(rdr->client, ACTION_READER_ECM_REQUEST, (void*)er, 0);
	return 1;
}


/**
 * distributes found ecm-request to all clients with rc=99
 **/
static void distribute_ecm(ECM_REQUEST *er, int32_t rc)
{
	struct ecm_request_t *ecm;

	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		if (ecm != er && ecm->rc >= E_99 && ecm->ecmcacheptr == er) {
			cacheex_init_cacheex_src(ecm, er);
			write_ecm_answer(er->selected_reader, ecm, rc, 0, er->cw, NULL);
		}
	}
	cs_readunlock(&ecmcache_lock);
}

void update_chid(ECM_REQUEST *er)
{
	if( (er->caid>>8) == 0x06 && !er->chid && er->ecmlen > 7)
		er->chid = (er->ecm[6]<<8)|er->ecm[7];
}

int32_t write_ecm_answer(struct s_reader * reader, ECM_REQUEST *er, int8_t rc, uint8_t rcEx, uchar *cw, char *msglog)
{
	int32_t i;
	uchar c;
	struct s_ecm_answer *ea = NULL, *ea_list, *ea_org = NULL;
	struct timeb now;

	//if (!er->parent && !er->client) //distribute also if no client is set!
	//	return 0;

	cs_ftime(&now);

	if (er->parent) {
		// parent is only set on reader->client->ecmtask[], but we want client->ecmtask[]
		// this means: reader has a ecm copy from client, so point to client
		er->rc = rc;
		er->idx = 0;
		er = er->parent; //Now er is "original" ecm, before it was the reader-copy
		er->grp |= reader->grp; // extend grp by grp of answering reader so clients in other group use cache

		if (er->rc < E_99) {
			send_reader_stat(reader, er, NULL, rc);
			return 0;  //Already done
		}
	}

	for(ea_list = er->matching_rdr; reader && ea_list && !ea_org; ea_list = ea_list->next) {
		if (ea_list->reader == reader)
			ea_org = ea_list;
	}

	if (!ea_org) {
		if (!cs_malloc(&ea, sizeof(struct s_ecm_answer))) // Freed by ACTION_CLIENT_ECM_ANSWER
			return 0;
	} else
		ea = ea_org;

	if (cw)
		memcpy(ea->cw, cw, 16);

	if (msglog)
		memcpy(ea->msglog, msglog, MSGLOGSIZE);

	ea->rc = rc;
	ea->rcEx = rcEx;
	ea->reader = reader;
	ea->status |= REQUEST_ANSWERED;
	ea->er = er;

	if (reader && rc<E_NOTFOUND) {
        if (reader->disablecrccws == 0) {
           for (i=0; i<16; i+=4) {
               c=((ea->cw[i]+ea->cw[i+1]+ea->cw[i+2]) & 0xff);
               if (ea->cw[i+3]!=c) {
                   if (reader->dropbadcws) {
                      ea->rc = E_NOTFOUND;
                      ea->rcEx = E2_WRONG_CHKSUM;
                      break;
                   } else {
                      cs_debug_mask(D_TRACE, "notice: changed dcw checksum byte cw[%i] from %02x to %02x", i+3, ea->cw[i+3],c);
                      ea->cw[i+3]=c;
                   }
               }
          }
        }
        else {
              cs_debug_mask(D_TRACE, "notice: CW checksum check disabled");
        }
	}

	if (reader && ea->rc==E_FOUND) {
		/* CWL logging only if cwlogdir is set in config */
		if (cfg.cwlogdir != NULL)
			logCWtoFile(er, ea->cw);
	}

	int32_t res = 0;
	struct s_client *cl = er->client;
	if (cl && !cl->kill) {
		if (ea_org) { //duplicate for queue
			if (!cs_malloc(&ea, sizeof(struct s_ecm_answer)))
				return 0;
			memcpy(ea, ea_org, sizeof(struct s_ecm_answer));
		}
		add_job(cl, ACTION_CLIENT_ECM_ANSWER, ea, sizeof(struct s_ecm_answer));
		res = 1;
	} else { //client has disconnected. Distribute ecms to other waiting clients
		if (!er->ecmcacheptr)
			chk_dcw(NULL, ea);
		if (!ea_org)
			free(ea);
	}

	if (reader && rc == E_FOUND && reader->resetcycle > 0)
	{
		reader->resetcounter++;
		if (reader->resetcounter > reader->resetcycle) {
			reader->resetcounter = 0;
			rdr_log(reader, "Resetting reader, resetcyle of %d ecms reached", reader->resetcycle);
			reader->card_status = CARD_NEED_INIT;
			cardreader_reset(cl);
		}
	}

	return res;
}

ECM_REQUEST *get_ecmtask(void)
{
	ECM_REQUEST *er = NULL;
	struct s_client *cl = cur_client();
	if(!cl) return NULL;

	if (!cs_malloc(&er,sizeof(ECM_REQUEST)))
		return NULL;

	cs_ftime(&er->tps);
	er->rc=E_UNHANDLED;
	er->client=cl;
	er->grp = cl->grp;
	//cs_log("client %s ECMTASK %d multi %d ctyp %d", username(cl), n, (modules[cl->ctyp].multi)?cfg.max_pending:1, cl->ctyp);

	return(er);
}

/**
 * Check for NULL CWs
 * Return them as "NOT FOUND"
 **/
static void checkCW(ECM_REQUEST *er)
{
	int8_t i;
	for (i=0;i<16;i++)
		if (er->cw[i]) return;
	er->rc = E_NOTFOUND;
}

static void add_cascade_data(struct s_client *client, ECM_REQUEST *er)
{
	if (!client->cascadeusers)
		client->cascadeusers = ll_create("cascade_data");
	LLIST *l = client->cascadeusers;
	LL_ITER it = ll_iter_create(l);
	time_t now = time(NULL);
	struct s_cascadeuser *cu;
	int8_t found=0;
	while ((cu=ll_iter_next(&it))) {
		if (er->caid==cu->caid && er->prid==cu->prid && er->srvid==cu->srvid) { //found it
			if (cu->time < now)
				cu->cwrate = now-cu->time;
			cu->time = now;
			found=1;
		}
		else if (cu->time+60 < now) //  old
			ll_iter_remove_data(&it);
	}
	if (!found) { //add it if not found
		if (!cs_malloc(&cu, sizeof(struct s_cascadeuser)))
			return;
		cu->caid = er->caid;
		cu->prid = er->prid;
		cu->srvid = er->srvid;
		cu->time = now;
		ll_append(l, cu);
	}
}

int32_t is_double_check_caid(ECM_REQUEST *er)
{
        if (!cfg.double_check_caid.caid[0]) //no caids defined: Check all
            return 1;
            
        int32_t i;
        for (i=0;i<CS_MAXCAIDTAB;i++) {
            uint16_t tcaid = cfg.double_check_caid.caid[i];
            if (!tcaid) break;
            if ((tcaid == er->caid) || (tcaid < 0x0100 && (er->caid >> 8) == tcaid)) {
                return 1;
            }
        }
        return 0;
}

int32_t send_dcw(struct s_client * client, ECM_REQUEST *er)
{
	if (!client || client->kill || client->typ != 'c')
		return 0;

	static const char stageTxt[]={'0','C','L','P','F','X'};
	static const char *stxt[]={"found", "cache1", "cache2", "cache3",
			"not found", "timeout", "sleeping",
			"fake", "invalid", "corrupt", "no card", "expdate", "disabled", "stopped"};
	static const char *stxtEx[16]={"", "group", "caid", "ident", "class", "chid", "queue", "peer", "sid", "", "", "", "", "", "", ""};
	static const char *stxtWh[16]={"", "user ", "reader ", "server ", "lserver ", "", "", "", "", "", "", "", "" ,"" ,"", ""};
	char sby[100]="", sreason[32]="", schaninfo[32]="";
	char erEx[32]="";
	char uname[38]="";
	char channame[32];
	struct timeb tpe;

	snprintf(uname,sizeof(uname)-1, "%s", username(client));

	if (er->rc < E_NOTFOUND)
		checkCW(er);

#ifdef WITH_DEBUG
        if (cs_dblevel & D_CLIENTECM) {		
                char buf[ECM_FMT_LEN];
                format_ecm(er, buf, ECM_FMT_LEN);

                char ecmd5[17*3];                
                cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
                char cwstr[17*3];
                cs_hexdump(0, er->cw, 16, cwstr, sizeof(cwstr));
#ifdef CS_CACHEEX
                char csphash[5*3];
                cs_hexdump(0, (void*)&er->csp_hash, 4, csphash, sizeof(csphash));
                cs_debug_mask(D_CLIENTECM, "Client %s csphash %s cw %s rc %d %s", username(client), csphash, cwstr, er->rc, buf);
#else            
                cs_debug_mask(D_CLIENTECM, "Client %s cw %s rc %d %s", username(client), cwstr, er->rc, buf);
#endif
        }
#endif

	struct s_reader *er_reader = er->selected_reader; //responding reader

	if (er_reader) {
		// add marker to reader if ECM_REQUEST was betatunneled
		if(er->ocaid)
			snprintf(sby, sizeof(sby)-1, " by %s(btun %04X)", er_reader->label, er->ocaid);
		else
			snprintf(sby, sizeof(sby)-1, " by %s", er_reader->label);
	} else if (er->rc == E_TIMEOUT) {
                struct s_ecm_answer *ea_list;
                int32_t ofs = 0;
	        for(ea_list = er->matching_rdr; ea_list; ea_list = ea_list->next) {
	                if (ea_list->reader && ofs < (int32_t)sizeof(sby) && (ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED)) == REQUEST_SENT) { //Request send, but no answer!
	                        ofs += snprintf(sby+ofs, sizeof(sby)-ofs-1, "%s%s", ofs?",":" by ", ea_list->reader->label);
                        }
                }
                if(er->ocaid && ofs < (int32_t)sizeof(sby))
	                ofs += snprintf(sby+ofs, sizeof(sby)-ofs-1, "(btun %04X)", er->ocaid);
	}

	if (er->rc < E_NOTFOUND) er->rcEx=0;
	if (er->rcEx)
		snprintf(erEx, sizeof(erEx)-1, "rejected %s%s", stxtWh[er->rcEx>>4],
				stxtEx[er->rcEx&0xf]);

	if (cfg.appendchaninfo)
		snprintf(schaninfo, sizeof(schaninfo)-1, " - %s", get_servicename(client, er->srvid, er->caid, channame));

	if(er->msglog[0])
		snprintf(sreason, sizeof(sreason)-1, " (%s)", er->msglog);

	cs_ftime(&tpe);
	client->cwlastresptime = 1000 * (tpe.time-er->tps.time) + tpe.millitm-er->tps.millitm;

	time_t now = time(NULL);
	webif_client_add_lastresponsetime(client, client->cwlastresptime, now, er->rc); // add to ringbuffer

	if (er_reader){
		struct s_client *er_cl = er_reader->client;
		if(er_cl){
			er_cl->cwlastresptime = client->cwlastresptime;
			webif_client_add_lastresponsetime(er_cl, client->cwlastresptime, now, er->rc);
			er_cl->last_srvidptr=client->last_srvidptr;
		}
	}

	webif_client_init_lastreader(client, er, er_reader, stxt);

	client->last = now;

	//cs_debug_mask(D_TRACE, "CHECK rc=%d er->cacheex_src=%s", er->rc, username(er->cacheex_src));
	switch(er->rc) {
		case E_FOUND:
					client->cwfound++;
			                client->account->cwfound++;
					first_client->cwfound++;
					break;

		case E_CACHE1:
		case E_CACHE2:
		case E_CACHEEX:
			client->cwcache++;
			client->account->cwcache++;
			first_client->cwcache++;
#ifdef CS_CACHEEX
			if (er->cacheex_src) {
				er->cacheex_src->cwcacheexhit++;
				if (er->cacheex_src->account)
					er->cacheex_src->account->cwcacheexhit++;
				first_client->cwcacheexhit++;
			}
#endif
			break;

		case E_NOTFOUND:
		case E_CORRUPT:
		case E_NOCARD:
			if (er->rcEx) {
				client->cwignored++;
				client->account->cwignored++;
				first_client->cwignored++;
			} else {
				client->cwnot++;
				client->account->cwnot++;
				first_client->cwnot++;
                        }
			break;

		case E_TIMEOUT:
			client->cwtout++;
			client->account->cwtout++;
			first_client->cwtout++;
			break;

		default:
			client->cwignored++;
			client->account->cwignored++;
			first_client->cwignored++;
	}

	ac_chk(client, er, 1);

	int32_t is_fake = 0;
	if (er->rc==E_FAKE) {
		is_fake = 1;
		er->rc=E_FOUND;
	}

	if (cfg.double_check &&  er->rc == E_FOUND && er->selected_reader && is_double_check_caid(er)) {
	  if (er->checked == 0) {//First CW, save it and wait for next one
	    er->checked = 1;
	    er->origin_reader = er->selected_reader;
	    memcpy(er->cw_checked, er->cw, sizeof(er->cw));
	    cs_log("DOUBLE CHECK FIRST CW by %s idx %d cpti %d", er->origin_reader->label, er->idx, er->msgid);
	  }
	  else if (er->origin_reader != er->selected_reader) { //Second (or third and so on) cw. We have to compare
	    if (memcmp(er->cw_checked, er->cw, sizeof(er->cw)) == 0) {
	    	er->checked++;
	    	cs_log("DOUBLE CHECKED! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->msgid);
	    }
	    else {
	    	cs_log("DOUBLE CHECKED NONMATCHING! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->msgid);
	    }
	  }

	  if (er->checked < 2) { //less as two same cw? mark as pending!
	    er->rc = E_UNHANDLED;
	    return 0;
	  }
	}

	modules[client->ctyp].send_dcw(client, er);

	add_cascade_data(client, er);

	if (is_fake)
		er->rc = E_FAKE;

	if (!(er->rc == E_SLEEPING && client->cwlastresptime == 0)) {
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		if (er->reader_avail == 1) {
			cs_log("%s (%s): %s (%d ms)%s %s%s",
				uname, buf,
				er->rcEx?erEx:stxt[er->rc], client->cwlastresptime, sby, schaninfo, sreason);
		} else {
			cs_log("%s (%s): %s (%d ms)%s (%c/%d/%d/%d)%s%s",
				uname, buf,
				er->rcEx?erEx:stxt[er->rc], client->cwlastresptime, sby,
						stageTxt[er->stage], er->reader_requested, er->reader_count, er->reader_avail,
						schaninfo, sreason);
		}
	}

	cs_ddump_mask (D_ATR, er->cw, 16, "cw:");

	led_status_cw_not_found(er);

	return 0;
}

/**
 * sends the ecm request to the readers
 * ECM_REQUEST er : the ecm
 * er->stage: 0 = no reader asked yet
 *            2 = ask only local reader (skipped without preferlocalcards)
 *            3 = ask any non fallback reader
 *            4 = ask fallback reader
 **/
static void request_cw(ECM_REQUEST *er)
{
	struct s_ecm_answer *ea;
	int8_t sent = 0;

	if (er->stage >= 4) return;

	while (1) {
		er->stage++;

#ifndef CS_CACHEEX
		if (er->stage == 1)
			er->stage++;
#endif
		if (er->stage == 2 && !cfg.preferlocalcards)
			er->stage++;

		for(ea = er->matching_rdr; ea; ea = ea->next) {

			switch(er->stage) {
#ifdef CS_CACHEEX
			case 1:
				// Cache-Echange
				if ((ea->status & REQUEST_SENT) ||
						(ea->status & (READER_CACHEEX|READER_ACTIVE)) != (READER_CACHEEX|READER_ACTIVE))
					continue;
				break;
#endif
			case 2:
				// only local reader
				if ((ea->status & REQUEST_SENT) ||
						(ea->status & (READER_ACTIVE|READER_FALLBACK|READER_LOCAL)) != (READER_ACTIVE|READER_LOCAL))
					continue;
				break;

			case 3:
				// any non fallback reader not asked yet
				if ((ea->status & REQUEST_SENT) ||
						(ea->status & (READER_ACTIVE|READER_FALLBACK)) != READER_ACTIVE)
					continue;
				break;

			default:
				// only fallbacks
				if (!(ea->status & (READER_ACTIVE|READER_FALLBACK)))
				    continue;
				    
				if (ea->status & REQUEST_SENT)
				{
				        if (ea->reader && ea->reader->client && ea->reader->client->is_udp) //Always resend on udp
				                break;
				                
					if (er->reader_count > 1) //do not resend to the same reader(s) if we have more than one reader
						continue;
				}
				break;
			}

			struct s_reader *rdr = ea->reader;
			char ecmd5[17*3];                
            cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
			cs_debug_mask(D_TRACE | D_CSPCWC, "request_cw stage=%d to reader %s ecm hash=%s", er->stage, rdr?rdr->label:"", ecmd5);
			
			ea->status |= REQUEST_SENT;
			er->reader_requested++;
			write_ecm_request(ea->reader, er);

			//set sent=1 only if reader is active/connected. If not, switch to next stage!
			if (!sent && rdr) {
				struct s_client *rcl = rdr->client;
				if(rcl){
					if (rcl->typ=='r' && rdr->card_status==CARD_INSERTED)
						sent = 1;
					else if (rcl->typ=='p' && (rdr->card_status==CARD_INSERTED ||rdr->tcp_connected))
						sent = 1;
				}
			}
		}
		if (sent || er->stage >= 4)
			break;
	}
}

static void chk_dcw(struct s_client *cl, struct s_ecm_answer *ea)
{
	if (!ea || !ea->er)
		return;

	ECM_REQUEST *ert = ea->er;
	struct s_ecm_answer *ea_list;
	struct s_reader *eardr = ea->reader;
	if(!ert)
		return;

	if (eardr) {
		char ecmd5[17*3];                
        cs_hexdump(0, ert->ecmd5, 16, ecmd5, sizeof(ecmd5));
		rdr_debug_mask(eardr, D_TRACE, "ecm answer for ecm hash %s rc=%d", ecmd5, ea->rc);
		//rdr_ddump_mask(eardr, D_TRACE, ea->cw, sizeof(ea->cw), "received cw caid=%04X srvid=%04X hash=%08X",
		//		ert->caid, ert->srvid, ert->csp_hash);
		//rdr_ddump_mask(eardr, D_TRACE, ert->ecm, ert->ecmlen, "received cw for ecm caid=%04X srvid=%04X hash=%08X",
		//		ert->caid, ert->srvid, ert->csp_hash);
	}

	ea->status |= REQUEST_ANSWERED;

	if (eardr) {
		//Update reader stats:
		if (ea->rc == E_FOUND) {
			eardr->ecmsok++;
#ifdef CS_CACHEEX
			struct s_client *eacl = eardr->client;
			if (cacheex_reader(eardr) && !ert->cacheex_done && eacl) {
				eacl->cwcacheexgot++;
				cacheex_add_stats(eacl, ea->er->caid, ea->er->srvid, ea->er->prid, 1);
				first_client->cwcacheexgot++;
			}
#endif
		}
		else if (ea->rc == E_NOTFOUND)
			eardr->ecmsnok++;

		//Reader ECMs Health Try (by Pickser)
		if (eardr->ecmsok != 0 || eardr->ecmsnok != 0)
		{
			eardr->ecmshealthok = ((double) eardr->ecmsok / (eardr->ecmsok + eardr->ecmsnok)) * 100;
			eardr->ecmshealthnok = ((double) eardr->ecmsnok / (eardr->ecmsok + eardr->ecmsnok)) * 100;
		}

		//Reader Dynamic Loadbalancer Try (by Pickser)
		/*
		 * todo: config-option!
		 *
#ifdef WITH_LB
		if (eardr->ecmshealthok >= 75) {
			eardr->lb_weight = 100;
		} else if (eardr->ecmshealthok >= 50) {
			eardr->lb_weight = 75;
		} else if (eardr->ecmshealthok >= 25) {
			eardr->lb_weight = 50;
		} else {
			eardr->lb_weight = 25;
		}
#endif
		*/
	}

	if (ert->rc<E_99) {
		send_reader_stat(eardr, ert, ea, ea->rc);
#ifdef CS_CACHEEX
		        if (ea && ert->rc < E_NOTFOUND && ea->rc < E_NOTFOUND && memcmp(ea->cw, ert->cw, sizeof(ert->cw)) != 0) {
		                char cw1[16*3+2], cw2[16*3+2];
		                cs_hexdump(0, ea->cw, 16, cw1, sizeof(cw1));
		                cs_hexdump(0, ert->cw, 16, cw2, sizeof(cw2));
		                
		                char ip1[20]="", ip2[20]="";
		                if (ea->reader) cs_strncpy(ip1, cs_inet_ntoa(ea->reader->client->ip), sizeof(ip1));
		                if (ert->cacheex_src) cs_strncpy(ip2, cs_inet_ntoa(ert->cacheex_src->ip), sizeof(ip2));
		                else if (ert->selected_reader) cs_strncpy(ip2, cs_inet_ntoa(ert->selected_reader->client->ip), sizeof(ip2));
		                
		                ECM_REQUEST *er = ert;
        			debug_ecm(D_TRACE, "WARNING2: Different CWs %s from %s(%s)<>%s(%s): %s<>%s", buf, 
        			    username(ea->reader?ea->reader->client:cl), ip1, 
        			    er->cacheex_src?username(er->cacheex_src):(ea->reader?ea->reader->label:"unknown/csp"), ip2,
        			    cw1, cw2);
                        }
#endif
                if (ea && ea->rc < ert->rc) { //answer too late, only cache update:
                    memcpy(ert->cw, ea->cw, sizeof(ea->cw));
                    ert->rc = ea->rc;
                }

		return; // already done
	}

	int32_t reader_left = 0, local_left = 0;
#ifdef CS_CACHEEX
	int8_t cacheex_left = 0;
#endif

	switch (ea->rc) {
		case E_FOUND:
		case E_CACHE2:
		case E_CACHE1:
		case E_CACHEEX:
			memcpy(ert->cw, ea->cw, 16);
			ert->rcEx=0;
			ert->rc = ea->rc;
			ert->selected_reader = eardr;
			break;
		case E_TIMEOUT:
			ert->rc = E_TIMEOUT;
			ert->rcEx = 0;
			break;
		case E_NOTFOUND:
			ert->rcEx=ea->rcEx;
			cs_strncpy(ert->msglog, ea->msglog, sizeof(ert->msglog));
			ert->selected_reader = eardr;
			if (!ert->ecmcacheptr) {
#ifdef CS_CACHEEX
				uchar has_cacheex = 0;
#endif
				for(ea_list = ert->matching_rdr; ea_list; ea_list = ea_list->next) {
#ifdef CS_CACHEEX
					if (((ea_list->status & READER_CACHEEX)) == READER_CACHEEX)
						has_cacheex = 1;
					if (((ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED|READER_CACHEEX|READER_ACTIVE)) == (REQUEST_SENT|READER_CACHEEX|READER_ACTIVE)))
						cacheex_left++;
#endif
					if (((ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED|READER_LOCAL|READER_ACTIVE)) == (REQUEST_SENT|READER_LOCAL|READER_ACTIVE)))
						local_left++;
					if (((ea_list->status & (REQUEST_ANSWERED|READER_ACTIVE)) == (READER_ACTIVE)))
						reader_left++;
				}

#ifdef CS_CACHEEX
				if (has_cacheex && !cacheex_left && !ert->cacheex_done) {
					ert->cacheex_done = 1;
					request_cw(ert);
				} else
#endif
				if (cfg.preferlocalcards && !local_left && !ert->locals_done) {
					ert->locals_done = 1;
					request_cw(ert);
				}
			}

			break;
		default:
			cs_log("unexpected ecm answer rc=%d.", ea->rc);
			return;
			break;
	}

	if (ea->rc == E_NOTFOUND && !reader_left) {
		// no more matching reader
		ert->rc=E_NOTFOUND; //so we set the return code
	}

	send_reader_stat(eardr, ert, ea, ea->rc);

#ifdef CS_CACHEEX
	if (ea->rc < E_NOTFOUND && !ert->ecmcacheptr)
		cacheex_cache_push(ert);
#endif

	if (ert->rc < E_99) {
		if (cl) send_dcw(cl, ert);
		if (!ert->ecmcacheptr && ert->rc != E_UNHANDLED)
			distribute_ecm(ert, (ert->rc == E_FOUND)?E_CACHE2:ert->rc);
	}

	return;
}

uint32_t chk_provid(uchar *ecm, uint16_t caid) {
	int32_t i, len, descriptor_length = 0;
	uint32_t provid = 0;

	switch(caid >> 8) {
		case 0x01:
			// seca
			provid = b2i(2, ecm+3);
			break;

		case 0x05:
			// viaccess
			i = (ecm[4] == 0xD2) ? ecm[5]+2 : 0;  // skip d2 nano
			if((ecm[5+i] == 3) && ((ecm[4+i] == 0x90) || (ecm[4+i] == 0x40)))
				provid = (b2i(3, ecm+6+i) & 0xFFFFF0);

			i = (ecm[6] == 0xD2) ? ecm[7]+2 : 0;  // skip d2 nano long ecm
			if((ecm[7+i] == 7) && ((ecm[6+i] == 0x90) || (ecm[6+i] == 0x40)))
				provid = (b2i(3, ecm+8+i) & 0xFFFFF0);

			break;

		case 0x0D:
			// cryptoworks
			len = (((ecm[1] & 0xf) << 8) | ecm[2])+3;
			for(i=8; i<len; i+=descriptor_length+2) {
				descriptor_length = ecm[i+1];
				if (ecm[i] == 0x83) {
					provid = (uint32_t)ecm[i+2] & 0xFE;
					break;
				}
			}
			break;

#ifdef WITH_LB
		default:
			for (i=0;i<CS_MAXCAIDTAB;i++) {
                            uint16_t tcaid = cfg.lb_noproviderforcaid.caid[i];
                            if (!tcaid) break;
                            if (tcaid == caid) {
                        	provid = 0;
                        	break;
                            }
                            if (tcaid < 0x0100 && (caid >> 8) == tcaid) {
                                provid = 0;
                                break;
                            }
			}
#endif
	}
	return(provid);
}

void convert_to_beta(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto)
{
	static uchar headerN3[10] = {0xc7, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x87, 0x12};
	static uchar headerN2[10] = {0xc9, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x48, 0x12};

	er->ocaid = er->caid;
	er->caid = caidto;
	er->prid = 0;
	er->ecmlen = er->ecm[2] + 3;

	memmove(er->ecm + 13, er->ecm + 3, er->ecmlen - 3);

	if (er->ecmlen > 0x88) {
		memcpy(er->ecm + 3, headerN3, 10);

		if (er->ecm[0] == 0x81)
			er->ecm[12] += 1;

		er->ecm[1]=0x70;
	}
	else
		memcpy(er->ecm + 3, headerN2, 10);

	er->ecmlen += 10;
	er->ecm[2] = er->ecmlen - 3;
	er->btun = 1;

	cl->cwtun++;
	cl->account->cwtun++;
	first_client->cwtun++;

	cs_debug_mask(D_TRACE, "ECM converted ocaid from 0x%04X to BetaCrypt caid 0x%04X for service id 0x%04X",
					er->ocaid, caidto, er->srvid);
}

void convert_to_nagra(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto)
{
	cs_debug_mask(D_TRACE, "convert_to_nagra");
	er->ocaid = er->caid;
	er->caid = caidto;
	er->prid = 0;
	er->ecmlen = er->ecm[2] + 3;

	//not sure
	if (er->ecmlen < 0x52) {
		er->ecm[1]=0x30;
	}

	memmove(er->ecm + 3, er->ecm + 13, er->ecmlen - 3);

	er->ecmlen -= 10;
	er->ecm[2] = er->ecmlen - 3;
	er->btun = 1;

	cl->cwtun++;
	cl->account->cwtun++;
	first_client->cwtun++;

	cs_debug_mask(D_TRACE, "ECM converted ocaid from: 0x%04X to Nagra: 0x04%X for service id:0x04%X",
					er->ocaid, caidto, er->srvid);
}

void cs_betatunnel(ECM_REQUEST *er)
{
	int32_t n;
	struct s_client *cl = cur_client();
	uint32_t mask_all = 0xFFFF;

	TUNTAB *ttab;
	ttab = &cl->ttab;

	if (er->caid>>8 == 0x18)
		cs_ddump_mask(D_TRACE, er->ecm, 13, "betatunnel? ecmlen=%d", er->ecmlen);

	for (n = 0; n<ttab->n; n++) {
		if ((er->caid==ttab->bt_caidfrom[n]) && ((er->srvid==ttab->bt_srvid[n]) || (ttab->bt_srvid[n])==mask_all)) {
			if ((er->caid == 0x1702 || er->caid == 0x1722) && er->ocaid == 0x0000){
				convert_to_nagra(cl, er, ttab->bt_caidto[n]);
			} else if (er->ocaid == 0x0000){
				convert_to_beta(cl, er, ttab->bt_caidto[n]);
			}

			return;
		}
	}
}

static void guess_cardsystem(ECM_REQUEST *er)
{
  uint16_t last_hope=0;

  // viaccess - check by provid-search
  if( (er->prid=chk_provid(er->ecm, 0x500)) )
    er->caid=0x500;

  // nagra
  // is ecm[1] always 0x30 ?
  // is ecm[3] always 0x07 ?
  if ((er->ecm[6]==1) && (er->ecm[4]==er->ecm[2]-2))
    er->caid=0x1801;

  // seca2 - very poor
  if ((er->ecm[8]==0x10) && ((er->ecm[9]&0xF1)==1))
    last_hope=0x100;

  // is cryptoworks, but which caid ?
  if ((er->ecm[3]==0x81) && (er->ecm[4]==0xFF) &&
      (!er->ecm[5]) && (!er->ecm[6]) && (er->ecm[7]==er->ecm[2]-5))
    last_hope=0xd00;

  if (!er->caid && er->ecm[2]==0x31 && er->ecm[0x0b]==0x28)
    guess_irdeto(er);

  if (!er->caid)    // guess by len ..
    er->caid=len4caid[er->ecm[2]+3];

  if (!er->caid)
    er->caid=last_hope;
}

void get_cw(struct s_client * client, ECM_REQUEST *er)
{
	int32_t i, j, m;
	time_t now = time((time_t*)0);
	uint32_t line = 0;

	er->client = client;
	if(now - client->lastecm > cfg.hideclient_to) client->lastswitch = 0;		// user was on freetv or didn't request for some time so we reset lastswitch to get correct stats/webif display
	client->lastecm = now;

	if (client == first_client || !client ->account || client->account == first_client->account) {
		//DVBApi+serial is allowed to request anonymous accounts:
		int16_t lt = modules[client->ctyp].listenertype;
		if (lt != LIS_DVBAPI && lt != LIS_SERIAL) {
			er->rc = E_INVALID;
			er->rcEx = E2_GLOBAL;
			snprintf(er->msglog, sizeof(er->msglog), "invalid user account %s", username(client));
		}
	}

	if (er->ecmlen > MAX_ECM_SIZE) {
		er->rc = E_INVALID;
		er->rcEx = E2_GLOBAL;
		snprintf(er->msglog, sizeof(er->msglog), "ECM size %d > Max Ecm size %d, ignored! client %s", er->ecmlen, MAX_ECM_SIZE, username(client));
	}

	if (!client->grp) {
		er->rc = E_INVALID;
		er->rcEx = E2_GROUP;
		snprintf(er->msglog, sizeof(er->msglog), "invalid user group %s", username(client));
	}


	if (!er->caid)
		guess_cardsystem(er);

	/* Quickfix Area */
	update_chid(er);

	// quickfix for 0100:000065
	if (er->caid == 0x100 && er->prid == 0x00006a){ // cds nl add fix so mismatch between ecm and secatype reader wont set channel on sid blacklist 
		er->chid = b2i(2, er->ecm+7); // not quite right but good enough to function, its also registered this way in module-stat 
	}
	
	if (er->caid == 0x100 && er->prid == 0x65 && er->srvid == 0)
		er->srvid = 0x0642;

	// Quickfixes for Opticum/Globo HD9500
	// Quickfix for 0500:030300
	if (er->caid == 0x500 && er->prid == 0x030300)
		er->prid = 0x030600;

	// Quickfix for 0500:D20200
	if (er->caid == 0x500 && er->prid == 0xD20200)
		er->prid = 0x030600;

	//betacrypt ecm with nagra header
	if ((er->caid == 0x1702 || er->caid == 0x1722) && (er->ecmlen == 0x89 || er->ecmlen == 0x4A) && er->ecm[3] == 0x07 && (er->ecm[4] == 0x84 || er->ecm[4] == 0x45)){
		//cs_debug_mask(D_TRACE, "Quickfix remap beta->nagra: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[3], er->ecm[4]);
		if (er->caid == 0x1702) {
			er->caid = 0x1833;
		} else {
			check_lb_auto_betatunnel_mode(er);
		}
		cs_debug_mask(D_TRACE, "Quickfix remap beta->nagra: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[3], er->ecm[4]);
	}

	//nagra ecm with betacrypt header 1801, 1833, 1834, 1835
	if ((er->caid == 0x1801 || er->caid == 0x1833 || er->caid == 0x1834 || er->caid == 0x1835) && (er->ecmlen == 0x93 || er->ecmlen == 0x54) && er->ecm[13] == 0x07 && (er->ecm[14] == 0x84 || er->ecm[14] == 0x45)){
		//cs_debug_mask(D_TRACE, "Quickfix remap nagra->beta: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[13], er->ecm[44]);
		if (er->caid == 0x1833) {
			er->caid = 0x1702;
		} else {
			er->caid = 0x1722;
		}
		cs_debug_mask(D_TRACE, "Quickfix remap nagra->beta: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[13], er->ecm[44]);
	}

	//Ariva quickfix (invalid nagra provider)
	if (((er->caid & 0xFF00) == 0x1800) && er->prid > 0x00FFFF) er->prid=0;

	//Check for invalid provider, extract provider out of ecm:
	uint32_t prid = chk_provid(er->ecm, er->caid);
	if (!er->prid)
		er->prid = prid;
	else
	{
		if (prid && prid != er->prid) {
			cs_debug_mask(D_TRACE, "provider fixed: %04X:%06X to %04X:%06X",er->caid, er->prid, er->caid, prid);
			er->prid = prid;
		}
	}

	// Set providerid for newcamd clients if none is given
	if( (!er->prid) && client->ncd_server ) {
		int32_t pi = client->port_idx;
		if( pi >= 0 && cfg.ncd_ptab.nports && cfg.ncd_ptab.nports >= pi )
			er->prid = cfg.ncd_ptab.ports[pi].ftab.filts[0].prids[0];
	}

	// ECM nano not supported
	if (er->caid == 0x0100 && (er->prid == 0x003311 || er->prid == 0x003315) && er->ecm[5] != 0x00) {
		er->rc = E_NOTFOUND;
		er->rcEx = E2_WRONG_CHKSUM;
		snprintf( er->msglog, MSGLOGSIZE, "ECM nano %02x not supported", er->ecm[5] );
	}

	// CAID not supported or found
	if (!er->caid) {
		er->rc = E_INVALID;
		er->rcEx = E2_CAID;
		snprintf( er->msglog, MSGLOGSIZE, "CAID not supported or found" );
	}

	// user expired
	if(client->expirationdate && client->expirationdate < client->lastecm)
		er->rc = E_EXPDATE;

	// out of timeframe
	if(client->allowedtimeframe[0] && client->allowedtimeframe[1]) {
		struct tm acttm;
		localtime_r(&now, &acttm);
		int32_t curtime = (acttm.tm_hour * 60) + acttm.tm_min;
		int32_t mintime = client->allowedtimeframe[0];
		int32_t maxtime = client->allowedtimeframe[1];
		if(!((mintime <= maxtime && curtime > mintime && curtime < maxtime) || (mintime > maxtime && (curtime > mintime || curtime < maxtime)))) {
			er->rc = E_EXPDATE;
		}
		cs_debug_mask(D_TRACE, "Check Timeframe - result: %d, start: %d, current: %d, end: %d\n",er->rc, mintime, curtime, maxtime);
	}

	// user disabled
	if(client->disabled != 0) {
		if (client->failban & BAN_DISABLED){
			cs_add_violation(client, client->account->usr);
			cs_disconnect_client(client);
		}
		er->rc = E_DISABLED;
	}

	if (!chk_global_whitelist(er, &line)) {
		debug_ecm(D_TRACE, "whitelist filtered: %s (%s) line %d", username(client), buf, line);
		er->rc = E_INVALID;
	}

	// rc<100 -> ecm error
	if (er->rc >= E_UNHANDLED) {
		m = er->caid;
		i = er->srvid;

		if ((i != client->last_srvid) || (!client->lastswitch)) {
			if(cfg.usrfileflag)
				cs_statistics(client);
			client->lastswitch = now;
		}

		// user sleeping
		if ((client->tosleep) && (now - client->lastswitch > client->tosleep)) {

			if (client->failban & BAN_SLEEPING) {
				cs_add_violation(client, client->account->usr);
				cs_disconnect_client(client);
			}

			if (client->c35_sleepsend != 0) {
				er->rc = E_STOPPED; // send stop command CMD08 {00 xx}
			} else {
				er->rc = E_SLEEPING;
			}
		}

		client->last_srvid = i;
		client->last_caid = m;

		int32_t ecm_len = (((er->ecm[1] & 0x0F) << 8) | er->ecm[2]) + 3;

		for (j = 0; (j < 6) && (er->rc >= E_UNHANDLED); j++)
		{
			switch(j) {

				case 0:
					// fake (uniq)
					if (client->dup)
						er->rc = E_FAKE;
					break;

				case 1:
					// invalid (caid)
					if (!chk_bcaid(er, &client->ctab)) {
						er->rc = E_INVALID;
						er->rcEx = E2_CAID;
						snprintf( er->msglog, MSGLOGSIZE, "invalid caid 0x%04X", er->caid );
						}
					break;

				case 2:
					// invalid (srvid)
					if (!chk_srvid(client, er))
					{
						er->rc = E_INVALID;
					    snprintf( er->msglog, MSGLOGSIZE, "invalid SID" );
					}

					break;

				case 3:
					// invalid (ufilters)
					if (!chk_ufilters(er))
						er->rc = E_INVALID;
					break;

				case 4:
					// invalid (sfilter)
					if (!chk_sfilter(er, modules[client->ctyp].ptab))
						er->rc = E_INVALID;
					break;

				case 5:
					// corrupt
					if( (i = er->ecmlen - ecm_len) ) {
						if (i > 0) {
							cs_debug_mask(D_TRACE, "warning: ecm size adjusted from %d to %d", er->ecmlen, ecm_len);
							er->ecmlen = ecm_len;
						}
						else
							er->rc = E_CORRUPT;
					}
					break;
			}
		}
	}

	//Schlocke: above checks could change er->rc so
	if (er->rc >= E_UNHANDLED) {
		/*BetaCrypt tunneling
		 *moved behind the check routines,
		 *because newcamd ECM will fail
		 *if ECM is converted before
		 */
		if (client->ttab.n)
			cs_betatunnel(er);

		// ignore ecm ...
		int32_t offset = 3;
		// ... and betacrypt header for cache md5 calculation
		if ((er->caid >> 8) == 0x17)
			offset = 13;
		unsigned char md5tmp[MD5_DIGEST_LENGTH];
		// store ECM in cache
		memcpy(er->ecmd5, MD5(er->ecm + offset, er->ecmlen - offset, md5tmp), CS_ECMSTORESIZE);
		cacheex_update_hash(er);
		ac_chk(client, er, 0);
	}

	struct s_ecm_answer *ea, *prv = NULL;
	if(er->rc >= E_99 && !cacheex_is_match_alias(client, er)) {
		er->reader_avail=0;
		struct s_reader *rdr;

		cs_readlock(&readerlist_lock);
		cs_readlock(&clientlist_lock);

		for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
			int8_t match = matching_reader(er, rdr, 1); // include ratelimitercheck
#ifdef WITH_LB
			//if this reader does not match, check betatunnel for it
			if (!match && cfg.lb_auto_betatunnel) {
				uint16_t caid = get_betatunnel_caid_to(er->caid);
				if (caid) {
					uint16_t save_caid = er->caid;
					er->caid = caid;
					match = matching_reader(er, rdr, 1); //matching (including ratelimitercheck)
					er->caid = save_caid;
				}
			}
#endif
			if (match) {
				if (!cs_malloc(&ea, sizeof(struct s_ecm_answer)))
					goto OUT;
				ea->reader = rdr;
				if (prv)
					prv->next = ea;
				else
					er->matching_rdr=ea;

				prv = ea;

				ea->status = READER_ACTIVE;
				if (!is_network_reader(rdr))
					ea->status |= READER_LOCAL;
				else if (cacheex_reader(rdr))
					ea->status |= READER_CACHEEX;
				if (rdr->fallback)
					ea->status |= READER_FALLBACK;

#ifdef WITH_LB
				if (cfg.lb_mode || !rdr->fallback)
#else
				if (!rdr->fallback)
#endif
					er->reader_avail++;
			}
		}

OUT:
		cs_readunlock(&clientlist_lock);
		cs_readunlock(&readerlist_lock);

		stat_get_best_reader(er);

		int32_t fallback_reader_count = 0;
		er->reader_count = 0;
		for (ea = er->matching_rdr; ea; ea = ea->next) {
			if (ea->status & READER_ACTIVE) {
				if (!(ea->status & READER_FALLBACK))
					er->reader_count++;
				else
					fallback_reader_count++;
			}
		}

		if ((er->reader_count + fallback_reader_count) == 0) { //no reader -> not found
			er->rc = E_NOTFOUND;
			if (!er->rcEx)
				er->rcEx = E2_GROUP;
			snprintf(er->msglog, MSGLOGSIZE, "no matching reader");
		}
	}

	//we have to go through matching_reader() to check services!
	struct ecm_request_t *ecm;
	if (er->rc == E_UNHANDLED) {
		ecm = check_cwcache(er, client);

		if (ecm) {
			if (ecm->rc < E_99) {
                                memcpy(er->cw, ecm->cw, 16);
                                er->selected_reader = ecm->selected_reader;
                                er->rc = (ecm->rc == E_FOUND)?E_CACHE1:ecm->rc;
			} else { //E_UNHANDLED
				er->ecmcacheptr = ecm;
				er->rc = E_99;
#ifdef CS_CACHEEX
				//to support cache without ecms we store the first client ecm request here
				//when we got a cache ecm from cacheex
				if (!ecm->ecmlen && er->ecmlen && !ecm->matching_rdr) {
					ecm->matching_rdr = er->matching_rdr;
					er->matching_rdr = NULL;
					ecm->ecmlen = er->ecmlen;
					ecm->client = er->client;
					er->client = NULL;
					memcpy(ecm->ecm, er->ecm, sizeof(ecm->ecm));
					memcpy(ecm->ecmd5, er->ecmd5, sizeof(ecm->ecmd5));
				}
#endif
			}
#ifdef CS_CACHEEX
			er->cacheex_src = ecm->cacheex_src;
#endif
		} else
			er->rc = E_UNHANDLED;
	}

#ifdef CS_CACHEEX
	int8_t cacheex = client->account?client->account->cacheex.mode:0;
	uint32_t c_csp_wait_time = get_csp_wait_time(er,client);
	cs_debug_mask(D_CACHEEX | D_CSPCWC, "[GET_CW] c_csp_wait_time %d caid %04X prov %06X srvid %04X rc %d cacheex %d", c_csp_wait_time, er->caid, er->prid, er->srvid, er->rc, cacheex);
	if ((cacheex == 1 || c_csp_wait_time) && er->rc == E_UNHANDLED) { //not found in cache, so wait!
		int32_t max_wait = (cacheex == 1)?cfg.cacheex_wait_time:c_csp_wait_time; // uint32_t can't value <> n/50
		while (max_wait > 0 && !client->kill) {
			cs_sleepms(50);
			max_wait -= 50;
			ecm = check_cwcache(er, client);
			if (ecm) {
				if (ecm->rc < E_99) { //Found cache!
					memcpy(er->cw, ecm->cw, 16);
					er->selected_reader = ecm->selected_reader;
					er->rc = (ecm->rc == E_FOUND)?E_CACHE1:ecm->rc;
				} else { //Found request!
					er->ecmcacheptr = ecm;
					er->rc = E_99;
				}
				er->cacheex_src = ecm->cacheex_src;
				break;
			}
		}
		if (max_wait <= 0 )
			cs_debug_mask(D_CACHEEX|D_CSPCWC, "[GET_CW] wait_time over");
	}
#endif

	if (er->rc >= E_99) {
#ifdef CS_CACHEEX
		if (cacheex != 1 || er->rc == E_99) { //Cacheex should not add to the ecmcache:
#endif
			if (er->rc == E_UNHANDLED) {
				ecm = check_cwcache(er, client);
				if (ecm && ecm != er) {
					er->rc = E_99;
					er->ecmcacheptr = ecm; //Linking ecm to first request
#ifdef CS_CACHEEX
					er->cacheex_src = ecm->cacheex_src;
#endif
				}
			}
			cs_writelock(&ecmcache_lock);
			er->next = ecmcwcache;
			ecmcwcache = er;
			ecmcwcache_size++;
			cs_writeunlock(&ecmcache_lock);
#ifdef CS_CACHEEX
		}
#endif
	}

	if (er->rc < E_99) {
#ifdef CS_CACHEEX
		if (cfg.delay && cacheex != 1) //No delay on cacheexchange!
			cs_sleepms(cfg.delay);

		if (cacheex == 1 && er->rc < E_NOTFOUND) {
			cacheex_add_stats(client, er->caid, er->srvid, er->prid, 0);
			client->cwcacheexpush++;
			if (client->account)
				client->account->cwcacheexpush++;
			first_client->cwcacheexpush++;
		}
#else
		if (cfg.delay)
			cs_sleepms(cfg.delay);
#endif
		send_dcw(client, er);
		free_ecm(er);
		return; //ECM found/not found/error/invalid
	}

	if (er->rc == E_99) {
		er->stage=4;
		if(timecheck_client){
			pthread_mutex_lock(&timecheck_client->thread_lock);
			if(timecheck_client->thread_active == 2)
				pthread_kill(timecheck_client->thread, OSCAM_SIGNAL_WAKEUP);
			pthread_mutex_unlock(&timecheck_client->thread_lock);
		}
		return; //ECM already requested / found in ECM cache
	}

#ifdef CS_CACHEEX
	//er->rc == E_UNHANDLED
	//Cache Exchange never request cws from readers!
	if (cacheex == 1) {
		er->rc = E_NOTFOUND;
		er->rcEx = E2_OFFLINE;
		send_dcw(client, er);
		free_ecm(er);
		return;
	}
#endif

	lb_mark_last_reader(er);

	er->rcEx = 0;
	request_cw(er);

#ifdef WITH_DEBUG
	if (D_CLIENTECM & cs_dblevel) {
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_ddump_mask(D_CLIENTECM, er->ecm, er->ecmlen, "Client %s ECM dump %s", username(client), buf);
  }
#endif

	if(timecheck_client){
		pthread_mutex_lock(&timecheck_client->thread_lock);
		if(timecheck_client->thread_active == 2)
			pthread_kill(timecheck_client->thread, OSCAM_SIGNAL_WAKEUP);
		pthread_mutex_unlock(&timecheck_client->thread_lock);
	}
}

/**
 * Function to filter emm by cardsystem.
 * Every cardsystem can export a function "get_emm_filter"
 *
 * the emm is checked against it an returns 1 for a valid emm or 0 if not
 */
int8_t do_simple_emm_filter(struct s_reader *rdr, struct s_cardsystem *cs, EMM_PACKET *ep)
{
	//copied and enhanced from module-dvbapi.c
	//dvbapi_start_emm_filter()

	int32_t i, j, k, match;
	uchar flt, mask;
	uchar dmx_filter[342]; // 10 filter + 2 byte header


	memset(dmx_filter, 0, sizeof(dmx_filter));
	dmx_filter[0]=0xFF;
	dmx_filter[1]=0;

	//Call cardsystems emm filter
        cs->get_emm_filter(rdr, dmx_filter);

	//only check matching emmtypes:
	uchar org_emmtype;
	if (ep->type == UNKNOWN)
	    org_emmtype = EMM_UNKNOWN;
	else
	    org_emmtype = 1 << (ep->type-1);


	//Now check all filter values

	//dmx_filter has 2 bytes header:
	//first byte is always 0xFF
	//second byte is filter count
	//all the other datas are the filter count * 34 bytes filter

	//every filter is 34 bytes
	//2 bytes emmtype+count
	//16 bytes filter data
	//16 bytes filter mask

	int32_t filter_count=dmx_filter[1];
	for (j=1;j<=filter_count && j <= 10;j++) {
		int32_t startpos=2+(34*(j-1));

		if (dmx_filter[startpos+1] != 0x00)
			continue;

		uchar emmtype=dmx_filter[startpos];
		if (emmtype != org_emmtype)
			continue;

                match = 1;
		for (i=0,k=0; i<10 && k < ep->emmlen && match; i++,k++) {
			flt = dmx_filter[startpos+2+i];
			mask = dmx_filter[startpos+2+16+i];
			if (!mask) break;
                        match = (flt == (ep->emm[k]&mask));
                        if (k==0) k+=2; //skip len
		}
		if (match)
		    return 1; //valid emm

	}
	return 0; //emm filter does not match, illegal emm, return
}

void do_emm(struct s_client * client, EMM_PACKET *ep)
{
	char *typtext[]={"unknown", "unique", "shared", "global"};
	char tmp[17];
	int32_t emmnok=0;

	struct s_reader *aureader = NULL;
	cs_ddump_mask(D_EMM, ep->emm, ep->emmlen, "emm:");

	LL_ITER itr = ll_iter_create(client->aureader_list);
	while ((aureader = ll_iter_next(&itr))) {
		if (!aureader->enable)
			continue;

		uint16_t caid = b2i(2, ep->caid);
		uint32_t provid = b2i(4, ep->provid);

		if (aureader->audisabled) {
			rdr_debug_mask(aureader, D_EMM, "AU is disabled");
			/* we have to write the log for blocked EMM here because
	  		 this EMM never reach the reader module where the rest
			 of EMM log is done. */
			if (aureader->logemm & 0x10)  {
				rdr_log(aureader, "%s emmtype=%s, len=%d, idx=0, cnt=1: audisabled (0 ms)",
						client->account->usr,
						typtext[ep->type],
						ep->emm[2]);
			}
			continue;
		}

		if (!(aureader->grp & client->grp)) {
			rdr_debug_mask(aureader, D_EMM, "skip emm, group mismatch");
			continue;
		}

		//TODO: provider possibly not set yet, this is done in get_emm_type()
		if (!emm_reader_match(aureader, caid, provid))
			continue;

		struct s_cardsystem *cs = NULL;

		if (is_cascading_reader(aureader)) { // network reader (R_CAMD35 R_NEWCAMD R_CS378X R_CCCAM)
			if (!aureader->ph.c_send_emm) // no emm support
				continue;

			cs = get_cardsystem_by_caid(caid);
			if (!cs) {
				rdr_debug_mask(aureader, D_EMM, "unable to find cardsystem for caid %04X", caid);
				continue;
			}
		} else { // local reader
			if (aureader->csystem.active)
				cs=&aureader->csystem;
		}

		if (cs && cs->get_emm_type) {
			if(!cs->get_emm_type(ep, aureader)) {
				rdr_debug_mask(aureader, D_EMM, "emm skipped, get_emm_type() returns error");
				emmnok++;
				continue;
			}
		}

		if (cs && cs->get_emm_filter) {
			if (!do_simple_emm_filter(aureader, cs, ep)) {
				rdr_debug_mask(aureader, D_EMM, "emm skipped, emm_filter() returns invalid");
				emmnok++;
				continue;
			}
		}

		rdr_debug_mask_sensitive(aureader, D_EMM, "emmtype %s. Reader serial {%s}.", typtext[ep->type],
			cs_hexdump(0, aureader->hexserial, 8, tmp, sizeof(tmp)));
		rdr_debug_mask_sensitive(aureader, D_EMM, "emm UA/SA: {%s}.",
			cs_hexdump(0, ep->hexserial, 8, tmp, sizeof(tmp)));

		uint32_t emmtype;
		if (ep->type == UNKNOWN)
			emmtype = EMM_UNKNOWN;
		else
			emmtype = 1 << (ep->type-1);
		client->last=time((time_t*)0);
		if (((1<<(ep->emm[0] % 0x80)) & aureader->s_nano) || (aureader->saveemm & emmtype)) { //should this nano be saved?
			char token[256];
			char *tmp2;
			FILE *fp;
			time_t rawtime;
			time (&rawtime);
			struct tm timeinfo;
			localtime_r (&rawtime, &timeinfo);	/* to access LOCAL date/time info */
			int32_t emm_length = ((ep->emm[1] & 0x0f) << 8) | ep->emm[2];
			char buf[80];
			strftime (buf, sizeof(buf), "%Y/%m/%d %H:%M:%S", &timeinfo);
			snprintf (token, sizeof(token), "%s/%s_emm.log", cfg.emmlogdir?cfg.emmlogdir:cs_confdir, aureader->label);

			if (!(fp = fopen (token, "a"))) {
				cs_log ("ERROR: Cannot open file '%s' (errno=%d: %s)\n", token, errno, strerror(errno));
			} else if (cs_malloc(&tmp2, (emm_length + 3) * 2 + 1)) {
				fprintf (fp, "%s   %s   ", buf, cs_hexdump(0, ep->hexserial, 8, tmp, sizeof(tmp)));
				fprintf (fp, "%s\n", cs_hexdump(0, ep->emm, emm_length + 3, tmp2, (emm_length + 3)*2 + 1));
				free(tmp2);
				fclose (fp);
				cs_log ("Successfully added EMM to %s.", token);
			}

			snprintf (token, sizeof(token), "%s/%s_emm.bin", cfg.emmlogdir?cfg.emmlogdir:cs_confdir, aureader->label);
			if (!(fp = fopen (token, "ab"))) {
				cs_log ("ERROR: Cannot open file '%s' (errno=%d: %s)\n", token, errno, strerror(errno));
			} else {
				if ((int)fwrite(ep->emm, 1, emm_length+3, fp) == emm_length+3)	{
					cs_log ("Successfully added binary EMM to %s.", token);
				} else {
					cs_log ("ERROR: Cannot write binary EMM to %s (errno=%d: %s)\n", token, errno, strerror(errno));
				}
				fclose (fp);
			}
		}

		int32_t is_blocked = 0;
		switch (ep->type) {
			case UNKNOWN: is_blocked = (aureader->blockemm & EMM_UNKNOWN) ? 1 : 0;
				break;
			case UNIQUE: is_blocked = (aureader->blockemm & EMM_UNIQUE) ? 1 : 0;
				break;
			case SHARED: is_blocked = (aureader->blockemm & EMM_SHARED) ? 1 : 0;
				break;
			case GLOBAL: is_blocked = (aureader->blockemm & EMM_GLOBAL) ? 1 : 0;
				break;
		}

		// if not already blocked we check for block by len
		if (!is_blocked) is_blocked = cs_emmlen_is_blocked( aureader, ep->emm[2] ) ;

		if (is_blocked != 0) {
#ifdef WEBIF
			aureader->emmblocked[ep->type]++;
			is_blocked = aureader->emmblocked[ep->type];
#endif
			/* we have to write the log for blocked EMM here because
	  		 this EMM never reach the reader module where the rest
			 of EMM log is done. */
			if (aureader->logemm & 0x08)  {
				rdr_log(aureader, "%s emmtype=%s, len=%d, idx=0, cnt=%d: blocked (0 ms)",
						client->account->usr,
						typtext[ep->type],
						ep->emm[2],
						is_blocked);
			}
			continue;
		}

		client->lastemm = time((time_t*)0);

		client->emmok++;
		if (client->account)
			client->account->emmok++;
		first_client->emmok++;

		//Check emmcache early:
		int32_t i;
		unsigned char md5tmp[CS_EMMSTORESIZE];
		struct s_client *au_cl = aureader->client;

		MD5(ep->emm, ep->emm[2], md5tmp);
		ep->client = client;

		for (i=0; i<CS_EMMCACHESIZE; i++) {
			if (!memcmp(au_cl->emmcache[i].emmd5, md5tmp, CS_EMMSTORESIZE)) {
				rdr_debug_mask(aureader, D_EMM, "emm found in cache: count %d rewrite %d",
					au_cl->emmcache[i].count, aureader->rewritemm);
				if (aureader->cachemm && (au_cl->emmcache[i].count > aureader->rewritemm)) {
					reader_log_emm(aureader, ep, i, 2, NULL);
					return;
				}
			}
		}

		EMM_PACKET *emm_pack;
		if (cs_malloc(&emm_pack, sizeof(EMM_PACKET))) {
			rdr_debug_mask(aureader, D_EMM, "emm is being sent to reader");
			memcpy(emm_pack, ep, sizeof(EMM_PACKET));
			add_job(aureader->client, ACTION_READER_EMM, emm_pack, sizeof(EMM_PACKET));
		}
	}
	if (emmnok > 0 && emmnok == ll_count(client->aureader_list)) {
		client->emmnok++;
		if (client->account)
			client->account->emmnok++;
		first_client->emmnok++;
	}
}

int32_t process_input(uchar *buf, int32_t l, int32_t timeout)
{
	int32_t rc, i, pfdcount, polltime;
	struct pollfd pfd[2];
	struct s_client *cl = cur_client();

	time_t starttime = time(NULL);

	while (1) {
		pfdcount = 0;
		if (cl->pfd) {
			pfd[pfdcount].fd = cl->pfd;
			pfd[pfdcount++].events = POLLIN | POLLPRI;
		}

		polltime  = timeout - (time(NULL) - starttime);
		if (polltime < 0) {
			polltime = 0;
		}

		int32_t p_rc = poll(pfd, pfdcount, polltime);

		if (p_rc < 0) {
			if (errno==EINTR) continue;
			else return(0);
		}

		if (p_rc == 0 && (starttime+timeout) < time(NULL)) { // client maxidle reached
			rc=(-9);
			break;
		}

		for (i=0;i<pfdcount && p_rc > 0;i++) {
			if (pfd[i].revents & POLLHUP){	// POLLHUP is only valid in revents so it doesn't need to be set above in events
				return(0);
			}
			if (!(pfd[i].revents & (POLLIN | POLLPRI)))
				continue;

			if (pfd[i].fd == cl->pfd)
				return modules[cl->ctyp].recv(cl, buf, l);
		}
	}
	return(rc);
}

void cs_waitforcardinit(void)
{
	if (cfg.waitforcards)
	{
		cs_log("waiting for local card init");
		int32_t card_init_done;
		do {
			card_init_done = 1;
			struct s_reader *rdr;
			LL_ITER itr = ll_iter_create(configured_readers);
			while((rdr = ll_iter_next(&itr))) {
				if (rdr->enable && !is_cascading_reader(rdr) && (rdr->card_status == CARD_NEED_INIT || rdr->card_status == UNKNOWN)) {
					card_init_done = 0;
					break;
				}
			}

			if (!card_init_done)
				cs_sleepms(300); // wait a little bit
			//alarm(cfg.cmaxidle + cfg.ctimeout / 1000 + 1);
		} while (!card_init_done);
		if (cfg.waitforcards_extra_delay>0)
			cs_sleepms(cfg.waitforcards_extra_delay);
		cs_log("init for all local cards done");
	}
}

static void check_status(struct s_client *cl) {
	if (!cl || cl->kill || !cl->init_done)
		return;

	switch (cl->typ) {
		case 'm':
		case 'c':
			//check clients for exceeding cmaxidle by checking cl->last
			if (!(cl->ncd_keepalive && (modules[cl->ctyp].listenertype & LIS_NEWCAMD))  && cl->last && cfg.cmaxidle && (time(NULL) - cl->last) > (time_t)cfg.cmaxidle) {
				add_job(cl, ACTION_CLIENT_IDLE, NULL, 0);
			}

			break;
		case 'r':
			cardreader_checkhealth(cl, cl->reader);
			break;
		case 'p':
			{
				struct s_reader *rdr = cl->reader;
				if (!rdr || !rdr->enable || !rdr->active)	//reader is disabled or restarting at this moment
					break;
				//execute reader do idle on proxy reader after a certain time (rdr->tcp_ito = inactivitytimeout)
				//disconnect when no keepalive available
				if ((rdr->tcp_ito && is_cascading_reader(rdr)) || rdr->typ == R_CCCAM) {
					time_t now = time(NULL);
					int32_t time_diff = abs(now - rdr->last_check);
	
					if (time_diff > 60 || (time_diff > 30 && rdr->typ == R_CCCAM)) { //check 1x per minute or every 30s for cccam
						add_job(rdr->client, ACTION_READER_IDLE, NULL, 0);
						rdr->last_check = now;
					}
				}
			}
			break;
	}
}

void * work_thread(void *ptr) {
	struct s_data *data = (struct s_data *) ptr;
	struct s_client *cl = data->cl;
	struct s_reader *reader = cl->reader;

	struct s_data tmp_data;
	struct pollfd pfd[1];

	pthread_setspecific(getclient, cl);
	cl->thread=pthread_self();
	cl->thread_active = 1;

	uint16_t bufsize = modules[cl->ctyp].bufsize; //CCCam needs more than 1024bytes!
	if (!bufsize) bufsize = 1024;
	uchar *mbuf;
	if (!cs_malloc(&mbuf, bufsize))
		return NULL;
	int32_t n=0, rc=0, i, idx, s;
	uchar dcw[16];
	time_t now;
	int8_t restart_reader=0;
	while (cl->thread_active) {
		while (cl->thread_active) {
			if (!cl || cl->kill || !is_valid_client(cl)) {
			        pthread_mutex_lock(&cl->thread_lock);
				cl->thread_active=0;
				pthread_mutex_unlock(&cl->thread_lock);
				cs_debug_mask(D_TRACE, "ending thread (kill)");
				if (data && data!=&tmp_data) free_data(data);
				data = NULL;
				cleanup_thread(cl);
				if (restart_reader)
					restart_cardreader(reader, 0);
				free(mbuf);
				pthread_exit(NULL);
				return NULL;
			}

			if (data && data->action != ACTION_READER_CHECK_HEALTH)
				cs_debug_mask(D_TRACE, "data from add_job action=%d client %c %s", data->action, cl->typ, username(cl));

			if (!data) {
				if (!cl->kill && cl->typ != 'r') check_status(cl);	// do not call for physical readers as this might cause an endless job loop
				pthread_mutex_lock(&cl->thread_lock);
				if (cl->joblist && ll_count(cl->joblist)>0) {
					LL_ITER itr = ll_iter_create(cl->joblist);
					data = ll_iter_next_remove(&itr);
					//cs_debug_mask(D_TRACE, "start next job from list action=%d", data->action);
				}
				pthread_mutex_unlock(&cl->thread_lock);
			}

			if (!data) {
	            /* for serial client cl->pfd is file descriptor for serial port not socket
	               for example: pfd=open("/dev/ttyUSB0"); */
				if (!cl->pfd || modules[cl->ctyp].listenertype == LIS_SERIAL)
					break;
				pfd[0].fd = cl->pfd;
				pfd[0].events = POLLIN | POLLPRI | POLLHUP;

				pthread_mutex_lock(&cl->thread_lock);
				cl->thread_active = 2;
				pthread_mutex_unlock(&cl->thread_lock);
				rc = poll(pfd, 1, 3000);
				pthread_mutex_lock(&cl->thread_lock);
				cl->thread_active = 1;
				pthread_mutex_unlock(&cl->thread_lock);

				if (rc == -1)
					cs_debug_mask(D_TRACE, "poll() timeout");

				if (rc>0) {
					data=&tmp_data;
					data->ptr = NULL;

					if (reader)
						data->action = ACTION_READER_REMOTE;
					else {
						if (cl->is_udp) {
							data->action = ACTION_CLIENT_UDP;
							data->ptr = mbuf;
							data->len = bufsize;
						}
						else
							data->action = ACTION_CLIENT_TCP;
						if (pfd[0].revents & (POLLHUP | POLLNVAL))
							cl->kill = 1;
					}
				}
			}

			if (!data)
				continue;

			if (data->action < 20 && !reader) {
				if (data!=&tmp_data) free_data(data);
				data = NULL;
				break;
			}

			if (!data->action)
				break;

			now = time(NULL);
			time_t diff = (time_t)(cfg.ctimeout/1000)+1;
			if (data != &tmp_data && data->time < now-diff) {
				cs_debug_mask(D_TRACE, "dropping client data for %s time %ds", username(cl), (int32_t)(now-data->time));
				free_data(data);
				data = NULL;
				continue;
			}

			switch(data->action) {
				case ACTION_READER_IDLE:
					reader_do_idle(reader);
					break;
				case ACTION_READER_REMOTE:
					s = check_fd_for_data(cl->pfd);

					if (s == 0) // no data, another thread already read from fd?
						break;

					if (s < 0) {
						if (reader->ph.type==MOD_CONN_TCP)
							network_tcp_connection_close(reader, "disconnect");
						break;
					}

					rc = reader->ph.recv(cl, mbuf, bufsize);
					if (rc < 0) {
						if (reader->ph.type==MOD_CONN_TCP)
							network_tcp_connection_close(reader, "disconnect on receive");
						break;
					}

					cl->last=now;
					idx=reader->ph.c_recv_chk(cl, dcw, &rc, mbuf, rc);

					if (idx<0) break;  // no dcw received
					if (!idx) idx=cl->last_idx;

					reader->last_g=now; // for reconnect timeout

					for (i = 0, n = 0; i < cfg.max_pending && n == 0; i++) {
						if (cl->ecmtask[i].idx==idx) {
							cl->pending--;
							casc_check_dcw(reader, i, rc, dcw);
							n++;
						}
					}
					break;
				case ACTION_READER_REMOTELOG:
					casc_do_sock_log(reader);
					break;
				case ACTION_READER_RESET:
					cardreader_do_reset(reader);
					break;
				case ACTION_READER_ECM_REQUEST:
					reader_get_ecm(reader, data->ptr);
					break;
				case ACTION_READER_EMM:
					reader_do_emm(reader, data->ptr);
					break;
				case ACTION_READER_CARDINFO:
					reader_do_card_info(reader);
					break;
				case ACTION_READER_INIT:
					if (!cl->init_done)
						reader_init(reader);
					break;
				case ACTION_READER_RESTART:
					cl->kill = 1;
					restart_reader = 1;
					break;
				case ACTION_READER_RESET_FAST:
					reader->card_status = CARD_NEED_INIT;
					cardreader_do_reset(reader);
					break;
				case ACTION_READER_CHECK_HEALTH:
					cardreader_do_checkhealth(reader);
					break;
				case ACTION_CLIENT_UDP:
					n = modules[cl->ctyp].recv(cl, data->ptr, data->len);
					if (n<0) break;
					modules[cl->ctyp].s_handler(cl, data->ptr, n);
					break;
				case ACTION_CLIENT_TCP:
					s = check_fd_for_data(cl->pfd);
					if (s == 0) // no data, another thread already read from fd?
						break;
					if (s < 0) { // system error or fd wants to be closed
						cl->kill=1; // kill client on next run
						continue;
					}

					n = modules[cl->ctyp].recv(cl, mbuf, bufsize);
					if (n < 0) {
						cl->kill=1; // kill client on next run
						continue;
					}
					modules[cl->ctyp].s_handler(cl, mbuf, n);

					break;
				case ACTION_CLIENT_ECM_ANSWER:
					chk_dcw(cl, data->ptr);
					break;
				case ACTION_CLIENT_INIT:
					if (modules[cl->ctyp].s_init)
						modules[cl->ctyp].s_init(cl);
					cl->init_done=1;
					break;
				case ACTION_CLIENT_IDLE:
					if (modules[cl->ctyp].s_idle)
						modules[cl->ctyp].s_idle(cl);
					else {
						cs_log("user %s reached %d sec idle limit.", username(cl), cfg.cmaxidle);
						cl->kill = 1;
					}
					break;
#ifdef CS_CACHEEX
				case ACTION_CACHE_PUSH_OUT: {
					ECM_REQUEST *er = data->ptr;
					int32_t res=0, stats = -1;

					// cc-nodeid-list-check
					if (reader) {
						if (reader->ph.c_cache_push_chk && !reader->ph.c_cache_push_chk(cl, er))
							break;
						res = reader->ph.c_cache_push(cl, er);
						stats = cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 0);
					} else  {
						if (modules[cl->ctyp].c_cache_push_chk && !modules[cl->ctyp].c_cache_push_chk(cl, er))
							break;
						res = modules[cl->ctyp].c_cache_push(cl, er);
					}
					debug_ecm(D_CACHEEX, "pushed ECM %s to %s res %d stats %d", buf, username(cl), res, stats);

					cl->cwcacheexpush++;
					if (cl->account)
						cl->account->cwcacheexpush++;
					first_client->cwcacheexpush++;

					break;
				}
#endif
				case ACTION_CLIENT_KILL:
					cl->kill = 1;
					break;
			}

			if (data!=&tmp_data) free_data(data);
			data = NULL;
		}

		if (thread_pipe[1]){
			if(write(thread_pipe[1], mbuf, 1) == -1){ //wakeup client check
				cs_debug_mask(D_TRACE, "Writing to pipe failed (errno=%d %s)", errno, strerror(errno));
			}
		}

		// Check for some race condition where while we ended, another thread added a job
		pthread_mutex_lock(&cl->thread_lock);
		if (cl->joblist && ll_count(cl->joblist)>0) {
			pthread_mutex_unlock(&cl->thread_lock);
			continue;
		} else {
			cl->thread_active = 0;
			pthread_mutex_unlock(&cl->thread_lock);
			break;
		}
	}
	free(mbuf);
	pthread_exit(NULL);
	cl->thread_active = 0;
	return NULL;
}

/**
 * adds a job to the job queue
 * if ptr should be free() after use, set len to the size
 * else set size to 0
**/
int32_t add_job(struct s_client *cl, int8_t action, void *ptr, int32_t len) {

	if (!cl || cl->kill) {
		if (!cl) cs_log("WARNING: add_job failed."); //Ignore jobs for killed clients
		if (len && ptr) free(ptr);
		return 0;
	}
	
	//Avoid full running queues:
	if (action == ACTION_CACHE_PUSH_OUT && ll_count(cl->joblist) > 2000) {
                cs_debug_mask(D_TRACE, "WARNING: job queue %s %s has more than 2000 jobs! count=%d, dropped!",
                    cl->typ=='c'?"client":"reader",
                    username(cl),
                    ll_count(cl->joblist));
                if (len && ptr) free(ptr);
                
                //Thread down???
                pthread_mutex_lock(&cl->thread_lock);
                if (cl->thread_active) {
                    //Just test for invalid thread id:
                    if (pthread_detach(cl->thread) == ESRCH) {
                        cl->thread_active = 0;
                        cs_debug_mask(D_TRACE, "WARNING: %s %s thread died!",  cl->typ=='c'?"client":"reader", username(cl));
                    }
                }
                pthread_mutex_unlock(&cl->thread_lock);
                return 0;                
	}
	
	struct s_data *data;
	if (!cs_malloc(&data, sizeof(struct s_data))) {
		if (len && ptr)
			free(ptr);
		return 0;
	}

	data->action = action;
	data->ptr = ptr;
	data->cl = cl;
	data->len = len;
	data->time = time(NULL);

	pthread_mutex_lock(&cl->thread_lock);
	if (cl->thread_active) {
		if (!cl->joblist)
			cl->joblist = ll_create("joblist");

		ll_append(cl->joblist, data);
		if(cl->thread_active == 2)
			pthread_kill(cl->thread, OSCAM_SIGNAL_WAKEUP);
		pthread_mutex_unlock(&cl->thread_lock);
		cs_debug_mask(D_TRACE, "add %s job action %d queue length %d %s", action > ACTION_CLIENT_FIRST ? "client" : "reader", action, ll_count(cl->joblist), username(cl));
		return 1;
	}


	pthread_attr_t attr;
	pthread_attr_init(&attr);
	/* pcsc doesn't like this either; segfaults on x86, x86_64 */
	struct s_reader *rdr = cl->reader;
	if(cl->typ != 'r' || !rdr || rdr->typ != R_PCSC)
		pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);

	if (action != ACTION_READER_CHECK_HEALTH)
		cs_debug_mask(D_TRACE, "start %s thread action %d", action > ACTION_CLIENT_FIRST ? "client" : "reader", action);

	int32_t ret = pthread_create(&cl->thread, &attr, work_thread, (void *)data);
	if (ret) {
		cs_log("ERROR: can't create thread for %s (errno=%d %s)", action > ACTION_CLIENT_FIRST ? "client" : "reader", ret, strerror(ret));
		free_data(data);
	} else
		pthread_detach(cl->thread);

	pthread_attr_destroy(&attr);

	cl->thread_active = 1;
	pthread_mutex_unlock(&cl->thread_lock);
	return 1;
}

static uint32_t auto_timeout(ECM_REQUEST *er, uint32_t timeout) {
        (void)er; // Prevent warning about unused er, when WITH_LB is disabled
#ifdef WITH_LB
        if (cfg.lb_auto_timeout)
                return lb_auto_timeout(er, timeout);
#endif
        return timeout;
}


static void * check_thread(void) {
	int32_t time_to_check, next_check, ecmc_next, msec_wait = 3000;
	struct timeb t_now, tbc, ecmc_time;
	ECM_REQUEST *er = NULL;
	time_t ecm_timeout;
	time_t ecm_mintimeout;
	struct timespec ts;
	struct s_client *cl = create_client(first_client->ip);
	cl->typ = 's';
#ifdef WEBIF
	cl->wihidden = 1;
#endif
	cl->thread = pthread_self();

	timecheck_client = cl;

#ifdef CS_ANTICASC
	int32_t ac_next;
	struct timeb ac_time;
	cs_ftime(&ac_time);
	add_ms_to_timeb(&ac_time, cfg.ac_stime*60*1000);
#endif

	cs_ftime(&ecmc_time);
	add_ms_to_timeb(&ecmc_time, 1000);

	while(1) {
		ts.tv_sec = msec_wait/1000;
		ts.tv_nsec = (msec_wait % 1000) * 1000000L;
		pthread_mutex_lock(&cl->thread_lock);
		cl->thread_active = 2;
		pthread_mutex_unlock(&cl->thread_lock);
		nanosleep(&ts, NULL);
		pthread_mutex_lock(&cl->thread_lock);
		cl->thread_active = 1;
		pthread_mutex_unlock(&cl->thread_lock);

		next_check = 0;
#ifdef CS_ANTICASC
		ac_next = 0;
#endif
		ecmc_next = 0;
		msec_wait = 0;

		cs_ftime(&t_now);
		cs_readlock(&ecmcache_lock);

		for (er = ecmcwcache; er; er = er->next) {
			if (er->rc < E_99 || !er->ecmlen || !er->matching_rdr) //ignore CACHEEX pending ECMs
				continue;

			tbc = er->tps;
#ifdef CS_CACHEEX
			time_to_check = add_ms_to_timeb(&tbc, (er->stage < 2) ? cfg.cacheex_wait_time:((er->stage < 4) ? auto_timeout(er, cfg.ftimeout) : auto_timeout(er, cfg.ctimeout)));
#else
			time_to_check = add_ms_to_timeb(&tbc, ((er->stage < 4) ? auto_timeout(er, cfg.ftimeout) : auto_timeout(er, cfg.ctimeout)));
#endif

			if (comp_timeb(&t_now, &tbc) >= 0) {
				if (er->stage < 4) {
					debug_ecm(D_TRACE, "fallback for %s %s", username(er->client), buf);

					if (er->rc >= E_UNHANDLED) //do not request rc=99
						request_cw(er);

					tbc = er->tps;
					time_to_check = add_ms_to_timeb(&tbc, auto_timeout(er, cfg.ctimeout));
				} else {
					if (er->client) {
					        er->selected_reader = NULL;
						debug_ecm(D_TRACE, "timeout for %s %s", username(er->client), buf);
						write_ecm_answer(NULL, er, E_TIMEOUT, 0, NULL, NULL);
					}
#ifdef WITH_LB
					if (!er->ecmcacheptr) { //do not add stat for cache entries:
						//because of lb, send E_TIMEOUT for all readers:
						struct s_ecm_answer *ea_list;

						for(ea_list = er->matching_rdr; ea_list; ea_list = ea_list->next) {
							if ((ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED)) == REQUEST_SENT) //Request send, but no answer!
								send_reader_stat(ea_list->reader, er, NULL, E_TIMEOUT);
						}
					}
#endif

					time_to_check = 0;
				}
			}
			if (!next_check || (time_to_check > 0 && time_to_check < next_check))
				next_check = time_to_check;
		}
		cs_readunlock(&ecmcache_lock);

#ifdef CS_ANTICASC
		if ((ac_next = comp_timeb(&ac_time, &t_now)) <= 10) {
			if (cfg.ac_enabled)
				ac_do_stat();
			cs_ftime(&ac_time);
			ac_next = add_ms_to_timeb(&ac_time, cfg.ac_stime*60*1000);
		}
#endif

		if ((ecmc_next = comp_timeb(&ecmc_time, &t_now)) <= 10) {
			ecm_timeout = t_now.time-cfg.max_cache_time;
			ecm_mintimeout = t_now.time-(cfg.ctimeout/1000+2);
			uint32_t count = 0;

			struct ecm_request_t *ecm, *ecmt=NULL, *prv;
			cs_readlock(&ecmcache_lock);
			for (ecm = ecmcwcache, prv = NULL; ecm; prv = ecm, ecm = ecm->next, count++) {
				if (ecm->tps.time < ecm_timeout || (ecm->tps.time<ecm_mintimeout && count>cfg.max_cache_count)) {
					cs_readunlock(&ecmcache_lock);
					cs_writelock(&ecmcache_lock);
					ecmt = ecm;
					if (prv)
						prv->next = NULL;
					else
						ecmcwcache = NULL;
					cs_writeunlock(&ecmcache_lock);
					break;
				}
			}
			if (!ecmt)
				cs_readunlock(&ecmcache_lock);
			ecmcwcache_size = count;

			while (ecmt) {
				ecm = ecmt->next;
				free_ecm(ecmt);
				ecmt = ecm;
			}

			cs_ftime(&ecmc_time);
			ecmc_next = add_ms_to_timeb(&ecmc_time, 1000);
		}

		msec_wait = next_check;

#ifdef CS_ANTICASC
		if (!msec_wait || (ac_next > 0 && ac_next < msec_wait))
			msec_wait = ac_next;
#endif

		if (!msec_wait || (ecmc_next > 0 && ecmc_next < msec_wait))
			msec_wait = ecmc_next;

		if (!msec_wait)
			msec_wait = 3000;

		cleanup_hitcache();
	}
	add_garbage(cl);
	timecheck_client = NULL;
	return NULL;
}

static uint32_t resize_pfd_cllist(struct pollfd **pfd, struct s_client ***cl_list, uint32_t old_size, uint32_t new_size) {
	if (old_size != new_size) {
		struct pollfd *pfd_new;
		if (!cs_malloc(&pfd_new, new_size * sizeof(struct pollfd))) {
			return old_size;
		}
		struct s_client **cl_list_new;
		if (!cs_malloc(&cl_list_new, new_size * sizeof(cl_list))) {
			free(pfd_new);
			return old_size;
		}
		if (old_size > 0) {
			memcpy(pfd_new, *pfd, old_size*sizeof(struct pollfd));
			memcpy(cl_list_new, *cl_list, old_size*sizeof(cl_list));
			free(*pfd);
			free(*cl_list);
		}
		*pfd = pfd_new;
		*cl_list = cl_list_new;
	}
	return new_size;
}

static uint32_t chk_resize_cllist(struct pollfd **pfd, struct s_client ***cl_list, uint32_t cur_size, uint32_t chk_size) {
	chk_size++;
	if (chk_size > cur_size) {
		uint32_t new_size = ((chk_size % 100)+1) * 100; //increase 100 step
		cur_size = resize_pfd_cllist(pfd, cl_list, cur_size, new_size);
	}
	return cur_size;
}

void * client_check(void) {
	int32_t i, k, j, rc, pfdcount = 0;
	struct s_client *cl;
	struct s_reader *rdr;
	struct pollfd *pfd;
	struct s_client **cl_list;
	uint32_t cl_size = 0;

	char buf[10];

	if (pipe(thread_pipe) == -1) {
		printf("cannot create pipe, errno=%d\n", errno);
		exit(1);
	}

	cl_size = chk_resize_cllist(&pfd, &cl_list, 0, 100);

	pfd[pfdcount].fd = thread_pipe[0];
	pfd[pfdcount].events = POLLIN | POLLPRI | POLLHUP;
	cl_list[pfdcount] = NULL;

	while (!exit_oscam) {
		pfdcount = 1;

		//connected tcp clients
		for (cl=first_client->next; cl; cl=cl->next) {
			if (cl->init_done && !cl->kill && cl->pfd && cl->typ=='c' && !cl->is_udp) {
				if (cl->pfd && !cl->thread_active) {
					cl_size = chk_resize_cllist(&pfd, &cl_list, cl_size, pfdcount);
					cl_list[pfdcount] = cl;
					pfd[pfdcount].fd = cl->pfd;
					pfd[pfdcount++].events = POLLIN | POLLPRI | POLLHUP;
				}
			}
			//reader:
			//TCP:
			//	- TCP socket must be connected
			//	- no active init thread
			//UDP:
			//	- connection status ignored
			//	- no active init thread
			rdr = cl->reader;
			if (rdr && cl->typ=='p' && cl->init_done) {
				if (cl->pfd && !cl->thread_active && ((rdr->tcp_connected && rdr->ph.type==MOD_CONN_TCP)||(rdr->ph.type==MOD_CONN_UDP))) {
					cl_size = chk_resize_cllist(&pfd, &cl_list, cl_size, pfdcount);
					cl_list[pfdcount] = cl;
					pfd[pfdcount].fd = cl->pfd;
					pfd[pfdcount++].events = POLLIN | POLLPRI | POLLHUP;
				}
			}
		}

		//server (new tcp connections or udp messages)
		for (k=0; k < CS_MAX_MOD; k++) {
			if ( (modules[k].type & MOD_CONN_NET) && modules[k].ptab ) {
				for (j=0; j<modules[k].ptab->nports; j++) {
					if (modules[k].ptab->ports[j].fd) {
						cl_size = chk_resize_cllist(&pfd, &cl_list, cl_size, pfdcount);
						cl_list[pfdcount] = NULL;
						pfd[pfdcount].fd = modules[k].ptab->ports[j].fd;
						pfd[pfdcount++].events = POLLIN | POLLPRI | POLLHUP;

					}
				}
			}
		}

		if (pfdcount >= 1024)
			cs_log("WARNING: too many users!");

		rc = poll(pfd, pfdcount, 5000);

		if (rc<1)
			continue;

		for (i=0; i<pfdcount; i++) {
			//clients
			cl = cl_list[i];
			if (cl && !is_valid_client(cl))
				continue;

			if (pfd[i].fd == thread_pipe[0] && (pfd[i].revents & (POLLIN | POLLPRI))) {
				// a thread ended and cl->pfd should be added to pollfd list again (thread_active==0)
				if(read(thread_pipe[0], buf, sizeof(buf)) == -1){
					cs_debug_mask(D_TRACE, "Reading from pipe failed (errno=%d %s)", errno, strerror(errno));
				}
				continue;
			}

			//clients
			// message on an open tcp connection
			if (cl && cl->init_done && cl->pfd && (cl->typ == 'c' || cl->typ == 'm')) {
				if (pfd[i].fd == cl->pfd && (pfd[i].revents & (POLLHUP | POLLNVAL))) {
					//client disconnects
					kill_thread(cl);
					continue;
				}
				if (pfd[i].fd == cl->pfd && (pfd[i].revents & (POLLIN | POLLPRI))) {
					add_job(cl, ACTION_CLIENT_TCP, NULL, 0);
				}
			}


			//reader
			// either an ecm answer, a keepalive or connection closed from a proxy
			// physical reader ('r') should never send data without request
			rdr = NULL;
			struct s_client *cl2 = NULL;
			if (cl && cl->typ == 'p'){
				rdr = cl->reader;
				if(rdr)
					cl2 = rdr->client;
			}

			if (rdr && cl2 && cl2->init_done) {
				if (cl2->pfd && pfd[i].fd == cl2->pfd && (pfd[i].revents & (POLLHUP | POLLNVAL))) {
					//connection to remote proxy was closed
					//oscam should check for rdr->tcp_connected and reconnect on next ecm request sent to the proxy
					network_tcp_connection_close(rdr, "closed");
					rdr_debug_mask(rdr, D_READER, "connection closed");
				}
				if (cl2->pfd && pfd[i].fd == cl2->pfd && (pfd[i].revents & (POLLIN | POLLPRI))) {
					add_job(cl2, ACTION_READER_REMOTE, NULL, 0);
				}
			}


			//server sockets
			// new connection on a tcp listen socket or new message on udp listen socket
			if (!cl && (pfd[i].revents & (POLLIN | POLLPRI))) {
				for (k=0; k<CS_MAX_MOD; k++) {
					if( (modules[k].type & MOD_CONN_NET) && modules[k].ptab ) {
						for ( j=0; j<modules[k].ptab->nports; j++ ) {
							if ( modules[k].ptab->ports[j].fd && pfd[i].fd == modules[k].ptab->ports[j].fd ) {
								accept_connection(k,j);
							}
						}
					}
				} // if (modules[i].type & MOD_CONN_NET)
			}
		}
		first_client->last=time((time_t *)0);
	}
	free(pfd);
	free(cl_list);
	return NULL;
}

void * reader_check(void) {
	struct s_client *cl;
	struct s_reader *rdr;
	while (1) {
		for (cl=first_client->next; cl ; cl=cl->next) {
			if (!cl->thread_active)
				check_status(cl);
		}
		cs_readlock(&readerlist_lock);
		for (rdr=first_active_reader; rdr; rdr=rdr->next) {
			if (rdr->enable) {
				cl = rdr->client;
				if (!cl || cl->kill)
					restart_cardreader(rdr, 0);
				else if (!cl->thread_active)
					check_status(cl);
			}
		}
		cs_readunlock(&readerlist_lock);
		cs_sleepms(1000);
	}
	return NULL;
}

int32_t accept_connection(int32_t i, int32_t j) {
	struct SOCKADDR cad;
	int32_t scad = sizeof(cad), n;
	struct s_client *cl;

	if (modules[i].type==MOD_CONN_UDP) {
		uchar *buf;
		if (!cs_malloc(&buf, 1024))
			return -1;
		if ((n=recvfrom(modules[i].ptab->ports[j].fd, buf+3, 1024-3, 0, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {
			cl=idx_from_ip(SIN_GET_ADDR(cad), ntohs(SIN_GET_PORT(cad)));

			uint16_t rl;
			rl=n;
			buf[0]='U';
			memcpy(buf+1, &rl, 2);

			if (cs_check_violation(SIN_GET_ADDR(cad), modules[i].ptab->ports[j].s_port)) {
				free(buf);
				return 0;
			}

			cs_debug_mask(D_TRACE, "got %d bytes on port %d from ip %s:%d client %s", 
			    n, modules[i].ptab->ports[j].s_port,
			    cs_inet_ntoa(SIN_GET_ADDR(cad)), SIN_GET_PORT(cad),
			    username(cl));

			if (!cl) {
				cl = create_client(SIN_GET_ADDR(cad));
				if (!cl) return 0;

				cl->ctyp=i;
				cl->port_idx=j;
				cl->udp_fd=modules[i].ptab->ports[j].fd;
				cl->udp_sa=cad;
				cl->udp_sa_len = sizeof(cl->udp_sa);

				cl->port=ntohs(SIN_GET_PORT(cad));
				cl->typ='c';

				add_job(cl, ACTION_CLIENT_INIT, NULL, 0);
			}
			add_job(cl, ACTION_CLIENT_UDP, buf, n+3);
		} else
			free(buf);
	} else { //TCP
		int32_t pfd3;
		if ((pfd3=accept(modules[i].ptab->ports[j].fd, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {

			if (cs_check_violation(SIN_GET_ADDR(cad), modules[i].ptab->ports[j].s_port)) {
				close(pfd3);
				return 0;
			}

			cl = create_client(SIN_GET_ADDR(cad));
			if (cl == NULL) {
				close(pfd3);
				return 0;
			}

			int32_t flag = 1;
			setsockopt(pfd3, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
			setTCPTimeouts(pfd3);

			cl->ctyp=i;
			cl->udp_fd=pfd3;
			cl->port_idx=j;

			cl->pfd=pfd3;
			cl->port=ntohs(SIN_GET_PORT(cad));
			cl->typ='c';

			add_job(cl, ACTION_CLIENT_INIT, NULL, 0);
		}
	}
	return 0;
}

#ifdef WEBIF
pid_t pid;


void fwd_sig(int32_t sig)
{
    kill(pid, sig);
}

static void restart_daemon(void)
{
  while (1) {

    //start client process:
    pid = fork();
    if (!pid)
      return; //client process=oscam process
    if (pid < 0)
      exit(1);

    //set signal handler for the restart daemon:
    set_signal_handler(SIGTERM, 0, fwd_sig);
    set_signal_handler(SIGQUIT, 0, fwd_sig);
    set_signal_handler(SIGHUP , 0, fwd_sig);
                                                                                                                                                
    //restart control process:
    int32_t res=0;
    int32_t status=0;
    do {
      res = waitpid(pid, &status, 0);
      if (res==-1) {
        if (errno!=EINTR)
          exit(1);
      }
    } while (res!=pid);

    if (cs_restart_mode==2 && WIFSIGNALED(status) && WTERMSIG(status)==SIGSEGV)
      status=99; //restart on segfault!
    else
      status = WEXITSTATUS(status);

    //status=99 restart oscam, all other->terminate
    if (status!=99) {
      exit(status);
    }
  }
}

void cs_restart_oscam(void) {
	exit_oscam=99;
	cs_log("restart oscam requested");
}

int32_t cs_get_restartmode(void) {
	return cs_restart_mode;
}
#endif

void cs_exit_oscam(void) {
	exit_oscam = 1;
	cs_log("exit oscam requested");
}

void pidfile_create(char *pidfile) {
	FILE *f = fopen(pidfile, "w");
	if (f) {
		pid_t my_pid = getpid();
		cs_log("creating pidfile %s with pid %d", pidfile, my_pid);
		fprintf(f, "%d\n", my_pid);
		fclose(f);
	}
}

int32_t main (int32_t argc, char *argv[])
{
	int32_t i, j;
	prog_name = argv[0];
	if (pthread_key_create(&getclient, NULL)) {
		fprintf(stderr, "Could not create getclient, exiting...");
		exit(1);
	}

  void (*mod_def[])(struct s_module *)=
  {
#ifdef MODULE_MONITOR
           module_monitor,
#endif
#ifdef MODULE_CAMD33
           module_camd33,
#endif
#ifdef MODULE_CAMD35
           module_camd35,
#endif
#ifdef MODULE_CAMD35_TCP
           module_camd35_tcp,
#endif
#ifdef MODULE_NEWCAMD
           module_newcamd,
#endif
#ifdef MODULE_CCCAM
           module_cccam,
#endif
#ifdef MODULE_PANDORA
           module_pandora,
#endif
#ifdef MODULE_GHTTP
           module_ghttp,
#endif
#ifdef CS_CACHEEX
           module_csp,
#endif
#ifdef MODULE_GBOX
           module_gbox,
#endif
#ifdef MODULE_CONSTCW
           module_constcw,
#endif
#ifdef MODULE_RADEGAST
           module_radegast,
#endif
#ifdef MODULE_SERIAL
           module_serial,
#endif
#ifdef HAVE_DVBAPI
	   module_dvbapi,
#endif
           0
  };

  void (*cardsystem_def[])(struct s_cardsystem *)=
  {
#ifdef READER_NAGRA
	reader_nagra,
#endif
#ifdef READER_IRDETO
	reader_irdeto,
#endif
#ifdef READER_CONAX
	reader_conax,
#endif
#ifdef READER_CRYPTOWORKS
	reader_cryptoworks,
#endif
#ifdef READER_SECA
	reader_seca,
#endif
#ifdef READER_VIACCESS
	reader_viaccess,
#endif
#ifdef READER_VIDEOGUARD
	reader_videoguard1,
	reader_videoguard2,
	reader_videoguard12,
#endif
#ifdef READER_DRE
	reader_dre,
#endif
#ifdef READER_TONGFANG
	reader_tongfang,
#endif
#ifdef READER_BULCRYPT
	reader_bulcrypt,
#endif
	0
  };

  void (*cardreader_def[])(struct s_cardreader *)=
  {
#ifdef CARDREADER_DB2COM
	cardreader_db2com,
#endif
#if defined(CARDREADER_INTERNAL_AZBOX)
	cardreader_internal_azbox,
#elif defined(CARDREADER_INTERNAL_COOLAPI)
	cardreader_internal_cool,
#elif defined(CARDREADER_INTERNAL_SCI)
	cardreader_internal_sci,
#endif
#ifdef CARDREADER_PHOENIX
	cardreader_mouse,
#endif
#ifdef CARDREADER_MP35
	cardreader_mp35,
#endif
#ifdef CARDREADER_PCSC
	cardreader_pcsc,
#endif
#ifdef CARDREADER_SC8IN1
	cardreader_sc8in1,
#endif
#ifdef CARDREADER_SMARGO
	cardreader_smargo,
#endif
#ifdef CARDREADER_SMART
	cardreader_smartreader,
#endif
#ifdef CARDREADER_STAPI
	cardreader_stapi,
#endif
	0
  };

  parse_cmdline_params(argc, argv);
  init_signal(true);

  if (bg && do_daemon(1,0))
  {
    printf("Error starting in background (errno=%d: %s)", errno, strerror(errno));
    cs_exit(1);
  }

  get_random_bytes_init();

#ifdef WEBIF
  if (cs_restart_mode)
    restart_daemon();
#endif

  memset(&cfg, 0, sizeof(struct s_config));
  cfg.max_pending = max_pending;

  if (cs_confdir[strlen(cs_confdir)]!='/') strcat(cs_confdir, "/");
  init_signal_pre(); // because log could cause SIGPIPE errors, init a signal handler first
  init_first_client();
  cs_lock_create(&system_lock, 5, "system_lock");
  cs_lock_create(&config_lock, 10, "config_lock");
  cs_lock_create(&gethostbyname_lock, 10, "gethostbyname_lock");
  cs_lock_create(&clientlist_lock, 5, "clientlist_lock");
  cs_lock_create(&readerlist_lock, 5, "readerlist_lock");
  cs_lock_create(&fakeuser_lock, 5, "fakeuser_lock");
  cs_lock_create(&ecmcache_lock, 5, "ecmcache_lock");
  cs_lock_create(&readdir_lock, 5, "readdir_lock");
  cs_lock_create(&hitcache_lock, 5, "hitcache_lock");
  coolapi_open_all();
  init_config();
  cs_init_log();
  if (!oscam_pidfile && cfg.pidfile)
    oscam_pidfile = cfg.pidfile;
  if (!oscam_pidfile) {
    snprintf(default_pidfile, sizeof(default_pidfile) - 1, "%s%s", get_tmp_dir(), "/oscam.pid");
    oscam_pidfile = default_pidfile;
  }
  if (oscam_pidfile)
    pidfile_create(oscam_pidfile);
  cs_init_statistics();
  init_check();
  init_stat();

  // These initializations *MUST* be called after init_config()
  // because modules depend on config values.
  for (i=0; mod_def[i]; i++)
  {
	memset(&modules[i], 0, sizeof(struct s_module));
	mod_def[i](&modules[i]);
  }
  for (i=0; cardsystem_def[i]; i++)
  {
	memset(&cardsystems[i], 0, sizeof(struct s_cardsystem));
	cardsystem_def[i](&cardsystems[i]);
  }
  for (i=0; cardreader_def[i]; i++)
  {
	memset(&cardreaders[i], 0, sizeof(struct s_cardreader));
	cardreader_def[i](&cardreaders[i]);
  }

  init_sidtab();
  init_readerdb();
  cfg.account = init_userdb();
  init_signal(false);
  init_srvid();
  init_tierid();
  init_provid();

  start_garbage_collector(gbdb);

  cacheex_init();

  init_len4caid();
  init_irdeto_guess_tab();

  write_versionfile(false);
  server_pid = getpid();

  led_init();
  led_status_default();

  azbox_init();

  mca_init();

  global_whitelist_read();
  cacheex_load_config_file();

  for (i=0; i<CS_MAX_MOD; i++)
    if( (modules[i].type & MOD_CONN_NET) && modules[i].ptab )
      for(j=0; j<modules[i].ptab->nports; j++)
      {
        start_listener(&modules[i], j);
      }

	//set time for server to now to avoid 0 in monitor/webif
	first_client->last=time((time_t *)0);

	webif_init();

	start_thread((void *) &reader_check, "reader check");
	start_thread((void *) &check_thread, "check");

	lcd_thread_start();

#ifndef WITH_CARDREADER
	cs_log("Binary without Cardreader Support! No EMM processing possible!");
#endif
#ifndef READER_NAGRA
	cs_log("Binary without Nagra Module - no EMM processing for Nagra possible!");
#endif
#ifndef READER_IRDETO
	cs_log("Binary without Irdeto Module - no EMM processing for Irdeto possible!");
#endif
#ifndef READER_CONAX
	cs_log("Binary without Conax Module - no EMM processing for Conax possible!");
#endif
#ifndef READER_CRYPTOWORKS
	cs_log("Binary without Cryptoworks Module - no EMM processing for Cryptoworks possible!");
#endif
#ifndef READER_SECA
	cs_log("Binary without Seca Module - no EMM processing for Seca possible!");
#endif
#ifndef READER_VIACCESS
	cs_log("Binary without Viaccess Module - no EMM processing for Viaccess possible!");
#endif
#ifndef READER_VIDEOGUARD
	cs_log("Binary without Videoguard Module - no EMM processing for Videoguard possible!");
#endif
#ifndef READER_DRE
	cs_log("Binary without Dre Module - no EMM processing for Dre possible!");
#endif
#ifndef READER_TONGFANG
	cs_log("Binary without Tongfang Module - no EMM processing for Tongfang possible!");
#endif
#ifndef READER_BULCRYPT
	cs_log("Binary without Bulcrypt Module - no EMM processing for Bulcrypt possible!");
#endif

	init_cardreader();

	cs_waitforcardinit();

	led_status_starting();

	ac_init();

	for (i=0; i<CS_MAX_MOD; i++)
		if (modules[i].type & MOD_CONN_SERIAL)   // for now: oscam_ser only
			if (modules[i].s_handler)
				modules[i].s_handler(NULL, NULL, i);

	// main loop function
	client_check();

	azbox_close();

	mca_close();

	cs_cleanup();
	while(ll_count(log_list) > 0)
		cs_sleepms(1);
	stop_garbage_collector();

	return exit_oscam;
}
