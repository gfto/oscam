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
#include "oscam-config.h"
#include "oscam-ecm.h"
#include "oscam-emm.h"
#include "oscam-failban.h"
#include "oscam-files.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "reader-common.h"

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
	_check(READER_GRIFFIN, "griffin");
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
		write_readerconf(READER_GRIFFIN, "Griffin");
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
  struct sigaction sa;
  sigaction(sig, (struct sigaction *) 0, &sa);
  if (!((flags & 2) && (sa.sa_handler==SIG_IGN)))
  {
    sigemptyset(&sa.sa_mask);
    sa.sa_flags=(flags & 1) ? SA_RESTART : 0;
    sa.sa_handler=sighandler;
    sigaction(sig, &sa, (struct sigaction *) 0);
  }
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
#if defined(__APPLE__)
		set_signal_handler(SIGEMT, 3, cs_exit);
#endif
		set_signal_handler(SIGTERM, 3, cs_exit);

		set_signal_handler(SIGWINCH, 1, SIG_IGN);
		set_signal_handler(SIGPIPE , 0, cs_sigpipe);
		set_signal_handler(SIGALRM , 0, cs_master_alarm);
		set_signal_handler(SIGHUP  , 1, isDaemon?cs_dummy:cs_reload_config);
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

			cs_log("signal handling initialized");
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
						request_cw_from_readers(er);

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
#ifdef READER_GRIFFIN
	reader_griffin,
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
#ifndef READER_GRIFFIN
	cs_log("Binary without Griffin Module - no EMM processing for Griffin possible!");
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
