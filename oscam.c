  //FIXME Not checked on threadsafety yet; after checking please remove this line
#define CS_CORE
#include "globals.h"
#include "csctapi/icc_async.h"
#ifdef MODULE_CCCAM
#include "module-cccam.h"
#endif
#if defined(AZBOX) && defined(HAVE_DVBAPI)
#  include "openxcas/openxcas_api.h"
#endif
#define CS_VERSION_X  CS_VERSION
#ifdef COOL
void coolapi_close_all();
void coolapi_open_all();
#endif

static void cs_fake_client(struct s_client *client, char *usr, int32_t uniq, in_addr_t ip);

/*****************************************************************************
        Globals
*****************************************************************************/
int32_t exit_oscam=0;
struct s_module 	ph[CS_MAX_MOD]; // Protocols
struct s_cardsystem	cardsystem[CS_MAX_MOD];
struct s_cardreader	cardreader[CS_MAX_MOD];

struct s_client * first_client = NULL; //Pointer to clients list, first client is master
struct s_reader * first_active_reader = NULL; //list of active readers (enable=1 deleted = 0)
LLIST * configured_readers = NULL; //list of all (configured) readers

uint16_t  len4caid[256];    // table for guessing caid (by len)
char  cs_confdir[128]=CS_CONFDIR;
int32_t cs_dblevel=0;   // Debug Level
int32_t thread_pipe[2] = {0, 0};
#ifdef WEBIF
int8_t cs_restart_mode=1; //Restartmode: 0=off, no restart fork, 1=(default)restart fork, restart by webif, 2=like=1, but also restart on segfaults
#endif
int8_t cs_capture_SEGV=0;
char  cs_tmpdir[200]={0x00};
pid_t server_pid=0;
#if defined(LIBUSB)
CS_MUTEX_LOCK sr_lock;
#endif
CS_MUTEX_LOCK system_lock;
CS_MUTEX_LOCK get_cw_lock;
CS_MUTEX_LOCK gethostbyname_lock;
CS_MUTEX_LOCK clientlist_lock;
CS_MUTEX_LOCK readerlist_lock;
CS_MUTEX_LOCK fakeuser_lock;
pthread_key_t getclient;

pthread_mutex_t	check_mutex;
pthread_cond_t	check_cond;

//Cache for  ecms, cws and rcs:
LLIST *ecmcache = NULL;
LLIST *checklist = NULL;

struct  s_config  cfg;

char    *processUsername = NULL;
char    *loghist = NULL;     // ptr of log-history
char    *loghistptr = NULL;

int8_t keep_threads_alive = 0;

int32_t cs_check_v(uint32_t ip, int32_t port, int32_t add) {
	int32_t result = 0;
	if (cfg.failbantime) {

		if (!cfg.v_list)
			cfg.v_list = ll_create();

		time_t now = time((time_t)0);
		LL_ITER itr = ll_iter_create(cfg.v_list);
		V_BAN *v_ban_entry;
		int32_t ftime = cfg.failbantime*60;

		//run over all banned entries to do housekeeping:
		while ((v_ban_entry=ll_iter_next(&itr))) {

			// housekeeping:
			if ((now - v_ban_entry->v_time) >= ftime) { // entry out of time->remove
				ll_iter_remove_data(&itr);
				continue;
			}

			if (ip == v_ban_entry->v_ip && port == v_ban_entry->v_port ) {
				result=1;
				if (!add) {
					if (v_ban_entry->v_count >= cfg.failbancount) {
						cs_debug_mask(D_TRACE, "failban: banned ip %s:%d - %ld seconds left",
								cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port,
								ftime - (now - v_ban_entry->v_time));
					} else {
						cs_debug_mask(D_TRACE, "failban: ip %s:%d chance %d of %d",
								cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port,
								v_ban_entry->v_count, cfg.failbancount);

						v_ban_entry->v_count++;
					}
				}
				else {
					cs_debug_mask(D_TRACE, "failban: banned ip %s:%d - already exist in list",
							cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port);
				}
			}
		}
		if (add && !result) {
			if(cs_malloc(&v_ban_entry, sizeof(V_BAN), -1)){
				v_ban_entry->v_time = time((time_t *)0);
				v_ban_entry->v_ip = ip;
				v_ban_entry->v_port = port;
				v_ban_entry->v_count = 1;

				ll_iter_insert(&itr, v_ban_entry);

				cs_debug_mask(D_TRACE, "failban: ban ip %s:%d with timestamp %d",
						cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_port, v_ban_entry->v_time);
			}
		}
	}
	return result;
}

int32_t cs_check_violation(uint32_t ip, int32_t port) {
        return cs_check_v(ip, port, 0);
}
void cs_add_violation(uint32_t ip, int32_t port) {
        cs_check_v(ip, port, 1);
}

#ifdef WEBIF
void cs_add_lastresponsetime(struct s_client *cl, int32_t ltime, time_t timestamp, int32_t rc){

	if(cl->cwlastresptimes_last == CS_ECM_RINGBUFFER_MAX - 1){
		cl->cwlastresptimes_last = 0;
	} else {
		cl->cwlastresptimes_last++;
	}
	cl->cwlastresptimes[cl->cwlastresptimes_last].duration = ltime > 9999 ? 9999 : ltime;
	cl->cwlastresptimes[cl->cwlastresptimes_last].timestamp = timestamp;
	cl->cwlastresptimes[cl->cwlastresptimes_last].rc = rc;
}
#endif

/*****************************************************************************
        Statics
*****************************************************************************/
static const char *logo = "  ___  ____   ___                \n / _ \\/ ___| / __|__ _ _ __ ___  \n| | | \\___ \\| |  / _` | '_ ` _ \\ \n| |_| |___) | |_| (_| | | | | | |\n \\___/|____/ \\___\\__,_|_| |_| |_|\n";

/* Prints usage information and information about the built-in modules. */
static void usage()
{
  fprintf(stderr, "%s\n\n", logo);
  fprintf(stderr, "OSCam cardserver v%s, build #%s (%s) - (w) 2009-2011 Streamboard SVN\n", CS_VERSION_X, CS_SVN_VERSION, CS_OSTYPE);
  fprintf(stderr, "\tsee http://streamboard.gmc.to/oscam/ for more details\n");
  fprintf(stderr, "\tbased on Streamboard mp-cardserver v0.9d - (w) 2004-2007 by dukat\n");
  fprintf(stderr, "\tThis program is distributed under GPL.\n");
  fprintf(stderr, "\tinbuilt add-ons: ");
#ifdef WEBIF
  fprintf(stderr, "webif ");
#endif
#ifdef MODULE_MONITOR
  fprintf(stderr, "monitor ");
#endif
#ifdef WITH_SSL
  fprintf(stderr, "ssl ");
#endif
#ifdef HAVE_DVBAPI
#ifdef WITH_STAPI
  fprintf(stderr, "dvbapi_stapi ");
#else
  fprintf(stderr, "dvbapi ");
#endif
#endif
#ifdef IRDETO_GUESSING
  fprintf(stderr, "irdeto-guessing ");
#endif
#ifdef CS_ANTICASC
  fprintf(stderr, "anticascading ");
#endif
#ifdef WITH_DEBUG
  fprintf(stderr, "debug ");
#endif
#ifdef CS_LED
  fprintf(stderr, "led ");
#endif
#ifdef CS_WITH_DOUBLECHECK
  fprintf(stderr, "doublecheck ");
#endif
#ifdef QBOXHD_LED
  fprintf(stderr, "qboxhd-led ");
#endif
#ifdef CS_LOGHISTORY
  fprintf(stderr, "loghistory ");
#endif
#ifdef LIBUSB
  fprintf(stderr, "smartreader ");
#endif
#ifdef HAVE_PCSC
  fprintf(stderr, "pcsc ");
#endif
#ifdef WITH_LB
  fprintf(stderr, "loadbalancing ");
#endif
#ifdef LCDSUPPORT
  fprintf(stderr, "lcd ");
#endif
  fprintf(stderr, "\n\tinbuilt protocols: ");
#ifdef MODULE_CAMD33
  fprintf(stderr, "camd33 ");
#endif
#ifdef MODULE_CAMD35
  fprintf(stderr, "camd35_udp ");
#endif
#ifdef MODULE_CAMD35_TCP
  fprintf(stderr, "camd35_tcp ");
#endif
#ifdef MODULE_NEWCAMD
  fprintf(stderr, "newcamd ");
#endif
#ifdef MODULE_CCCAM
  fprintf(stderr, "cccam ");
#endif
#ifdef MODULE_GBOX
  fprintf(stderr, "gbox ");
#endif
#ifdef MODULE_RADEGAST
  fprintf(stderr, "radegast ");
#endif
#ifdef MODULE_SERIAL
  fprintf(stderr, "serial ");
#endif
#ifdef MODULE_CONSTCW
  fprintf(stderr, "constcw ");
#endif
  fprintf(stderr, "\n\tinbuilt cardreaders: ");
#ifdef READER_NAGRA
  fprintf(stderr, "nagra ");
#endif
#ifdef READER_IRDETO
  fprintf(stderr, "irdeto ");
#endif
#ifdef READER_CONAX
  fprintf(stderr, "conax ");
#endif
#ifdef READER_CRYPTOWORKS
  fprintf(stderr, "cryptoworks ");
#endif
#ifdef READER_SECA
  fprintf(stderr, "seca ");
#endif
#ifdef READER_VIACCESS
  fprintf(stderr, "viaccess ");
#endif
#ifdef READER_VIDEOGUARD
  fprintf(stderr, "videoguard ");
#endif
#ifdef READER_DRE
  fprintf(stderr, "dre ");
#endif
#ifdef READER_TONGFANG
  fprintf(stderr, "tongfang ");
#endif
  fprintf(stderr, "\n\n");
  fprintf(stderr, "oscam [-b] [-s] [-c <config dir>] [-t <tmp dir>] [-d <level>] [-r <level>] [-h]");
  fprintf(stderr, "\n\n\t-b         : start in background\n");
  fprintf(stderr, "\t-s         : capture segmentation faults\n");
  fprintf(stderr, "\t-c <dir>   : read configuration from <dir>\n");
  fprintf(stderr, "\t             default = %s\n", CS_CONFDIR);
  fprintf(stderr, "\t-t <dir>   : tmp dir <dir>\n");
#ifdef CS_CYGWIN32
  fprintf(stderr, "\t             default = (OS-TMP)\n");
#else
  fprintf(stderr, "\t             default = /tmp/.oscam\n");
#endif
  fprintf(stderr, "\t-d <level> : debug level mask\n");
  fprintf(stderr, "\t               0 = no debugging (default)\n");
  fprintf(stderr, "\t               1 = detailed error messages\n");
  fprintf(stderr, "\t               2 = ATR parsing info, ECM, EMM and CW dumps\n");
  fprintf(stderr, "\t               4 = traffic from/to the reader\n");
  fprintf(stderr, "\t               8 = traffic from/to the clients\n");
  fprintf(stderr, "\t              16 = traffic to the reader-device on IFD layer\n");
  fprintf(stderr, "\t              32 = traffic to the reader-device on I/O layer\n");
  fprintf(stderr, "\t              64 = EMM logging\n");
  fprintf(stderr, "\t             128 = DVBAPI logging\n");
  fprintf(stderr, "\t             255 = debug all\n");
#ifdef WEBIF
  fprintf(stderr, "\t-r <level> : restart level\n");
  fprintf(stderr, "\t               0 = disabled, restart request sets exit status 99\n");
  fprintf(stderr, "\t               1 = restart activated, web interface can restart oscam (default)\n");
  fprintf(stderr, "\t               2 = like 1, but also restart on segmentation faults\n");
#endif
  fprintf(stderr, "\t-h         : show this help\n");
  fprintf(stderr, "\n");
  exit(1);
}

#ifdef NEED_DAEMON
#ifdef OS_MACOSX
// this is done because daemon is being deprecated starting with 10.5 and -Werror will always trigger an error
static int32_t daemon_compat(int32_t nochdir, int32_t noclose)
#else
static int32_t daemon(int32_t nochdir, int32_t noclose)
#endif
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

/* Returns the username from the client. You will always get a char reference back (no NULLs but it may be string containting "NULL")
   which you should never modify and not free()! */
char *username(struct s_client * client)
{
	if (!client)
		return "NULL";

	if (client->typ == 's' || client->typ == 'h' || client->typ == 'a')
	{
		return processUsername?processUsername:"NULL";
	}

	if (client->typ == 'c' || client->typ == 'm') {
		struct s_auth *acc = client->account;
		if(acc)
		{
			if (acc->usr[0])
				return acc->usr;
			else
				return "anonymous";
		}
		else
		{
			return "NULL";
		}
	} else if (client->typ == 'r' || client->typ == 'p'){
		struct s_reader *rdr = client->reader;
		if(rdr)
			return rdr->label;
	}
	return "NULL";
}

static struct s_client * idx_from_ip(in_addr_t ip, in_port_t port)
{
  struct s_client *cl;
  for (cl=first_client; cl ; cl=cl->next)
    if ((cl->ip==ip) && (cl->port==port) && ((cl->typ=='c') || (cl->typ=='m')))
      return cl;
  return NULL;
}

static int32_t chk_caid(uint16_t caid, CAIDTAB *ctab)
{
  int32_t n;
  int32_t rc;
  for (rc=(-1), n=0; (n<CS_MAXCAIDTAB) && (rc<0); n++)
    if ((caid & ctab->mask[n]) == ctab->caid[n])
      rc=ctab->cmap[n] ? ctab->cmap[n] : caid;
  return(rc);
}

int32_t chk_bcaid(ECM_REQUEST *er, CAIDTAB *ctab)
{
  int32_t caid;
  if ((caid=chk_caid(er->caid, ctab))<0)
    return(0);
  er->caid=caid;
  return(1);
}

#ifdef WEBIF
void clear_account_stats(struct s_auth *account)
{
  account->cwfound = 0;
  account->cwcache = 0;
  account->cwnot = 0;
  account->cwtun = 0;
  account->cwignored  = 0;
  account->cwtout = 0;
  account->emmok = 0;
  account->emmnok = 0;
}

void clear_all_account_stats()
{
  struct s_auth *account = cfg.account;
  while (account) {
    clear_account_stats(account);
    account = account->next;
  }
}

void clear_system_stats()
{
  first_client->cwfound = 0;
  first_client->cwcache = 0;
  first_client->cwnot = 0;
  first_client->cwtun = 0;
  first_client->cwignored  = 0;
  first_client->cwtout = 0;
  first_client->emmok = 0;
  first_client->emmnok = 0;
}
#endif

void cs_accounts_chk()
{
  struct s_auth *old_accounts = cfg.account;
  struct s_auth *new_accounts = init_userdb();
  struct s_auth *account1,*account2;
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
#ifdef CS_ANTICASC
		account2->ac_users = account1->ac_users;
		account2->ac_penalty = account1->ac_penalty;
		account2->ac_stat = account1->ac_stat;
#endif
      }
    }
  }
  cs_reinit_clients(new_accounts);
  cfg.account = new_accounts;
  init_free_userdb(old_accounts);

#ifdef CS_ANTICASC
  ac_clear();
#endif
}

static void cleanup_ecmtasks(struct s_client *cl)
{
	if (!cl->ecmtask)
		return;
	
	int32_t i, n=(ph[cl->ctyp].multi)?CS_MAXPENDING:1;
	ECM_REQUEST *ecm;
	for (i=0; i<n; i++) {
		ecm = &cl->ecmtask[i];
		ll_destroy(ecm->matching_rdr); //no need to garbage this
		ecm->matching_rdr=NULL;
	}
	add_garbage(cl->ecmtask);
}

void cleanup_thread(void *var)
{
	struct s_client *cl = var;
	if(!cl) return;

	// Remove client from client list. kill_thread also removes this client, so here just if client exits itself...
	struct s_client *prev, *cl2;
	cs_writelock(&clientlist_lock);
	for (prev=first_client, cl2=first_client->next; prev->next != NULL; prev=prev->next, cl2=cl2->next)
		if (cl == cl2)
			break;
	if (cl == cl2)
		prev->next = cl2->next; //remove client from list
	cs_writeunlock(&clientlist_lock);
		
	// Clean reader. The cleaned structures should be only used by the reader thread, so we should be save without waiting
	if (cl->reader){
		remove_reader_from_active(cl->reader);
		if(cl->reader->ph.cleanup)
		cl->reader->ph.cleanup(cl);
		if (cl->typ == 'r')
			ICC_Async_Close(cl->reader);
		if (cl->typ == 'p')
			network_tcp_connection_close(cl->reader);
		cl->reader->client = NULL;
		cl->reader = NULL;
	}

	// Clean client specific data
	if(cl->typ == 'c'){
#ifdef MODULE_CCCAM
		struct cc_data *cc = cl->cc;
		if (cc) cc->mode = CCCAM_MODE_SHUTDOWN;
#endif
		cs_statistics(cl);
		cl->last_caid = 0xFFFF;
		cl->last_srvid = 0xFFFF;
		cs_statistics(cl);
	    
		cs_sleepms(500); //just wait a bit that really really nobody is accessing client data

		if(ph[cl->ctyp].cleanup)
			ph[cl->ctyp].cleanup(cl);
	}
		
	// Close network socket if not already cleaned by previous cleanup functions
	if(cl->pfd)
		close(cl->pfd); 
			
	// Clean all remaining structures


	ll_destroy(cl->joblist);

	cleanup_ecmtasks(cl);
	add_garbage(cl->emmcache);
	add_garbage(cl->req);
#ifdef MODULE_CCCAM
	add_garbage(cl->cc);
#endif
	add_garbage(cl->serialdata);
	add_garbage(cl);
}

static void cs_cleanup()
{
#ifdef WITH_LB
	if (cfg.lb_mode && cfg.lb_save) {
		save_stat_to_file(0);
		cfg.lb_save = 0; //this is for avoiding duplicate saves
	}
#endif

#ifdef MODULE_CCCAM
	done_share();
#endif

	//cleanup clients:
	struct s_client *cl;
	for (cl=first_client->next; cl; cl=cl->next) {
		if (cl->typ=='c'){
			if(cl->account && cl->account->usr)
				cs_log("killing client %s", cl->account->usr);
			kill_thread(cl);
		}
	}

	//cleanup readers:
	struct s_reader *rdr;
	for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
		cs_log("killing reader %s", rdr->label);
		kill_thread(rdr->client);
	}
	first_active_reader = NULL;

	init_free_userdb(cfg.account);
	cfg.account = NULL;
	init_free_sidtab();
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

static void cs_master_alarm()
{
  cs_log("PANIC: master deadlock!");
  fprintf(stderr, "PANIC: master deadlock!");
  fflush(stderr);
}

static void cs_sigpipe()
{
	if (cs_dblevel & D_ALL_DUMP)
		cs_log("Got sigpipe signal -> captured");
}

static void cs_dummy() {
	return;
}

/* Switch debuglevel forward one step (called when receiving SIGUSR1). */
void cs_debug_level(){	
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

void cs_card_info()
{
	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		if( cl->typ=='r' && cl->reader )
			add_job(cl, ACTION_READER_CARDINFO, NULL, 0);
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
void cs_reload_config()
{
		cs_accounts_chk();
		init_srvid();
		init_tierid();
		#ifdef CS_ANTICASC
		ac_init_stat();
		#endif
}

/* Sets signal handlers to ignore for early startup of OSCam because for example log 
   could cause SIGPIPE errors and the normal signal handlers can't be used at this point. */
static void init_signal_pre()
{
		set_signal_handler(SIGPIPE , 1, SIG_IGN);
		set_signal_handler(SIGWINCH, 1, SIG_IGN);
		set_signal_handler(SIGALRM , 1, SIG_IGN);
		set_signal_handler(SIGHUP  , 1, SIG_IGN);
}

/* Sets the signal handlers.*/
static void init_signal()
{
		set_signal_handler(SIGINT, 3, cs_exit);
		//set_signal_handler(SIGKILL, 3, cs_exit);
#ifdef OS_MACOSX
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
		set_signal_handler(SIGHUP  , 1, cs_reload_config);
		//set_signal_handler(SIGHUP , 1, cs_sighup);
		set_signal_handler(SIGUSR1, 1, cs_debug_level);
		set_signal_handler(SIGUSR2, 1, cs_card_info);
		set_signal_handler(SIGCONT, 1, cs_dummy);

		if (cs_capture_SEGV)
			set_signal_handler(SIGSEGV, 1, cs_exit);

		cs_log("signal handling initialized (type=%s)",
#ifdef CS_SIGBSD
		"bsd"
#else
		"sysv"
#endif
		);
	return;
}

void cs_exit(int32_t sig)
{


	set_signal_handler(SIGCHLD, 1, SIG_IGN);
	set_signal_handler(SIGHUP , 1, SIG_IGN);
	set_signal_handler(SIGPIPE, 1, SIG_IGN);

	if (sig==SIGALRM) {
		cs_debug_mask(D_TRACE, "thread %8X: SIGALRM, skipping", pthread_self());
		return;
	}

  if (sig && (sig!=SIGQUIT))
    cs_log("thread %8X exit with signal %d", pthread_self(), sig);

  struct s_client *cl = cur_client();
  if (!cl)
  	return;

  if(cl->typ == 'h' || cl->typ == 's'){
#ifdef CS_LED
		cs_switch_led(LED1B, LED_OFF);
		cs_switch_led(LED2, LED_OFF);
		cs_switch_led(LED3, LED_OFF);
		cs_switch_led(LED1A, LED_ON);
#endif
#ifdef QBOXHD_LED
    qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_RED,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA,QBOXHD_LED_BLINK_FAST);
#endif
#ifdef LCDSUPPORT
    end_lcd_thread();
#endif

#ifndef OS_CYGWIN32
	char targetfile[256];
		snprintf(targetfile, 255, "%s%s", get_tmp_dir(), "/oscam.version");
		if (unlink(targetfile) < 0)
			cs_log("cannot remove oscam version file %s (errno=%d %s)", targetfile, errno, strerror(errno));
#endif
#ifdef COOL
		coolapi_close_all();
#endif
  }

	// this is very important - do not remove
	if (cl->typ != 's') {
		cs_log("thread %8X ended!", pthread_self());

		cleanup_thread(cl);

		//Restore signals before exiting thread
		set_signal_handler(SIGPIPE , 0, cs_sigpipe);
		set_signal_handler(SIGHUP  , 1, cs_reload_config);

		pthread_exit(NULL);
		return;
	}

	cs_log("cardserver down");
	cs_close_log();

	if (sig == SIGINT)
		exit(sig);

	cs_cleanup();

	if (!exit_oscam)
	  exit_oscam = sig?sig:1;
}

void cs_reinit_clients(struct s_auth *new_accounts)
{
	struct s_auth *account;
	unsigned char md5tmp[MD5_DIGEST_LENGTH];

	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		if( (cl->typ == 'c' || cl->typ == 'm') && cl->account ) {
			for (account = new_accounts; (account) ; account = account->next)
				if (!strcmp(cl->account->usr, account->usr))
					break;

			if (account && !account->disabled && cl->pcrc == crc32(0L, MD5((uchar *)account->pwd, strlen(account->pwd), md5tmp), MD5_DIGEST_LENGTH)) {
				cl->account = account;
				if(cl->typ == 'c'){
					cl->grp	= account->grp;
					cl->aureader_list	= account->aureader_list;
					cl->autoau = account->autoau;
					cl->expirationdate = account->expirationdate;
					cl->allowedtimeframe[0] = account->allowedtimeframe[0];
					cl->allowedtimeframe[1] = account->allowedtimeframe[1];
					cl->ncd_keepalive = account->ncd_keepalive;
					cl->c35_suppresscmd08 = account->c35_suppresscmd08;
					cl->tosleep	= (60*account->tosleep);
					cl->c35_sleepsend = account->c35_sleepsend;
					cl->monlvl = account->monlvl;
					cl->disabled	= account->disabled;
					cl->fchid	= account->fchid;  // CHID filters
					cl->cltab	= account->cltab;  // Class
					// newcamd module doesn't like ident reloading
					if(!cl->ncd_server)
						cl->ftab = account->ftab;   // Ident

					cl->sidtabok = account->sidtabok;   // services
					cl->sidtabno = account->sidtabno;   // services
					cl->failban = account->failban;

					memcpy(&cl->ctab, &account->ctab, sizeof(cl->ctab));
					memcpy(&cl->ttab, &account->ttab, sizeof(cl->ttab));
#ifdef WEBIF
					int32_t i;
					for(i = 0; i < CS_ECM_RINGBUFFER_MAX; i++) {
						cl->cwlastresptimes[i].duration = 0;
						cl->cwlastresptimes[i].timestamp = time((time_t)0);
						cl->cwlastresptimes[i].rc = 0;
					}
					cl->cwlastresptimes_last = 0;
#endif
					if (account->uniq)
						cs_fake_client(cl, account->usr, (account->uniq == 1 || account->uniq == 2)?account->uniq+2:account->uniq, cl->ip);
#ifdef CS_ANTICASC
					int32_t numusers = account->ac_users;
					if ( numusers == -1)
						numusers = cfg.ac_users;
					cl->ac_limit	= (numusers * 100 + 80) * cfg.ac_stime;
					cl->ac_penalty = account->ac_penalty == -1 ? cfg.ac_penalty : account->ac_penalty;
					cs_debug_mask(D_CLIENT, "acasc: client '%s', users=%d, stime=%d min, dwlimit=%d per min, penalty=%d",
								  account->usr, numusers, cfg.ac_stime,
								  numusers*100+80, cl->ac_penalty);
#endif
				}
			} else {
				if (ph[cl->ctyp].type & MOD_CONN_NET) {
					cs_debug_mask(D_TRACE, "client '%s', thread=%8X not found in db (or password changed)", cl->account->usr, cl->thread);
					kill_thread(cl);
				} else {
					cl->account = first_client->account;
				}
			}
		} else {
			cl->account = NULL;
		}
}

struct s_client * create_client(in_addr_t ip) {
	struct s_client *cl;

	if(cs_malloc(&cl, sizeof(struct s_client), -1)){
		//client part
		cl->ip=ip;
		cl->account = first_client->account;

		//master part
		pthread_mutex_init(&cl->thread_lock, NULL);

		cl->login=cl->last=time((time_t *)0);

		//Now add new client to the list:
		struct s_client *last;
		cs_writelock(&clientlist_lock);
		for (last=first_client; last->next != NULL; last=last->next); //ends with cl on last client
		last->next = cl;
		cs_writeunlock(&clientlist_lock);
	} else {
		cs_log("max connections reached (out of memory) -> reject client %s", cs_inet_ntoa(ip));
		return NULL;
	}
	return(cl);
}


/* Creates the master client of OSCam and inits some global variables/mutexes. */
static void init_first_client()
{
	// get username OScam is running under
	struct passwd pwd;
	char buf[256];
	struct passwd *pwdbuf;
	if ((getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &pwdbuf)) == 0){
		if(cs_malloc(&processUsername, strlen(pwd.pw_name) + 1, -1))
			cs_strncpy(processUsername, pwd.pw_name, strlen(pwd.pw_name) + 1);
		else
			processUsername = "root";
	} else
		processUsername = "root";

  //Generate 5 ECM cache entries:
  ecmcache = ll_create();

  if(!cs_malloc(&first_client, sizeof(struct s_client), -1)){
    fprintf(stderr, "Could not allocate memory for master client, exiting...");
    exit(1);
  }
  first_client->next = NULL; //terminate clients list with NULL
  first_client->login=time((time_t *)0);
  first_client->ip=cs_inet_addr("127.0.0.1");
  first_client->typ='s';
  first_client->thread=pthread_self();
  struct s_auth *null_account;
  if(!cs_malloc(&null_account, sizeof(struct s_auth), -1)){
  	fprintf(stderr, "Could not allocate memory for master account, exiting...");
    exit(1);
  }
  first_client->account = null_account;
  if (pthread_setspecific(getclient, first_client)) {
    fprintf(stderr, "Could not setspecific getclient in master process, exiting...");
    exit(1);
  }

#if defined(LIBUSB)
  cs_lock_create(&sr_lock, 10, "sr_lock");
#endif
  cs_lock_create(&sc8in1_lock, 10, "sc8in1_lock");
  cs_lock_create(&system_lock, 5, "system_lock");
  cs_lock_create(&get_cw_lock, 5, "get_cw_lock");  
  cs_lock_create(&gethostbyname_lock, 10, "gethostbyname_lock");
  cs_lock_create(&clientlist_lock, 5, "clientlist_lock");
  cs_lock_create(&readerlist_lock, 5, "readerlist_lock");
  cs_lock_create(&fakeuser_lock, 5, "fakeuser_lock");

#ifdef COOL
  coolapi_open_all();
#endif
}

/* Checks if the date of the system is correct and waits if necessary. */
static void init_check(){
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
	  while(time((time_t)0) < builddate){
	  	cs_log("The current system time is smaller than the build date (%s). Waiting 5s for time to correct...", ptr);
	  	cs_sleepms(5000);
	  	++i;
	  	if(i > 6){
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
  struct   sockaddr_in sad;     /* structure to hold server's address */

  ptxt[0][0]=ptxt[1][0]='\0';
  if (!ph->ptab->ports[port_idx].s_port)
  {
    cs_log("%s: disabled", ph->desc);
    return(0);
  }
  is_udp=(ph->type==MOD_CONN_UDP);

  memset((char  *)&sad,0,sizeof(sad)); /* clear sockaddr structure   */
  sad.sin_family = AF_INET;            /* set family to Internet     */
  if (!ph->s_ip)
    ph->s_ip=cfg.srvip;
  if (ph->s_ip)
  {
    sad.sin_addr.s_addr=ph->s_ip;
    snprintf(ptxt[0], sizeof(ptxt[0]), ", ip=%s", inet_ntoa(sad.sin_addr));
  }
  else
    sad.sin_addr.s_addr=INADDR_ANY;
  timeout=cfg.bindwait;
  //ph->fd=0;
  ph->ptab->ports[port_idx].fd = 0;

  if (ph->ptab->ports[port_idx].s_port > 0)   /* test for illegal value    */
    sad.sin_port = htons((uint16_t)ph->ptab->ports[port_idx].s_port);
  else
  {
    cs_log("%s: Bad port %d", ph->desc, ph->ptab->ports[port_idx].s_port);
    return(0);
  }

  if ((ph->ptab->ports[port_idx].fd=socket(PF_INET,is_udp ? SOCK_DGRAM : SOCK_STREAM, is_udp ? IPPROTO_UDP : IPPROTO_TCP))<0)
  {
    cs_log("%s: Cannot create socket (errno=%d: %s)", ph->desc, errno, strerror(errno));
    return(0);
  }

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

#ifdef SO_PRIORITY
  if (cfg.netprio)
    if (!setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_PRIORITY, (void *)&cfg.netprio, sizeof(uint32_t)))
      snprintf(ptxt[1], sizeof(ptxt[1]), ", prio=%d", cfg.netprio);
#endif

  if( !is_udp )
  {
    int32_t keep_alive = 1;
    setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_KEEPALIVE,
               (void *)&keep_alive, sizeof(keep_alive));
  }

  while (timeout--)
  {
    if (bind(ph->ptab->ports[port_idx].fd, (struct sockaddr *)&sad, sizeof (sad))<0)
    {
      if (timeout)
      {
        cs_log("%s: Bind request failed, waiting another %d seconds",
               ph->desc, timeout);
        cs_sleepms(1000);
      }
      else
      {
        cs_log("%s: Bind request failed, giving up", ph->desc);
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
		char buf[120];
		pos += snprintf(buf, sizeof(buf), "-> CAID: %04X PROVID: ", ph->ptab->ports[port_idx].ftab.filts[i].caid );
		
		for( j=0; j<ph->ptab->ports[port_idx].ftab.filts[i].nprids; j++ )
			pos += snprintf(buf+pos, sizeof(buf)-pos, "%06X, ", ph->ptab->ports[port_idx].ftab.filts[i].prids[j]);

		if(pos>2 && j>0)
			buf[pos-2] = '\0';

		cs_log(buf);
	}

	return(ph->ptab->ports[port_idx].fd);
}

/* Resolves the ip of the hostname of the specified account and saves it in account->dynip.
   If the hostname is not configured, the ip is set to 0. */
void cs_user_resolve(struct s_auth *account){
	if (account->dyndns[0]){
		in_addr_t lastip = account->dynip;
		account->dynip = cs_getIPfromHost((char*)account->dyndns);
		
		if (lastip != account->dynip)  {
			cs_log("%s: resolved ip=%s", (char*)account->dyndns, cs_inet_ntoa(account->dynip));
		}
	} else account->dynip=0;
}

/* Starts a thread named nameroutine with the start function startroutine. */
void start_thread(void * startroutine, char * nameroutine) {
	pthread_t temp;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
#ifndef TUXBOX
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	cs_writelock(&system_lock);
	if (pthread_create(&temp, &attr, startroutine, NULL))
		cs_log("ERROR: can't create %s thread", nameroutine);
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
	cl->kill=1;
	add_job(cl, ACTION_CLIENT_KILL, NULL, 0);
}

/* Removes a reader from the list of active readers so that no ecms can be requested anymore. */
void remove_reader_from_active(struct s_reader *rdr) {
	struct s_reader *rdr2, *prv = NULL;
	cs_writelock(&readerlist_lock);
	for (rdr2=first_active_reader; rdr2 ; rdr2=rdr2->next) {
		if (rdr2==rdr) {
			if (prv) prv->next = rdr2->next;
			else first_active_reader = rdr2->next;
			break;
		}
		prv = rdr2;
	}
	cs_writeunlock(&readerlist_lock);
}

/* Adds a reader to the list of active readers so that it can serve ecms. */
void add_reader_to_active(struct s_reader *rdr) {
	struct s_reader *rdr2;
	rdr->next = NULL;
	cs_writelock(&readerlist_lock);
	if (first_active_reader) {
		for (rdr2=first_active_reader; rdr2->next ; rdr2=rdr2->next) ; //search last element
		rdr2->next = rdr;
	} else first_active_reader = rdr;
	cs_writeunlock(&readerlist_lock);
}

/* Starts or restarts a cardreader without locking. If restart=1, the existing thread is killed before restarting,
   if restart=0 the cardreader is only started. */
static int32_t restart_cardreader_int(struct s_reader *rdr, int32_t restart) {
	if (restart){
		remove_reader_from_active(rdr);		//remove from list
		if (rdr->client) {		//kill old thread
			kill_thread(rdr->client);
			rdr->client = NULL;
		}
	}

	rdr->tcp_connected = 0;
	rdr->card_status = UNKNOWN;
	rdr->tcp_block_delay = 100;
	cs_ftime(&rdr->tcp_block_connect_till);

	if (rdr->device[0] && (rdr->typ & R_IS_CASCADING)) {
		if (!rdr->ph.num) {
			cs_log("Protocol Support missing. (typ=%d)", rdr->typ);
			return 0;
		}
		cs_debug_mask(D_TRACE, "reader %s protocol: %s", rdr->label, rdr->ph.desc);
	}

	if (rdr->enable == 0)
		return 0;

	if (rdr->device[0]) {
		if (restart) {
			cs_log("restarting reader %s", rdr->label);
		}

		struct s_client * cl = create_client(first_client->ip);
		if (cl == NULL) return 0;

		cl->reader=rdr;
		cs_log("creating thread for device %s", rdr->device);

		cl->sidtabok=rdr->sidtabok;
		cl->sidtabno=rdr->sidtabno;

		rdr->client=cl;

		cl->typ='r';
		//client[i].ctyp=99;

		add_job(rdr->client, ACTION_READER_INIT, NULL, 0);

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

static void init_cardreader() {

	cs_writelock(&system_lock);
	struct s_reader *rdr;

	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) {
		if (rdr->enable) {
			restart_cardreader_int(rdr, 0);
		}
	}


#ifdef WITH_LB
	load_stat_from_file();
#endif
	cs_writeunlock(&system_lock);
}

static void cs_fake_client(struct s_client *client, char *usr, int32_t uniq, in_addr_t ip)
{
    /* Uniq = 1: only one connection per user
     *
     * Uniq = 2: set (new connected) user only to fake if source
     *           ip is different (e.g. for newcamd clients with
     *	         different CAID's -> Ports)
     *
     * Uniq = 3: only one connection per user, but only the last
     *           login will survive (old mpcs behavior)
     *
     * Uniq = 4: set user only to fake if source ip is
     *           different, but only the last login will survive
     */

	struct s_client *cl;
	struct s_auth *account;
	cs_writelock(&fakeuser_lock);
	for (cl=first_client->next; cl ; cl=cl->next)
	{
		account = cl->account;
		if (cl != client && (cl->typ == 'c') && !cl->dup && account && !strcmp(account->usr, usr)
		   && (uniq < 5) && ((uniq % 2) || (cl->ip != ip)))
		{
		        char buf[20];
			if (uniq  == 3 || uniq == 4)
			{
				cl->dup = 1;
				cl->aureader_list = NULL;
				cs_strncpy(buf, cs_inet_ntoa(cl->ip), sizeof(buf));
				cs_log("client(%8X) duplicate user '%s' from %s (prev %s) set to fake (uniq=%d)",
					cl->thread, usr, cs_inet_ntoa(ip), buf, uniq);
				if (cl->failban & BAN_DUPLICATE) {
					cs_add_violation(cl->ip, ph[cl->ctyp].ptab->ports[cl->port_idx].s_port);
				}
				if (cfg.dropdups){
					cs_writeunlock(&fakeuser_lock);
					kill_thread(cl);
					cs_writelock(&fakeuser_lock);
				}
			}
			else
			{
				client->dup = 1;
				client->aureader_list = NULL;
				cs_strncpy(buf, cs_inet_ntoa(ip), sizeof(buf));
				cs_log("client(%8X) duplicate user '%s' from %s (current %s) set to fake (uniq=%d)",
					pthread_self(), usr, cs_inet_ntoa(cl->ip), buf, uniq);
				if (client->failban & BAN_DUPLICATE) {
					cs_add_violation(ip, ph[client->ctyp].ptab->ports[client->port_idx].s_port);
				}
				if (cfg.dropdups){
					cs_writeunlock(&fakeuser_lock);		// we need to unlock here as cs_disconnect_client kills the current thread!
					cs_disconnect_client(client);
				}
				break;
			}
		}
	}
	cs_writeunlock(&fakeuser_lock);
}

int32_t cs_auth_client(struct s_client * client, struct s_auth *account, const char *e_txt)
{
	int32_t rc=0;
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	char buf[32];
	char *t_crypt="encrypted";
	char *t_plain="plain";
	char *t_grant=" granted";
	char *t_reject=" rejected";
	char *t_msg[]= { buf, "invalid access", "invalid ip", "unknown reason", "protocol not allowed" };
	memset(&client->grp, 0xff, sizeof(uint64_t));
	//client->grp=0xffffffffffffff;
	if ((intptr_t)account != 0 && (intptr_t)account != -1 && account->disabled){
		cs_add_violation((uint32_t)client->ip, ph[client->ctyp].ptab ? ph[client->ctyp].ptab->ports[client->port_idx].s_port : 0);
		cs_log("%s %s-client %s%s (%s%sdisabled account)",
				client->crypted ? t_crypt : t_plain,
				ph[client->ctyp].desc,
				client->ip ? cs_inet_ntoa(client->ip) : "",
				client->ip ? t_reject : t_reject+1,
				e_txt ? e_txt : "",
				e_txt ? " " : "");
		return(1);
	}

	// check whether client comes in over allowed protocol
	if ((intptr_t)account != 0 && (intptr_t)account != -1 && (intptr_t)account->allowedprotocols &&
			(((intptr_t)account->allowedprotocols & ph[client->ctyp].listenertype) != ph[client->ctyp].listenertype )){
		cs_add_violation((uint32_t)client->ip, ph[client->ctyp].ptab->ports[client->port_idx].s_port);
		cs_log("%s %s-client %s%s (%s%sprotocol not allowed)",
						client->crypted ? t_crypt : t_plain,
						ph[client->ctyp].desc,
						client->ip ? cs_inet_ntoa(client->ip) : "",
						client->ip ? t_reject : t_reject+1,
						e_txt ? e_txt : "",
						e_txt ? " " : "");
		return(1);
	}

	client->account=first_client->account;
	switch((intptr_t)account)
	{
	case 0:           // reject access
		rc=1;
		cs_add_violation((uint32_t)client->ip, ph[client->ctyp].ptab->ports[client->port_idx].s_port);
		cs_log("%s %s-client %s%s (%s)",
				client->crypted ? t_crypt : t_plain,
				ph[client->ctyp].desc,
				client->ip ? cs_inet_ntoa(client->ip) : "",
				client->ip ? t_reject : t_reject+1,
				e_txt ? e_txt : t_msg[rc]);
		break;
	default:            // grant/check access
		if (client->ip && account->dyndns[0]) {
			if (client->ip != account->dynip)
				cs_user_resolve(account);
			if (client->ip != account->dynip) {
				cs_add_violation((uint32_t)client->ip, ph[client->ctyp].ptab->ports[client->port_idx].s_port);
				rc=2;
			}
		}

		client->monlvl=account->monlvl;
		client->account = account;
		if (!rc)
		{
			client->dup=0;
			if (client->typ=='c' || client->typ=='m')
				client->pcrc = crc32(0L, MD5((uchar *)account->pwd, strlen(account->pwd), md5tmp), MD5_DIGEST_LENGTH);
			if (client->typ=='c')
			{
				client->last_caid = 0xFFFE;
				client->last_srvid = 0xFFFE;
				client->expirationdate = account->expirationdate;
				client->disabled = account->disabled;
				client->allowedtimeframe[0] = account->allowedtimeframe[0];
				client->allowedtimeframe[1] = account->allowedtimeframe[1];
				if(account->firstlogin == 0) account->firstlogin = time((time_t)0);
				client->failban = account->failban;
				client->c35_suppresscmd08 = account->c35_suppresscmd08;
				client->ncd_keepalive = account->ncd_keepalive;
				client->grp = account->grp;
				client->aureader_list = account->aureader_list;
				client->autoau = account->autoau;
				client->tosleep = (60*account->tosleep);
				client->c35_sleepsend = account->c35_sleepsend;
				memcpy(&client->ctab, &account->ctab, sizeof(client->ctab));
				if (account->uniq)
					cs_fake_client(client, account->usr, account->uniq, client->ip);
				client->ftab  = account->ftab;   // IDENT filter
				client->cltab = account->cltab;  // CLASS filter
				client->fchid = account->fchid;  // CHID filter
				client->sidtabok= account->sidtabok;   // services
				client->sidtabno= account->sidtabno;   // services
				memcpy(&client->ttab, &account->ttab, sizeof(client->ttab));
#ifdef CS_ANTICASC
				ac_init_client(client, account);
#endif
			}
		}
	case -1:            // anonymous grant access
		if (rc)
			t_grant=t_reject;
		else {
			if (client->typ=='m')
				snprintf(t_msg[0], sizeof(buf), "lvl=%d", client->monlvl);
			else {
				int32_t rcount = ll_count(client->aureader_list);
				snprintf(buf, sizeof(buf), "au=");
				if (!rcount)
					snprintf(buf+3, sizeof(buf)-3, "off");
				else {
					if (client->autoau)
						snprintf(buf+3, sizeof(buf)-3, "auto (%d reader)", rcount);
					else
						snprintf(buf+3, sizeof(buf)-3, "on (%d reader)", rcount);
				}
			}
		}

		cs_log("%s %s-client %s%s (%s, %s)",
			client->crypted ? t_crypt : t_plain,
			e_txt ? e_txt : ph[client->ctyp].desc,
			client->ip ? cs_inet_ntoa(client->ip) : "",
			client->ip ? t_grant : t_grant+1,
			username(client), t_msg[rc]);

		break;
	}
	return(rc);
}

void cs_disconnect_client(struct s_client * client)
{
	char buf[32]={0};
	if (client->ip)
		snprintf(buf, sizeof(buf), " from %s", cs_inet_ntoa(client->ip));
	cs_log("%s disconnected %s", username(client), buf);
	cs_exit(0);
}

/**
 * ecm cache
 **/
static int32_t check_and_store_ecmcache(ECM_REQUEST *er, uint64_t grp)
{
	time_t now = time(NULL);
	time_t timeout = now-(time_t)(cfg.ctimeout/1000)-CS_CACHE_TIMEOUT;
	struct s_ecm *ecmc;
	LL_ITER it = ll_iter_create(ecmcache);
	while ((ecmc=ll_iter_next(&it))) {
		if (ecmc->time < timeout) {
			ll_iter_remove_data(&it);
			continue;
		}

		if (grp && !(grp & ecmc->grp))
			continue;

		if (ecmc->caid!=er->caid)
			continue;

		if (memcmp(ecmc->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
			continue;

		//cs_debug_mask(D_TRACE, "cachehit! (ecm)");
		memcpy(er->cw, ecmc->cw, 16);
		er->selected_reader = ecmc->reader;
		if (ecmc->rc == E_FOUND)
				return E_CACHE1;
		er->ecmcacheptr = ecmc;
		return ecmc->rc;
	}

	//Add cache entry:
	ecmc = cs_malloc(&ecmc, sizeof(struct s_ecm), 0);
	memcpy(ecmc->ecmd5, er->ecmd5, CS_ECMSTORESIZE);
	ecmc->caid = er->caid;
	ecmc->grp = grp;
	ecmc->rc = E_99;
	ecmc->time = now;
	er->ecmcacheptr = ecmc;
	ll_prepend(ecmcache, ecmc);

	return E_UNHANDLED;
}

/**
 * cache 1: client-invoked
 * returns found ecm task index
 **/
static int32_t check_cwcache1(ECM_REQUEST *er, uint64_t grp)
{
	//cs_ddump(ecmd5, CS_ECMSTORESIZE, "ECM search");
	//cs_log("cache1 CHECK: grp=%lX", grp);

	//cs_debug_mask(D_TRACE, "cachesize %d", ll_count(ecmcache));
	time_t now = time(NULL);
	time_t timeout = now-(time_t)(cfg.ctimeout/1000)-CS_CACHE_TIMEOUT;
	struct s_ecm *ecmc;

    LL_ITER it = ll_iter_create(ecmcache);
    while ((ecmc=ll_iter_next(&it))) {
        if (ecmc->time < timeout) {
			ll_iter_remove_data(&it);
			continue;
		}

   		if (ecmc->rc != E_FOUND)
			continue;

		if (ecmc->caid != er->caid)
			continue;

		if (grp && !(grp & ecmc->grp))
			continue;

		if (memcmp(ecmc->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
			continue;

		memcpy(er->cw, ecmc->cw, 16);
		er->selected_reader = ecmc->reader;
		//cs_debug_mask(D_TRACE, "cachehit!");
		return 1;
	}
	return 0;
}

/**
 * cache 2: reader-invoked
 * returns 1 if found in cache. cw is copied to er
 **/
int32_t check_cwcache2(ECM_REQUEST *er, uint64_t grp)
{
	int32_t rc = check_cwcache1(er, grp);
	return rc;
}


static void store_cw_in_cache(ECM_REQUEST *er, uint64_t grp, int32_t rc, uchar *cw)
{
#ifdef CS_WITH_DOUBLECHECK
	if (cfg.double_check && er->checked < 2)
		return;
#endif
	// Check if ecm is outdated and ecmcacheptr thus is invalid (freed from ecmcache),
	// We don't calculate with cfg.ctimeout as this may be changed by WebIf and ECMs older than CS_CACHE_TIMEOUT=60s are useless anyway
	struct timeb tpe;
	cs_ftime(&tpe);
	if(tpe.time - er->tps.time - CS_CACHE_TIMEOUT >= 0) return;

	struct s_ecm *ecm = er->ecmcacheptr;
	if (!ecm || rc >= ecm->rc) return;	
 
	//cs_log("store ecm from reader %d", er->selected_reader);
	memcpy(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE);
	if (cw)
		memcpy(ecm->cw, cw, 16);
	ecm->caid = er->caid;
	ecm->grp = grp;
	ecm->reader = er->selected_reader;
	ecm->rc = rc;
	ecm->time = time(NULL);

	//cs_ddump(cwcache[*cwidx].ecmd5, CS_ECMSTORESIZE, "ECM stored (idx=%d)", *cwidx);
}

/*
 * write_ecm_request():
 */
static int32_t write_ecm_request(struct s_reader *rdr, ECM_REQUEST *er)
{
	add_job(rdr->client, ACTION_READER_ECM_REQUEST, (void*)er, sizeof(ECM_REQUEST));
	return 1;
}


/**
 * distributes found ecm-request to all clients with rc=99
 **/
void distribute_ecm(ECM_REQUEST *er, uint64_t grp, int32_t rc)
{
	struct s_client *cl;
	ECM_REQUEST *ecm;
	int32_t n, i, pending;

	for (cl=first_client->next; cl ; cl=cl->next) {
		if (cl->typ=='c' && cl->ecmtask && (cl->grp&grp)) {
			n=(ph[cl->ctyp].multi)?CS_MAXPENDING:1;
			pending=0;
			for (i=0; i<n; i++) {
				ecm = &cl->ecmtask[i];
				if (ecm->rc >= E_99) {
					pending++;
					if (ecm->ecmcacheptr == er->ecmcacheptr) {
						//cs_log("distribute %04X:%06X:%04X cpti %d to client %s", ecm->caid, ecm->prid, ecm->srvid, ecm->cpti, username(cl));
						write_ecm_answer(er->selected_reader, ecm, rc, 0, er->cw, NULL);
					}
				}
				//else if (ecm->rc == E_99)
				//	cs_log("NO-distribute %04X:%06X:%04X cpti %d to client %s", ecm->caid, ecm->prid, ecm->srvid, ecm->cpti, username(cl));
			}
			cl->pending=pending;
		}
	}
}


int32_t write_ecm_answer(struct s_reader * reader, ECM_REQUEST *er, int8_t rc, uint8_t rcEx, uchar *cw, char *msglog)
{
	int32_t i;
	uchar c;
	struct s_ecm_answer *ea = cs_malloc(&ea, sizeof(struct s_ecm_answer), -1);

	if (cw)
		memcpy(ea->cw, cw, 16);

	if (msglog)
		memcpy(ea->msglog, msglog, MSGLOGSIZE);

	ea->rc = rc;
	ea->rcEx = rcEx;
	ea->reader = reader;

	if (er->parent) {
		// parent is only set on reader->client->ecmtask[], but we want client->ecmtask[]
		er->rc = rc;
		er->idx = 0;
		er = er->parent;
	}

	ea->er = er;

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

	if (reader && ea->rc==E_FOUND) {
		store_cw_in_cache(er, reader->grp, E_FOUND, ea->cw);

		/* CWL logging only if cwlogdir is set in config */
		if (cfg.cwlogdir != NULL)
			logCWtoFile(er, ea->cw);
	}

	int res = 0;
	if (er->client) {
		if (ea->rc==E_TIMEOUT)
			store_cw_in_cache(er, er->client->grp, E_TIMEOUT, NULL);

		add_job(er->client, ACTION_CLIENT_ECM_ANSWER, ea, sizeof(struct s_ecm_answer));
		res = 1;
	}
	
	if (rc == E_FOUND && reader->resetcycle > 0)
	{
		reader->resetcounter++;
		if (reader->resetcounter > reader->resetcycle) {
			reader->resetcounter = 0;
			cs_log("resetting reader %s resetcyle of %d ecms reached", reader->label, reader->resetcycle);
			reader_reset(reader);
		}
	}

	return res;
}

ECM_REQUEST *get_ecmtask()
{
	int32_t i, n, pending=0;
	ECM_REQUEST *er=0;
	struct s_client *cl = cur_client();
	if(!cl) return NULL;
	if (!cl->ecmtask)
	{
		n=(ph[cl->ctyp].multi)?CS_MAXPENDING:1;
		if(!cs_malloc(&cl->ecmtask,n*sizeof(ECM_REQUEST), -1)) return NULL;
	}

	n=(-1);
	if (ph[cl->ctyp].multi)
	{
		for (i=0; (n<0) && (i<CS_MAXPENDING); i++)
			if (cl->ecmtask[i].rc<E_99)
				er=&cl->ecmtask[n=i];
			else
				pending++;
	}
	else
		er=&cl->ecmtask[n=0];

	if (n<0)
		cs_log("WARNING: ecm pending table overflow !");
	else
	{
		LLIST *save = er->matching_rdr, *save_al = er->answer_list;
		memset(er, 0, sizeof(ECM_REQUEST));
		cs_ftime(&er->tps);
		er->rc=E_UNHANDLED;
		er->cpti=n;
		er->client=cl;

		if (cl->typ=='c') { //for clients only! Not for readers!
			if (save) {
				ll_clear(save);
				er->matching_rdr = save;
			} else
				er->matching_rdr = ll_create();

			if (save_al) {
				ll_clear(save_al);
				er->answer_list = save_al;
			} else
				er->answer_list = ll_create();

			//cs_log("client %s ECMTASK %d multi %d ctyp %d", username(cl), n, (ph[cl->ctyp].multi)?CS_MAXPENDING:1, cl->ctyp);
                }
	}

	cl->pending=pending+1;
	return(er);
}

#ifdef WITH_LB
void send_reader_stat(struct s_reader *rdr, ECM_REQUEST *er, int32_t rc)
{
	if (rc>=E_99)
		return;
	struct timeb tpe;
	cs_ftime(&tpe);
	int32_t time = 1000*(tpe.time-er->tps.time)+tpe.millitm-er->tps.millitm;
	if (time < 1)
	        time = 1;

	add_stat(rdr, er, time, rc);
}
#endif

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

int32_t send_dcw(struct s_client * client, ECM_REQUEST *er)
{
	if (!client || client->kill || client->typ != 'c')
		return 0;
		
	static const char *stxt[]={"found", "cache1", "cache2", "emu",
			"not found", "timeout", "sleeping",
			"fake", "invalid", "corrupt", "no card", "expdate", "disabled", "stopped"};
	static const char *stxtEx[]={"", "group", "caid", "ident", "class", "chid", "queue", "peer"};
	static const char *stxtWh[]={"", "user ", "reader ", "server ", "lserver "};
	char sby[32]="", sreason[32]="", schaninfo[32]="";
	char erEx[32]="";
	char uname[38]="";
	char channame[32];
	struct timeb tpe;

	snprintf(uname,sizeof(uname)-1, "%s", username(client));

	if (er->rc == E_FOUND||er->rc == E_CACHE1||er->rc == E_CACHE2)
		checkCW(er);

	struct s_reader *er_reader = er->selected_reader; //responding reader
	if (!er_reader) er_reader = ll_has_elements(er->matching_rdr); //no reader? use first reader

	if (er_reader)
	{
			// add marker to reader if ECM_REQUEST was betatunneled
			if(er->btun)
				snprintf(sby, sizeof(sby)-1, " by %s(btun)", er_reader->label);
			else
				snprintf(sby, sizeof(sby)-1, " by %s", er_reader->label);
	}
	if (er->rc < E_NOTFOUND) er->rcEx=0;
	if (er->rcEx)
		snprintf(erEx, sizeof(erEx)-1, "rejected %s%s", stxtWh[er->rcEx>>4],
				stxtEx[er->rcEx&0xf]);

	if(cfg.mon_appendchaninfo)
		snprintf(schaninfo, sizeof(schaninfo)-1, " - %s", get_servicename(client, er->srvid, er->caid, channame));

	if(er->msglog[0])
		snprintf(sreason, sizeof(sreason)-1, " (%s)", er->msglog);

	cs_ftime(&tpe);
	client->cwlastresptime = 1000 * (tpe.time-er->tps.time) + tpe.millitm-er->tps.millitm;

#ifdef WEBIF
	cs_add_lastresponsetime(client, client->cwlastresptime,time((time_t)0) ,er->rc); // add to ringbuffer
#endif

	if (er_reader){
		struct s_client *er_cl = er_reader->client;
		if(er_cl){
			er_cl->cwlastresptime = client->cwlastresptime;
#ifdef WEBIF
			cs_add_lastresponsetime(er_cl, client->cwlastresptime,time((time_t)0) ,er->rc);
#endif
			er_cl->last_srvidptr=client->last_srvidptr;
		}
	}

#ifdef CS_LED
	if(!er->rc) cs_switch_led(LED2, LED_BLINK_OFF);
#endif

#ifdef WEBIF
	if (er_reader) {
		if(er->rc == E_FOUND)
			cs_strncpy(client->lastreader, er_reader->label, sizeof(client->lastreader));
		else if ((er->rc == E_CACHE1) || (er->rc == E_CACHE2))
			snprintf(client->lastreader, sizeof(client->lastreader)-1, "%s (cache)", er_reader->label);
		else
			cs_strncpy(client->lastreader, stxt[er->rc], sizeof(client->lastreader));
	}
#endif

	er->caid = er->ocaid;
	switch(er->rc) {
		case E_FOUND:
		case E_EMU: //FIXME obsolete ?
					client->cwfound++;
			                client->account->cwfound++;
					first_client->cwfound++;
					break;

		case E_CACHE1:
		case E_CACHE2:
			client->cwcache++;
			client->account->cwcache++;
			first_client->cwcache++;
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

#ifdef CS_ANTICASC
	ac_chk(client, er, 1);
#endif

	int32_t is_fake = 0;
	if (er->rc==E_FAKE) {
		is_fake = 1;
		er->rc=E_FOUND;
	}

#ifdef CS_WITH_DOUBLECHECK
	if (cfg.double_check && er->rc < E_NOTFOUND) {
	  if (er->checked == 0) {//First CW, save it and wait for next one
	    er->checked = 1;
	    er->origin_reader = er->selected_reader;
	    memcpy(er->cw_checked, er->cw, sizeof(er->cw));
	    cs_log("DOUBLE CHECK FIRST CW by %s idx %d cpti %d", er->origin_reader->label, er->idx, er->cpti);
	  }
	  else if (er->origin_reader != er->selected_reader) { //Second (or third and so on) cw. We have to compare
	    if (memcmp(er->cw_checked, er->cw, sizeof(er->cw)) == 0) {
	    	er->checked++;
	    	cs_log("DOUBLE CHECKED! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->cpti);
	    }
	    else {
	    	cs_log("DOUBLE CHECKED NONMATCHING! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->cpti);
	    }
	  }

	  if (er->checked < 2) { //less as two same cw? mark as pending!
	    er->rc = E_UNHANDLED;
	    return 0;
	  }

	  store_cw_in_cache(er, er->selected_reader->grp, E_FOUND, er->cw); //Store in cache!

	}
#endif

	ph[client->ctyp].send_dcw(client, er);

	if (is_fake)
		er->rc = E_FAKE;

	cs_log("%s (%04X&%06X/%04X/%02X:%04X): %s (%d ms)%s (of %d avail %d)%s%s",
			uname, er->caid, er->prid, er->srvid, er->l, htons(er->checksum),
			er->rcEx?erEx:stxt[er->rc], client->cwlastresptime, sby, er->reader_count, er->reader_avail, schaninfo, sreason);

	cs_ddump_mask (D_ATR, er->cw, 16, "cw:");

#ifdef QBOXHD_LED
    if (er->rc < E_NOTFOUND) {
        qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN, QBOXHD_LED_BLINK_MEDIUM);
    } else if (er->rc <= E_STOPPED) {
        qboxhd_led_blink(QBOXHD_LED_COLOR_RED, QBOXHD_LED_BLINK_MEDIUM);
    }
#endif

	return 0;
}

static void chk_dcw(struct s_client *cl, struct s_ecm_answer *ea)
{
	if (!cl || !ea || !ea->er)
		return;

	ECM_REQUEST *ert = ea->er;

	if (ea->reader)
		cs_debug_mask(D_TRACE, "ecm answer from %s for ecm %04X rc=%d", ea->reader->label, ert->checksum, ea->rc);

	if (ert->rc<E_99) {
#ifdef WITH_LB
		if (ea->reader)
			send_reader_stat(ea->reader, ert, ea->rc);
#endif
		return; // already done
	}

	int32_t reader_left = 0;

	switch (ea->rc) {
		case E_FOUND:
		case E_CACHE2:
		case E_CACHE1:
		case E_EMU:
			memcpy(ert->cw, ea->cw, 16);
			ert->rcEx=0;
			ert->rc = ea->rc;
			ert->selected_reader = ea->reader;
			break;
		case E_TIMEOUT:
			ert->rc = E_TIMEOUT;
#ifdef WITH_LB
			if (cfg.lb_mode) {
				LL_NODE *ptr;
				for (ptr = ert->matching_rdr?ert->matching_rdr->initial:NULL; ptr ; ptr = ptr->nxt)
					send_reader_stat((struct s_reader *)ptr->obj, ert, E_TIMEOUT);
			}
#endif
			break;
		case E_NOTFOUND:
			ert->rcEx=ea->rcEx;
			cs_strncpy(ert->msglog, ea->msglog, sizeof(ert->msglog));
			ll_remove(ert->matching_rdr, ea->reader);
			ert->selected_reader=ea->reader;

			if (ll_has_elements(ert->matching_rdr)) {//we have still another chance
				if (cfg.preferlocalcards && !ert->locals_done) {
					ert->locals_done=1;
					LL_NODE *ptr;
					struct s_reader *rdr;
					for (ptr = ert->matching_rdr?ert->matching_rdr->initial:NULL; ptr; ptr = ptr->nxt) {
						rdr = (struct s_reader*)ptr->obj;
						if (!(rdr->typ & R_IS_NETWORK))
							ert->locals_done=0;
					}
					// if there is no local reader left send request to network reader
					if (ert->locals_done)
						request_cw(ert, ert->stage, 2);
				}
				reader_left++;
			}
			break;
		default:
			cs_log("unexpected ecm answer rc=%d.", ea->rc);
			return;
			break;
	}

	if (ert->rc >= E_99 && !reader_left) {
		// no more matching reader
		ert->rc=E_NOTFOUND; //so we set the return code
		store_cw_in_cache(ert, ert->selected_reader ? ert->selected_reader->grp : cl->grp, E_NOTFOUND, NULL);
	}

#ifdef WITH_LB
	if (ea->reader)
		send_reader_stat(ea->reader, ert, ea->rc);
#endif

	if (ert->rc < E_99) {
		send_dcw(cl, ert);
		distribute_ecm(ert, cl->grp, (ert->rc<E_NOTFOUND)?E_CACHE2:ert->rc);
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

#ifdef IRDETO_GUESSING
void guess_irdeto(ECM_REQUEST *er)
{
  uchar  b3;
  int32_t    b47;
  //uint16_t chid;
  struct s_irdeto_quess *ptr;

  b3  = er->ecm[3];
  ptr = cfg.itab[b3];
  if( !ptr ) {
    cs_debug_mask(D_TRACE, "unknown irdeto byte 3: %02X", b3);
    return;
  }
  b47  = b2i(4, er->ecm+4);
  //chid = b2i(2, er->ecm+6);
  //cs_debug_mask(D_TRACE, "ecm: b47=%08X, ptr->b47=%08X, ptr->caid=%04X", b47, ptr->b47, ptr->caid);
  while( ptr )
  {
    if( b47==ptr->b47 )
    {
      if( er->srvid && (er->srvid!=ptr->sid) )
      {
        cs_debug_mask(D_TRACE, "sid mismatched (ecm: %04X, guess: %04X), wrong oscam.ird file?",
                  er->srvid, ptr->sid);
        return;
      }
      er->caid=ptr->caid;
      er->srvid=ptr->sid;
      er->chid=(uint16_t)ptr->b47;
//      cs_debug_mask(D_TRACE, "quess_irdeto() found caid=%04X, sid=%04X, chid=%04X",
//               er->caid, er->srvid, er->chid);
      return;
    }
    ptr=ptr->next;
  }
}
#endif

void convert_to_beta(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto)
{
	static uchar headerN3[10] = {0xc7, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x87, 0x12};
	static uchar headerN2[10] = {0xc9, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x48, 0x12};

#ifdef WITH_DEBUG
	uint16_t caidfrom = er->caid;
#endif
	er->caid = caidto;
	er->prid = 0;
	er->l = er->ecm[2] + 3;

	memmove(er->ecm + 13, er->ecm + 3, er->l - 3);

	if (er->l > 0x88) {
		memcpy(er->ecm + 3, headerN3, 10);

		if (er->ecm[0] == 0x81)
			er->ecm[12] += 1;

		er->ecm[1]=0x70;
	}
	else
		memcpy(er->ecm + 3, headerN2, 10);

    er->l += 10;
	er->ecm[2] = er->l - 3;
	er->btun = 1;

	cl->cwtun++;
	cl->account->cwtun++;
	first_client->cwtun++;

	cs_debug_mask(D_TRACE, "ECM converted from: 0x%X to BetaCrypt: 0x%X for service id:0x%X",
					caidfrom, caidto, er->srvid);
}


void cs_betatunnel(ECM_REQUEST *er)
{
	int32_t n;
	struct s_client *cl = cur_client();
	uint32_t mask_all = 0xFFFF;

	TUNTAB *ttab;
	ttab = &cl->ttab;

	if (er->caid>>8 == 0x18)
		cs_ddump_mask(D_TRACE, er->ecm, 13, "betatunnel? ecmlen=%d", er->l);

	for (n = 0; n<ttab->n; n++) {
		if ((er->caid==ttab->bt_caidfrom[n]) && ((er->srvid==ttab->bt_srvid[n]) || (ttab->bt_srvid[n])==mask_all)) {

			convert_to_beta(cl, er, ttab->bt_caidto[n]);

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

#ifdef IRDETO_GUESSING
  if (!er->caid && er->ecm[2]==0x31 && er->ecm[0x0b]==0x28)
    guess_irdeto(er);
#endif

  if (!er->caid)    // guess by len ..
    er->caid=len4caid[er->ecm[2]+3];

  if (!er->caid)
    er->caid=last_hope;
}

/**
 * sends the ecm request to the readers
 * ECM_REQUEST er : the ecm
 * int32_t flag : 0=primary readers (no fallback)
 *            1=all readers (primary+fallback)
 * int32_t reader_types : 0=all readsers
 *                    1=Hardware/local readers
 *                    2=Proxy/network readers
 **/
void request_cw(ECM_REQUEST *er, int32_t flag, int32_t reader_types)
{
	if ((reader_types == 0) || (reader_types == 2))
		er->level=flag;
	struct s_reader *rdr;

	LL_NODE *ptr;
	for (ptr = er->matching_rdr?er->matching_rdr->initial:NULL; ptr; ptr = ptr->nxt) {
	        if (!flag && ptr == er->fallback)
	          break;

		rdr = (struct s_reader*)ptr->obj;

		int32_t status = 0;
		//reader_types:
		//0 = network and local cards
		//1 = only local cards
		//2 = only network
		if ((reader_types == 0) || ((reader_types == 1) && (!(rdr->typ & R_IS_NETWORK))) || ((reader_types == 2) && (rdr->typ & R_IS_NETWORK))) {
			cs_debug_mask(D_TRACE, "request_cw%i to reader %s fd=%d ecm=%04X", reader_types+1, rdr->label, 0, htons(er->checksum));
			status = write_ecm_request(rdr, er);
		}
	}
}

void get_cw(struct s_client * client, ECM_REQUEST *er)
{
	int32_t i, j, m;
	time_t now = time((time_t)0);

	client->lastecm = now;

	if (!er->caid)
		guess_cardsystem(er);

	/* Quickfix Area */

	if( (er->caid & 0xFF00) == 0x600 && !er->chid )
		er->chid = (er->ecm[6]<<8)|er->ecm[7];

	// quickfix for 0100:000065
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
	if (er->caid == 0x1702 && er->l == 0x89 && er->ecm[3] == 0x07 && er->ecm[4] == 0x84)
		er->caid = 0x1833;

	//Ariva quickfix (invalid nagra provider)
	if (((er->caid & 0xFF00) == 0x1800) && er->prid > 0x00FFFF) er->prid=0;

	if (!er->prid)
		er->prid = chk_provid(er->ecm, er->caid);

	// Set providerid for newcamd clients if none is given
	if( (!er->prid) && client->ncd_server ) {
		int32_t pi = client->port_idx;
		if( pi >= 0 && cfg.ncd_ptab.nports && cfg.ncd_ptab.nports >= pi )
			er->prid = cfg.ncd_ptab.ports[pi].ftab.filts[0].prids[0];
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
			cs_add_violation(client->ip, ph[client->ctyp].ptab->ports[client->port_idx].s_port);
			cs_disconnect_client(client);
		}
		er->rc = E_DISABLED;
	}


	// rc<100 -> ecm error
	if (er->rc >= E_UNHANDLED) {

		m = er->caid;
		er->ocaid = er->caid;
		i = er->srvid;

		if ((i != client->last_srvid) || (!client->lastswitch)) {
			if(cfg.usrfileflag)
				cs_statistics(client);
			client->lastswitch = now;
		}

		// user sleeping
		if ((client->tosleep) && (now - client->lastswitch > client->tosleep)) {

			if (client->failban & BAN_SLEEPING) {
				cs_add_violation(client->ip, ph[client->ctyp].ptab->ports[client->port_idx].s_port);
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
						snprintf( er->msglog, MSGLOGSIZE, "invalid caid %x",er->caid );
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
					if (!chk_sfilter(er, ph[client->ctyp].ptab))
						er->rc = E_INVALID;
					break;

				case 5:
					// corrupt
					if( (i = er->l - ecm_len) ) {
						if (i > 0) {
							cs_debug_mask(D_TRACE, "warning: ecm size adjusted from 0x%X to 0x%X", er->l, ecm_len);
							er->l = ecm_len;
						}
						else
							er->rc = E_CORRUPT;
					}
					break;
			}
		}
	}

#ifdef WITH_LB
    //Use locking - now default=FALSE, activate on problems!
	int32_t locked;
	if (cfg.lb_mode && cfg.lb_use_locking) {
			cs_writelock(&get_cw_lock);
			locked=1;
	}
	else
			locked=0;
#endif

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
		memcpy(er->ecmd5, MD5(er->ecm+offset, er->l-offset, md5tmp), CS_ECMSTORESIZE);

		// cache1
		//cache check now done by check_and_store_ecmcache() !!
		//if (check_cwcache1(er, client->grp))
		//		er->rc = E_CACHE1;

#ifdef CS_ANTICASC
		ac_chk(client, er, 0);
#endif
	}

	int local_reader_count = 0;
	if(er->rc >= E_99) {
		er->reader_avail=0;
		struct s_reader *rdr;
		for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
			if (matching_reader(er, rdr)) {
				if (rdr->fallback) {
					if (er->fallback == NULL) //first fallbackreader to be added
						er->fallback=ll_append(er->matching_rdr, rdr);
					else
						ll_append(er->matching_rdr, rdr);

				}
				else {
					ll_prepend(er->matching_rdr, rdr);
					if (!(rdr->typ & R_IS_NETWORK))
						local_reader_count++;
				}
#ifdef WITH_LB
				if (cfg.lb_mode || !rdr->fallback)
#else
                                if (!rdr->fallback)
#endif
					er->reader_avail++;
			}
		}

#ifdef WITH_LB
		if (cfg.lb_mode && er->reader_avail) {
			cs_debug_mask(D_TRACE, "requesting client %s best reader for %04X/%06X/%04X",
				username(client), er->caid, er->prid, er->srvid);
			get_best_reader(er);
		}
#endif
		LL_NODE *ptr;
		for (ptr = er->matching_rdr->initial; ptr && ptr != er->fallback; ptr = ptr->nxt)
			er->reader_count++;

		if (!ll_has_elements(er->matching_rdr)) { //no reader -> not found
				er->rc = E_NOTFOUND;
				if (!er->rcEx)
					er->rcEx = E2_GROUP;
				snprintf(er->msglog, MSGLOGSIZE, "no matching reader");
		}
		else
			if (er->matching_rdr->initial == er->fallback) { //fallbacks only
					er->fallback = NULL; //switch them
					er->reader_count = er->reader_avail;
			}

		//we have to go through matching_reader() to check services!
		if (er->rc == E_UNHANDLED)
				er->rc = check_and_store_ecmcache(er, client->grp);
	}

#ifdef WITH_LB
	if (locked)
		cs_writeunlock(&get_cw_lock);
#endif

	uint16_t *lp;
	for (lp=(uint16_t *)er->ecm+(er->l>>2), er->checksum=0; lp>=(uint16_t *)er->ecm; lp--)
		er->checksum^=*lp;

	if (er->rc == E_99) {
		er->stage++;
		add_check(er->client, CHECK_WAKEUP, er, sizeof(ECM_REQUEST), cfg.ctimeout);
		return; //ECM already requested / found in ECM cache
	}

	if (er->rc < E_UNHANDLED) {
		if (cfg.delay)
			cs_sleepms(cfg.delay);

		send_dcw(client, er);
		return;
	}

	er->rcEx = 0;
	request_cw(er, 0, (cfg.preferlocalcards && local_reader_count) ? 1 : 0);

	//send ecm request to fallback reader after fallbacktimeout
	add_check(er->client, CHECK_WAKEUP, er, sizeof(ECM_REQUEST), cfg.ftimeout);
}

void do_emm(struct s_client * client, EMM_PACKET *ep)
{
	char *typtext[]={"unknown", "unique", "shared", "global"};
	char tmp[17];

	struct s_reader *aureader = NULL;
	cs_ddump_mask(D_EMM, ep->emm, ep->l, "emm:");

	LL_ITER itr = ll_iter_create(client->aureader_list);
	while ((aureader = ll_iter_next(&itr))) {
		if (!aureader->enable)
			continue;

		uint16_t caid = b2i(2, ep->caid);
		uint32_t provid = b2i(4, ep->provid);

		if (aureader->audisabled) {
			cs_debug_mask(D_EMM, "AU is disabled for reader %s", aureader->label);
			/* we have to write the log for blocked EMM here because
	  		 this EMM never reach the reader module where the rest
			 of EMM log is done. */
			if (aureader->logemm & 0x10)  {
				cs_log("%s emmtype=%s, len=%d, idx=0, cnt=1: audisabled (0 ms) by %s",
						client->account->usr,
						typtext[ep->type],
						ep->emm[2],
						aureader->label);
			}
			continue;
		}

		if (!(aureader->grp & client->grp)) {
			cs_debug_mask(D_EMM, "skip emm reader %s group mismatch", aureader->label);
			continue;
		}

		//TODO: provider possibly not set yet, this is done in get_emm_type()
		if (!emm_reader_match(aureader, caid, provid))
			continue;

		struct s_cardsystem *cs = NULL;

		if (aureader->typ & R_IS_CASCADING) { // network reader (R_CAMD35 R_NEWCAMD R_CS378X R_CCCAM)
			if (!aureader->ph.c_send_emm) // no emm support
				continue;

			cs = get_cardsystem_by_caid(caid);
			if (!cs) {
				cs_debug_mask(D_EMM, "unable to find cardsystem for caid %04X, reader %s", caid, aureader->label);
				continue;
			}
		} else { // local reader
			if (aureader->csystem.active)
				cs=&aureader->csystem;
		}

		if (cs && cs->get_emm_type) {
			if(!cs->get_emm_type(ep, aureader)) {
				cs_debug_mask(D_EMM, "emm skipped, get_emm_type() returns error, reader %s", aureader->label);
				client->emmnok++;
				if (client->account)
					client->account->emmnok++;
				first_client->emmnok++;
				continue;
			}
		}

		cs_debug_mask(D_EMM, "emmtype %s. Reader %s has serial %s.", typtext[ep->type], aureader->label, cs_hexdump(0, aureader->hexserial, 8, tmp, sizeof(tmp)));
		cs_ddump_mask(D_EMM, ep->hexserial, 8, "emm UA/SA:");

		client->last=time((time_t)0);
		if ((1<<(ep->emm[0] % 0x80)) & aureader->s_nano) { //should this nano be saved?
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
			snprintf (token, sizeof(token), "%s%s_emm.log", cfg.emmlogdir?cfg.emmlogdir:cs_confdir, aureader->label);
			
			if (!(fp = fopen (token, "a"))) {
				cs_log ("ERROR: Cannot open file '%s' (errno=%d: %s)\n", token, errno, strerror(errno));
			} else if(cs_malloc(&tmp2, (emm_length + 3)*2 + 1, -1)){
				fprintf (fp, "%s   %s   ", buf, cs_hexdump(0, ep->hexserial, 8, tmp, sizeof(tmp)));
				fprintf (fp, "%s\n", cs_hexdump(0, ep->emm, emm_length + 3, tmp2, (emm_length + 3)*2 + 1));
				free(tmp2);
				fclose (fp);
				cs_log ("Successfully added EMM to %s.", token);
			}

			snprintf (token, sizeof(token), "%s%s_emm.bin", cfg.emmlogdir?cfg.emmlogdir:cs_confdir, aureader->label);
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
				cs_log("%s emmtype=%s, len=%d, idx=0, cnt=%d: blocked (0 ms) by %s",
						client->account->usr,
						typtext[ep->type],
						ep->emm[2],
						is_blocked,
						aureader->label);
			}
			continue;
		}

		client->lastemm = time((time_t)0);

		client->emmok++;
		if (client->account)
			client->account->emmok++;
		first_client->emmok++;

		ep->client = cur_client();
		cs_debug_mask(D_EMM, "emm is being sent to reader %s.", aureader->label);

		EMM_PACKET *emm_pack = cs_malloc(&emm_pack, sizeof(EMM_PACKET), -1);
		memcpy(emm_pack, ep, sizeof(EMM_PACKET));
		add_job(aureader->client, ACTION_READER_EMM, emm_pack, sizeof(EMM_PACKET));
	}
}

void add_check(struct s_client *client, int8_t action, void *ptr, int32_t size, int32_t ms_delay) {

	if (!checklist)
		return;

	if (action == CHECK_WAKEUP) {
		pthread_mutex_lock(&check_mutex);
		pthread_cond_signal(&check_cond);
		pthread_mutex_unlock(&check_mutex);
		return;
	}

	struct timeb t_now;
	cs_ftime(&t_now);
	add_ms_to_timeb(&t_now, ms_delay);

	struct s_check *tt = cs_malloc(&tt, sizeof(struct s_check), -1);

	tt->cl = client;
	tt->ptr = ptr;
	tt->len = size;
	tt->action = action;
	tt->t_check = t_now;

	ll_append(checklist, tt);

	cs_debug_mask(D_TRACE, "adding check action=%d ms_delay=%d", action, ms_delay);

	pthread_mutex_lock(&check_mutex);
	pthread_cond_signal(&check_cond);
	pthread_mutex_unlock(&check_mutex);
}

int32_t process_input(uchar *buf, int32_t l, int32_t timeout)
{
	int32_t rc, i, pfdcount;
	struct pollfd pfd[2];
	struct s_client *cl = cur_client();

	time_t starttime = time(NULL);

	while (1) {
		pfdcount = 0;
		if (cl->pfd) {
			pfd[pfdcount].fd = cl->pfd;
			pfd[pfdcount++].events = POLLIN | POLLPRI;
		}

		int32_t p_rc = poll(pfd, pfdcount, 0);

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
				return ph[cl->ctyp].recv(cl, buf, l);
		}
	}
	return(rc);
}

void cs_waitforcardinit()
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
				if (rdr->enable && (!(rdr->typ & R_IS_CASCADING)) && (rdr->card_status == CARD_NEED_INIT || rdr->card_status == UNKNOWN)) {
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

	struct s_reader *rdr = cl->reader;

	switch (cl->typ) {
		case 'c':
			//check clients for exceeding cmaxidle by checking cl->last
			if (cl->last && cfg.cmaxidle && (time(NULL) - cl->last) > (time_t)cfg.cmaxidle) {
				add_job(cl, ACTION_CLIENT_IDLE, NULL, 0);
			}

			break;
#ifdef WITH_CARDREADER
		case 'r':
			//check for card inserted or card removed on pysical reader
			if (!rdr || !rdr->enable)
				break;
			reader_checkhealth(rdr);
			break;
#endif
		case 'p':
			//execute reader do idle on proxy reader after a certain time (rdr->tcp_ito = inactivitytimeout)
			//disconnect when no keepalive available
			if (!rdr || !rdr->enable)
				break;
			if (rdr->tcp_ito && (rdr->typ & R_IS_CASCADING)) {
				int32_t time_diff;
				time_diff = abs(time(NULL) - rdr->last_s);

				if (time_diff>(rdr->tcp_ito*60)) {
					add_job(rdr->client, ACTION_READER_IDLE, NULL, 0);
					rdr->last_s = time(NULL);
				}
			}
			if (!rdr->tcp_connected && ((time(NULL) - rdr->last_s) > 30) && rdr->typ == R_CCCAM) {
				add_job(rdr->client, ACTION_READER_IDLE, NULL, 0);
				rdr->last_s = time(NULL);
			}
			break;
		default:
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

	uchar mbuf[1024];
	int32_t n=0, rc=0, i, idx, s;
	uchar dcw[16];
	sigset_t newmask;

	if (keep_threads_alive) {
		sigemptyset(&newmask);
		sigaddset(&newmask, SIGCONT);
		pthread_sigmask(SIG_BLOCK, &newmask, NULL);
	}

	while (1) {
		if (data)
			cs_debug_mask(D_TRACE, "data from add_job action=%d", data->action);

		if (!cl || !is_valid_client(cl)) {
			if (data && data!=&tmp_data)
				free(data);
			data = NULL;
			return NULL;
		}

		if (cl->kill) {
			cs_debug_mask(D_TRACE, "ending thread");
			if (data && data!=&tmp_data)
				free(data);

			data = NULL;
			cleanup_thread(cl);
			pthread_exit(NULL);
			return NULL;
		}

		if (!data) {
			if (keep_threads_alive)
				check_status(cl);

			pthread_mutex_lock(&cl->thread_lock);
			if (cl->joblist && ll_count(cl->joblist)>0) {
				LL_ITER itr = ll_iter_create(cl->joblist);
				data = ll_iter_next(&itr);
				ll_iter_remove(&itr);
				cs_debug_mask(D_TRACE, "start next job from list action=%d", data->action);
			}

			if (!keep_threads_alive && !data)
				cl->thread_active=0;
			pthread_mutex_unlock(&cl->thread_lock);
		}

		if (keep_threads_alive && !data) {
			pfd[0].fd = cl->pfd;
			pfd[0].events = POLLIN | POLLPRI | POLLHUP;

			pthread_sigmask(SIG_UNBLOCK, &newmask, NULL);
			rc = poll(pfd, 1, 3000);
			pthread_sigmask(SIG_BLOCK, &newmask, NULL);

			if (rc == -1)
				cs_debug_mask(D_TRACE, "poll wakeup");

			if (rc>0) {
				cs_debug_mask(D_TRACE, "data on socket");
				data=&tmp_data;
				
				data->action = ACTION_CLIENT_TCP;
				data->ptr = NULL;

				if (pfd[0].revents & (POLLHUP | POLLNVAL)) {
					cl->kill = 1;
					continue;
				}
			}
		}

		if (!data) {
			if (keep_threads_alive) 
				continue;
			else
				break;
		}

		if (data->action < 20 && !reader) {
			if (data!=&tmp_data)
				free(data);
			data = NULL;
			break;
		}

		if (!data->action)
			break;
	
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
						network_tcp_connection_close(reader);
					break;
				}

				rc = reader->ph.recv(cl, mbuf, sizeof(mbuf));
				if (rc < 0) {
					if (reader->ph.type==MOD_CONN_TCP)
						network_tcp_connection_close(reader);
					break;
				}

				cl->last=time((time_t)0);
				idx=reader->ph.c_recv_chk(cl, dcw, &rc, mbuf, rc);

				if (idx<0) break;  // no dcw received
				if (!idx) idx=cl->last_idx;

				reader->last_g=time((time_t*)0); // for reconnect timeout

				for (i=0; i<CS_MAXPENDING; i++) {
					if (cl->ecmtask[i].idx==idx) {
						cl->pending--;
						casc_check_dcw(reader, i, rc, dcw);
						break;
					}
				}
				break;
			case ACTION_READER_REMOTELOG:
				casc_do_sock_log(reader);
 				break;
			case ACTION_READER_RESET:
		 		reader_reset(reader);
 				break;
			case ACTION_READER_ECM_REQUEST:
				reader_get_ecm(reader, data->ptr);
				break;
			case ACTION_READER_EMM:
				reader_do_emm(reader, data->ptr);
				free(data->ptr); // allocated in do_emm()
				break;
			case ACTION_READER_CARDINFO:
				reader_do_card_info(reader);
				break;
			case ACTION_READER_INIT:
				if (!cl->init_done) {
					reader_init(reader);
					add_reader_to_active(reader);
				}
				break;
			case ACTION_READER_RESTART:
				cleanup_thread(cl); //should close connections
				restart_cardreader(reader, 0);
				//original cl struct was destroyed by restart reader, so we exit here
				//init is done by a new thread

				if (data!=&tmp_data)
					free(data);
				data = NULL;
				return NULL;
				break;

			case ACTION_CLIENT_UDP:
				n = ph[cl->ctyp].recv(cl, data->ptr, data->len);
				if (n<0) {
					cl->init_done=0;
					break;
				}
				ph[cl->ctyp].s_handler(cl, data->ptr, n);
				free(data->ptr); // allocated in accept_connection()
				break;
			case ACTION_CLIENT_TCP:
				s = check_fd_for_data(cl->pfd);
				if (s == 0) // no data, another thread already read from fd?
					break;
				if (s < 0) { // system error or fd wants to be closed
					cl->kill=1; // kill client on next run
					continue;
				}

				n = ph[cl->ctyp].recv(cl, mbuf, sizeof(mbuf));
				if (n < 0) {
					cl->kill=1; // kill client on next run
					continue;
				}
				ph[cl->ctyp].s_handler(cl, mbuf, n);
	
				break;
			case ACTION_CLIENT_ECM_ANSWER:
				chk_dcw(cl, data->ptr);
				free(data->ptr);
				break;
			case ACTION_CLIENT_INIT:
				if (ph[cl->ctyp].s_init)
					ph[cl->ctyp].s_init(cl);
				cl->init_done=1;
				break;
			case ACTION_CLIENT_IDLE:
				if (ph[cl->ctyp].s_idle)
					ph[cl->ctyp].s_idle(cl);
				else {
					cs_log("user %s reached %d sec idle limit.", username(cl), cfg.cmaxidle);
					cl->kill = 1;
				}

				break;
		}

		if (data!=&tmp_data)
			free(data);

		data = NULL;
	}

	if (!keep_threads_alive && thread_pipe[1])
		write(thread_pipe[1], mbuf, 1); //wakeup client check

	cs_debug_mask(D_TRACE, "ending thread");

	pthread_exit(NULL);
	return NULL;
}

void add_job(struct s_client *cl, int8_t action, void *ptr, int len) {

	if (!cl) {
		cs_log("WARNING: add_job failed.");
		return;
	}

	struct s_data *data = cs_malloc(&data, sizeof(struct s_data), -1);
	data->action = action;
	data->ptr = ptr;
	data->cl = cl;
	data->len = len;

	pthread_mutex_lock(&cl->thread_lock);
	if (cl->thread_active) {
		if (!cl->joblist)
			cl->joblist = ll_create();

		ll_append(cl->joblist, data);
		cs_debug_mask(D_TRACE, "add %s job action %d", action > 20 ? "client" : "reader", action);
		pthread_mutex_unlock(&cl->thread_lock);
		if (keep_threads_alive)
			pthread_kill(cl->thread, SIGCONT);
		return;
	}


	pthread_attr_t attr;
	pthread_attr_init(&attr);
#if !defined(TUXBOX) && !defined(HAVE_PCSC)
	/* pcsc doesn't like this either; segfaults on x86, x86_64 */
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif

	cs_debug_mask(D_TRACE, "start %s thread action %d", action > 20 ? "client" : "reader", action);

	if (pthread_create(&cl->thread, &attr, work_thread, (void *)data)) {
		cs_log("ERROR: can't create thread for %s", action > 20 ? "client" : "reader");
	} else
		pthread_detach(cl->thread);

	pthread_attr_destroy(&attr);

	cl->thread_active = 1;
	pthread_mutex_unlock(&cl->thread_lock);
}

static void * check_thread(void) {
	int32_t next_check = 100, time_to_check, rc, i;
	struct timeb t_now, tbc;
	ECM_REQUEST *er = NULL;
	struct s_client *cl;
	struct s_check *t1;

	pthread_mutex_init(&check_mutex,NULL);
	pthread_cond_init(&check_cond,NULL);

	checklist = ll_create();

	struct timespec timeout;
	add_ms_to_timespec(&timeout, 30000);

	while(1) {
		pthread_mutex_lock(&check_mutex);
		rc = pthread_cond_timedwait(&check_cond, &check_mutex, &timeout);
		pthread_mutex_unlock(&check_mutex);

		cs_ftime(&t_now);

		next_check = 0;
		for (cl=first_client->next; cl ; cl=cl->next) {
			if (cl->init_done && cl->typ=='c' && cl->ecmtask) {
				for (i=0; i<CS_MAXPENDING; i++) {
					if (cl->ecmtask[i].rc >= E_99) {
						er = &cl->ecmtask[i];
						tbc = er->tps;
						time_to_check = add_ms_to_timeb(&tbc, !er->stage ? cfg.ftimeout : cfg.ctimeout);

						if (comp_timeb(&t_now, &tbc) >= 0) {
							if (!er->stage) {
								er->stage++;
								cs_debug_mask(D_TRACE, "fallback for %s %04X&%06X/%04X", username(er->client), er->caid, er->prid, er->srvid);
								if (er->rc >= E_UNHANDLED) //do not request rc=99
								        request_cw(er, er->stage, 0);

							} else {
								cs_debug_mask(D_TRACE, "timeout for %s %04X&%06X/%04X", username(er->client), er->caid, er->prid, er->srvid);
								if (er->client && is_valid_client(er->client))
									write_ecm_answer(NULL, er, E_TIMEOUT, 0, NULL, NULL);
							}
						}
						if (!next_check || time_to_check < next_check) {
							add_ms_to_timespec(&timeout, time_to_check);
							next_check = time_to_check;
						}
					}
				}
			}
		}

		if (ll_count(checklist) == 0) {
			if (!next_check)
				add_ms_to_timespec(&timeout, 30000);
			continue;
		}	

		LL_ITER itr = ll_iter_create(checklist);

		next_check = 0;
		while ((t1 = ll_iter_next(&itr))) {
			time_to_check = ((t1->t_check.time - t_now.time) * 1000) + (t1->t_check.millitm - t_now.millitm);
			if (time_to_check <= 0) {
				if (t1->cl && !is_valid_client(t1->cl)) {
					cs_log("removing invalid check");
					ll_iter_remove(&itr);
					add_garbage(t1);
					continue;
				}
				switch(t1->action) {
#ifdef CS_ANTICASC
					case CHECK_ANTICASCADER:
						if (cfg.ac_enabled) {
							ac_do_stat();
							cs_ftime(&t1->t_check);
							add_ms_to_timeb(&t1->t_check, cfg.ac_stime*60*1000);
							time_to_check = cfg.ac_stime*60*1000;
						}
						break;
#endif
					default:
						break;
				}
			} else {
				if (!next_check || time_to_check < next_check) {
					add_ms_to_timespec(&timeout, time_to_check);
					next_check = time_to_check;
				}
			}
		}
		if (!next_check)
			add_ms_to_timespec(&timeout, 30000);
	}
	return NULL;
}

void * client_check(void) {
	int32_t i, k, j, rc, pfdcount = 0;
	struct s_client *cl;
	struct s_reader *rdr;
	struct pollfd pfd[1024];
	struct s_client *cl_list[1024];
	char buf[10];

	if (pipe(thread_pipe) == -1) {
		printf("cannot create pipe, errno=%d\n", errno);
		exit(1);
	}

	pfd[pfdcount].fd = thread_pipe[0];
	pfd[pfdcount].events = POLLIN | POLLPRI | POLLHUP;
	cl_list[pfdcount] = NULL;

	while (!exit_oscam) {
		pfdcount = 1;

		//connected tcp clients
		for (cl=first_client->next; cl ; cl=cl->next) {
			if (cl->init_done && !cl->kill && cl->pfd && cl->typ=='c' && !cl->is_udp) {
				if (cl->pfd && !cl->thread_active) {				
					cl_list[pfdcount] = cl;
					pfd[pfdcount].fd = cl->pfd;
					pfd[pfdcount++].events = POLLIN | POLLPRI | POLLHUP;
				}
			}
		}

		//reader (only connected tcp proxy reader)
		for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
			if (rdr->client && rdr->client->init_done) {
				if (rdr->client->pfd && !rdr->client->thread_active && rdr->tcp_connected) {
					cl_list[pfdcount] = rdr->client;
					pfd[pfdcount].fd = rdr->client->pfd;
					pfd[pfdcount++].events = POLLIN | POLLPRI | POLLHUP;
				}
			}
		}

		//server (new tcp connections or udp messages)
		for (k=0; k<CS_MAX_MOD; k++) {
			if ( (ph[k].type & MOD_CONN_NET) && ph[k].ptab ) {
				for (j=0; j<ph[k].ptab->nports; j++) {
					if (ph[k].ptab->ports[j].fd) {
						cl_list[pfdcount] = NULL;
						pfd[pfdcount].fd = ph[k].ptab->ports[j].fd;
						pfd[pfdcount++].events = POLLIN | POLLPRI | POLLHUP;

					}
				}
			}
		}

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
				read(thread_pipe[0], buf, sizeof(buf));
				continue;
			}

			//clients
			// message on an open tcp connection
			if (cl && cl->init_done && cl->pfd && (cl->typ == 'c' || cl->typ == 'm')) {
				if (pfd[i].fd == cl->pfd && (pfd[i].revents & (POLLHUP | POLLNVAL))) {
					//client disconnects
					cl->kill=1;
					add_job(cl, ACTION_CLIENT_KILL, NULL, 0);
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
			if (cl && cl->typ == 'p')
				rdr = cl->reader;

			if (rdr && rdr->client && rdr->client->init_done) {
				if (rdr->client->pfd && pfd[i].fd == rdr->client->pfd && (pfd[i].revents & (POLLHUP | POLLNVAL))) {
					//connection to remote proxy was closed
					//oscam should check for rdr->tcp_connected and reconnect on next ecm request sent to the proxy
					network_tcp_connection_close(rdr);
					cs_debug_mask(D_READER, "connection to %s closed.", rdr->label);
				}
				if (rdr->client->pfd && pfd[i].fd == rdr->client->pfd && (pfd[i].revents & (POLLIN | POLLPRI))) {
					add_job(rdr->client, ACTION_READER_REMOTE, NULL, 0);
				}
			}


			//server sockets
			// new connection on a tcp listen socket or new message on udp listen socket
			if (!cl && pfd[i].revents & (POLLIN | POLLPRI)) {
				for (k=0; k<CS_MAX_MOD; k++) {
					if( (ph[k].type & MOD_CONN_NET) && ph[k].ptab ) {
						for ( j=0; j<ph[k].ptab->nports; j++ ) {
							if ( ph[k].ptab->ports[j].fd && pfd[i].fd == ph[k].ptab->ports[j].fd ) {
								accept_connection(k,j);
							}
						}
					}
				} // if (ph[i].type & MOD_CONN_NET)
			}
		}
		first_client->last=time((time_t *)0);
	}
	return NULL;
}

void * reader_check(void) {
	struct s_client *cl;

	while (1) {
		for (cl=first_client->next; cl ; cl=cl->next) {
			if (!cl->thread_active)
				check_status(cl);
		}
		cs_sleepms(1000);
	}
}

int32_t accept_connection(int32_t i, int32_t j) {
	struct   sockaddr_in cad;
	int32_t scad = sizeof(cad), n;

	if (ph[i].type==MOD_CONN_UDP) {
		uchar *buf = cs_malloc(&buf, 1024, -1);
		if ((n=recvfrom(ph[i].ptab->ports[j].fd, buf+3, 1024-3, 0, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {
			struct s_client *cl;
			cl=idx_from_ip(cad.sin_addr.s_addr, ntohs(cad.sin_port));

			uint16_t rl;
			rl=n;
			buf[0]='U';
			memcpy(buf+1, &rl, 2);

			if (!cl) {
				if (cs_check_violation((uint32_t)cad.sin_addr.s_addr, ph[i].ptab->ports[j].s_port))
					return 0;

				cl = create_client(cad.sin_addr.s_addr);
				if (!cl) return 0;

				cl->ctyp=i;
				cl->port_idx=j;
				cl->udp_fd=ph[i].ptab->ports[j].fd;
				cl->udp_sa=cad;

				cl->port=ntohs(cad.sin_port);
				cl->typ='c';

				add_job(cl, ACTION_CLIENT_INIT, NULL, 0);
			}
			add_job(cl, ACTION_CLIENT_UDP, buf, n+3);
		}
	} else { //TCP
		int32_t pfd3;
		if ((pfd3=accept(ph[i].ptab->ports[j].fd, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {

			if (cs_check_violation((uint32_t)cad.sin_addr.s_addr, ph[i].ptab->ports[j].s_port)) {
				close(pfd3);
				return 0;
			}

			struct s_client * cl = create_client(cad.sin_addr.s_addr);
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
			cl->port=ntohs(cad.sin_port);
			cl->typ='c';
			
			add_job(cl, ACTION_CLIENT_INIT, NULL, 0);
		}
	}
	return 0;
}

#ifdef WEBIF
static void restart_daemon()
{
  while (1) {

    //start client process:
    pid_t pid = fork();
    if (!pid)
      return; //client process=oscam process
    if (pid < 0)
      exit(1);

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
#endif

int32_t main (int32_t argc, char *argv[])
{
	if (pthread_key_create(&getclient, NULL)) {
		fprintf(stderr, "Could not create getclient, exiting...");
		exit(1);
	}

#ifdef CS_LED
	cs_switch_led(LED1A, LED_DEFAULT);
	cs_switch_led(LED1A, LED_ON);
#endif

	int32_t      i, j, bg=0, gbdb=0;

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
           module_oscam_ser,
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
	0
  };

  void (*cardreader_def[])(struct s_cardreader *)=
  {
	cardreader_mouse,
	cardreader_smargo,
#ifdef WITH_STAPI
	cardreader_stapi,
#endif
	0
  };

  while ((i=getopt(argc, argv, "gbsc:t:d:r:hm:x"))!=EOF)
  {
	  switch(i) {
	  	  case 'g':
		      gbdb=1;
		      break;
		  case 'b':
			  bg=1;
			  break;
		  case 's':
		      cs_capture_SEGV=1;
		      break;
		  case 'c':
			  cs_strncpy(cs_confdir, optarg, sizeof(cs_confdir));
			  break;
		  case 'd':
			  cs_dblevel=atoi(optarg);
			  break;
#ifdef WEBIF
                  case 'r':
                          cs_restart_mode=atoi(optarg);
                          break;
#endif
		  case 't':
			  mkdir(optarg, S_IRWXU);
			  j = open(optarg, O_RDONLY);
			  if (j >= 0) {
			 	close(j);
			 	cs_strncpy(cs_tmpdir, optarg, sizeof(cs_tmpdir));
			  } else {
				printf("WARNING: tmpdir does not exist. using default value.\n");
			  }
			  break;
		  case 'm':
				printf("WARNING: -m parameter is deprecated, ignoring it.\n");
				break;
		  case 'h':
		  default :
			  usage();
	  }
  }


#ifdef OS_MACOSX
  if (bg && daemon_compat(1,0))
#else
  if (bg && daemon(1,0))
#endif
  {
    printf("Error starting in background (errno=%d: %s)", errno, strerror(errno));
    cs_exit(1);
  }

#ifdef WEBIF
  if (cs_restart_mode)
    restart_daemon();
#endif

  memset(&cfg, 0, sizeof(struct s_config));

  if (cs_confdir[strlen(cs_confdir)]!='/') strcat(cs_confdir, "/");
  init_signal_pre(); // because log could cause SIGPIPE errors, init a signal handler first
  init_first_client();
  init_config();
  init_check();
#ifdef WITH_LB
  init_stat();
#endif

  for (i=0; mod_def[i]; i++)  // must be later BEFORE init_config()
  {
    memset(&ph[i], 0, sizeof(struct s_module));
    mod_def[i](&ph[i]);
  }
  for (i=0; cardsystem_def[i]; i++)  // must be later BEFORE init_config()
  {
    memset(&cardsystem[i], 0, sizeof(struct s_cardsystem));
    cardsystem_def[i](&cardsystem[i]);
  }

  for (i=0; cardreader_def[i]; i++)  // must be later BEFORE init_config()
  {
    memset(&cardreader[i], 0, sizeof(struct s_cardreader));
    cardreader_def[i](&cardreader[i]);
  }

  init_rnd();
  init_sidtab();
  init_readerdb();
  cfg.account = init_userdb();
  init_signal();
  init_srvid();
  init_tierid();
  //Todo #ifdef CCCAM
  init_provid();

  start_garbage_collector(gbdb);

  init_len4caid();
#ifdef IRDETO_GUESSING
  init_irdeto_guess_tab();
#endif

  write_versionfile();
  server_pid = getpid();

#if defined(AZBOX) && defined(HAVE_DVBAPI)
  openxcas_debug_message_onoff(1);  // debug

#ifdef WITH_CARDREADER
  if (openxcas_open_with_smartcard("oscamCAS") < 0) {
#else
  if (openxcas_open("oscamCAS") < 0) {
#endif
    cs_log("openxcas: could not init");
  }
#endif

  for (i=0; i<CS_MAX_MOD; i++)
    if( (ph[i].type & MOD_CONN_NET) && ph[i].ptab )
      for(j=0; j<ph[i].ptab->nports; j++)
      {
        start_listener(&ph[i], j);
      }

	//set time for server to now to avoid 0 in monitor/webif
	first_client->last=time((time_t *)0);

#ifdef WEBIF
	if(cfg.http_port == 0)
		cs_log("http disabled");
	else
		start_thread((void *) &http_srv, "http");
#endif
	start_thread((void *) &reader_check, "reader check"); 
	start_thread((void *) &check_thread, "check"); 
#ifdef LCDSUPPORT
	start_lcd_thread();
#endif

	init_cardreader();

	cs_waitforcardinit();

#ifdef CS_LED
	cs_switch_led(LED1A, LED_OFF);
	cs_switch_led(LED1B, LED_ON);
#endif

#ifdef QBOXHD_LED
	if(!cfg.disableqboxhdled)
		cs_log("QboxHD LED enabled");
    qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_RED,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA,QBOXHD_LED_BLINK_FAST);
#endif

#ifdef CS_ANTICASC
	if( !cfg.ac_enabled )
		cs_log("anti cascading disabled");
	else {
		init_ac();
		ac_init_stat();
		add_check(NULL, CHECK_ANTICASCADER, NULL, 0, cfg.ac_stime*60*1000);
	}
#endif

	for (i=0; i<CS_MAX_MOD; i++)
		if (ph[i].type & MOD_CONN_SERIAL)   // for now: oscam_ser only
			if (ph[i].s_handler)
				ph[i].s_handler(NULL, NULL, i);

	// main loop function
	client_check();


#if defined(AZBOX) && defined(HAVE_DVBAPI)
  if (openxcas_close() < 0) {
    cs_log("openxcas: could not close");
  }
#endif

		cs_cleanup();

        stop_garbage_collector();

	return exit_oscam;
}

void cs_exit_oscam()
{
  exit_oscam=1;
  cs_log("exit oscam requested");
}

#ifdef WEBIF
void cs_restart_oscam()
{
  exit_oscam=99;
  cs_log("restart oscam requested");
}

int32_t cs_get_restartmode() {
	return cs_restart_mode;
}

#endif

#ifdef CS_LED
void cs_switch_led(int32_t led, int32_t action) {

	if(action < 2) { // only LED_ON and LED_OFF
		char ledfile[256];
		FILE *f;

		#ifdef DOCKSTAR
			switch(led){
			case LED1A:snprintf(ledfile, 255, "/sys/class/leds/dockstar:orange:misc/brightness");
			break;
			case LED1B:snprintf(ledfile, 255, "/sys/class/leds/dockstar:green:health/brightness");
			break;
			case LED2:snprintf(ledfile, 255, "/sys/class/leds/dockstar:green:health/brightness");
			break;
			case LED3:snprintf(ledfile, 255, "/sys/class/leds/dockstar:orange:misc/brightness");
			break;
			}
		#elif WRT350NV2
			switch(led){
			case LED1A:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:orange:power/brightness");
			break;
			case LED1B:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:green:power/brightness");
			break;
			case LED2:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:green:wireless/brightness");
			break;
			case LED3:snprintf(ledfile, 255, "/sys/class/leds/wrt350nv2:green:security/brightness");
			break;
			}
		#else
			switch(led){
			case LED1A:snprintf(ledfile, 255, "/sys/class/leds/nslu2:red:status/brightness");
			break;
			case LED1B:snprintf(ledfile, 255, "/sys/class/leds/nslu2:green:ready/brightness");
			break;
			case LED2:snprintf(ledfile, 255, "/sys/class/leds/nslu2:green:disk-1/brightness");
			break;
			case LED3:snprintf(ledfile, 255, "/sys/class/leds/nslu2:green:disk-2/brightness");
			break;
			}
		#endif

		if (!(f=fopen(ledfile, "w"))){
			// FIXME: sometimes cs_log was not available when calling cs_switch_led -> signal 11
			//cs_log("Cannot open file \"%s\" (errno=%d %s)", ledfile, errno, strerror(errno));
			return;
		}
		fprintf(f,"%d", action);
		fclose(f);
	} else { // LED Macros
		switch(action){
		case LED_DEFAULT:
			cs_switch_led(LED1A, LED_OFF);
			cs_switch_led(LED1B, LED_OFF);
			cs_switch_led(LED2, LED_ON);
			cs_switch_led(LED3, LED_OFF);
			break;
		case LED_BLINK_OFF:
			cs_switch_led(led, LED_OFF);
			cs_sleepms(100);
			cs_switch_led(led, LED_ON);
			break;
		case LED_BLINK_ON:
			cs_switch_led(led, LED_ON);
			cs_sleepms(300);
			cs_switch_led(led, LED_OFF);
			break;
		}
	}
}
#endif

#ifdef QBOXHD_LED
void qboxhd_led_blink(int32_t color, int32_t duration) {
    int32_t f;

    if (cfg.disableqboxhdled) {
        return;
    }

    // try QboxHD-MINI first
    if ( (f = open ( QBOXHDMINI_LED_DEVICE,  O_RDWR |O_NONBLOCK )) > -1 ) {
        qboxhdmini_led_color_struct qbminiled;
        uint32_t qboxhdmini_color = 0x000000;

        if (color != QBOXHD_LED_COLOR_OFF) {
            switch(color) {
                case QBOXHD_LED_COLOR_RED:
                    qboxhdmini_color = QBOXHDMINI_LED_COLOR_RED;
                    break;
                case QBOXHD_LED_COLOR_GREEN:
                    qboxhdmini_color = QBOXHDMINI_LED_COLOR_GREEN;
                    break;
                case QBOXHD_LED_COLOR_BLUE:
                    qboxhdmini_color = QBOXHDMINI_LED_COLOR_BLUE;
                    break;
                case QBOXHD_LED_COLOR_YELLOW:
                    qboxhdmini_color = QBOXHDMINI_LED_COLOR_YELLOW;
                    break;
                case QBOXHD_LED_COLOR_MAGENTA:
                    qboxhdmini_color = QBOXHDMINI_LED_COLOR_MAGENTA;
                    break;
            }

            // set LED on with color
            qbminiled.red = (uchar)((qboxhdmini_color&0xFF0000)>>16);  // R
            qbminiled.green = (uchar)((qboxhdmini_color&0x00FF00)>>8); // G
            qbminiled.blue = (uchar)(qboxhdmini_color&0x0000FF);       // B

            ioctl(f,QBOXHDMINI_IOSET_RGB,&qbminiled);
            cs_sleepms(duration);
        }

        // set LED off
        qbminiled.red = 0;
        qbminiled.green = 0;
        qbminiled.blue = 0;

        ioctl(f,QBOXHDMINI_IOSET_RGB,&qbminiled);
        close(f);

    } else if ( (f = open ( QBOXHD_LED_DEVICE,  O_RDWR |O_NONBLOCK )) > -1 ) {

        qboxhd_led_color_struct qbled;

        if (color != QBOXHD_LED_COLOR_OFF) {
            // set LED on with color
            qbled.H = color;
            qbled.S = 99;
            qbled.V = 99;
            ioctl(f,QBOXHD_SET_LED_ALL_PANEL_COLOR, &qbled);
            cs_sleepms(duration);
        }

        // set LED off
        qbled.H = 0;
        qbled.S = 0;
        qbled.V = 0;
        ioctl(f,QBOXHD_SET_LED_ALL_PANEL_COLOR, &qbled);
        close(f);
    }

    return;
}
#endif
