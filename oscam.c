  //FIXME Not checked on threadsafety yet; after checking please remove this line
#define CS_CORE
#include "globals.h"
#if defined(AZBOX) && defined(HAVE_DVBAPI)
#  include "openxcas/openxcas_api.h"
#endif
#define CS_VERSION_X  CS_VERSION
#ifdef COOL
void coolapi_close_all();
void coolapi_open_all();
#endif

extern void cs_statistics(struct s_client * client);
extern int ICC_Async_Close (struct s_reader *reader);

/*****************************************************************************
        Globals
*****************************************************************************/
int exit_oscam=0;
struct s_module 	ph[CS_MAX_MOD]; // Protocols
struct s_cardsystem	cardsystem[CS_MAX_MOD];
struct s_cardreader	cardreader[CS_MAX_MOD];

struct s_client * first_client = NULL; //Pointer to clients list, first client is master
struct s_reader * first_active_reader = NULL; //list of active readers (enable=1 deleted = 0)
LLIST * configured_readers = NULL; //list of all (configured) readers

ushort  len4caid[256];    // table for guessing caid (by len)
char  cs_confdir[128]=CS_CONFDIR;
int cs_dblevel=0;   // Debug Level (TODO !!)
#ifdef WEBIF
int cs_restart_mode=1; //Restartmode: 0=off, no restart fork, 1=(default)restart fork, restart by webif, 2=like=1, but also restart on segfaults
#endif
char  cs_tmpdir[200]={0x00};
pthread_mutex_t gethostbyname_lock;
pthread_mutex_t get_cw_lock;
pthread_key_t getclient;

//Cache for  ecms, cws and rcs:
LLIST *ecmcache;

struct  s_config  cfg;
#ifdef CS_LOGHISTORY
int     loghistidx;  // ptr to current entry
char    loghist[CS_MAXLOGHIST*CS_LOGHISTSIZE];     // ptr of log-history
#endif

int get_threadnum(struct s_client *client) {
	struct s_client *cl;
	int count=0;

	for (cl=first_client->next; cl ; cl=cl->next) {
		if (cl->typ==client->typ)
			count++;
		if(cl==client)
			return count;
	}
	return 0;
}

struct s_client * cur_client(void)
{
	return (struct s_client *) pthread_getspecific(getclient);
}

int cs_check_v(uint ip, int add) {
        int result = 0;
	if (cfg.failbantime) {

		if (!cfg.v_list)
			cfg.v_list = ll_create();

		time_t now = time((time_t)0);
		LL_ITER *itr = ll_iter_create(cfg.v_list);
		V_BAN *v_ban_entry;
		int ftime = cfg.failbantime*60;

		//run over all banned entries to do housekeeping:
		while ((v_ban_entry=ll_iter_next(itr))) {

			// housekeeping:
			if ((now - v_ban_entry->v_time) >= ftime) { // entry out of time->remove
				ll_iter_remove_data(itr);
				continue;
                        }

			if (ip == v_ban_entry->v_ip) {
			        result=1;
			        if (!add) {
        				if (v_ban_entry->v_count >= cfg.failbancount) {
        					cs_debug_mask(D_TRACE, "failban: banned ip %s - %ld seconds left",
	        						cs_inet_ntoa(v_ban_entry->v_ip),ftime - (now - v_ban_entry->v_time));
			        	} else {
				        	cs_debug_mask(D_TRACE, "failban: ip %s chance %d of %d",
					        		cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_count, cfg.failbancount);
        					v_ban_entry->v_count++;
	        			}
                                }
                                else {
        				cs_debug_mask(D_TRACE, "failban: banned ip %s - already exist in list", cs_inet_ntoa(v_ban_entry->v_ip));
                                }

			}
		}
		if (add && !result) {
  		        v_ban_entry = malloc(sizeof(V_BAN));
  		        memset(v_ban_entry, 0, sizeof(V_BAN));

        		v_ban_entry->v_time = time((time_t *)0);
	        	v_ban_entry->v_ip = ip;

        		ll_iter_insert(itr, v_ban_entry);

        		cs_debug_mask(D_TRACE, "failban: ban ip %s with timestamp %d", cs_inet_ntoa(v_ban_entry->v_ip), v_ban_entry->v_time);
                }
		ll_iter_release(itr);
	}
	return result;
}

int cs_check_violation(uint ip) {
        return cs_check_v(ip, 0);
}
void cs_add_violation(uint ip) {
        cs_check_v(ip, 1);
}

void cs_add_lastresponsetime(struct s_client *cl, int ltime){

	if(cl->cwlastresptimes_last == CS_ECM_RINGBUFFER_MAX - 1){
		cl->cwlastresptimes_last = 0;
	} else {
		cl->cwlastresptimes_last++;
	}
	cl->cwlastresptimes[cl->cwlastresptimes_last] = ltime;
}

//Alno Test End
/*****************************************************************************
        Statics
*****************************************************************************/
static const char *logo = "  ___  ____   ___                \n / _ \\/ ___| / __|__ _ _ __ ___  \n| | | \\___ \\| |  / _` | '_ ` _ \\ \n| |_| |___) | |_| (_| | | | | | |\n \\___/|____/ \\___\\__,_|_| |_| |_|\n";

static void usage()
{
  fprintf(stderr, "%s\n\n", logo);
  fprintf(stderr, "OSCam cardserver v%s, build #%s (%s) - (w) 2009-2011 Streamboard SVN\n", CS_VERSION_X, CS_SVN_VERSION, CS_OSTYPE);
  fprintf(stderr, "\tsee http://streamboard.gmc.to/oscam/ for more details\n");
  fprintf(stderr, "\tbased on Streamboard mp-cardserver v0.9d - (w) 2004-2007 by dukat\n");
  fprintf(stderr, "\tThis program is distributed under GPL.\n");
  fprintf(stderr, "\tinbuilt add-ons: ");
#ifdef WEBIF
  fprintf(stderr, "webinterface ");
#endif
#ifdef MODULE_MONITOR
  fprintf(stderr, "monitor ");
#endif
#ifdef WITH_SSL
  fprintf(stderr, "openssl ");
#endif
#ifdef HAVE_DVBAPI
#ifdef WITH_STAPI
  fprintf(stderr, "dvbapi-with-stapi ");
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
  fprintf(stderr, "led-trigger ");
#endif
#ifdef CS_WITH_DOUBLECHECK
  fprintf(stderr, "doublecheck ");
#endif
#ifdef QBOXHD_LED
  fprintf(stderr, "qboxhd-led-trigger ");
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
  fprintf(stderr, "\n\tinbuilt protocols: ");
#ifdef MODULE_CAMD33
  fprintf(stderr, "camd33 ");
#endif
#ifdef MODULE_CAMD35
  fprintf(stderr, "camd35-udp ");
#endif
#ifdef MODULE_CAMD35_TCP
  fprintf(stderr, "camd35-tcp ");
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
  fprintf(stderr, "oscam [-b] [-c <config dir>] [-t <tmp dir>] [-d <level>] [-r <level>] [-h]");
  fprintf(stderr, "\n\n\t-b         : start in background\n");
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
  fprintf(stderr, "\t               2 = like 1, but also restart on SEGFAULTS\n");
#endif
  fprintf(stderr, "\t-h         : show this help\n");
  fprintf(stderr, "\n");
  exit(1);
}

#ifdef NEED_DAEMON
#ifdef OS_MACOSX
// this is done because daemon is being deprecated starting with 10.5 and -Werror will always trigger an error
static int daemon_compat(int nochdir, int noclose)
#else
static int daemon(int nochdir, int noclose)
#endif
{
  int fd;

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

int recv_from_udpipe(uchar *buf)
{
  unsigned short n;
  if (buf[0]!='U')
  {
    cs_log("INTERNAL PIPE-ERROR");
    cs_exit(1);
  }
  memcpy(&n, buf+1, 2);

  memmove(buf, buf+3, n);

  return n;
}

char *username(struct s_client * client)
{
	if (!client)
		return "NULL";

	if (client->typ == 's' || client->typ == 'h')
	{
		// get username master running under
		struct passwd *pwd;
		if ((pwd = getpwuid(getuid())) != NULL)
			return pwd->pw_name;
		else
			return "root";
	}

	if(client->account)
	{
		if (client->account->usr[0])
			return(client->account->usr);
		else
			return("anonymous");
	}
	else
	{
		return("NULL");
	}
}

static struct s_client * idx_from_ip(in_addr_t ip, in_port_t port)
{
  struct s_client *cl;
  for (cl=first_client; cl ; cl=cl->next)
    if ((cl->ip==ip) && (cl->port==port) && ((cl->typ=='c') || (cl->typ=='m')))
      return cl;
  return NULL;
}

struct s_client * get_client_by_tid(unsigned long tid) //FIXME untested!! no longer pid in output...
{
  struct s_client *cl;
  for (cl=first_client; cl ; cl=cl->next)
    if ((unsigned long)(cl->thread)==tid)
      return cl;
  return NULL;
}

static long chk_caid(ushort caid, CAIDTAB *ctab)
{
  int n;
  long rc;
  for (rc=(-1), n=0; (n<CS_MAXCAIDTAB) && (rc<0); n++)
    if ((caid & ctab->mask[n]) == ctab->caid[n])
      rc=ctab->cmap[n] ? ctab->cmap[n] : caid;
  return(rc);
}

int chk_bcaid(ECM_REQUEST *er, CAIDTAB *ctab)
{
  long caid;
  if ((caid=chk_caid(er->caid, ctab))<0)
    return(0);
  er->caid=caid;
  return(1);
}

/*
 * void set_signal_handler(int sig, int flags, void (*sighandler)(int))
 * flags: 1 = restart, 2 = don't modify if SIG_IGN, may be combined
 */
void set_signal_handler(int sig, int flags, void (*sighandler))
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
      }
    }
  }
  cs_reinit_clients(new_accounts);
  cfg.account = new_accounts;
  init_free_userdb(old_accounts);

#ifdef CS_ANTICASC
//	struct s_client *cl;
//	for (cl=first_client->next; cl ; cl=cl->next)
//    if (cl->typ=='a')
//      break;
  ac_clear();
#endif
}

void nullclose(int *fd)
{
	//if closing an already closed pipe, we get a sigpipe signal, and this causes a cs_exit
	//and this causes a close and this causes a sigpipe...and so on
	int f = *fd;
	*fd = 0; //so first null client-fd
	close(f); //then close fd
}

static void cleanup_ecmtasks(struct s_client *cl)
{
        if (!cl->ecmtask)
                return;

        int i, n=(ph[cl->ctyp].multi)?CS_MAXPENDING:1;
        ECM_REQUEST *ecm;
        for (i=0; i<n; i++) {
                ecm = &cl->ecmtask[i];
                ll_destroy(ecm->matching_rdr); //no need to garbage this
                ecm->matching_rdr=NULL;
        }
        add_garbage(cl->ecmtask);
        cl->ecmtask = NULL;
}

void cleanup_thread(void *var)
{
	struct s_client *cl = var;
	if(cl && !cl->cleaned){
		struct s_client *prev, *cl2;
		for (prev=first_client, cl2=first_client->next; prev->next != NULL; prev=prev->next, cl2=cl2->next)
			if (cl == cl2)
				break;
		if (cl != cl2)
			cs_log("FATAL ERROR: could not find client to remove from list.");
		else
			prev->next = cl2->next; //remove client from list
	
		if(cl->typ == 'c' && ph[cl->ctyp].cleanup)
			ph[cl->ctyp].cleanup(cl);
	    else if (cl->reader && cl->reader->ph.cleanup)
	        cl->reader->ph.cleanup(cl);
	  if(cl->typ == 'c'){
	    cs_statistics(cl);
	    cl->last_caid = 0xFFFF;
	    cl->last_srvid = 0xFFFF;
	    cs_statistics(cl);
	  }
	
		if(cl->pfd)		nullclose(&cl->pfd); //Closing Network socket
		if(cl->fd_m2c_c)	nullclose(&cl->fd_m2c_c); //Closing client read fd
		if(cl->fd_m2c)	nullclose(&cl->fd_m2c); //Closing client read fd
	
		if(cl->typ == 'r' && cl->reader){
			// Maybe we also need a "nullclose" mechanism here...
			ICC_Async_Close(cl->reader);
		}
		if (cl->reader) {
			cl->reader->client = NULL;
			cl->reader = NULL;
	    }
		cleanup_ecmtasks(cl);
		add_garbage(cl->emmcache);
		add_garbage(cl->req);
		add_garbage(cl->cc);
		add_garbage(cl->serialdata);
		add_garbage(cl);
		cl->cleaned++;
	}
}

static void cs_cleanup()
{
		if (cfg.lb_mode && cfg.lb_save) {
				save_stat_to_file();
				cfg.lb_save = 0; //this is for avoiding duplicate saves
		}
		
		done_share();

        //cleanup clients:
        struct s_client *cl;
        for (cl=first_client->next; cl; cl=cl->next) {
                if (cl->typ=='c')
                        kill_thread(cl);
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

void cs_exit(int sig)
{
	char targetfile[256];

	set_signal_handler(SIGCHLD, 1, SIG_IGN);
	set_signal_handler(SIGHUP , 1, SIG_IGN);
	set_signal_handler(SIGPIPE, 1, SIG_IGN);

	if (sig==SIGALRM) {
		cs_debug_mask(D_TRACE, "thread %8X: SIGALRM, skipping", pthread_self());
		return;
	}

  if (sig && (sig!=SIGQUIT))
    cs_log("exit with signal %d", sig);

  struct s_client *cl = cur_client();

  switch(cl->typ)
  {
    case 'c':
    	cs_statistics(cl);
    	cl->last_caid = 0xFFFF;
    	cl->last_srvid = 0xFFFF;
    	cs_statistics(cl);
    	break;

    case 'm': break;
    case 'r': break; //reader-cleanup now in cleanup_thread()

    case 'h':
    case 's':
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

#ifndef OS_CYGWIN32
	snprintf(targetfile, 255, "%s%s", get_tmp_dir(), "/oscam.version");
	if (unlink(targetfile) < 0)
		cs_log("cannot remove oscam version file %s (errno=%d %s)", targetfile, errno, strerror(errno));
#endif
#ifdef COOL
	coolapi_close_all();
#endif
	break;
  }

	// this is very important - do not remove
	if (cl->typ != 's') {
		cs_log("thread %8X ended!", pthread_self());
		//Restore signals before exiting thread
		set_signal_handler(SIGPIPE , 0, cs_sigpipe);
		set_signal_handler(SIGHUP  , 1, cs_reload_config);

		pthread_exit(NULL);
		return;
	}

	cs_log("cardserver down");
	cs_close_log();

	cs_cleanup();

	if (!exit_oscam)
	  exit_oscam = sig?sig:1;
}

void cs_reinit_clients(struct s_auth *new_accounts)
{
	struct s_auth *account;

	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		if( cl->typ == 'c' && cl->account ) {
			for (account = new_accounts; (account) ; account = account->next)
				if (!strcmp(cl->account->usr, account->usr))
					break;

			if (account && cl->pcrc == crc32(0L, MD5((uchar *)account->pwd, strlen(account->pwd), cur_client()->dump), 16)) {
                                cl->account = account;
				cl->grp		= account->grp;
				cl->aureader_list		= account->aureader_list;
				cl->autoau	= account->autoau;
				cl->expirationdate = account->expirationdate;
				cl->allowedtimeframe[0] = account->allowedtimeframe[0];
				cl->allowedtimeframe[1] = account->allowedtimeframe[1];
				cl->ncd_keepalive = account->ncd_keepalive;
				cl->c35_suppresscmd08 = account->c35_suppresscmd08;
				cl->tosleep	= (60*account->tosleep);
				cl->c35_sleepsend = account->c35_sleepsend;
				cl->monlvl	= account->monlvl;
				cl->disabled	= account->disabled;
				cl->fchid		= account->fchid;  // CHID filters
				cl->cltab		= account->cltab;  // Class
				// newcamd module dosent like ident reloading
				if(!cl->ncd_server)
					cl->ftab	= account->ftab;   // Ident

				cl->sidtabok	= account->sidtabok;   // services
				cl->sidtabno	= account->sidtabno;   // services
				cl->failban	= account->failban;

				memcpy(&cl->ctab, &account->ctab, sizeof(cl->ctab));
				memcpy(&cl->ttab, &account->ttab, sizeof(cl->ttab));

				int i;
				for(i = 0; i < CS_ECM_RINGBUFFER_MAX; i++)
					cl->cwlastresptimes[i] = 0;
				cl->cwlastresptimes_last = 0;

#ifdef CS_ANTICASC
				cl->ac_idx	= account->ac_idx;
				cl->ac_penalty= account->ac_penalty;
				cl->ac_limit	= (account->ac_users * 100 + 80) * cfg.ac_stime;
#endif
			} else {
				if (ph[cl->ctyp].type & MOD_CONN_NET) {
					cs_debug_mask(D_TRACE, "client '%s', thread=%8X not found in db (or password changed)", cl->account->usr, cl->thread);
					kill_thread(cl);
				}
			}
		}
}

void cs_debug_level()
{
	//switch debuglevel forward one step if not set from outside
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

	cs_log("%sdebug_level=%d", "all", cs_dblevel);
}

void cs_card_info()
{
  uchar dummy[1]={0x00};
	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
    if( cl->typ=='r' && cl->fd_m2c )
      write_to_pipe(cl->fd_m2c, PIP_ID_CIN, dummy, 1);
      //kill(client[i].pid, SIGUSR2);
}

struct s_client * create_client(in_addr_t ip) {
	struct s_client *cl;

	cl = malloc(sizeof(struct s_client));
	if (cl) {
		memset(cl, 0, sizeof(struct s_client));
		int fdp[2];
		if (pipe(fdp)) {
			cs_log("Cannot create pipe (errno=%d: %s)", errno, strerror(errno));
			free(cl);
			return NULL;
		}
		//client part

		//make_non_blocking(fdp[0]);
		//make_non_blocking(fdp[1]);
		cl->fd_m2c_c = fdp[0]; //store client read fd
		cl->fd_m2c = fdp[1]; //store client read fd
		cl->ip=ip;
		cl->account = first_client->account;

		//master part
		cl->stat=1;

		cl->login=cl->last=time((time_t *)0);

        //Now add new client to the list:
		struct s_client *last;
		for (last=first_client; last->next != NULL; last=last->next); //ends with cl on last client
		last->next = cl;
	} else {
		cs_log("max connections reached (out of memory) -> reject client %s", cs_inet_ntoa(ip));
		return NULL;
	}
	return(cl);
}

/**
 * called by signal SIGHUB
 *
 * reloads configs:
 *  - useraccounts (oscom.user)
 *  - services ids (oscam.srvid)
 *  - tier ids     (oscam.tiers)
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

static void init_signal_pre()
{
		set_signal_handler(SIGPIPE , 1, SIG_IGN);
		set_signal_handler(SIGWINCH, 1, SIG_IGN);
		set_signal_handler(SIGALRM , 1, SIG_IGN);
		set_signal_handler(SIGHUP  , 1, SIG_IGN);
}

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
		set_signal_handler(SIGCONT, 1, SIG_IGN);
		cs_log("signal handling initialized (type=%s)",
#ifdef CS_SIGBSD
		"bsd"
#else
		"sysv"
#endif
		);
	return;
}

static void init_first_client()
{
  //Generate 5 ECM cache entries:
  ecmcache = ll_create();

  first_client = malloc(sizeof(struct s_client));
	if (!first_client) {
    fprintf(stderr, "Could not allocate memory for master client, exiting...");
  exit(1);
  }
  memset(first_client, 0, sizeof(struct s_auth));
  first_client->next = NULL; //terminate clients list with NULL
  first_client->login=time((time_t *)0);
  first_client->ip=cs_inet_addr("127.0.0.1");
  first_client->typ='s';
  first_client->thread=pthread_self();
  struct s_auth *null_account = malloc(sizeof(struct s_auth));
  memset(null_account, 0, sizeof(struct s_auth));
  first_client->account = null_account;
  if (pthread_setspecific(getclient, first_client)) {
    fprintf(stderr, "Could not setspecific getclient in master process, exiting...");
  exit(1);
  }


  pthread_mutex_init(&gethostbyname_lock, NULL);
  pthread_mutex_init(&get_cw_lock, NULL);

#ifdef CS_LOGHISTORY
  loghistidx=0;
  memset(loghist, 0, CS_MAXLOGHIST*CS_LOGHISTSIZE);
#endif

#ifdef COOL
  coolapi_open_all();
#endif
}

static void init_check(){
	char *ptr = __DATE__;
	int month, year = atoi(ptr + strlen(ptr) - 4), day = atoi(ptr + 4);
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
	  int i = 0;
	  while(time((time_t)0) < builddate){
	  	cs_log("The current system time is smaller than the build date (%s). Waiting 5s for time to correct...", ptr);
	  	cs_sleepms(5000);
	  	++i;
	  	if(i > 12){
	  		cs_log("Waiting was not successful. OSCam will be started but is UNSUPPORTED this way. Do not report any errors with this version.");
				break;
	  	}
	  }
	}
}

static int start_listener(struct s_module *ph, int port_idx)
{
  int ov=1, timeout, is_udp, i;
  char ptxt[2][32];
  //struct   hostent   *ptrh;     /* pointer to a host table entry */
  struct   protoent  *ptrp;     /* pointer to a protocol table entry */
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
    sad.sin_port = htons((u_short)ph->ptab->ports[port_idx].s_port);
  else
  {
    cs_log("%s: Bad port %d", ph->desc, ph->ptab->ports[port_idx].s_port);
    return(0);
  }

  /* Map transport protocol name to protocol number */

  if( (ptrp=getprotobyname(is_udp ? "udp" : "tcp")) )
    ov=ptrp->p_proto;
  else
    ov=(is_udp) ? 17 : 6; // use defaults on error

  if ((ph->ptab->ports[port_idx].fd=socket(PF_INET,is_udp ? SOCK_DGRAM : SOCK_STREAM, ov))<0)
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
    if (!setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_PRIORITY, (void *)&cfg.netprio, sizeof(ulong)))
      snprintf(ptxt[1], sizeof(ptxt[1]), ", prio=%ld", cfg.netprio);
#endif

  if( !is_udp )
  {
    int keep_alive = 1;
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
    int j;
    cs_log("CAID: %04X", ph->ptab->ports[port_idx].ftab.filts[i].caid );
    for( j=0; j<ph->ptab->ports[port_idx].ftab.filts[i].nprids; j++ )
      cs_log("provid #%d: %06X", j, ph->ptab->ports[port_idx].ftab.filts[i].prids[j]);
  }
  return(ph->ptab->ports[port_idx].fd);
}

int cs_user_resolve(struct s_auth *account)
{
	struct hostent *rht;
	struct sockaddr_in udp_sa;
	int result=0;
	if (account->dyndns[0])
	{
		pthread_mutex_lock(&gethostbyname_lock);
		in_addr_t lastip = account->dynip;
		//Resolve with gethostbyname:
		if (cfg.resolve_gethostbyname) {
			rht = gethostbyname((char*)account->dyndns);
			if (!rht)
				cs_log("can't resolve %s", account->dyndns);
			else {
				memcpy(&udp_sa.sin_addr, rht->h_addr, sizeof(udp_sa.sin_addr));
				account->dynip=udp_sa.sin_addr.s_addr;
				result=1;
			}
		}
		else { //Resolve with getaddrinfo:
			struct addrinfo hints, *res = NULL;
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = AF_INET;
			hints.ai_protocol = IPPROTO_TCP;

			int err = getaddrinfo((const char*)account->dyndns, NULL, &hints, &res);
			if (err != 0 || !res || !res->ai_addr) {
				cs_log("can't resolve %s, error: %s", account->dyndns, err ? gai_strerror(err) : "unknown");
			}
			else {
				account->dynip=((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
				result=1;
			}
			if (res) freeaddrinfo(res);
		}
		if (lastip != account->dynip)  {
			cs_log("%s: resolved ip=%s", (char*)account->dyndns, cs_inet_ntoa(account->dynip));
		}
		pthread_mutex_unlock(&gethostbyname_lock);
	}
	if (!result)
		account->dynip=0;
	return result;
}

#pragma GCC diagnostic ignored "-Wempty-body" 
void *clientthread_init(void * init){
	struct s_clientinit clientinit;
	memcpy(&clientinit, init, sizeof(struct s_clientinit)); //copy to stack to free init pointer
	free(init);
	
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_setspecific(getclient, clientinit.client);
	pthread_cleanup_push(cleanup_thread, (void *) clientinit.client);
	clientinit.handler(clientinit.client);
	pthread_cleanup_pop(1);
	return NULL;
}
#pragma GCC diagnostic warning "-Wempty-body" 

void start_thread(void * startroutine, char * nameroutine) {
	pthread_t temp;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
#ifndef TUXBOX
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	if (pthread_create(&temp, &attr, startroutine, NULL))
		cs_log("ERROR: can't create %s thread", nameroutine);
	else {
		cs_log("%s thread started", nameroutine);
		pthread_detach(temp);
	}
	pthread_attr_destroy(&attr);
}

void kill_thread(struct s_client *cl) { //cs_exit is used to let thread kill itself, this routine is for a thread to kill other thread

	if (!cl) return;
	pthread_t thread = cl->thread;
	if (pthread_equal(thread, pthread_self())) return; //cant kill yourself

	pthread_cancel(thread);
	pthread_join(thread, NULL);
	while(!cl->cleaned)
		cs_sleepms(50);
	cs_log("thread %8X killed!", thread);
	return;
}

#ifdef CS_ANTICASC
void start_anticascader()
{
  struct s_client * cl = create_client(first_client->ip);
  if (cl == NULL) return;
  cl->thread = pthread_self();
  pthread_setspecific(getclient, cl);
  cl->typ = 'a';

  //set_signal_handler(SIGHUP, 1, ac_init_stat);
  ac_init_stat();
  while(1)
  {
    cs_sleepms(1000); //FIXME this is a cpu-killer!
    ac_do_stat();
  }
}
#endif

static void remove_reader_from_active(struct s_reader *rdr) {
  struct s_reader *rdr2, *prv = NULL;
  for (rdr2=first_active_reader; rdr2 ; rdr2=rdr2->next) {
    if (rdr2==rdr) {
	  if (prv) prv->next = rdr2->next;
	  else first_active_reader = rdr2->next;
	  break;
	}
	prv = rdr2;
  }
}

static void add_reader_to_active(struct s_reader *rdr) {
  struct s_reader *rdr2;
  rdr->next = NULL;
  if (first_active_reader) {
    for (rdr2=first_active_reader; rdr2->next ; rdr2=rdr2->next) ; //search last element
	rdr2->next = rdr;
  } else first_active_reader = rdr;
}

int restart_cardreader(struct s_reader *rdr, int restart) {

	if (restart) {
		//remove from list:	
		remove_reader_from_active(rdr);
	}

	if (restart) //kill old thread
		if (rdr->client) {
			kill_thread(rdr->client);
			rdr->client = NULL;
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


		rdr->fd=cl->fd_m2c;
		cl->reader=rdr;
		cs_log("creating thread for device %s", rdr->device);

		cl->sidtabok=rdr->sidtabok;
		cl->sidtabno=rdr->sidtabno;

		rdr->client=cl;

		cl->typ='r';
		//client[i].ctyp=99;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
#if !defined(TUXBOX) && !defined(HAVE_PCSC)
        /* pcsc doesn't like this either; segfaults on x86, x86_64 */
		pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	
		if (pthread_create(&cl->thread, &attr, start_cardreader, (void *)rdr)) {
			cs_log("ERROR: can't create thread for %s", rdr->label);
			cleanup_thread(cl);
			restart = 0;
		}
		else
			pthread_detach(cl->thread);
		pthread_attr_destroy(&attr);
		
		if (restart) {
			//add to list
			add_reader_to_active(rdr);
		}
		return 1;
	}
	return 0;
}

static void init_cardreader() {

	struct s_reader *rdr;
	for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
		if (!restart_cardreader(rdr, 0))
			remove_reader_from_active(rdr);
	}
	load_stat_from_file();
}

static void cs_fake_client(struct s_client *client, char *usr, int uniq, in_addr_t ip)
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
	for (cl=first_client->next; cl ; cl=cl->next)
	{
		if (cl != client && (cl->typ == 'c') && !cl->dup && !strcmp(cl->account->usr, usr)
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
					cs_add_violation(cl->ip);
				}
				if (cfg.dropdups)
					kill_thread(cl);
			}
			else
			{
				client->dup = 1;
				client->aureader_list = NULL;
				cs_strncpy(buf, cs_inet_ntoa(ip), sizeof(buf));
				cs_log("client(%8X) duplicate user '%s' from %s (current %s) set to fake (uniq=%d)",
					pthread_self(), usr, cs_inet_ntoa(cl->ip), buf, uniq);
				if (client->failban & BAN_DUPLICATE) {
					cs_add_violation(ip);
				}
				if (cfg.dropdups)
					cs_disconnect_client(client);	
				break;
			}

		}
	}

}

int cs_auth_client(struct s_client * client, struct s_auth *account, const char *e_txt)
{
	int rc=0;
	char buf[32];
	char *t_crypt="encrypted";
	char *t_plain="plain";
	char *t_grant=" granted";
	char *t_reject=" rejected";
	char *t_msg[]= { buf, "invalid access", "invalid ip", "unknown reason" };
	memset(&client->grp, 0xff, sizeof(uint64));
	//client->grp=0xffffffffffffff;
	client->account=first_client->account;
	switch((long)account)
	{
	case 0:           // reject access
		rc=1;
		cs_add_violation((uint)client->ip);
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
				cs_add_violation((uint)client->ip);
				rc=2;
			}
		}

		if (!rc)
		{
			client->dup=0;
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
				client->pcrc  = crc32(0L, MD5((uchar *)account->pwd, strlen(account->pwd), client->dump), 16);
				memcpy(&client->ttab, &account->ttab, sizeof(client->ttab));
#ifdef CS_ANTICASC
				ac_init_client(account);
#endif
			}
		}
		client->monlvl=account->monlvl;
		client->account = account;
	case -1:            // anonymous grant access
		if (rc)
			t_grant=t_reject;
		else {
			if (client->typ=='m')
				snprintf(t_msg[0], sizeof(buf), "lvl=%d", client->monlvl);
			else {
				int rcount = ll_count(client->aureader_list);
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
static int check_and_store_ecmcache(ECM_REQUEST *er, uint64 grp)
{
	time_t now = time(NULL);
	time_t timeout = now-(time_t)(cfg.ctimeout/1000)-CS_CACHE_TIMEOUT;
	struct s_ecm *ecmc;
	LL_ITER *it = ll_iter_create(ecmcache);
	while ((ecmc=ll_iter_next(it))) {
		if (ecmc->time < timeout) {
			ll_iter_remove_data(it);
			continue;
		}

		if (grp && !(grp & ecmc->grp))
			continue;

		if (ecmc->caid!=er->caid)
			continue;

		if (memcmp(ecmc->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
			continue;

		ll_iter_release(it);
		//cs_debug_mask(D_TRACE, "cachehit! (ecm)");
		memcpy(er->cw, ecmc->cw, 16);
		er->selected_reader = ecmc->reader;
		if (ecmc->rc == E_FOUND)
				return E_CACHE1;
		er->ecmcacheptr = ecmc;
		return ecmc->rc;
	}
	ll_iter_release(it);

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
static int check_cwcache1(ECM_REQUEST *er, uint64 grp)
{
	//cs_ddump(ecmd5, CS_ECMSTORESIZE, "ECM search");
	//cs_log("cache1 CHECK: grp=%lX", grp);

	//cs_debug_mask(D_TRACE, "cachesize %d", ll_count(ecmcache));
	time_t now = time(NULL);
	time_t timeout = now-(time_t)(cfg.ctimeout/1000)-CS_CACHE_TIMEOUT;
	struct s_ecm *ecmc;

    LL_ITER *it = ll_iter_create(ecmcache);
    while ((ecmc=ll_iter_next(it))) {
        if (ecmc->time < timeout) {
			ll_iter_remove_data(it);
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
		ll_iter_release(it);
		//cs_debug_mask(D_TRACE, "cachehit!");
		return 1;
	}
	ll_iter_release(it);
	return 0;
}

/**
 * cache 2: reader-invoked
 * returns 1 if found in cache. cw is copied to er
 **/
int check_cwcache2(ECM_REQUEST *er, uint64 grp)
{
	int rc = check_cwcache1(er, grp);
	return rc;
}


static void store_cw_in_cache(ECM_REQUEST *er, uint64 grp, int rc)
{
#ifdef CS_WITH_DOUBLECHECK
	if (cfg.double_check && er->checked < 2)
		return;
#endif
	struct s_ecm *ecm = er->ecmcacheptr;
	if (!ecm || rc >= ecm->rc) return;

	//cs_log("store ecm from reader %d", er->selected_reader);
	memcpy(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE);
	memcpy(ecm->cw, er->cw, 16);
	ecm->caid = er->caid;
	ecm->grp = grp;
	ecm->reader = er->selected_reader;
	ecm->rc = rc;
	ecm->time = time(NULL);

	//cs_ddump(cwcache[*cwidx].ecmd5, CS_ECMSTORESIZE, "ECM stored (idx=%d)", *cwidx);
}

/*
// only for debug
static struct s_client * get_thread_by_pipefd(int fd)
{
	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		if (fd==cl->fd_m2c || fd==cl->fd_m2c_c)
			return cl;
	return first_client; //master process
}
*/

/*
 * write_to_pipe():
 * write all kind of data to pipe specified by fd
 */
int write_to_pipe(int fd, int id, uchar *data, int n)
{
	if (!fd) {
		cs_log("write_to_pipe: fd==0 id: %d", id);
		return -1;
	}

	//cs_debug_mask(D_TRACE, "write to pipe %d (%s) thread: %8X to %8X", fd, PIP_ID_TXT[id], pthread_self(), get_thread_by_pipefd(fd)->thread);

	uchar buf[3+sizeof(void*)];

	// fixme
	// copy data to allocated memory
	// needed for compatibility
	// need to be freed after read_from_pipe
	void *d = malloc(n);
	memcpy(d, data, n);

	if ((id<0) || (id>PIP_ID_MAX))
		return(PIP_ID_ERR);

	memcpy(buf, PIP_ID_TXT[id], 3);
	memcpy(buf+3, &d, sizeof(void*));

	n=3+sizeof(void*);

	return(write(fd, buf, n));
}


/*
 * read_from_pipe():
 * read all kind of data from pipe specified by fd
 * special-flag redir: if set AND data is ECM: this will redirected to appr. client
 */
int read_from_pipe(int fd, uchar **data, int redir)
{
	int rc;
	long hdr=0;
	uchar buf[3+sizeof(void*)];
	memset(buf, 0, sizeof(buf));

	redir=redir;
	*data=(uchar *)0;
	rc=PIP_ID_NUL;

	if (bytes_available(fd)) {
		if (read(fd, buf, sizeof(buf))==sizeof(buf)) {
			memcpy(&hdr, buf+3, sizeof(void*));
		} else {
			cs_log("WARNING: pipe header to small !");
			return PIP_ID_ERR;
		}
	} else {
		cs_log("!bytes_available(fd)");
		return PIP_ID_NUL;
	}

	uchar id[4];
	memcpy(id, buf, 3);
	id[3]='\0';

	//cs_debug_mask(D_TRACE, "read from pipe %d (%s) thread: %8X", fd, id, (unsigned int)pthread_self());

	int l;
	for (l=0; (rc<0) && (PIP_ID_TXT[l]); l++)
		if (!memcmp(buf, PIP_ID_TXT[l], 3))
			rc=l;

	if (rc<0) {
		cs_log("WARNING: pipe garbage from pipe %i", fd);
		return PIP_ID_ERR;
	}

	*data = (void*)hdr;

	return(rc);
}

/*
 * write_ecm_request():
 */
static int write_ecm_request(int fd, ECM_REQUEST *er)
{
  return(write_to_pipe(fd, PIP_ID_ECM, (uchar *) er, sizeof(ECM_REQUEST)));
}

/*
 * This function writes the current CW from ECM struct to a cwl file.
 * The filename is re-calculated and file re-opened every time.
 * This will consume a bit cpu time, but nothing has to be stored between
 * each call. If not file exists, a header is prepended
 */
void logCWtoFile(ECM_REQUEST *er)
{
	FILE *pfCWL;
	char srvname[128];
	/* %s / %s   _I  %04X  _  %s  .cwl  */
	char buf[256 + sizeof(srvname)];
	char date[7];
	unsigned char  i, parity, writeheader = 0;
	time_t t;
	struct tm timeinfo;
	struct s_srvid *this;

	/*
	* search service name for that id and change characters
	* causing problems in file name
	*/
	srvname[0] = 0;
	for (this=cfg.srvid; this; this = this->next) {
		if (this->srvid == er->srvid) {
			cs_strncpy(srvname, this->name, sizeof(srvname));
			srvname[sizeof(srvname)-1] = 0;
			for (i = 0; srvname[i]; i++)
				if (srvname[i] == ' ') srvname[i] = '_';
			break;
		}
	}

	/* calc log file name */
	time(&t);
	localtime_r(&t, &timeinfo);
	strftime(date, sizeof(date), "%Y%m%d", &timeinfo);
	snprintf(buf, sizeof(buf), "%s/%s_I%04X_%s.cwl", cfg.cwlogdir, date, er->srvid, srvname);

	/* open failed, assuming file does not exist, yet */
	if((pfCWL = fopen(buf, "r")) == NULL) {
		writeheader = 1;
	} else {
	/* we need to close the file if it was opened correctly */
		fclose(pfCWL);
	}

	if ((pfCWL = fopen(buf, "a+")) == NULL) {
		/* maybe this fails because the subdir does not exist. Is there a common function to create it?
			for the moment do not print to log on every ecm
			cs_log(""error opening cw logfile for writing: %s (errno=%d %s)", buf, errno, strerror(errno)); */
		return;
	}
	if (writeheader) {
		/* no global macro for cardserver name :( */
		fprintf(pfCWL, "# OSCam cardserver v%s - http://streamboard.gmc.to/oscam/\n", CS_VERSION_X);
		fprintf(pfCWL, "# control word log file for use with tsdec offline decrypter\n");
		strftime(buf, sizeof(buf),"DATE %Y-%m-%d, TIME %H:%M:%S, TZ %Z\n", &timeinfo);
		fprintf(pfCWL, "# %s", buf);
		fprintf(pfCWL, "# CAID 0x%04X, SID 0x%04X, SERVICE \"%s\"\n", er->caid, er->srvid, srvname);
	}

	parity = er->ecm[0]&1;
	fprintf(pfCWL, "%d ", parity);
	for (i = parity * 8; i < 8 + parity * 8; i++)
		fprintf(pfCWL, "%02X ", er->cw[i]);
	/* better use incoming time er->tps rather than current time? */
	strftime(buf,sizeof(buf),"%H:%M:%S\n", &timeinfo);
	fprintf(pfCWL, "# %s", buf);
	fflush(pfCWL);
	fclose(pfCWL);
}

/**
 * distributes found ecm-request to all clients with rc=99
 **/
void distribute_ecm(ECM_REQUEST *er, uint64 grp)
{
  struct s_client *cl;
  ECM_REQUEST *ecm;
  int n, i;

  if (er->rc == E_RDR_FOUND) //found converted to cache...
    er->rc = E_CACHE2; //cache

  for (cl=first_client->next; cl ; cl=cl->next) {
    if (cl->fd_m2c && cl->typ=='c' && cl->ecmtask && (cl->grp&grp)) {

      n=(ph[cl->ctyp].multi)?CS_MAXPENDING:1;
      for (i=0; i<n; i++) {
        ecm = &cl->ecmtask[i];
        if (ecm->rc >= E_99 && (ecm->ecmcacheptr == er->ecmcacheptr)) { //
        		 //||
        		//((ecm->caid==er->caid || ecm->ocaid==er->ocaid) && !memcmp(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE)))) {
          er->cpti = ecm->cpti;
          //cs_log("distribute %04X:%06X:%04X cpti %d to client %s", ecm->caid, ecm->prid, ecm->srvid, ecm->cpti, username(cl));
          write_ecm_request(cl->fd_m2c, er);
        }
        //else if (ecm->rc == E_99)
        //  cs_log("NO-distribute %04X:%06X:%04X cpti %d to client %s", ecm->caid, ecm->prid, ecm->srvid, ecm->cpti, username(cl));
      }
    }
  }
}


int write_ecm_answer(struct s_reader * reader, ECM_REQUEST *er)
{
  int i;
  uchar c;
  for (i=0; i<16; i+=4)
  {
    c=((er->cw[i]+er->cw[i+1]+er->cw[i+2]) & 0xff);
    if (er->cw[i+3]!=c)
    {
      cs_debug_mask(D_TRACE, "notice: changed dcw checksum byte cw[%i] from %02x to %02x", i+3, er->cw[i+3],c);
      er->cw[i+3]=c;
    }
  }

  er->selected_reader=reader;
//cs_log("answer from reader %d (rc=%d)", er->selected_reader, er->rc);
  er->caid=er->ocaid;

  if (er->rc==E_RDR_FOUND) {

	store_cw_in_cache(er, reader->grp, E_FOUND);

    /* CWL logging only if cwlogdir is set in config */
    if (cfg.cwlogdir != NULL)
      logCWtoFile(er);
  }

  int res=0;
  if( er->client && er->client->fd_m2c ) {
    //Wie got an ECM (or nok). Now we should check for another clients waiting for it:
    res = write_ecm_request(er->client->fd_m2c, er);
  }

  return res;
}

  /*
static int cs_read_timer(int fd, uchar *buf, int l, int msec)
{
  struct timeval tv;
  fd_set fds;
  int rc;

  if (!fd) return(-1);
  tv.tv_sec = msec / 1000;
  tv.tv_usec = (msec % 1000) * 1000;
  FD_ZERO(&fds);
  FD_SET(cur_client()->pfd, &fds);

  select(fd+1, &fds, 0, 0, &tv);

  rc=0;
  if (FD_ISSET(cur_client()->pfd, &fds))
    if (!(rc=read(fd, buf, l)))
      rc=-1;

  return(rc);
}*/

ECM_REQUEST *get_ecmtask()
{
	int i, n;
	ECM_REQUEST *er=0;
	struct s_client *cl = cur_client();
	if(!cl) return NULL;
	if (!cl->ecmtask)
	{
		n=(ph[cl->ctyp].multi)?CS_MAXPENDING:1;
		if( (cl->ecmtask=(ECM_REQUEST *)malloc(n*sizeof(ECM_REQUEST))) )
			memset(cl->ecmtask, 0, n*sizeof(ECM_REQUEST));
	}

	n=(-1);
	if (!cl->ecmtask)
	{
		cs_log("Cannot allocate memory (errno=%d %s)", errno, strerror(errno));
		n=(-2);
	}
	else
		if (ph[cl->ctyp].multi)
		{
			for (i=0; (n<0) && (i<CS_MAXPENDING); i++)
				if (cl->ecmtask[i].rc<E_99)
					er=&cl->ecmtask[n=i];
		}
		else
			er=&cl->ecmtask[n=0];

	if (n<0)
		cs_log("WARNING: ecm pending table overflow !");
	else
	{

                LLIST *save = er->matching_rdr;
		memset(er, 0, sizeof(ECM_REQUEST));
		er->rc=E_UNHANDLED;
		er->cpti=n;
		er->client=cl;
		cs_ftime(&er->tps);

		if (cl->typ=='c') { //for clients only! Not for readers!
  		  if (save) {
		    ll_clear(save);
		    er->matching_rdr = save;
                  }
                  else
                    er->matching_rdr = ll_create();

                    //cs_log("client %s ECMTASK %d multi %d ctyp %d", username(cl), n, (ph[cl->ctyp].multi)?CS_MAXPENDING:1, cl->ctyp);
                }
	}


	return(er);
}

static void send_reader_stat(struct s_reader *rdr, ECM_REQUEST *er, int rc)
{
	if (rc>=E_99)
		return;
	struct timeb tpe;
	cs_ftime(&tpe);
	int time = 1000*(tpe.time-er->tps.time)+tpe.millitm-er->tps.millitm;
	if (time < 1)
	        time = 1;

	add_stat(rdr, er, time, rc);
}

int send_dcw(struct s_client * client, ECM_REQUEST *er)
{
	static const char *stxt[]={"found", "cache1", "cache2", "emu",
			"not found", "timeout", "sleeping",
			"fake", "invalid", "corrupt", "no card", "expdate", "disabled", "stopped"};
	static const char *stxtEx[]={"", "group", "caid", "ident", "class", "chid", "queue", "peer"};
	static const char *stxtWh[]={"", "user ", "reader ", "server ", "lserver "};
	char sby[32]="", sreason[32]="", schaninfo[32]="";
	char erEx[32]="";
	char uname[38]="";
	struct timeb tpe;
	ushort lc, *lp;
	for (lp=(ushort *)er->ecm+(er->l>>2), lc=0; lp>=(ushort *)er->ecm; lp--)
		lc^=*lp;

		snprintf(uname,sizeof(uname)-1, "%s", username(client));
	if (er->rc==E_FOUND)
	{
			// add marker to reader if ECM_REQUEST was betatunneled
			if(er->btun)
				snprintf(sby, sizeof(sby)-1, " by %s(btun)", er->selected_reader->label);
			else
				snprintf(sby, sizeof(sby)-1, " by %s", er->selected_reader->label);
	}
	else {
			struct s_reader *err_reader = er->selected_reader;
			if (!err_reader) err_reader = ll_has_elements(er->matching_rdr);
			if (err_reader)
					snprintf(sby, sizeof(sby)-1, " by %s", err_reader->label);
	}
	if (er->rc < E_NOTFOUND) er->rcEx=0;
	if (er->rcEx)
		snprintf(erEx, sizeof(erEx)-1, "rejected %s%s", stxtWh[er->rcEx>>4],
				stxtEx[er->rcEx&0xf]);



	if(cfg.mon_appendchaninfo)
		snprintf(schaninfo, sizeof(schaninfo)-1, " - %s", get_servicename(er->srvid, er->caid));

	if(er->msglog[0])
		snprintf(sreason, sizeof(sreason)-1, " (%s)", er->msglog);

	cs_ftime(&tpe);
	client->cwlastresptime = 1000 * (tpe.time-er->tps.time) + tpe.millitm-er->tps.millitm;
	cs_add_lastresponsetime(client, client->cwlastresptime); // add to ringbuffer

	if (er->selected_reader && er->selected_reader->client){
	  er->selected_reader->client->cwlastresptime = client->cwlastresptime;
	  cs_add_lastresponsetime(er->selected_reader->client, client->cwlastresptime);
	}

#ifdef CS_LED
	if(!er->rc) cs_switch_led(LED2, LED_BLINK_OFF);
#endif

	send_reader_stat(er->selected_reader, er, er->rc);

#ifdef WEBIF
	if(er->rc == E_FOUND)
		snprintf(client->lastreader, sizeof(client->lastreader)-1, "%s", er->selected_reader->label);
	else if ((er->rc == E_CACHE1) || (er->rc == E_CACHE2))
		snprintf(client->lastreader, sizeof(client->lastreader)-1, "%s (cache)", er->selected_reader->label);
	else
		snprintf(client->lastreader, sizeof(client->lastreader)-1, "%s", stxt[er->rc]);
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
	ac_chk(er, 1);
#endif

	int is_fake = 0;
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

	  store_cw_in_cache(er, er->selected_reader->grp, E_FOUND); //Store in cache!

	}
#endif

	ph[client->ctyp].send_dcw(client, er);

	if (is_fake)
		er->rc = E_FAKE;

	cs_log("%s (%04X&%06X/%04X/%02X:%04X): %s (%d ms)%s (of %d avail %d)%s%s",
			uname, er->caid, er->prid, er->srvid, er->l, lc,
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

void chk_dcw(struct s_client *cl, ECM_REQUEST *er)
{
  if (!cl || !cl->ecmtask)
  	return;

  ECM_REQUEST *ert;

  //cs_log("dcw check from reader %s for idx %d (rc=%d)", er->selected_reader->label, er->cpti, er->rc);
  ert=&cl->ecmtask[er->cpti];
  if (ert->rc<E_99) {
	//cs_debug_mask(D_TRACE, "chk_dcw: already done rc=%d %s", er->rc, er->selected_reader->label);
	send_reader_stat(er->selected_reader, er, (er->rc <= E_RDR_NOTFOUND)?E_NOTFOUND:E_FOUND);
	return; // already done
  }
  if( (er->caid!=ert->caid && er->ocaid!=ert->ocaid) || memcmp(er->ecmd5, ert->ecmd5, sizeof(er->ecmd5)) ) {
    //cs_debug_mask(D_TRACE, "OBSOLETE? %04X / %04X", er->caid, ert->caid);
    return; // obsolete
  }

	ert->selected_reader=er->selected_reader;

	if (er->rc>=E_RDR_FOUND)
	{
		if (er->rc == E_CACHE2 || er->rc == E_EMU)
				ert->rc=er->rc;
		else
				ert->rc=E_FOUND;

		ert->rcEx=0;
		memcpy(ert->cw , er->cw , sizeof(er->cw));
  } else { // not found (from ONE of the readers !) er->rc==E_RDR_NOTFOUND
		ert->rcEx=er->rcEx;
		cs_strncpy(ert->msglog, er->msglog, sizeof(ert->msglog));

		ll_remove(ert->matching_rdr, er->selected_reader);

		if (ll_has_elements(ert->matching_rdr)) {//we have still another chance
				ert->selected_reader=NULL;
				ert=NULL;
		}
		//at this point ert is only not NULL when it has no matching readers...
		if (ert) {
				ert->rc=E_NOTFOUND; //so we set the return code
				store_cw_in_cache(ert, er->selected_reader->grp, E_NOTFOUND);
		}
		else send_reader_stat(er->selected_reader, er, E_NOTFOUND);
	}
	if (ert) {
		send_dcw(cl, ert);

		distribute_ecm(er, ert->selected_reader->grp);
    }
	return;
}

ulong chk_provid(uchar *ecm, ushort caid) {
	int i, len, descriptor_length = 0;
	ulong provid = 0;

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
					provid = (ulong)ecm[i+2] & 0xFE;
					break;
				}
			}
			break;
	}
	return(provid);
}

#ifdef IRDETO_GUESSING
void guess_irdeto(ECM_REQUEST *er)
{
  uchar  b3;
  int    b47;
  //ushort chid;
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
      er->chid=(ushort)ptr->b47;
//      cs_debug_mask(D_TRACE, "quess_irdeto() found caid=%04X, sid=%04X, chid=%04X",
//               er->caid, er->srvid, er->chid);
      return;
    }
    ptr=ptr->next;
  }
}
#endif

void cs_betatunnel(ECM_REQUEST *er)
{
	int n;
	struct s_client *cl = cur_client();
	ulong mask_all = 0xFFFF;
	uchar headerN3[10] = {0xc7, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x87, 0x12};
	uchar headerN2[10] = {0xc9, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x48, 0x12};
	TUNTAB *ttab;
	ttab = &cl->ttab;

	for (n = 0; (n < CS_MAXTUNTAB); n++) {
		if ((er->caid==ttab->bt_caidfrom[n]) && ((er->srvid==ttab->bt_srvid[n]) || (ttab->bt_srvid[n])==mask_all)) {

			er->caid = ttab->bt_caidto[n];
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
				ttab->bt_caidfrom[n], ttab->bt_caidto[n], ttab->bt_srvid[n]);
		}
	}
}

static void guess_cardsystem(ECM_REQUEST *er)
{
  ushort last_hope=0;

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
 * int flag : 0=primary readers (no fallback)
 *            1=all readers (primary+fallback)
 * int reader_types : 0=all readsers
 *                    1=Hardware/local readers
 *                    2=Proxy/network readers
 **/
void request_cw(ECM_REQUEST *er, int flag, int reader_types)
{
	if ((reader_types == 0) || (reader_types == 2))
		er->level=flag;
	struct s_reader *rdr;

	ushort lc=0, *lp;
	if (cs_dblevel) {
		for (lp=(ushort *)er->ecm+(er->l>>2), lc=0; lp>=(ushort *)er->ecm; lp--)
			lc^=*lp;
	}

	LL_NODE *ptr;
	for (ptr = er->matching_rdr->initial; ptr; ptr = ptr->nxt) {
	        if (!flag && ptr == er->fallback)
	          break;

		rdr = (struct s_reader*)ptr->obj;

		int status = 0;
		//reader_types:
		//0 = network and local cards
		//1 = only local cards
		//2 = only network
		if ((reader_types == 0) || ((reader_types == 1) && (!(rdr->typ & R_IS_NETWORK))) || ((reader_types == 2) && (rdr->typ & R_IS_NETWORK))) {
			cs_debug_mask(D_TRACE, "request_cw%i to reader %s fd=%d ecm=%04X", reader_types+1, rdr->label, rdr->fd, lc);
			status = write_ecm_request(rdr->fd, er);
		}
		if (status == -1) {
			cs_log("request_cw() failed on reader %s errno=%d, %s", rdr->label, errno, strerror(errno));
			if (rdr->fd) {
				rdr->fd_error++;
				if (rdr->fd_error > 5) {
					rdr->fd_error = 0;
					cs_log("Restarting reader %s", rdr->label);
					restart_cardreader(rdr, 1); //Schlocke: This restarts the reader!
				}
			}
		}
		else
			rdr->fd_error = 0;
  }
}

void get_cw(struct s_client * client, ECM_REQUEST *er)
{
	int i, j, m;
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

	/* END quickfixes */

	if (!er->prid)
		er->prid = chk_provid(er->ecm, er->caid);

	// Set providerid for newcamd clients if none is given
	if( (!er->prid) && client->ncd_server ) {
		int pi = client->port_idx;
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
		int curtime = (acttm.tm_hour * 60) + acttm.tm_min;
		int mintime = client->allowedtimeframe[0];
		int maxtime = client->allowedtimeframe[1];
		if(!((mintime <= maxtime && curtime > mintime && curtime < maxtime) || (mintime > maxtime && (curtime > mintime || curtime < maxtime)))) {
			er->rc = E_EXPDATE;
		}
		cs_debug_mask(D_TRACE, "Check Timeframe - result: %d, start: %d, current: %d, end: %d\n",er->rc, mintime, curtime, maxtime);
	}

	// user disabled
	if(client->disabled != 0) {
		if (client->failban & BAN_DISABLED){
			cs_add_violation(client->ip);
			cs_exit(SIGQUIT); // don't know whether this is best way to kill the thread
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
				cs_add_violation(client->ip);
				cs_exit(SIGQUIT); // todo don't know whether this is best way to kill the thread
			}

			if (client->c35_sleepsend != 0) {
				er->rc = E_STOPPED; // send stop command CMD08 {00 xx}
			} else {
				er->rc = E_SLEEPING;
			}
		}

		client->last_srvid = i;
		client->last_caid = m;

		int ecm_len = (((er->ecm[1] & 0x0F) << 8) | er->ecm[2]) + 3;

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

    //Use locking - now default=FALSE, activate on problems!
	int locked;
	if (cfg.lb_mode && cfg.lb_use_locking) {
			pthread_mutex_lock(&get_cw_lock);
			locked=1;
	}
	else
			locked=0;


	//Schlocke: above checks could change er->rc so
	if (er->rc >= E_UNHANDLED) {
		/*BetaCrypt tunneling
		 *moved behind the check routines,
		 *because newcamd ECM will fail
		 *if ECM is converted before
		 */
		if (&client->ttab)
			cs_betatunnel(er);

		// ignore ecm ...
		int offset = 3;
		// ... and betacrypt header for cache md5 calculation
		if ((er->caid >> 8) == 0x17)
			offset = 13;

		// store ECM in cache
		memcpy(er->ecmd5, MD5(er->ecm+offset, er->l-offset, client->dump), CS_ECMSTORESIZE);

		// cache1
		//cache check now done by check_and_store_ecmcache() !!
		//if (check_cwcache1(er, client->grp))
		//		er->rc = E_CACHE1;

#ifdef CS_ANTICASC
		ac_chk(er, 0);
#endif
	}

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
				}
				if (cfg.lb_mode || !rdr->fallback)
					er->reader_avail++;
			}
		}

		if (cfg.lb_mode && er->reader_avail) {
			cs_debug_mask(D_TRACE, "requesting client %s best reader for %04X/%06X/%04X",
				username(client), er->caid, er->prid, er->srvid);
			get_best_reader(er);
		}

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
			}

		//we have to go through matching_reader() to check services!
		if (er->rc == E_UNHANDLED)
				er->rc = check_and_store_ecmcache(er, client->grp);
	}

	if (locked)
		pthread_mutex_unlock(&get_cw_lock);

	if (er->rc == E_99)
			return; //ECM already requested / found in ECM cache

	if (er->rc < E_UNHANDLED) {
		if (cfg.delay)
			cs_sleepms(cfg.delay);

		send_dcw(client, er);
		return;
	}

	er->rcEx = 0;
	request_cw(er, 0, cfg.preferlocalcards ? 1 : 0);
}

void log_emm_request(struct s_reader *rdr)
{
	cs_log("%s emm-request sent (reader=%s, caid=%04X, auprovid=%06lX)",
			username(cur_client()), rdr->label, rdr->caid,
			rdr->auprovid ? rdr->auprovid : b2i(4, rdr->prid[0]));
}

void do_emm(struct s_client * client, EMM_PACKET *ep)
{
	char *typtext[]={"unknown", "unique", "shared", "global"};

	struct s_reader *aureader = NULL;
	cs_ddump_mask(D_EMM, ep->emm, ep->l, "emm:");

	LL_ITER *itr = ll_iter_create(client->aureader_list);
	while ((aureader = ll_iter_next(itr))) {
		if (!aureader->enable)
			continue;

		ushort caid = b2i(2, ep->caid);
		ulong provid = b2i(4, ep->provid);

		if (aureader->audisabled) {
			cs_debug_mask(D_EMM, "AU is disabled for reader %s", aureader->label);
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

		cs_debug_mask(D_EMM, "emmtype %s. Reader %s has serial %s.", typtext[ep->type], aureader->label, cs_hexdump(0, aureader->hexserial, 8));
		cs_ddump_mask(D_EMM, ep->hexserial, 8, "emm UA/SA:");

		client->last=time((time_t)0);
		if (aureader->b_nano[ep->emm[0]] & 0x02) { //should this nano be saved?
			char token[256];
			FILE *fp;
			time_t rawtime;
			time (&rawtime);
			struct tm timeinfo;
			localtime_r (&rawtime, &timeinfo);	/* to access LOCAL date/time info */
			char buf[80];
			strftime (buf, 80, "%Y/%m/%d %H:%M:%S", &timeinfo);
			snprintf (token, sizeof(token), "%s%s_emm.log", cs_confdir, aureader->label);
			int emm_length = ((ep->emm[1] & 0x0f) << 8) | ep->emm[2];

			if (!(fp = fopen (token, "a"))) {
				cs_log ("ERROR: Cannot open file '%s' (errno=%d: %s)\n", token, errno, strerror(errno));
			} else {
				fprintf (fp, "%s   %s   ", buf, cs_hexdump(0, ep->hexserial, 8));
				fprintf (fp, "%s\n", cs_hexdump(0, ep->emm, emm_length + 3));
				fclose (fp);
				cs_log ("Succesfully added EMM to %s.", token);
			}

			snprintf (token, sizeof(token), "%s%s_emm.bin", cs_confdir, aureader->label);
			if (!(fp = fopen (token, "ab"))) {
				cs_log ("ERROR: Cannot open file '%s' (errno=%d: %s)\n", token, errno, strerror(errno));
			} else {
				if ((int)fwrite(ep->emm, 1, emm_length+3, fp) == emm_length+3)	{
					cs_log ("Succesfully added binary EMM to %s.", token);
				} else {
					cs_log ("ERROR: Cannot write binary EMM to %s (errno=%d: %s)\n", token, errno, strerror(errno));
				}
				fclose (fp);
			}
		}

		int is_blocked = 0;
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
		write_to_pipe(aureader->fd, PIP_ID_EMM, (uchar *) ep, sizeof(EMM_PACKET));
	}
	ll_iter_release(itr);
}

int comp_timeb(struct timeb *tpa, struct timeb *tpb)
{
  if (tpa->time>tpb->time) return(1);
  if (tpa->time<tpb->time) return(-1);
  if (tpa->millitm>tpb->millitm) return(1);
  if (tpa->millitm<tpb->millitm) return(-1);
  return(0);
}

struct timeval *chk_pending(struct timeb tp_ctimeout)
{
	int i;
	ulong td;
	struct timeb tpn, tpe, tpc; // <n>ow, <e>nd, <c>heck

	ECM_REQUEST *er;
	cs_ftime(&tpn);
	tpe=tp_ctimeout;    // latest delay -> disconnect

	struct s_client *cl = cur_client();

	if (cl->ecmtask)
		i=(ph[cl->ctyp].multi)?CS_MAXPENDING:1;
	else
		i=0;

	//cs_log("num pend=%d", i);

	for (--i; i>=0; i--) {

		if (cl->ecmtask[i].rc>=E_99) { // check all pending ecm-requests
			int act=1;
			er=&cl->ecmtask[i];

			//additional cache check:
			if (check_cwcache2(er, cl->grp)) {
					//cs_log("found lost entry in cache! %s %04X&%06X/%04X", username(cl), er->caid, er->prid, er->srvid);
					er->rc = E_CACHE2;
					send_dcw(cl, er);
					continue;
			}


			tpc=er->tps;
			unsigned int tt;
			tt = (er->stage) ? cfg.ctimeout : cfg.ftimeout;
			tpc.time +=tt / 1000;
			tpc.millitm += tt % 1000;
			if (!er->stage && er->rc >= E_UNHANDLED) {

				LL_NODE *ptr;
				for (ptr = er->matching_rdr->initial; ptr && ptr != er->fallback; ptr = ptr->nxt)
					if (!cfg.preferlocalcards ||
								(cfg.preferlocalcards && !er->locals_done && (!(((struct s_reader*)ptr->obj)->typ & R_IS_NETWORK))) ||
								(cfg.preferlocalcards && er->locals_done && (((struct s_reader*)ptr->obj)->typ & R_IS_NETWORK)))
								act=0;

				//cs_log("stage 0, act=%d r0=%d, r1=%d, r2=%d, r3=%d, r4=%d r5=%d", act,
				//    er->matching_rdr[0], er->matching_rdr[1], er->matching_rdr[2],
				//    er->matching_rdr[3], er->matching_rdr[4], er->matching_rdr[5]);

				if (act) {
					int inc_stage = 1;
					if (cfg.preferlocalcards && !er->locals_done) {
						er->locals_done = 1;
						struct s_reader *rdr;
						for (rdr=first_active_reader; rdr ; rdr=rdr->next)
							if (rdr->typ & R_IS_NETWORK)
								inc_stage = 0;
					}
					unsigned int tt;
					if (!inc_stage) {
						request_cw(er, er->stage, 2);
						tt = 1000 * (tpn.time - er->tps.time) + tpn.millitm - er->tps.millitm;
					} else {
						er->locals_done = 0;
						er->stage++;
						request_cw(er, er->stage, cfg.preferlocalcards ? 1 : 0);

						tt = (cfg.ctimeout-cfg.ftimeout);
					}
					tpc.time += tt / 1000;
					tpc.millitm += tt % 1000;
				}
			}
			if (comp_timeb(&tpn, &tpc)>0) { // action needed
				//cs_log("Action now %d.%03d", tpn.time, tpn.millitm);
				//cs_log("           %d.%03d", tpc.time, tpc.millitm);
				if (er->stage) {
					er->rc = E_TIMEOUT;
					if (cfg.lb_mode) {
						LL_NODE *ptr;
						for (ptr = er->matching_rdr->initial; ptr ; ptr = ptr->nxt)
							send_reader_stat((struct s_reader *)ptr->obj, er, E_TIMEOUT);
					}
					store_cw_in_cache(er, cl->grp, E_TIMEOUT);
					send_dcw(cl, er);
					continue;
				} else {
					er->stage++;
					cs_debug_mask(D_TRACE, "fallback for %s %04X&%06X/%04X", username(cl), er->caid, er->prid, er->srvid);
					if (er->rc >= E_UNHANDLED) //do not request rc=99
					        request_cw(er, er->stage, 0);
					unsigned int tt;
					tt = (cfg.ctimeout-cfg.ftimeout);
					tpc.time += tt / 1000;
					tpc.millitm += tt % 1000;
				}
			}

			//build_delay(&tpe, &tpc);
			if (comp_timeb(&tpe, &tpc)>0) {
				tpe.time=tpc.time;
				tpe.millitm=tpc.millitm;
			}
		}
	}

	td=(tpe.time-tpn.time)*1000+(tpe.millitm-tpn.millitm)+5;
	cl->tv.tv_sec = td/1000;
	cl->tv.tv_usec = (td%1000)*1000;
	//cs_log("delay %d.%06d", tv.tv_sec, tv.tv_usec);

	return(&cl->tv);
}

int process_input(uchar *buf, int l, int timeout)
{
	int rc;
	fd_set fds;
	struct timeb tp;

	struct s_client *cl = cur_client();

	cs_ftime(&tp);
	tp.time+=timeout;

	while (1) {
		FD_ZERO(&fds);

		if (cl->pfd)
			FD_SET(cl->pfd, &fds);

		FD_SET(cl->fd_m2c_c, &fds);

		rc=select(((cl->pfd > cl->fd_m2c_c) ? cl->pfd : cl->fd_m2c_c)+1, &fds, 0, 0, chk_pending(tp));
		if (rc<0) {
			if (errno==EINTR) continue;
			else return(0);
		}

		if (FD_ISSET(cl->fd_m2c_c, &fds)) { // read from pipe
			if (process_client_pipe(cl, buf, l)==PIP_ID_UDP) {
				rc=ph[cl->ctyp].recv(cl, buf, l);
				break;
			}
		}

		if (cl->pfd && FD_ISSET(cl->pfd, &fds)) { // read from client
			rc=ph[cl->ctyp].recv(cl, buf, l);
			break;
		}

		if (tp.time<=time((time_t *)0)) { // client maxidle reached
			rc=(-9);
			break;
		}
	}
	return(rc);
}

static void restart_clients()
{
	cs_log("restarting clients");
	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		if (cl->typ=='c' && ph[cl->ctyp].type & MOD_CONN_NET) {
			kill_thread(cl);
			cs_log("killing client c %8X", (unsigned long)(cl->thread));
		}
}


static void process_master_pipe(int mfdr)
{
  int n;
  uchar *ptr;

  switch(n=read_from_pipe(mfdr, &ptr, 1))
  {
    case PIP_ID_KCL: //Kill all clients
    	restart_clients();
    	break;
    case PIP_ID_ERR:
        cs_exit(1); //better than reading from dead pipe!
        break;
    default:
       cs_log("unhandled pipe message %d (master pipe)", n);
       break;
  }
  if (ptr) free(ptr);
}


int process_client_pipe(struct s_client *cl, uchar *buf, int l) {
	uchar *ptr;
	unsigned short n;
	int pipeCmd = read_from_pipe(cl->fd_m2c_c, &ptr, 0);

	switch(pipeCmd) {
		case PIP_ID_ECM:
			chk_dcw(cl, (ECM_REQUEST *)ptr);
			break;
		case PIP_ID_UDP:
			if (ptr[0]!='U') {
				cs_log("INTERNAL PIPE-ERROR");
			}
			memcpy(&n, ptr+1, 2);
			if (n+3<=l) {
				memcpy(buf, ptr, n+3);
			}
			break;
		case PIP_ID_ERR:
			cs_exit(1);
			break;
		default:
			cs_log("unhandled pipe message %d (client %s)", pipeCmd, cl->account->usr);
			break;
	}
	if (ptr) free(ptr);
	return pipeCmd;
}

void cs_log_config()
{
  uchar buf[20];

  if (cfg.nice!=99)
    snprintf((char *)buf, sizeof(buf), ", nice=%d", cfg.nice);
  else
    buf[0]='\0';
  cs_log("version=%s, build #%s, system=%s-%s-%s%s", CS_VERSION_X, CS_SVN_VERSION, CS_OS_CPU, CS_OS_HW, CS_OS_SYS, buf);
  cs_log("client max. idle=%d sec, debug level=%d", cfg.cmaxidle, cs_dblevel);

  if( cfg.max_log_size )
    snprintf((char *)buf, sizeof(buf), "%d Kb", cfg.max_log_size);
  else
    cs_strncpy((char *)buf, "unlimited", sizeof(buf));
  cs_log("max. logsize=%s", buf);
  cs_log("client timeout=%lu ms, fallback timeout=%lu ms, cache delay=%d ms",
         cfg.ctimeout, cfg.ftimeout, cfg.delay);
}

void cs_waitforcardinit()
{
	if (cfg.waitforcards)
	{
		cs_log("waiting for local card init");
		int card_init_done;
		do {
			card_init_done = 1;
			struct s_reader *rdr;
			for (rdr=first_active_reader; rdr ; rdr=rdr->next)
				if (((rdr->typ & R_IS_CASCADING) == 0) && (rdr->card_status == CARD_NEED_INIT || rdr->card_status == UNKNOWN)) {
					card_init_done = 0;
					break;
				}
			if (!card_init_done)
				cs_sleepms(300); // wait a little bit
			//alarm(cfg.cmaxidle + cfg.ctimeout / 1000 + 1);
		} while (!card_init_done);
		cs_log("init for all local cards done");
	}
}

int accept_connection(int i, int j) {
	struct   sockaddr_in cad;
	int scad,n;
	scad = sizeof(cad);
	uchar    buf[2048];

	if (ph[i].type==MOD_CONN_UDP) {

		if ((n=recvfrom(ph[i].ptab->ports[j].fd, buf+3, sizeof(buf)-3, 0, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {
			struct s_client *cl;
			cl=idx_from_ip(cad.sin_addr.s_addr, ntohs(cad.sin_port));

			unsigned short rl;
			rl=n;
			buf[0]='U';
			memcpy(buf+1, &rl, 2);

			if (!cl) {
				if (cs_check_violation((uint)cad.sin_addr.s_addr))
					return 0;
				//printf("IP: %s - %d\n", inet_ntoa(*(struct in_addr *)&cad.sin_addr.s_addr), cad.sin_addr.s_addr);

				cl = create_client(cad.sin_addr.s_addr);
				if (!cl) return 0;

				cl->ctyp=i;
				cl->port_idx=j;
				cl->udp_fd=ph[i].ptab->ports[j].fd;
				cl->udp_sa=cad;

				cl->port=ntohs(cad.sin_port);
				cl->typ='c';

				write_to_pipe(cl->fd_m2c, PIP_ID_UDP, (uchar*)&buf, n+3);

				pthread_attr_t attr;
				pthread_attr_init(&attr);
#ifndef TUXBOX
				pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
				//We need memory here, because when on stack and we leave the function, stack is overwritten, 
				//but assigned to the thread
				//So alloc memory for the init data and free them in clientthread_init:
				struct s_clientinit *init = cs_malloc(&init, sizeof(struct s_clientinit), 0); 
				init->handler = ph[i].s_handler;
				init->client = cl;
				if (pthread_create(&cl->thread, &attr, clientthread_init, (void*) init)) {
					cs_log("ERROR: can't create thread for UDP client from %s", inet_ntoa(*(struct in_addr *)&cad.sin_addr.s_addr));
					cleanup_thread(cl);
					free(init);
				}
				else
					pthread_detach(cl->thread);
				pthread_attr_destroy(&attr);
			} else {
				write_to_pipe(cl->fd_m2c, PIP_ID_UDP, (uchar*)&buf, n+3);
			}
		}
	} else { //TCP

		int pfd3;
		if ((pfd3=accept(ph[i].ptab->ports[j].fd, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {

			if (cs_check_violation((uint)cad.sin_addr.s_addr)) {
				close(pfd3);
				return 0;
			}

			struct s_client * cl = create_client(cad.sin_addr.s_addr);
			if (cl == NULL) {
				close(pfd3);
				return 0;
			}

			int flag = 1;
			setsockopt(pfd3, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

			cl->ctyp=i;
			cl->udp_fd=pfd3;
			cl->port_idx=j;

			cl->pfd=pfd3;
			cl->port=ntohs(cad.sin_port);
			cl->typ='c';

			pthread_attr_t attr;
			pthread_attr_init(&attr);
#ifndef TUXBOX
			pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif

			//We need memory here, because when on stack and we leave the function, stack is overwritten, 
			//but assigned to the thread
			//So alloc memory for the init data and free them in clientthread_init:
			struct s_clientinit *init = cs_malloc(&init, sizeof(struct s_clientinit), 0);
			init->handler = ph[i].s_handler;
			init->client = cl;			
			if (pthread_create(&cl->thread, &attr, clientthread_init, (void*) init)) {
				cs_log("ERROR: can't create thread for TCP client from %s", inet_ntoa(*(struct in_addr *)&cad.sin_addr.s_addr));
				cleanup_thread(cl);
				free(init);
			}
			else
				pthread_detach(cl->thread);
			pthread_attr_destroy(&attr);
		}
	}
	return 0;
}

/**
 * get tmp dir
  **/
char * get_tmp_dir()
{
  if (cs_tmpdir[0])
    return cs_tmpdir;

#ifdef OS_CYGWIN32
  char *d = getenv("TMPDIR");
  if (!d || !d[0])
    d = getenv("TMP");
  if (!d || !d[0])
    d = getenv("TEMP");
  if (!d || !d[0])
    getcwd(cs_tmpdir, sizeof(cs_tmpdir)-1);

  cs_strncpy(cs_tmpdir, d, sizeof(cs_tmpdir));
  char *p = cs_tmpdir;
  while(*p) p++;
  p--;
  if (*p != '/' && *p != '\\')
    strcat(cs_tmpdir, "/");
  strcat(cs_tmpdir, "_oscam");
#else
  cs_strncpy(cs_tmpdir, "/tmp/.oscam", sizeof(cs_tmpdir));
#endif
  mkdir(cs_tmpdir, S_IRWXU);
  return cs_tmpdir;
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
    int res=0;
    int status=0;
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

int main (int argc, char *argv[])
{

/* init random number generator with seed. */
srand((unsigned int)time((time_t *)NULL));

if (pthread_key_create(&getclient, NULL)) {
  fprintf(stderr, "Could not create getclient, exiting...");
  exit(1);
}
#ifdef CS_LED
  cs_switch_led(LED1A, LED_DEFAULT);
  cs_switch_led(LED1A, LED_ON);
#endif

  //struct   sockaddr_in cad;     /* structure to hold client's address */
  //int      scad;                /* length of address */
  //int      fd;                  /* socket descriptors */
  int      i, j;
  int      bg=0;
  int      gbdb=0;
  int      gfd; //nph,
  int      fdp[2];
  int      mfdr=0;     // Master FD (read)
  int      fd_c2m=0;

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

  while ((i=getopt(argc, argv, "gbc:t:d:r:hm:x"))!=EOF)
  {
	  switch(i) {
	  	  case 'g':
		      gbdb=1;
		      break;
		  case 'b':
			  bg=1;
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
  init_stat();

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

  memset(&cardreader, 0, sizeof(struct s_cardsystem) * CS_MAX_MOD);
  for (i=0; cardreader_def[i]; i++)  // must be later BEFORE init_config()
  {
    cardreader_def[i](&cardreader[i]);
  }


  cs_log("auth size=%d", sizeof(struct s_auth));

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


  if (pipe(fdp))
  {
    cs_log("Cannot create pipe (errno=%d: %s)", errno, strerror(errno));
    cs_exit(1);
  }
  mfdr=fdp[0];
  fd_c2m=fdp[1];
  gfd=mfdr+1;

  first_client->fd_m2c=fd_c2m;
  first_client->fd_m2c_c=mfdr;

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
        if( ph[i].ptab->ports[j].fd+1>gfd )
          gfd=ph[i].ptab->ports[j].fd+1;
      }

	//set time for server to now to avoid 0 in monitor/webif
	first_client->last=time((time_t *)0);

#ifdef WEBIF
  if(cfg.http_port == 0)
    cs_log("http disabled");
  else
    start_thread((void *) &http_srv, "http");
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
		start_thread((void *) &start_anticascader, "anticascader"); // 96

	}
#endif

	for (i=0; i<CS_MAX_MOD; i++)
		if (ph[i].type & MOD_CONN_SERIAL)   // for now: oscam_ser only
			if (ph[i].s_handler)
				ph[i].s_handler(i);

	//cs_close_log();
	while (!exit_oscam) {
		fd_set fds;

		do {
		        //timeout value for checking exit_oscam:
                        struct timeval timeout;
                        timeout.tv_sec = 1;
                        timeout.tv_usec = 0;

                        //Wait for incoming data
			FD_ZERO(&fds);
			FD_SET(mfdr, &fds);
			for (i=0; i<CS_MAX_MOD; i++)
				if ( (ph[i].type & MOD_CONN_NET) && ph[i].ptab )
					for (j=0; j<ph[i].ptab->nports; j++)
						if (ph[i].ptab->ports[j].fd)
							FD_SET(ph[i].ptab->ports[j].fd, &fds);
			errno=0;
			select(gfd, &fds, 0, 0, &timeout);
		} while (errno==EINTR && !exit_oscam); //if timeout accurs and exit_oscam is set, we break the loop

		if (exit_oscam)
		        break;

		first_client->last=time((time_t *)0);

		if (FD_ISSET(mfdr, &fds)) {
			process_master_pipe(mfdr);
		}
		for (i=0; i<CS_MAX_MOD; i++) {
			if( (ph[i].type & MOD_CONN_NET) && ph[i].ptab ) {
				for( j=0; j<ph[i].ptab->nports; j++ ) {
					if( ph[i].ptab->ports[j].fd && FD_ISSET(ph[i].ptab->ports[j].fd, &fds) ) {
						accept_connection(i,j);
					}
				}
			} // if (ph[i].type & MOD_CONN_NET)
		}
	}

#if defined(AZBOX) && defined(HAVE_DVBAPI)
  if (openxcas_close() < 0) {
    cs_log("openxcas: could not close");
  }
#endif

		cs_cleanup();

        stop_garbage_collector();

	return exit_oscam;
}

#ifdef WEBIF
void cs_exit_oscam()
{
  exit_oscam=1;
  cs_log("exit oscam requested");
}

void cs_restart_oscam()
{
  exit_oscam=99;
  cs_log("restart oscam requested");
}

int cs_get_restartmode() {
	return cs_restart_mode;
}

#endif

#ifdef CS_LED
void cs_switch_led(int led, int action) {

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
void qboxhd_led_blink(int color, int duration) {
    int f;

    if (cfg.disableqboxhdled) {
        return;
    }

    // try QboxHD-MINI first
    if ( (f = open ( QBOXHDMINI_LED_DEVICE,  O_RDWR |O_NONBLOCK )) > -1 ) {
        qboxhdmini_led_color_struct qbminiled;
        ulong qboxhdmini_color = 0x000000;

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
