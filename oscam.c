//FIXME Not checked on threadsafety yet; after checking please remove this line
#define CS_CORE
#include "globals.h"
#ifdef AZBOX
#  include "openxcas/openxcas_api.h"
#endif
#ifdef CS_WITH_GBOX
#  include "csgbox/gbox.h"
#  define CS_VERSION_X  CS_VERSION "-gbx-" GBXVERSION
#else
#  define CS_VERSION_X  CS_VERSION
#endif
/*****************************************************************************
        Globals
*****************************************************************************/
struct s_module ph[CS_MAX_MOD]; // Protocols
struct s_cardsystem cardsystem[CS_MAX_MOD]; // Protocols

int mfdr=0;     // Master FD (read)
int fd_c2m=0;

ushort  len4caid[256];    // table for guessing caid (by len)
char  cs_confdir[128]=CS_CONFDIR;
int cs_dblevel=0;   // Debug Level (TODO !!)
char  cs_tmpdir[200]={0x00};
pthread_mutex_t gethostbyname_lock;

#ifdef CS_ANTICASC
struct s_acasc ac_stat[CS_MAXPID];
#endif

/*****************************************************************************
        Shared Memory
*****************************************************************************/
int     *ecmidx;  // Shared Memory
int     *logidx;  // Shared Memory
int     *oscam_sem; // sem (multicam.o)
int     *c_start; // idx of 1st client
struct  s_ecm     *ecmcache;  // Shared Memory
struct  s_client  *client;    // Shared Memory
struct  s_reader  *reader;    // Shared Memory

#ifdef CS_WITH_GBOX
struct  card_struct *Cards;   // Shared Memory
struct  idstore_struct  *idstore;   // Shared Memory
unsigned long *IgnoreList;    // Shared Memory
#endif

struct  s_config  *cfg;       // Shared Memory
#ifdef CS_ANTICASC
struct  s_acasc_shm   *acasc; // anti-cascading table indexed by account.ac_idx
#endif
#ifdef CS_LOGHISTORY
int     *loghistidx;  // ptr to current entry
char    *loghist;     // ptr of log-history
#endif

static const int  shmsize =  CS_ECMCACHESIZE*(sizeof(struct s_ecm)) +
                        CS_MAXPID*(sizeof(struct s_client)) +
                        CS_MAXREADER*(sizeof(struct s_reader)) +
#ifdef CS_WITH_GBOX
                        CS_MAXCARDS*(sizeof(struct card_struct))+
                        CS_MAXIGNORE*(sizeof(long))+
                        CS_MAXPID*(sizeof(struct idstore_struct))+
#endif
#ifdef CS_ANTICASC
                        CS_MAXPID*(sizeof(struct s_acasc_shm)) +
#endif
#ifdef CS_LOGHISTORY
                        CS_MAXLOGHIST*CS_LOGHISTSIZE + sizeof(int) +
#endif
                        sizeof(struct s_config)+(6*sizeof(int));

#ifdef CS_NOSHM
char  cs_memfile[128]=CS_MMAPFILE;
#endif

int get_csidx() {
	int i;

	for (i=1; i<CS_MAXPID; i++) {
		if (pthread_equal(client[i].thread, pthread_self())) {
			return i;
		}
	}

	return 0; // main process
}

/*****************************************************************************
        Statics
*****************************************************************************/
static  int cs_last_idx=0;    // client index of last fork (master only)
static const char *logo = "  ___  ____   ___                \n / _ \\/ ___| / __|__ _ _ __ ___  \n| | | \\___ \\| |  / _` | '_ ` _ \\ \n| |_| |___) | |_| (_| | | | | | |\n \\___/|____/ \\___\\__,_|_| |_| |_|\n";

static void usage()
{
  fprintf(stderr, "%s\n\n", logo);
  fprintf(stderr, "OSCam cardserver v%s, build #%s (%s) - (w) 2009-2010 streamboard SVN\n", CS_VERSION_X, CS_SVN_VERSION, CS_OSTYPE);
  fprintf(stderr, "\tsee http://streamboard.gmc.to:8001/wiki/ for more details\n");
  fprintf(stderr, "\tbased on streamboard mp-cardserver v0.9d - (w) 2004-2007 by dukat\n");
  fprintf(stderr, "\tinbuilt modules: ");
#ifdef HAVE_DVBAPI
#ifdef WITH_STAPI
  fprintf(stderr, "dvbapi with stapi");
#else
  fprintf(stderr, "dvbapi ");
#endif
#endif
#ifdef WEBIF
  fprintf(stderr, "webinterface ");
#endif
#ifdef CS_ANTICASC
  fprintf(stderr, "anticascading ");
#endif
#ifdef LIBUSB
  fprintf(stderr, "smartreader ");
#endif
#ifdef HAVE_PCSC
  fprintf(stderr, "pcsc ");
#endif
#ifdef CS_WITH_GBOX
  fprintf(stderr, "gbox ");
#endif
#ifdef IRDETO_GUESSING
  fprintf(stderr, "irdeto-guessing ");
#endif
#ifdef CS_LED
  fprintf(stderr, "led-trigger ");
#endif
  fprintf(stderr, "\n\n");
  fprintf(stderr, "oscam [-b] [-c config-dir] [-d]");
#ifdef CS_NOSHM
  fprintf(stderr, " [-m memory-file]");
#endif
  fprintf(stderr, " [-h]");
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
  fprintf(stderr, "\t             255 = debug all\n");
#ifdef CS_NOSHM
  fprintf(stderr, "\t-m <file>  : use <file> as mmaped memory file\n");
  fprintf(stderr, "\t             default = %s\n", CS_MMAPFILE);
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
  if (!client[cs_idx].pfd) return(-9);
  if (!read(client[cs_idx].pfd, buf, 3)) cs_exit(1);
  if (buf[0]!='U')
  {
    cs_log("INTERNAL PIPE-ERROR");
    cs_exit(1);
  }
  memcpy(&n, buf+1, 2);
  return(read(client[cs_idx].pfd, buf, n));
}

char *username(int idx)
{
  if (client[idx].usr[0])
    return(client[idx].usr);
  else
    return("anonymous");
}

static int idx_from_ip(in_addr_t ip, in_port_t port)
{
  int i, idx;
  for (i=idx=0; (i<CS_MAXPID) && (!idx); i++)
    if ((client[i].ip==ip) && (client[i].port==port) &&
        ((client[i].typ=='c') || (client[i].typ=='m')))
      idx=i;
  return(idx);
}

int idx_from_pid(pid_t pid)
{
  int i, idx;
  for (i=0, idx=(-1); (i<CS_MAXPID) && (idx<0); i++)
    if (client[i].pid==pid)
      idx=i;
  return(idx);
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
void set_signal_handler(int sig, int flags, void (*sighandler)(int))
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

  cs_log("Got sigpipe signal -> captured");
}

void cs_exit(int sig)
{
	set_signal_handler(SIGCHLD, 1, SIG_IGN);
	set_signal_handler(SIGHUP , 1, SIG_IGN);

	if (sig==SIGALRM) {
		cs_debug("thread %d: SIGALRM, skipping", get_csidx());
		return;
	}

  if (sig && (sig!=SIGQUIT))
    cs_log("exit with signal %d", sig);

  switch(client[cs_idx].typ)
  {
    case 'c':
    	cs_statistics(cs_idx);
    	client[cs_idx].last_caid = 0xFFFF;
    	client[cs_idx].last_srvid = 0xFFFF;
    	cs_statistics(cs_idx);
    	break;
    case 'm': break;
    case 'n': break;
    case 'r':
        // free AES entries allocated memory
        if(reader[client[cs_idx].ridx].aes_list) {
            aes_clear_entries(&reader[client[cs_idx].ridx]);
        }
        // close the device
        reader_device_close(&reader[client[cs_idx].ridx]);
        break;
    case 'h':
    case 's':
#ifdef CS_LED
              cs_switch_led(LED1B, LED_OFF);
              cs_switch_led(LED2, LED_OFF);
              cs_switch_led(LED3, LED_OFF);
              cs_switch_led(LED1A, LED_ON);
#endif
			if (cfg->pidfile != NULL) {
				if (unlink(cfg->pidfile) < 0)
					cs_log("cannot remove pid file %s errno=(%d)", cfg->pidfile, errno);
			}
#ifndef OS_CYGWIN32
 			if (unlink("/tmp/oscam.version") < 0)
				cs_log("cannot remove /tmp/oscam.version errno=(%d)", errno);
#endif
			cs_log("cardserver down");
			break;
	}

	int i;
	for (i=1; i<CS_MAXPID; i++) {
		if (pthread_equal(client[i].thread, pthread_self())) {
			client[i].pid=0;
			if(client[i].ecmtask) 	free(client[i].ecmtask);
			if(client[i].emmcache) 	free(client[i].emmcache);
			if(client[i].req) 		free(client[i].req);
			if(client[i].prefix) 	free(client[i].prefix);
			if(client[i].cc) 		free(client[i].cc);
			cs_log("thread %d ended!", i);
			pthread_exit(NULL);
			return;
		}
	}



	for (i=0; i<CS_MAXPID; i++) {
		if(client[i].ecmtask) 	free(client[i].ecmtask);
		if(client[i].emmcache) 	free(client[i].emmcache);
		if(client[i].req) 		free(client[i].req);
		if(client[i].prefix) 	free(client[i].prefix);
		if(client[i].cc) 		free(client[i].cc);
	}
	cs_log("memory freed");

	cs_close_log();

	if (ecmcache) free((void *)ecmcache);

	exit(sig);
}

void cs_reinit_clients()
{
	int i;
	struct s_auth *account;

	for( i = 1; i < CS_MAXPID; i++ )
		if( client[i].pid && client[i].typ == 'c' && client[i].usr[0] ) {
			for (account = cfg->account; (account) ; account = account->next)
				if (!strcmp(client[i].usr, account->usr))
					break;

			if (account && client[i].pcrc == crc32(0L, MD5((uchar *)account->pwd, strlen(account->pwd), NULL), 16)) {
				client[i].grp		= account->grp;
				client[i].au		= account->au;
				client[i].autoau	= account->autoau;
				client[i].expirationdate = account->expirationdate;
				client[i].allowedtimeframe[0] = account->allowedtimeframe[0];
				client[i].allowedtimeframe[1] = account->allowedtimeframe[1];
				client[i].ncd_keepalive = account->ncd_keepalive;
				client[i].c35_suppresscmd08 = account->c35_suppresscmd08;
				client[i].tosleep	= (60*account->tosleep);
				client[i].c35_sleepsend = account->c35_sleepsend;
				client[i].monlvl	= account->monlvl;
				client[i].disabled	= account->disabled;
				client[i].fchid		= account->fchid;  // CHID filters
				client[i].cltab		= account->cltab;  // Class

				// newcamd module dosent like ident reloading
				if(!client[i].ncd_server)
					client[i].ftab	= account->ftab;   // Ident

				client[i].sidtabok	= account->sidtabok;   // services
				client[i].sidtabno	= account->sidtabno;   // services

				memcpy(&client[i].ctab, &account->ctab, sizeof(client[i].ctab));
				memcpy(&client[i].ttab, &account->ttab, sizeof(client[i].ttab));

#ifdef CS_ANTICASC
				client[i].ac_idx	= account->ac_idx;
				client[i].ac_penalty= account->ac_penalty;
				client[i].ac_limit	= (account->ac_users * 100 + 80) * cfg->ac_stime;
#endif
			} else {
				if (ph[client[i].ctyp].type & MOD_CONN_NET) {
					cs_debug("client '%s', pid=%d not found in db (or password changed)", client[i].usr, client[i].pid);
					pthread_cancel(client[i].thread);
				}
			}
		}
}

static void cs_sighup()
{
  uchar dummy[1]={0x00};
  write_to_pipe(fd_c2m, PIP_ID_HUP, dummy, 1);
}

static void cs_accounts_chk()
{
  init_userdb(&cfg->account);
  cs_reinit_clients();
#ifdef CS_ANTICASC
  int i;
  for (i=0; i<CS_MAXPID; i++)
    if (client[i].typ=='a')
    {
      //kill(client[i].pid, SIGHUP);
      break;
    }
#endif
}

static void cs_debug_level()
{
	//switch debuglevel forward one step if not set from outside
	if(cfg->debuglvl == cs_dblevel) {
		switch (cs_dblevel) {
			case 0:
				cs_dblevel = 1;
				break;
			case 64:
				cs_dblevel = 255;
				break;
			case 255:
				cs_dblevel = 0;
				break;
			default:
				cs_dblevel <<= 1;
		}
	} else {
		cs_dblevel = cfg->debuglvl;
	}

	cfg->debuglvl = cs_dblevel;
	cs_log("%sdebug_level=%d", "all", cs_dblevel);
}

static void cs_card_info(int i)
{
  uchar dummy[1]={0x00};

  for( i=1; i<CS_MAXPID; i++ )
    if( client[i].pid && client[i].typ=='r' && client[i].fd_m2c ){
      write_to_pipe(client[i].fd_m2c, PIP_ID_CIN, dummy, 1);
    }

      //kill(client[i].pid, SIGUSR2);
}

int cs_fork(in_addr_t ip, in_port_t port) {
	int i;

	pid_t pid=getpid();
	for (i=1; (i<CS_MAXPID) && (client[i].pid); i++); //find next available client index i
	if (i<CS_MAXPID) {
		int fdp[2];
		memset(&client[i], 0, sizeof(struct s_client));
		client[i].au=(-1);
		if (pipe(fdp)) {
			cs_log("Cannot create pipe (errno=%d)", errno);
			cs_exit(1);
		}
		//client part

		//make_non_blocking(fdp[0]);
		//make_non_blocking(fdp[1]);

		client[i].is_server=((ip) || (port<90)) ? 1 : 0; //FIXME global should be local per thread
		   
		client[i].cs_ptyp=D_CLIENT;
		client[i].fd_m2c_c = fdp[0]; //store client read fd
		client[i].fd_m2c = fdp[1]; //store client read fd

		//master part
		client[i].stat=1;

		client[i].login=client[i].last=time((time_t *)0);
		client[i].pid=pid;    // MUST be last -> wait4master()

		cs_last_idx=i;

		
	} else {
		cs_log("max connections reached -> reject client %s", cs_inet_ntoa(ip));
		i=(-1);
	}
	return(i);
}

static void init_signal()
{
  int i;
  for (i=1; i<NSIG; i++)
		set_signal_handler(i, 3, cs_exit);
		set_signal_handler(SIGWINCH, 1, SIG_IGN);
		//  set_signal_handler(SIGPIPE , 0, SIG_IGN);
		set_signal_handler(SIGPIPE , 0, cs_sigpipe);
		//  set_signal_handler(SIGALRM , 0, cs_alarm);
		set_signal_handler(SIGALRM , 0, cs_master_alarm);
		// set_signal_handler(SIGCHLD , 1, cs_child_chk);
		//  set_signal_handler(SIGHUP  , 1, cs_accounts_chk);
		set_signal_handler(SIGHUP , 1, cs_sighup);
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

static void init_shm()
{
	ecmcache=(struct s_ecm *)malloc(shmsize);
	memset(ecmcache, 0, shmsize);

#ifdef CS_ANTICASC
  acasc=(struct s_acasc_shm *)&ecmcache[CS_ECMCACHESIZE];
  ecmidx=(int *)&acasc[CS_MAXPID];
#else
  ecmidx=(int *)&ecmcache[CS_ECMCACHESIZE];
#endif
  logidx=(int *)((void *)ecmidx+sizeof(int));
  c_start=(int *)((void *)logidx+sizeof(int));
  oscam_sem=(int *)((void *)c_start+sizeof(int));
  client=(struct s_client *)((void *)oscam_sem+sizeof(int));
  reader=(struct s_reader *)&client[CS_MAXPID];
#ifdef CS_WITH_GBOX
  Cards=(struct card_struct*)&reader[CS_MAXREADER];
  IgnoreList=(unsigned long*)&Cards[CS_MAXCARDS];
  idstore=(struct idstore_struct*)&IgnoreList[CS_MAXIGNORE];
  cfg=(struct s_config *)&idstore[CS_MAXPID];
#else
  cfg=(struct s_config *)&reader[CS_MAXREADER];
#endif
#ifdef CS_LOGHISTORY
  loghistidx=(int *)((void *)cfg+sizeof(struct s_config));
  loghist=(char *)((void *)loghistidx+sizeof(int));
#endif


  *ecmidx=0;
  *logidx=0;
  *oscam_sem=0;
  client[0].pid=getpid();
  client[0].login=time((time_t *)0);
  client[0].ip=cs_inet_addr("127.0.0.1");
  client[0].typ='s';
  client[0].au=(-1);

  // get username master running under
  struct passwd *pwd;
  if ((pwd = getpwuid(getuid())) != NULL)
    strcpy(client[0].usr, pwd->pw_name);
  else
    strcpy(client[0].usr, "root");

  pthread_mutex_init(&gethostbyname_lock, NULL); 

#ifdef CS_LOGHISTORY
  *loghistidx=0;
  memset(loghist, 0, CS_MAXLOGHIST*CS_LOGHISTSIZE);
#endif
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
    ph->s_ip=cfg->srvip;
  if (ph->s_ip)
  {
    sad.sin_addr.s_addr=ph->s_ip;
    sprintf(ptxt[0], ", ip=%s", inet_ntoa(sad.sin_addr));
  }
  else
    sad.sin_addr.s_addr=INADDR_ANY;
  timeout=cfg->bindwait;
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
    cs_log("%s: Cannot create socket (errno=%d)", ph->desc, errno);
    return(0);
  }

  ov=1;
  if (setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_REUSEADDR, (void *)&ov, sizeof(ov))<0)
  {
    cs_log("%s: setsockopt failed (errno=%d)", ph->desc, errno);
    close(ph->ptab->ports[port_idx].fd);
    return(ph->ptab->ports[port_idx].fd=0);
  }

#ifdef SO_REUSEPORT
  setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_REUSEPORT, (void *)&ov, sizeof(ov));
#endif

#ifdef SO_PRIORITY
  if (cfg->netprio)
    if (!setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_PRIORITY, (void *)&cfg->netprio, sizeof(ulong)))
      sprintf(ptxt[1], ", prio=%ld", cfg->netprio);
#endif

  if( !is_udp )
  {
    ulong keep_alive = 1;
    setsockopt(ph->ptab->ports[port_idx].fd, SOL_SOCKET, SO_KEEPALIVE,
               (void *)&keep_alive, sizeof(ulong));
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
      cs_log("%s: Cannot start listen mode (errno=%d)", ph->desc, errno);
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
      if (cfg->resolve_gethostbyname) {
        rht = gethostbyname((char*)account->dyndns);
	if (!rht)
	  cs_log("can't resolve %s", account->dyndns);
	else {
          memcpy(&udp_sa.sin_addr, rht->h_addr, sizeof(udp_sa.sin_addr));
          account->dynip=cs_inet_order(udp_sa.sin_addr.s_addr);
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
          account->dynip=cs_inet_order(((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr);
          result=1;
        }
        if (res) freeaddrinfo(res);
      }
      if (lastip != account->dynip)  {
        uchar *ip = (uchar*) &account->dynip;
        cs_log("%s: resolved ip=%d.%d.%d.%d", (char*)account->dyndns, ip[3], ip[2], ip[1], ip[0]);
      }
      pthread_mutex_unlock(&gethostbyname_lock);
    }
    if (!result)
    	account->dynip=0;
    return result;
}

static void start_thread(void * startroutine, char * nameroutine, char typ) {
	int i,o;

	if (typ == 'h')
		o=cs_fork(0,95);
	else
		o=cs_fork(0,97);

	if (o<0) return;

	client[o].typ=typ;

	client[o].ip=client[0].ip;
	strcpy(client[o].usr, client[0].usr);

	i=pthread_create(&client[o].thread, (pthread_attr_t *)0, startroutine, (void *) 0);

	if (i)
		cs_log("ERROR: can't create %s thread (err=%d)", i, nameroutine);
	else {
		cs_log("%s thread started", nameroutine);
		pthread_detach(client[o].thread);
	}
}

#ifdef CS_ANTICASC
void start_anticascader()
{
  set_signal_handler(SIGHUP, 1, ac_init_stat);

  ac_init_stat();
  while(1)
  {
    ac_do_stat();
  }
}
#endif

static void restart_cardreader(int reader_idx, int restart) {
	int i,n;
	if ((reader[reader_idx].device[0]) && (reader[reader_idx].enable == 1) && (!reader[reader_idx].deleted)) {

		if (restart) {
			cs_sleepms(cfg->reader_restart_seconds * 1000); // SS: wait
			cs_log("restarting reader %s (index=%d)", reader[reader_idx].label, reader_idx);
		}

		if ((reader[reader_idx].typ & R_IS_CASCADING)) {
			n=0;
			for (i=0; i<CS_MAX_MOD; i++) {
				if (ph[i].num) {
					if (reader[reader_idx].typ==ph[i].num) {
						cs_debug("reader %s protocol: %s", reader[reader_idx].label, ph[i].desc);
						reader[reader_idx].ph=ph[i];
						n=1;
						break;
					}
				}
			}
			if (!n) {
				cs_log("Protocol Support missing.");
				return;
			}
		}

		i=cs_fork(0, 99);

		if (i<0) return;

		reader[reader_idx].fd=client[i].fd_m2c;
		client[i].ridx=reader_idx;
		cs_log("creating thread for device %s slot %i with ridx %i cs_idx %i", reader[reader_idx].device, reader[reader_idx].slot, reader_idx, i);
             	
		client[i].sidtabok=reader[reader_idx].sidtabok;
		client[i].sidtabno=reader[reader_idx].sidtabno;
   
		reader[reader_idx].pid=getpid();

		reader[reader_idx].cidx=i;

		client[i].typ='r';
		//client[i].ctyp=99;
		pthread_create(&client[i].thread, NULL, start_cardreader, (void *)&reader[reader_idx]);

       	if (reader[reader_idx].r_port)
			cs_log("proxy thread started (pid=%d, server=%s)",reader[reader_idx].pid, reader[reader_idx].device);
		else {
			switch(reader[reader_idx].typ) {
				case R_MOUSE:
				case R_SMART:
					cs_log("reader thread started (pid=%d, device=%s, detect=%s%s, mhz=%d, cardmhz=%d)",reader[reader_idx].pid, 
						reader[reader_idx].device,reader[reader_idx].detect&0x80 ? "!" : "",RDR_CD_TXT[reader[reader_idx].detect&0x7f],
						reader[reader_idx].mhz,reader[reader_idx].cardmhz);
					break;
				case R_SC8in1:
					cs_log("reader thread started (pid=%d, device=%s:%i, detect=%s%s, mhz=%d, cardmhz=%d)",reader[reader_idx].pid, 
						reader[reader_idx].device,reader[reader_idx].slot,reader[reader_idx].detect&0x80 ? "!" : "",
						RDR_CD_TXT[reader[reader_idx].detect&0x7f],reader[reader_idx].mhz,reader[reader_idx].cardmhz);
					break;
				default:
					cs_log("reader thread started (pid=%d, device=%s)",reader[reader_idx].pid, reader[reader_idx].device);
			}
			client[i].ip=client[0].ip;
			strcpy(client[i].usr, client[0].usr);
		}  
	}
}

static void init_cardreader() {
	int reader_idx;
	for (reader_idx=0; reader_idx<CS_MAXREADER; reader_idx++) {
		if ((reader[reader_idx].device[0]) && (reader[reader_idx].enable == 1)) {
			restart_cardreader(reader_idx, 0);
		}
	}
}

void wait4master()
{
  //int i;
  //for (i=0; (i<1000) && (client[cs_idx].pid!=getpid()); i++)
    //cs_sleepms(1);
  if (client[cs_idx].pid!=getpid())
  {
    cs_log("PANIC: client not found in shared memory");
    //cs_exit(1);
  }
  cs_debug("starting client %d with ip %s",
            cs_idx-cdiff, cs_inet_ntoa(client[cs_idx].ip));
}

static void cs_fake_client(char *usr, int uniq, in_addr_t ip)
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

	int i;
	for (i=cdiff+1; i<CS_MAXPID; i++)
	{
		if (client[i].pid && (client[i].typ == 'c') && !client[i].dup && !strcmp(client[i].usr, usr)
		   && (uniq < 5) && ((uniq % 2) || (client[i].ip != ip)))
		{
			if (uniq  == 3 || uniq == 4)
			{
				client[i].dup = 1;
				client[i].au = -1;
				cs_log("client(%d) duplicate user '%s' from %s set to fake (uniq=%d)", i-cdiff, usr, cs_inet_ntoa(ip), uniq);
			}
			else
			{
				client[cs_idx].dup = 1;
				client[cs_idx].au = -1;
				cs_log("client(%d) duplicate user '%s' from %s set to fake (uniq=%d)", cs_idx-cdiff, usr, cs_inet_ntoa(ip), uniq);
				break;
			}

		}
	}

}

int cs_auth_client(struct s_auth *account, const char *e_txt)
{
	int rc=0;
	char buf[32];
	char *t_crypt="encrypted";
	char *t_plain="plain";
	char *t_grant=" granted";
	char *t_reject=" rejected";
	char *t_msg[]= { buf, "invalid access", "invalid ip", "unknown reason" };
	client[cs_idx].grp=0xffffffff;
	client[cs_idx].au=(-1);
	switch((long)account)
	{
#ifdef CS_WITH_GBOX
	case -2:            // gbx-dummy
	client[cs_idx].dup=0;
	break;
#endif
	case 0:           // reject access
		rc=1;
		cs_log("%s %s-client %s%s (%s)",
				client[cs_idx].crypted ? t_crypt : t_plain,
				ph[client[cs_idx].ctyp].desc,
				client[cs_idx].ip ? cs_inet_ntoa(client[cs_idx].ip) : "",
				client[cs_idx].ip ? t_reject : t_reject+1,
				e_txt ? e_txt : t_msg[rc]);
		break;
	default:            // grant/check access
		if (client[cs_idx].ip && account->dyndns[0]) {
			if (cfg->clientdyndns) {
				if (client[cs_idx].ip != account->dynip)
					cs_user_resolve(account);
				if (client[cs_idx].ip != account->dynip)
					rc=2;
			}
			else
				cs_log("Warning: clientdyndns disabled in config. Enable clientdyndns to use hostname restrictions");
		}

		if (!rc)
		{
			client[cs_idx].dup=0;
			if (client[cs_idx].typ=='c')
			{
				client[cs_idx].last_caid = 0xFFFE;
				client[cs_idx].last_srvid = 0xFFFE;
				client[cs_idx].expirationdate=account->expirationdate;
				client[cs_idx].disabled=account->disabled;
				client[cs_idx].c35_suppresscmd08 = account->c35_suppresscmd08;
				client[cs_idx].ncd_keepalive = account->ncd_keepalive;
				client[cs_idx].grp=account->grp;
				client[cs_idx].au=account->au;
				client[cs_idx].autoau=account->autoau;
				client[cs_idx].tosleep=(60*account->tosleep);
				client[cs_idx].c35_sleepsend = account->c35_sleepsend;
				memcpy(&client[cs_idx].ctab, &account->ctab, sizeof(client[cs_idx].ctab));
				if (account->uniq)
					cs_fake_client(account->usr, account->uniq, client[cs_idx].ip);
				client[cs_idx].ftab  = account->ftab;   // IDENT filter
				client[cs_idx].cltab = account->cltab;  // CLASS filter
				client[cs_idx].fchid = account->fchid;  // CHID filter
				client[cs_idx].sidtabok= account->sidtabok;   // services
				client[cs_idx].sidtabno= account->sidtabno;   // services
				client[cs_idx].pcrc  = crc32(0L, MD5((uchar *)account->pwd, strlen(account->pwd), NULL), 16);
				memcpy(&client[cs_idx].ttab, &account->ttab, sizeof(client[cs_idx].ttab));
#ifdef CS_ANTICASC
				ac_init_client(account);
#endif
			}
		}
		client[cs_idx].monlvl=account->monlvl;
		strcpy(client[cs_idx].usr, account->usr);
	case -1:            // anonymous grant access
	if (rc)
		t_grant=t_reject;
	else
	{
		if (client[cs_idx].typ=='m')
			sprintf(t_msg[0], "lvl=%d", client[cs_idx].monlvl);
		else
		{
			if(client[cs_idx].autoau)
			{
				if(client[cs_idx].ncd_server)
				{
					int r=0;
					for(r=0;r<CS_MAXREADER;r++)
					{
						if(reader[r].caid[0]==cfg->ncd_ptab.ports[client[cs_idx].port_idx].ftab.filts[0].caid)
						{
							client[cs_idx].au=r;
							break;
						}
					}
					if(client[cs_idx].au<0) sprintf(t_msg[0], "au(auto)=%d", client[cs_idx].au+1);
					else sprintf(t_msg[0], "au(auto)=%s", reader[client[cs_idx].au].label);
				}
				else
				{
					sprintf(t_msg[0], "au=auto");
				}
			}
			else
			{
				if(client[cs_idx].au<0) sprintf(t_msg[0], "au=%d", client[cs_idx].au+1);
				else sprintf(t_msg[0], "au=%s", reader[client[cs_idx].au].label);
			}
		}
	}
	if(client[cs_idx].ncd_server)
	{
		cs_log("%s %s:%d-client %s%s (%s, %s)",
				client[cs_idx].crypted ? t_crypt : t_plain,
				e_txt ? e_txt : ph[client[cs_idx].ctyp].desc,
				cfg->ncd_ptab.ports[client[cs_idx].port_idx].s_port,
				client[cs_idx].ip ? cs_inet_ntoa(client[cs_idx].ip) : "",
				client[cs_idx].ip ? t_grant : t_grant+1,
				username(cs_idx), t_msg[rc]);
	}
	else
	{
		cs_log("%s %s-client %s%s (%s, %s)",
				client[cs_idx].crypted ? t_crypt : t_plain,
				e_txt ? e_txt : ph[client[cs_idx].ctyp].desc,
				client[cs_idx].ip ? cs_inet_ntoa(client[cs_idx].ip) : "",
				client[cs_idx].ip ? t_grant : t_grant+1,
				username(cs_idx), t_msg[rc]);
	}

	break;
	}
	return(rc);
}

void cs_disconnect_client(void)
{
	char buf[32]={0};
	if (client[cs_idx].ip)
		sprintf(buf, " from %s", cs_inet_ntoa(client[cs_idx].ip));
	cs_log("%s disconnected %s", username(cs_idx), buf);
	cs_exit(0);
}

/**
 * cache 1: client-invoked
 * returns found ecm task index
 **/
int check_ecmcache1(ECM_REQUEST *er, ulong grp)
{
	int i;
	//cs_ddump(ecmd5, CS_ECMSTORESIZE, "ECM search");
	//cs_log("cache1 CHECK: grp=%lX", grp);
	for(i=0; i<CS_ECMCACHESIZE; i++) {
		if ((grp & ecmcache[i].grp) &&
		     ecmcache[i].caid==er->caid &&
		     (!memcmp(ecmcache[i].ecmd5, er->ecmd5, CS_ECMSTORESIZE)))
		{
			//cs_log("cache1 found: grp=%lX cgrp=%lX", grp, ecmcache[i].grp);
			memcpy(er->cw, ecmcache[i].cw, 16);
			er->reader[0] = ecmcache[i].reader;
			return(1);
		}
	}
	return(0);
}

/**
 * cache 2: reader-invoked
 * returns 1 if found in cache. cw is copied to er
 **/
int check_ecmcache2(ECM_REQUEST *er, ulong grp)
{
	// disable cache2
	if (!reader[client[get_csidx()].ridx].cachecm) return(0);
	
	int i;
	//cs_ddump(ecmd5, CS_ECMSTORESIZE, "ECM search");
	//cs_log("cache2 CHECK: grp=%lX", grp);
	for(i=0; i<CS_ECMCACHESIZE; i++) {
		if ((grp & ecmcache[i].grp) &&
		     ecmcache[i].caid==er->caid &&
		     (!memcmp(ecmcache[i].ecmd5, er->ecmd5, CS_ECMSTORESIZE)))
		{
			//cs_log("cache2 found: grp=%lX cgrp=%lX", grp, ecmcache[i].grp);
			memcpy(er->cw, ecmcache[i].cw, 16);
			return(1);
		}
	}
	return(0);
}


static void store_ecm(ECM_REQUEST *er)
{
#ifdef CS_WITH_DOUBLECHECK
	if (cfg->double_check && er->checked < 2)
		return;
#endif
	int rc;
	rc=*ecmidx;
	*ecmidx=(*ecmidx+1) % CS_ECMCACHESIZE;
	//cs_log("store ecm from reader %d", er->reader[0]);
	memcpy(ecmcache[rc].ecmd5, er->ecmd5, CS_ECMSTORESIZE);
	memcpy(ecmcache[rc].cw, er->cw, 16);
	ecmcache[rc].caid = er->caid;
	ecmcache[rc].grp = reader[er->reader[0]].grp;
	ecmcache[rc].reader = er->reader[0];
	//cs_ddump(ecmcache[*ecmidx].ecmd5, CS_ECMSTORESIZE, "ECM stored (idx=%d)", *ecmidx);
}

void store_logentry(char *txt)
{
#ifdef CS_LOGHISTORY
	char *ptr;
	ptr=(char *)(loghist+(*loghistidx*CS_LOGHISTSIZE));
	ptr[0]='\1';    // make username unusable
	ptr[1]='\0';
	if ((client[cs_idx].typ=='c') || (client[cs_idx].typ=='m'))
		cs_strncpy(ptr, client[cs_idx].usr, 31);
	cs_strncpy(ptr+32, txt, CS_LOGHISTSIZE-33);
	*loghistidx=(*loghistidx+1) % CS_MAXLOGHIST;
#endif
}

/*
 * write_to_pipe():
 * write all kind of data to pipe specified by fd
 */
int write_to_pipe(int fd, int id, uchar *data, int n)
{
  if( !fd ) {
        cs_log("write_to_pipe: fd==0 id: %d", id);
        return -1;
  }

//printf("WRITE_START pid=%d", getpid()); fflush(stdout);

  uchar buf[1024+3+sizeof(int)];

  if ((id<0) || (id>PIP_ID_MAX))
    return(PIP_ID_ERR);
  memcpy(buf, PIP_ID_TXT[id], 3);
  memcpy(buf+3, &n, sizeof(int));
  memcpy(buf+3+sizeof(int), data, n);
  n+=3+sizeof(int);

//n=write(fd, buf, n);
//printf("WRITE_END pid=%d", getpid()); fflush(stdout);
//return(n);

  if( !fd ) {
    cs_log("write_to_pipe: fd==0");
    return(PIP_ID_ERR);
  }

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
  static int hdr=0;
  static uchar buf[1024+1+3+sizeof(int)];

  *data=(uchar *)0;
  rc=PIP_ID_NUL;

  if (!hdr)
  {
    if (bytes_available(fd))
    {
      if (read(fd, buf, 3+sizeof(int))==3+sizeof(int))
        memcpy(&hdr, buf+3, sizeof(int));
      else
        cs_log("WARNING: pipe header to small !");
    }
  }
  if (hdr)
  {
    int l;
    for (l=0; (rc<0) && (PIP_ID_TXT[l]); l++)
      if (!memcmp(buf, PIP_ID_TXT[l], 3))
        rc=l;

    if (rc<0)
    {
      fprintf(stderr, "WARNING: pipe garbage from pipe %i", fd);
      fflush(stderr);
      cs_log("WARNING: pipe garbage from pipe %i", fd);
      rc=PIP_ID_ERR;
    }
    else
    {
      l=hdr;
      if ((l+3-1+sizeof(int))>sizeof(buf))
      {
        cs_log("WARNING: packet size (%d) to large", l);
        l=sizeof(buf)+3-1+sizeof(int);
      }
      if (!bytes_available(fd))
        return(PIP_ID_NUL);
      hdr=0;
      if (read(fd, buf+3+sizeof(int), l)==l)
        *data=buf+3+sizeof(int);
      else
      {
        cs_log("WARNING: pipe data to small !");
        return(PIP_ID_ERR);
      }
      buf[l+3+sizeof(int)]=0;
      if ((redir) && (rc==PIP_ID_ECM))
      {
        //int idx;
        ECM_REQUEST *er;
        er=(ECM_REQUEST *)(buf+3+sizeof(int));
        if( er->cidx && client[er->cidx].fd_m2c )
            if (!write(client[er->cidx].fd_m2c, buf, l+3+sizeof(int))) cs_exit(1);
        rc=PIP_ID_DIR;
      }
    }
  }
  return(rc);
}

/*
 * write_ecm_request():
 */
int write_ecm_request(int fd, ECM_REQUEST *er)
{
  return(write_to_pipe(fd, PIP_ID_ECM, (uchar *) er, sizeof(ECM_REQUEST)));
}

int write_ecm_DCW(int fd, ECM_REQUEST *er)
{
  return(write_to_pipe(fd, PIP_ID_DCW, (uchar *) er, sizeof(ECM_REQUEST)));
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
	struct tm *timeinfo;
	struct s_srvid *this;

	/* 
	* search service name for that id and change characters
	* causing problems in file name 
	*/
	srvname[0] = 0;
	for (this=cfg->srvid; this; this = this->next) {
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
	timeinfo = localtime(&t);
	strftime(date, sizeof(date), "%Y%m%d", timeinfo);
	sprintf(buf, "%s/%s_I%04X_%s.cwl", cfg->cwlogdir, date, er->srvid, srvname);

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
			cs_log(""error opening cw logfile for writing: %s (errno %d)", buf, errno); */
		return;
	}
	if (writeheader) {
		/* no global macro for cardserver name :( */
		fprintf(pfCWL, "# OSCam cardserver v%s - http://streamboard.gmc.to:8001/oscam/wiki\n", CS_VERSION_X);
		fprintf(pfCWL, "# control word log file for use with tsdec offline decrypter\n");
		strftime(buf, sizeof(buf),"DATE %Y-%m-%d, TIME %H:%M:%S, TZ %Z\n", timeinfo);
		fprintf(pfCWL, "# %s", buf);
		fprintf(pfCWL, "# CAID 0x%04X, SID 0x%04X, SERVICE \"%s\"\n", er->caid, er->srvid, srvname);
	}

	parity = er->ecm[0]&1;
	fprintf(pfCWL, "%d ", parity);
	for (i = parity * 8; i < 8 + parity * 8; i++)
		fprintf(pfCWL, "%02X ", er->cw[i]);
	/* better use incoming time er->tps rather than current time? */
	strftime(buf,sizeof(buf),"%H:%M:%S\n", timeinfo);
	fprintf(pfCWL, "# %s", buf);
	fflush(pfCWL);
	fclose(pfCWL);
}

int write_ecm_answer(struct s_reader * reader, int fd, ECM_REQUEST *er)
{
  int i;
  uchar c;
  for (i=0; i<16; i+=4)
  {
    c=((er->cw[i]+er->cw[i+1]+er->cw[i+2]) & 0xff);
    if (er->cw[i+3]!=c)
    {
      cs_debug("notice: changed dcw checksum byte cw[%i] from %02x to %02x", i+3, er->cw[i+3],c);
      er->cw[i+3]=c;
    }
  }

  er->reader[0]=client[reader->cidx].ridx;
//cs_log("answer from reader %d (rc=%d)", er->reader[0], er->rc);
  er->caid=er->ocaid;

#ifdef CS_WITH_GBOX
  if (er->rc==1||(er->gbxRidx&&er->rc==0)) {
#else
  if (er->rc==1) {
#endif
    store_ecm(er);

  /* CWL logging only if cwlogdir is set in config */
  if (cfg->cwlogdir != NULL)
    logCWtoFile(er);
  }

  return(write_ecm_request(fd, er));
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
  FD_SET(client[cs_idx].pfd, &fds);

  select(fd+1, &fds, 0, 0, &tv);

  rc=0;
  if (FD_ISSET(client[cs_idx].pfd, &fds))
    if (!(rc=read(fd, buf, l)))
      rc=-1;

  return(rc);
}*/

ECM_REQUEST *get_ecmtask()
{
	int i, n;
	ECM_REQUEST *er=0;

	if (!client[cs_idx].ecmtask)
	{
		n=(ph[client[cs_idx].ctyp].multi)?CS_MAXPENDING:1;
		if( (client[cs_idx].ecmtask=(ECM_REQUEST *)malloc(n*sizeof(ECM_REQUEST))) )
			memset(client[cs_idx].ecmtask, 0, n*sizeof(ECM_REQUEST));
	}

	n=(-1);
	if (!client[cs_idx].ecmtask)
	{
		cs_log("Cannot allocate memory (errno=%d)", errno);
		n=(-2);
	}
	else
		if (ph[client[cs_idx].ctyp].multi)
		{
			for (i=0; (n<0) && (i<CS_MAXPENDING); i++)
				if (client[cs_idx].ecmtask[i].rc<100)
					er=&client[cs_idx].ecmtask[n=i];
		}
		else
			er=&client[cs_idx].ecmtask[n=0];

	if (n<0)
		cs_log("WARNING: ecm pending table overflow !");
	else
	{
		memset(er, 0, sizeof(ECM_REQUEST));
		er->rc=100;
		er->cpti=n;
		er->cidx=cs_idx;
		cs_ftime(&er->tps);
	}
	return(er);
}

void send_reader_stat(int ridx9, ECM_REQUEST *er, int rc)
{
	if (!cfg->lb_mode || rc == 100)
		return;
	struct timeb tpe;
	cs_ftime(&tpe);
	int time = 1000*(tpe.time-er->tps.time)+tpe.millitm-er->tps.millitm;

	ADD_READER_STAT add_stat;
	memset(&add_stat, 0, sizeof(ADD_READER_STAT));
	add_stat.ridx = ridx9;
	add_stat.time = time;
	add_stat.rc   = rc;
	add_stat.caid = er->caid;
	add_stat.prid = er->prid;
	add_stat.srvid = er->srvid;
	add_reader_stat(&add_stat);
}

int hexserialset(int ridx)
{
	int i;
	for (i = 0; i < 8; i++)
		if (reader[ridx].hexserial[i])
			return 1;
	return 0;
}

// rc codes:
// 0 = found
// 1 = cache1
// 2 = cache2
// 3 = emu
// 4 = not found
// 5 = timeout
// 6 = sleeping
// 7 = fake
// 8 = invalid
// 9 = corrupt
// 10= no card
// 11= expdate
// 12= disabled
// 13= stopped
// 100=unhandled
                                                                                                                        
int send_dcw(ECM_REQUEST *er)
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

#ifdef CS_WITH_GBOX
	if(er->gbxFrom)
		snprintf(uname,sizeof(uname)-1, "%s(%04X)", username(cs_idx), er->gbxFrom);
	else
#endif
		snprintf(uname,sizeof(uname)-1, "%s", username(cs_idx));
	if (er->rc==0)
	{
#ifdef CS_WITH_GBOX
		if(reader[er->reader[0]].typ==R_GBOX)
			snprintf(sby, sizeof(sby)-1, " by %s(%04X)", reader[er->reader[0]].label,er->gbxCWFrom);
		else
#endif
			// add marker to reader if ECM_REQUEST was betatunneled
			if(er->btun)
				snprintf(sby, sizeof(sby)-1, " by %s(btun)", reader[er->reader[0]].label);
			else
				snprintf(sby, sizeof(sby)-1, " by %s", reader[er->reader[0]].label);
	}
	if (er->rc<4) er->rcEx=0;
	if (er->rcEx)
		snprintf(erEx, sizeof(erEx)-1, "rejected %s%s", stxtWh[er->rcEx>>4],
				stxtEx[er->rcEx&0xf]);

	if(cfg->mon_appendchaninfo)
		snprintf(schaninfo, sizeof(schaninfo)-1, " - %s", get_servicename(er->srvid, er->caid));

	if(er->msglog[0])
		snprintf(sreason, sizeof(sreason)-1, " (%s)", er->msglog);

	cs_ftime(&tpe);
	client[cs_idx].cwlastresptime = 1000*(tpe.time-er->tps.time)+tpe.millitm-er->tps.millitm;

#ifdef CS_LED
	if(!er->rc) cs_switch_led(LED2, LED_BLINK_OFF);
#endif

	send_reader_stat(er->reader[0], er, er->rc);

	cs_log("%s (%04X&%06X/%04X/%02X:%04X): %s (%d ms)%s%s%s",
			uname, er->caid, er->prid, er->srvid, er->l, lc,
			er->rcEx?erEx:stxt[er->rc], client[cs_idx].cwlastresptime, sby, schaninfo, sreason);

#ifdef WEBIF
	if(er->rc == 0)
		snprintf(client[cs_idx].lastreader, sizeof(client[cs_idx].lastreader)-1, "%s", sby);
	else if ((er->rc == 1) || (er->rc == 2))
		snprintf(client[cs_idx].lastreader, sizeof(client[cs_idx].lastreader)-1, "by %s (cache)", reader[er->reader[0]].label);
	else
		snprintf(client[cs_idx].lastreader, sizeof(client[cs_idx].lastreader)-1, "%s", stxt[er->rc]);
#endif

	if(!client[cs_idx].ncd_server && client[cs_idx].autoau && er->rcEx==0)
	{
		if(client[cs_idx].au>=0 && er->caid!=reader[client[cs_idx].au].caid[0])
		{
			client[cs_idx].au=(-1);
		}
		//martin
		//client[cs_idx].au=er->reader[0];
		//if(client[cs_idx].au<0)
		//{
		struct s_reader *cur = &reader[er->reader[0]];
		
		if (cur->typ == R_CCCAM && !cur->caid[0] && !cur->audisabled && 
				cur->card_system == get_cardsystem(er->caid) && hexserialset(er->reader[0]))
			client[cs_idx].au = er->reader[0];
		else if((er->caid == cur->caid[0]) && (!cur->audisabled)) {
			client[cs_idx].au = er->reader[0]; // First chance - check whether actual reader can AU
		} else {
			int r=0;
			for(r=0;r<CS_MAXREADER;r++) //second chance loop through all readers to find an AU reader
			{
				cur = &reader[r];
				if (matching_reader(er, cur)) {
					if (cur->typ == R_CCCAM && !cur->caid[0] && !cur->audisabled && 
						cur->card_system == get_cardsystem(er->caid) && hexserialset(r))
					{
						client[cs_idx].au = r;
						break;
					}
					else if((er->caid == cur->caid[0]) && (er->prid == cur->auprovid) && (!cur->audisabled))
					{
						client[cs_idx].au=r;
						break;
					}
				}
			}
			if(r==CS_MAXREADER)
			{
				client[cs_idx].au=(-1);
			}
		}
		//}
	}

	er->caid = er->ocaid;
	switch(er->rc) {
		case 0:
		case 3:
			// 0 - found
			// 3 - emu FIXME: obsolete ?
					client[cs_idx].cwfound++;
					break;

		case 1:
		case 2:
			// 1 - cache1
			// 2 - cache2
			client[cs_idx].cwcache++;
			break;

		case 4:
		case 9:
		case 10:
			// 4 - not found
			// 9 - corrupt
			// 10 - no card
			if (er->rcEx)
				client[cs_idx].cwignored++;
			else
				client[cs_idx].cwnot++;
			break;

		case 5:
			// 5 - timeout
			client[cs_idx].cwtout++;
			break;

		default:
			client[cs_idx].cwignored++;
	}

#ifdef CS_ANTICASC
	ac_chk(er, 1);
#endif

	cs_ddump_mask (D_ATR, er->cw, 16, "cw:");
	if (er->rc==7) er->rc=0;

#ifdef CS_WITH_DOUBLECHECK
	if (cfg->double_check && er->rc < 4) {
	  if (er->checked == 0) {//First CW, save it and wait for next one
	    er->checked = 1;
	    er->origin_reader = er->reader[0]; //contains ridx
	    memcpy(er->cw_checked, er->cw, sizeof(er->cw));
	    cs_log("DOUBLE CHECK FIRST CW by %s idx %d cpti %d", reader[er->origin_reader].label, er->idx, er->cpti);
	  }
	  else if (er->origin_reader != er->reader[0]) { //Second (or third and so on) cw. We have to compare
	    if (memcmp(er->cw_checked, er->cw, sizeof(er->cw)) == 0) {
	    	er->checked++;
	    	cs_log("DOUBLE CHECKED! %d. CW by %s idx %d cpti %d", er->checked, reader[er->reader[0]].label, er->idx, er->cpti);
	    }
	    else {
	    	cs_log("DOUBLE CHECKED NONMATCHING! %d. CW by %s idx %d cpti %d", er->checked, reader[er->reader[0]].label, er->idx, er->cpti);
	    }
	  }
	  
	  if (er->checked < 2) { //less as two same cw? mark as pending!
	    er->rc = 100; 
	    return 0;
	  }

	  store_ecm(er); //Store in cache!
	}
#endif
	
	ph[client[cs_idx].ctyp].send_dcw(er);
	return 0;
}

void chk_dcw(int fd)
{
  ECM_REQUEST *er, *ert;
  if (read_from_pipe(fd, (uchar **)(void *)&er, 0) != PIP_ID_ECM)
	  return;
  //cs_log("dcw check from reader %d for idx %d (rc=%d)", er->reader[0], er->cpti, er->rc);
  ert=&client[cs_idx].ecmtask[er->cpti];
  if (ert->rc<100) {
	//cs_debug_mask(D_TRACE, "chk_dcw: already done rc=%d %s", er->rc, reader[er->reader[0]].label);
	send_reader_stat(er->reader[0], er, (er->rc <= 0)?4:0);
	return; // already done
  }
  if( (er->caid!=ert->caid) || memcmp(er->ecm , ert->ecm , sizeof(er->ecm)) )
    return; // obsolete
  ert->rcEx=er->rcEx;
  strcpy(ert->msglog, er->msglog);
  if (er->rc>0) // found
  {
    switch(er->rc)
    {
      case 2:
        ert->rc=2;
        break;
      case 3:
        ert->rc=3;
        break;
      default:
        ert->rc=0;
    }
    ert->rcEx=0;
    ert->reader[0]=er->reader[0];
    memcpy(ert->cw , er->cw , sizeof(er->cw));
#ifdef CS_WITH_GBOX
    ert->gbxCWFrom=er->gbxCWFrom;
#endif
  }
  else    // not found (from ONE of the readers !)
  {
    //save reader informations for loadbalance-statistics:
	ECM_REQUEST *save_ert = ert;
	int save_ridx = er->reader[0];

	//
    int i;
    ert->reader[er->reader[0]]=0;
    for (i=0; (ert) && (i<CS_MAXREADER); i++)
      if (ert->reader[i]) {// we have still another chance
        ert=(ECM_REQUEST *)0;
      }
    if (ert) ert->rc=4;
    else send_reader_stat(save_ridx, save_ert, 4);
  }
  if (ert) send_dcw(ert);
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
  ptr = cfg->itab[b3];
  if( !ptr ) {
    cs_debug("unknown irdeto byte 3: %02X", b3);
    return;
  }
  b47  = b2i(4, er->ecm+4);
  //chid = b2i(2, er->ecm+6);
  //cs_debug("ecm: b47=%08X, ptr->b47=%08X, ptr->caid=%04X", b47, ptr->b47, ptr->caid);
  while( ptr )
  {
    if( b47==ptr->b47 )
    {
      if( er->srvid && (er->srvid!=ptr->sid) )
      {
        cs_debug("sid mismatched (ecm: %04X, guess: %04X), wrong oscam.ird file?",
                  er->srvid, ptr->sid);
        return;
      }
      er->caid=ptr->caid;
      er->srvid=ptr->sid;
      er->chid=(ushort)ptr->b47;
//      cs_debug("quess_irdeto() found caid=%04X, sid=%04X, chid=%04X",
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
	ulong mask_all = 0xFFFF;
	TUNTAB *ttab;
	ttab = &client[cs_idx].ttab;
	for (n = 0; (n < CS_MAXTUNTAB); n++) {
		if ((er->caid==ttab->bt_caidfrom[n]) && ((er->srvid==ttab->bt_srvid[n]) || (ttab->bt_srvid[n])==mask_all)) {
			uchar hack_n3[13] = {0x70, 0x51, 0xc7, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x87, 0x12, 0x07};
			uchar hack_n2[13] = {0x70, 0x51, 0xc9, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x48, 0x12, 0x07};
			er->caid = ttab->bt_caidto[n];
			er->prid = 0;
			er->l = (er->ecm[2]+3);
			memmove(er->ecm+14, er->ecm+4, er->l-1);
			if (er->l > 0x88) {
				memcpy(er->ecm+1, hack_n3, 13);
				if (er->ecm[0] == 0x81)
					er->ecm[12] += 1;
			}
			else {
				memcpy(er->ecm+1, hack_n2, 13);
			}
			er->l += 10;
			er->ecm[2] = er->l-3;
			er->btun = 1;
			client[cs_idx].cwtun++;
			cs_debug("ECM converted from: 0x%X to BetaCrypt: 0x%X for service id:0x%X",
				ttab->bt_caidfrom[n], ttab->bt_caidto[n], ttab->bt_srvid[n]);
		}
	}
}

void guess_cardsystem(ECM_REQUEST *er)
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

void request_cw(ECM_REQUEST *er, int flag, int reader_types)
{
  int i;
  if ((reader_types == 0) || (reader_types == 2))
    er->level=flag;
  flag=(flag)?3:1;    // flag specifies with/without fallback-readers
  for (i=0; i<CS_MAXREADER; i++)
  {
	    //if (reader[i].pid)
	    //	  cs_log("active reader: %d pid %d fd %d", i, reader[i].pid, reader[i].fd);
      int status = 0;
      switch (reader_types)
      {
          // network and local cards
          default:
          case 0:
              if (er->reader[i]&flag){
                  cs_debug_mask(D_TRACE, "request_cw1 to reader %s ridx=%d fd=%d", reader[i].label, i, reader[i].fd);
                  status = write_ecm_request(reader[i].fd, er);
              }
              break;
              // only local cards
          case 1:
              if (!(reader[i].typ & R_IS_NETWORK))
                  if (er->reader[i]&flag) {
                	  cs_debug_mask(D_TRACE, "request_cw2 to reader %s ridx=%d fd=%d", reader[i].label, i, reader[i].fd);
                    status = write_ecm_request(reader[i].fd, er);
                  }
              break;
              // only network
          case 2:
        	  //cs_log("request_cw3 ridx=%d fd=%d", i, reader[i].fd);
              if ((reader[i].typ & R_IS_NETWORK))
                  if (er->reader[i]&flag) {
                	  cs_debug_mask(D_TRACE, "request_cw3 to reader %s ridx=%d fd=%d", reader[i].label, i, reader[i].fd);
                    status = write_ecm_request(reader[i].fd, er);
                  }
              break;
      }
      if (status == -1) {
                cs_log("request_cw() failed on reader %s (%d) errno=%d, %s", reader[i].label, i, errno, strerror(errno));
      		if (reader[i].fd) {
 	     		reader[i].fd_error++;
      			if (reader[i].fd_error > 5) {
      				reader[i].fd_error = 0;
      				send_restart_cardreader(i, 1); //Schlocke: This restarts the reader!
      			} 
		}
      }
      else
      	reader[i].fd_error = 0;
  }
}

//receive best reader from master process. Call this function from client!
void recv_best_reader(ECM_REQUEST *er, int *reader_avail)
{
	GET_READER_STAT grs;
	memset(&grs, 0, sizeof(grs));
	grs.caid = er->caid;
	grs.prid = er->prid;
	grs.srvid = er->srvid;
	grs.cidx = cs_idx;
	memcpy(grs.ecmd5, er->ecmd5, sizeof(er->ecmd5));
	memcpy(grs.reader_avail, reader_avail, sizeof(int)*CS_MAXREADER);
	cs_debug_mask(D_TRACE, "requesting client %s best reader for %04X/%06X/%04X", username(cs_idx), grs.caid, grs.prid, grs.srvid);

        get_best_reader(&grs, reader_avail);
}

void get_cw(ECM_REQUEST *er)
{
	int i, j, m;
	time_t now = time((time_t)0);

	client[cs_idx].lastecm = now;

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

	/* END quickfixes */

	if (!er->prid)
		er->prid = chk_provid(er->ecm, er->caid);

	// Set providerid for newcamd clients if none is given
	if( (!er->prid) && client[cs_idx].ncd_server ) {
		int pi = client[cs_idx].port_idx;
		if( pi >= 0 && cfg->ncd_ptab.nports && cfg->ncd_ptab.nports >= pi )
			er->prid = cfg->ncd_ptab.ports[pi].ftab.filts[0].prids[0];
	}

	// CAID not supported or found
	if (!er->caid) {
		er->rc = 8;
		er->rcEx = E2_CAID;
		snprintf( er->msglog, MSGLOGSIZE, "CAID not supported or found" );
	}

	// user expired
	if(client[cs_idx].expirationdate && client[cs_idx].expirationdate < client[cs_idx].lastecm)
		er->rc = 11;

	// out of timeframe
	if(client[cs_idx].allowedtimeframe[0] && client[cs_idx].allowedtimeframe[1]) {
		struct tm *acttm;
		acttm = localtime(&now);
		int curtime = (acttm->tm_hour * 60) + acttm->tm_min;
		int mintime = client[cs_idx].allowedtimeframe[0];
		int maxtime = client[cs_idx].allowedtimeframe[1];
		if(!((mintime <= maxtime && curtime > mintime && curtime < maxtime) || (mintime > maxtime && (curtime > mintime || curtime < maxtime)))) {
			er->rc = 11;
		}
		cs_debug("Check Timeframe - result: %d, start: %d, current: %d, end: %d\n",er->rc, mintime, curtime, maxtime);
	}

	// user disabled
	if(client[cs_idx].disabled != 0)
		er->rc = 12;

	// rc<100 -> ecm error
	if (er->rc > 99) {

		m = er->caid;
		er->ocaid = er->caid;
		i = er->srvid;

		if ((i != client[cs_idx].last_srvid) || (!client[cs_idx].lastswitch)) {
			if(cfg->usrfileflag)
				cs_statistics(cs_idx);
			client[cs_idx].lastswitch = now;
		}

		// user sleeping
		if ((client[cs_idx].tosleep) && (now - client[cs_idx].lastswitch > client[cs_idx].tosleep)) {
			if (client[cs_idx].c35_sleepsend != 0) {
				er->rc = 13; // send stop command CMD08 {00 xx}
			} else {
				er->rc = 6;
			}
		}

		client[cs_idx].last_srvid = i;
		client[cs_idx].last_caid = m;

		for (j = 0; (j < 6) && (er->rc > 99); j++)
		{
			switch(j) {

				case 0:
					// fake (uniq)
					if (client[cs_idx].dup)
						er->rc = 7;
					break;

				case 1:
					// invalid (caid)
					if (!chk_bcaid(er, &client[cs_idx].ctab)) {
						er->rc = 8;
						er->rcEx = E2_CAID;
						snprintf( er->msglog, MSGLOGSIZE, "invalid caid %x",er->caid );
						}
					break;

				case 2:
					// invalid (srvid)
					if (!chk_srvid(er, cs_idx))
					{
						er->rc = 8;
					    snprintf( er->msglog, MSGLOGSIZE, "invalid SID" );
					}

					break;

				case 3:
					// invalid (ufilters)
					if (!chk_ufilters(er))
						er->rc = 8;
					break;

				case 4:
					// invalid (sfilter)
					if (!chk_sfilter(er, ph[client[cs_idx].ctyp].ptab))
						er->rc = 8;
					break;

				case 5:
					// corrupt
					if( (i = er->l - (er->ecm[2] + 3)) ) {
						if (i > 0) {
							cs_debug("warning: ecm size adjusted from 0x%X to 0x%X",
							er->l, er->ecm[2] + 3);
							er->l = (er->ecm[2] + 3);
						}
						else
							er->rc = 9;
					}
					break;
			}
		}
	}
	
	//Schlocke: above checks could change er->rc so 
	if (er->rc > 99) {
		/*BetaCrypt tunneling
		 *moved behind the check routines,
		 *because newcamd ECM will fail
		 *if ECM is converted before
		 */
		if (&client[cs_idx].ttab)
			cs_betatunnel(er);
    
		// store ECM in cache
		memcpy(er->ecmd5, MD5(er->ecm, er->l, NULL), CS_ECMSTORESIZE);

		// cache1
		if (check_ecmcache1(er, client[cs_idx].grp))
			er->rc = 1;

#ifdef CS_ANTICASC
		ac_chk(er, 0);
#endif
	}

	if(er->rc > 99) {

		if (cfg->lb_mode) {
			int reader_avail[CS_MAXREADER];
			for (i =0; i < CS_MAXREADER; i++)
				reader_avail[i] = matching_reader(er, &reader[i]);
				
			recv_best_reader(er, reader_avail);
				
			for (i = m = 0; i < CS_MAXREADER; i++) {
				if (reader_avail[i]) {
					m|=er->reader[i] = reader_avail[i];
				}
			}
		}
		else
		{
			for (i = m = 0; i < CS_MAXREADER; i++)
				if (matching_reader(er, &reader[i]))
					m|=er->reader[i] = (reader[i].fallback)? 2: 1;
		}

		switch(m) {
			// no reader -> not found
			case 0:
				er->rc = 4;
				if (!er->rcEx)
					er->rcEx = E2_GROUP;
				break;
				
			// fallbacks only, switch them
			case 2:
				for (i = 0; i < CS_MAXREADER; i++)
					er->reader[i]>>=1;
		}
	}

	if (er->rc < 100) {
		if (cfg->delay)
			cs_sleepms(cfg->delay);

		send_dcw(er);
		return;
	}

	er->rcEx = 0;
	request_cw(er, 0, cfg->preferlocalcards ? 1 : 0);
}

void log_emm_request(int auidx)
{
	cs_log("%s emm-request sent (reader=%s, caid=%04X, auprovid=%06lX)",
			username(cs_idx), reader[auidx].label, reader[auidx].caid[0],
			reader[auidx].auprovid ? reader[auidx].auprovid : b2i(4, reader[auidx].prid[0]));
}

void do_emm(EMM_PACKET *ep)
{
	int au;
	char *typtext[]={"UNKNOWN", "UNIQUE", "SHARED", "GLOBAL"}; 

	au = client[cs_idx].au;
	cs_ddump_mask(D_ATR, ep->emm, ep->l, "emm:");

	//Unique Id matching for pay-per-view channels:
	if (client[cs_idx].autoau) {
		int i;
		for (i=0;i<CS_MAXREADER;i++) {
			if (reader[i].card_system>0 && !reader[i].audisabled) {
				if (reader_get_emm_type(ep, &reader[i])) { //decodes ep->type and ep->hexserial from the EMM
					if (memcmp(ep->hexserial, reader[i].hexserial, sizeof(ep->hexserial))==0) {
						au = i;
						break; //
					}
				}
			}
		}
	}
	
	if ((au < 0) || (au >= CS_MAXREADER)) {
		cs_debug_mask(D_EMM, "emm disabled, client has no au-reader!");
		return;
	}

	if (reader[au].card_system>0) {
		if (!reader_get_emm_type(ep, &reader[au])) { //decodes ep->type and ep->hexserial from the EMM
			cs_debug_mask(D_EMM, "emm skipped");
			return;
		}
	}
	else {
		cs_debug_mask(D_EMM, "emm skipped, reader %s (%d) has no cardsystem defined!", reader[au].label, au); 
		return;
	}

	//test: EMM becomes skipped if auprivid doesn't match with provid from EMM
	if(reader[au].auprovid) {
		if(reader[au].auprovid != b2i(4, ep->provid)) {
			cs_debug_mask(D_EMM, "emm skipped, reader %s (%d) auprovid doesn't match %06lX != %06lX!", reader[au].label, au, reader[au].auprovid, b2i(4, ep->provid));
			return;
		}
	}

	cs_debug_mask(D_EMM, "emmtype %s. Reader %s has serial %s.", typtext[ep->type], reader[au].label, cs_hexdump(0, reader[au].hexserial, 8)); 
	cs_ddump_mask(D_EMM, ep->hexserial, 8, "emm UA/SA:");
	cs_ddump_mask(D_EMM, ep->emm, ep->l, "emm:");

	client[cs_idx].last=time((time_t)0);
	if (reader[au].b_nano[ep->emm[0]] & 0x02) //should this nano be saved?
	{
		char token[256];
		FILE *fp;
		time_t rawtime;
		time (&rawtime);
		struct tm *timeinfo;
		timeinfo = localtime (&rawtime);	/* to access LOCAL date/time info */
		char buf[80];
		strftime (buf, 80, "%Y/%m/%d %H:%M:%S", timeinfo);
		sprintf (token, "%s%s_emm.log", cs_confdir, reader[au].label);
		int emm_length = ((ep->emm[1] & 0x0f) << 8) | ep->emm[2];

		if (!(fp = fopen (token, "a")))
		{
			cs_log ("ERROR: Cannot open file '%s' (errno=%d)\n", token, errno);
		}
		else
		{
			fprintf (fp, "%s   %s   ", buf, cs_hexdump(0, ep->hexserial, 8)); 
			fprintf (fp, "%s\n", cs_hexdump(0, ep->emm, emm_length + 3));
			fclose (fp);
			cs_log ("Succesfully added EMM to %s.", token);
		}

		sprintf (token, "%s%s_emm.bin", cs_confdir, reader[au].label);
		if (!(fp = fopen (token, "ab")))
		{
			cs_log ("ERROR: Cannot open file '%s' (errno=%d)\n", token, errno);
		}
		else 
		{
			if ((int)fwrite(ep->emm, 1, emm_length+3, fp) == emm_length+3)
			{
				cs_log ("Succesfully added binary EMM to %s.", token);
			}
			else
			{
				cs_log ("ERROR: Cannot write binary EMM to %s (errno=%d)\n", token, errno);
			}
			fclose (fp);
		}
	}

	switch (ep->type) {
		case UNKNOWN:
			if (reader[au].blockemm_unknown) {
#ifdef WEBIF
				reader[au].emmblocked[UNKNOWN]++;
#endif
				return;
			}
			break;

		case UNIQUE:
			if (reader[au].blockemm_u) {
#ifdef WEBIF
				reader[au].emmblocked[UNIQUE]++;
#endif
				return;
			}
			break;

		case SHARED:
			if (reader[au].blockemm_s) {
#ifdef WEBIF
				reader[au].emmblocked[SHARED]++;
#endif
				return;
			}
			break;

		// FIXME only camd33 delivers hexserial from the net, newcamd, camd35 copy 
		// cardreader hexserial in; reader_get_emm_type overwrites this with real SA value if known!
		case GLOBAL:
			if (reader[au].blockemm_g) {
#ifdef WEBIF
				reader[au].emmblocked[GLOBAL]++;
#endif
				return;
			}
			break;
	}

	client[cs_idx].lastemm = time((time_t)0);

	if (reader[au].card_system > 0) {
		if (!check_emm_cardsystem(&reader[au], ep)) {   // wrong caid
			client[cs_idx].emmnok++;
			return;
		}
		client[cs_idx].emmok++;
	}
	ep->cidx = cs_idx;
	cs_debug_mask(D_EMM, "emm is being sent to reader %s.", reader[au].label);
	write_to_pipe(reader[au].fd, PIP_ID_EMM, (uchar *) ep, sizeof(EMM_PACKET));
}

static int comp_timeb(struct timeb *tpa, struct timeb *tpb)
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
	static struct timeval tv;

	ECM_REQUEST *er;
	cs_ftime(&tpn);
	tpe=tp_ctimeout;    // latest delay -> disconnect

	if (client[cs_idx].ecmtask)
		i=(ph[client[cs_idx].ctyp].multi)?CS_MAXPENDING:1;
	else
		i=0;

	//cs_log("num pend=%d", i);

	for (--i; i>=0; i--) {
		if (client[cs_idx].ecmtask[i].rc>=100) { // check all pending ecm-requests 
			er=&client[cs_idx].ecmtask[i];
			if (check_ecmcache1(er, client[cs_idx].grp)) { //Schlocke: caching dupplicate requests from different clients
				er->rc = 1;
				send_dcw(er);
			}
		}
		if (client[cs_idx].ecmtask[i].rc>=100) { // check all pending ecm-requests 
			int act, j;
			er=&client[cs_idx].ecmtask[i];
			tpc=er->tps;
			tpc.millitm += (er->stage) ? cfg->ctimeout : cfg->ftimeout;
			tpc.time += tpc.millitm / 1000;
			tpc.millitm = tpc.millitm % 1000;
			if (!er->stage) {
				for (j=0, act=1; (act) && (j<CS_MAXREADER); j++) {
					if (cfg->preferlocalcards && !er->locals_done) {
						if ((er->reader[j]&1) && !(reader[j].typ & R_IS_NETWORK))
							act=0;
					} else if (cfg->preferlocalcards && er->locals_done) {
						if ((er->reader[j]&1) && (reader[j].typ & R_IS_NETWORK))
							act=0;
					} else {
						if (er->reader[j]&1)
							act=0;
					}
				}

				//cs_log("stage 0, act=%d r0=%d, r1=%d, r2=%d, r3=%d, r4=%d r5=%d", act,
				//    er->reader[0], er->reader[1], er->reader[2],
				//    er->reader[3], er->reader[4], er->reader[5]);

				if (act) {
					int inc_stage = 1;
					if (cfg->preferlocalcards && !er->locals_done) {
						er->locals_done = 1;
						for (j = 0; j < CS_MAXREADER; j++) {
							if (reader[j].typ & R_IS_NETWORK)
								inc_stage = 0;
						}
					}
					if (!inc_stage) {
						request_cw(er, er->stage, 2);
						tpc.millitm += 1000 * (tpn.time - er->tps.time) + tpn.millitm - er->tps.millitm;
						tpc.time += tpc.millitm / 1000;
						tpc.millitm = tpc.millitm % 1000;
					} else {
						er->locals_done = 0;
						er->stage++;
						request_cw(er, er->stage, cfg->preferlocalcards ? 1 : 0);

						tpc.millitm += (cfg->ctimeout-cfg->ftimeout);
						tpc.time += tpc.millitm / 1000;
						tpc.millitm = tpc.millitm % 1000;
					}
				}
			}
			if (comp_timeb(&tpn, &tpc)>0) { // action needed 
				//cs_log("Action now %d.%03d", tpn.time, tpn.millitm);
				//cs_log("           %d.%03d", tpc.time, tpc.millitm);
				if (er->stage) {
					er->rc=5; // timeout
					if (cfg->lb_mode) {
						int r;
						for (r=0; r<CS_MAXREADER; r++)
							if (er->reader[r])
								send_reader_stat(r, er, 5);
					}
					send_dcw(er);
					continue;
				} else {
					er->stage++;
					request_cw(er, er->stage, 0);
					tpc.millitm += (cfg->ctimeout-cfg->ftimeout);
					tpc.time += tpc.millitm / 1000;
					tpc.millitm = tpc.millitm % 1000;
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
	tv.tv_sec = td/1000;
	tv.tv_usec = (td%1000)*1000;
	//cs_log("delay %d.%06d", tv.tv_sec, tv.tv_usec);
	return(&tv);
}

int process_input(uchar *buf, int l, int timeout)
{
  int rc;
  fd_set fds;
  struct timeb tp;

  if (!client[cs_idx].pfd) return(-1);
  cs_ftime(&tp);
  tp.time+=timeout;
  if (ph[client[cs_idx].ctyp].watchdog)
      alarm(cfg->cmaxidle + (cfg->ctimeout + 500) / 1000 + 1);
  while (1)
  {
    FD_ZERO(&fds);
    FD_SET(client[cs_idx].pfd, &fds);
    FD_SET(client[cs_idx].fd_m2c_c, &fds);

    rc=select(((client[cs_idx].pfd>client[cs_idx].fd_m2c_c)?client[cs_idx].pfd:client[cs_idx].fd_m2c_c)+1, &fds, 0, 0, chk_pending(tp));
    if (rc<0)
    {
      if (errno==EINTR) continue;
      else return(0);
    }

    if (FD_ISSET(client[cs_idx].fd_m2c_c, &fds))   // read from pipe
      chk_dcw(client[cs_idx].fd_m2c_c);

    if (FD_ISSET(client[cs_idx].pfd, &fds))    // read from client
    {
      rc=ph[client[cs_idx].ctyp].recv(buf, l);
      break;
    }
    if (tp.time<=time((time_t *)0)) // client maxidle reached
    {
      rc=(-9);
      break;
    }
  }
  if (ph[client[cs_idx].ctyp].watchdog)
      alarm(cfg->cmaxidle + (cfg->ctimeout + 500) / 1000 + 1);
  return(rc);
}

static void restart_clients()
{
	int i;
	cs_log("restarting clients");
	for (i=0; i<CS_MAXPID; i++) {
		if (client[i].pid && client[i].typ=='c' && ph[client[i].ctyp].type & MOD_CONN_NET) {
			pthread_cancel(client[i].thread);
			cs_log("killing client c%02d pid %d", i, client[i].pid);
		}
	}
}


void send_clear_reader_stat(int ridx)
{
  write_to_pipe(fd_c2m, PIP_ID_RES, (uchar*)&ridx, sizeof(ridx)); 
}

void send_restart_cardreader(int ridx, int force_now)
{
  int restart_info[2];
  restart_info[0] = ridx;
  restart_info[1] = force_now;
  write_to_pipe(fd_c2m, PIP_ID_RST, (uchar*)&restart_info, sizeof(restart_info)); 
}

static void process_master_pipe()
{
  int n;
  uchar *ptr;

  switch(n=read_from_pipe(mfdr, &ptr, 1))
  {
    case PIP_ID_HUP:
    	cs_accounts_chk();
    	break;
    case PIP_ID_RST:{ //Restart Cardreader with ridx=prt[0] 
        int *restart_info = (int *)ptr;
    	restart_cardreader(restart_info[0], restart_info[1]);
    	break; }
    case PIP_ID_KCL: //Kill all clients
    	restart_clients();
    	break;
    case PIP_ID_RES: //Reset reader statistics
    	clear_reader_stat(*(int*)ptr);
    	break;
  }
}

void cs_log_config()
{
  uchar buf[20];

  if (cfg->nice!=99)
    sprintf((char *)buf, ", nice=%d", cfg->nice);
  else
    buf[0]='\0';
  cs_log("version=%s, build #%s, system=%s-%s-%s%s", CS_VERSION_X, CS_SVN_VERSION, CS_OS_CPU, CS_OS_HW, CS_OS_SYS, buf);
  cs_log("max. clients=%d, client max. idle=%d sec",
#ifdef CS_ANTICASC
         CS_MAXPID-3, cfg->cmaxidle);
#else
         CS_MAXPID-2, cfg->cmaxidle);
#endif
  if( cfg->max_log_size )
    sprintf((char *)buf, "%d Kb", cfg->max_log_size);
  else
    strcpy((char *)buf, "unlimited");
  cs_log("max. logsize=%s", buf);
  cs_log("client timeout=%lu ms, fallback timeout=%lu ms, cache delay=%d ms",
         cfg->ctimeout, cfg->ftimeout, cfg->delay);
#ifdef CS_NOSHM
  cs_log("shared memory initialized (size=%d)", shmsize);
#else
  cs_log("shared memory initialized (size=%d)", shmsize);
#endif
}

void cs_waitforcardinit()
{
	if (cfg->waitforcards)
	{
  		cs_log("waiting for local card init");
		int card_init_done, i;
		cs_sleepms(3000);  // short sleep for card detect to work proberly
		do {
			card_init_done = 1;
			for (i = 0; i < CS_MAXREADER; i++) {
				if (!(reader[i].typ & R_IS_CASCADING) && reader[i].card_status == CARD_NEED_INIT) {
					card_init_done = 0;
					break;
				}
			}
			cs_sleepms(300); // wait a little bit
			alarm(cfg->cmaxidle + cfg->ctimeout / 1000 + 1); 
		} while (!card_init_done);
  		cs_log("init for all local cards done");
	}
}

int accept_connection(int i, int j) {
	struct   sockaddr_in cad;
	int scad,n,o;
	scad = sizeof(cad);
	uchar    buf[2048];
	int      fdp[2];

	if (ph[i].type==MOD_CONN_UDP) {

		if ((n=recvfrom(ph[i].ptab->ports[j].fd, buf+3, sizeof(buf)-3, 0, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {
			int idx;
			idx=idx_from_ip(cs_inet_order(cad.sin_addr.s_addr), ntohs(cad.sin_port));

			if (!idx) {
				if (pipe(fdp)) {
					cs_log("Cannot create pipe (errno=%d)", errno);
					return 0;
				}
				o=cs_fork(cs_inet_order(cad.sin_addr.s_addr), ntohs(cad.sin_port));

				if (o<0) return 0;

				client[o].ufd=fdp[1];
				client[o].pfd=fdp[0];

				client[o].is_server=1; //FIXME global should be local per thread

				client[o].ctyp=i;
				client[o].port_idx=j;
				client[o].udp_fd=ph[i].ptab->ports[j].fd;
				client[o].udp_sa=cad;

             	       	client[o].ip=cs_inet_order(cad.sin_addr.s_addr);
				client[o].port=ntohs(cad.sin_port);
				client[o].typ='c';

				//if (ph[client[o].ctyp].watchdog)
				//	alarm(cfg->cmaxidle + cfg->ctimeout / 1000 + 1);

				//ph[i].s_handler(cad);   // never return
				pthread_create(&client[o].thread, NULL, ph[i].s_handler, (void *) &client[o]); //pass client[o] since o is local variable that will not survive the thread
				pthread_detach(client[o].thread);
			} else {
				unsigned short rl;
				rl=n;
				buf[0]='U';
				memcpy(buf+1, &rl, 2);
				if (!write(client[idx].ufd, buf, n+3)) return 0;
			}
		}
	} else { //TCP

		int pfd3;
		if ((pfd3=accept(ph[i].ptab->ports[j].fd, (struct sockaddr *)&cad, (socklen_t *)&scad))>0) {
			o=cs_fork(cs_inet_order(cad.sin_addr.s_addr), ntohs(cad.sin_port));

			if (o<0) return 0;			

			client[o].ctyp=i;
			client[o].udp_fd=pfd3;
			client[o].port_idx=j;

			client[o].pfd=pfd3;

			client[o].is_server=1; //FIXME global should be local per thread

			client[o].ip=cs_inet_order(cad.sin_addr.s_addr);
			client[o].port=ntohs(cad.sin_port);
			client[o].typ='c';

			//if (ph[client[o].ctyp].watchdog)
			//	alarm(cfg->cmaxidle + cfg->ctimeout / 1000 + 1);

			pthread_create(&client[o].thread, NULL, ph[i].s_handler, (void*) &client[o]);
			pthread_detach(client[o].thread);
		}
	}
	return 0;
}
//void cs_resolve()
//{
//  int i;
//  for (i=0; i<CS_MAXREADER; i++)
//    if (reader[i].enable && !reader[i].deleted && (reader[i].cs_idx) && (reader[i].typ & R_IS_NETWORK) && (reader[i].typ!=R_CONSTCW))
//      hostResolve(i);
//}

//static void loop_resolver(void *dummy __attribute__ ((unused)))
//{
//  cs_sleepms(1000); // wait for reader
//  while(cfg->resolvedelay > 0)
//  {
//    cs_resolve();
//    cs_sleepms(1000*cfg->resolvedelay);
//  }
//}


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
                                        
  strcpy(cs_tmpdir, d);
  char *p = cs_tmpdir;
  while(*p) p++;
  p--;
  if (*p != '/' && *p != '\\')
    strcat(cs_tmpdir, "/");
  strcat(cs_tmpdir, "_oscam");
#else
  strcpy(cs_tmpdir, "/tmp/.oscam");
#endif
  mkdir(cs_tmpdir, S_IRWXU);
  return cs_tmpdir;
}
                                                              
                                                                            
int main (int argc, char *argv[])
{

#ifdef CS_LED
  cs_switch_led(LED1A, LED_DEFAULT);
  cs_switch_led(LED1A, LED_ON);
#endif

  //struct   sockaddr_in cad;     /* structure to hold client's address */
  //int      scad;                /* length of address */
  //int      fd;                  /* socket descriptors */
  int      i, j;
  int      bg=0;
  int      gfd; //nph,
  int      fdp[2];
  //uchar    buf[2048];
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
#ifdef MODULE_CONSTCW
           module_constcw,
#endif
#ifdef CS_WITH_GBOX
           module_gbox,
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
	reader_tongfang,
	0
  };

  while ((i=getopt(argc, argv, "bc:t:d:hm:"))!=EOF)
  {
    switch(i)
    {
      case 'b': bg=1;
                break;
      case 'c': cs_strncpy(cs_confdir, optarg, sizeof(cs_confdir));
                break;
      case 'd': cs_dblevel=atoi(optarg);
                break;
      case 't': cs_strncpy(cs_tmpdir, optarg, sizeof(cs_tmpdir));
      case 'm':
#ifdef CS_NOSHM
                cs_strncpy(cs_memfile, optarg, sizeof(cs_memfile));
                break;
#endif
      case 'h':
      default : usage();
    }
  }
  if (cs_confdir[strlen(cs_confdir)]!='/') strcat(cs_confdir, "/");
  init_shm();
  init_config();
  init_stat();
  cfg->debuglvl = cs_dblevel; // give static debuglevel to outer world
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


  cs_log("auth size=%d", sizeof(struct s_auth));

  init_sidtab();
  init_readerdb();
  init_userdb(&cfg->account);
  init_signal();
  init_srvid();
  init_tierid();
  //Todo #ifdef CCCAM
  init_provid();

  init_len4caid();
#ifdef IRDETO_GUESSING
  init_irdeto_guess_tab(); 
#endif


  if (pipe(fdp))
  {
    cs_log("Cannot create pipe (errno=%d)", errno);
    cs_exit(1);
  }
  mfdr=fdp[0];
  fd_c2m=fdp[1];
  gfd=mfdr+1;

#ifdef OS_MACOSX
  if (bg && daemon_compat(1,0))
#else
  if (bg && daemon(1,0))
#endif
  {
    cs_log("Error starting in background (errno=%d)", errno);
    cs_exit(1);
  }

  if (cfg->pidfile != NULL)
  {
    FILE *fp;
    if (!(fp=fopen(cfg->pidfile, "w")))
    {
      cs_log("Cannot open pid-file (errno=%d)", errno);
      cs_exit(1);
    }
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
  }

#ifndef OS_CYGWIN32
  // /tmp/oscam.version file (Uptime + Version)
  char targetfile[256];
  snprintf(targetfile, 255,"%s%s", get_tmp_dir(), "/oscam.version");
  FILE *fp;

  if (!(fp=fopen(targetfile, "w"))) {
	  cs_log("Cannot open %s (errno=%d)", targetfile, errno);
  } else {
	  time_t now = time((time_t)0);
	  struct tm *st;
	  st = localtime(&now);
	  fprintf(fp, "uxstarttime: %d\n", (int)now);
	  fprintf(fp, "starttime: %02d.%02d.%02d", st->tm_mday, st->tm_mon+1, st->tm_year%100);
	  fprintf(fp, " %02d:%02d:%02d\n", st->tm_hour, st->tm_min, st->tm_sec);
	  fprintf(fp, "version: %s#%s\n", CS_VERSION, CS_SVN_VERSION);
	  fprintf(fp, "maxpid: %d\n", CS_MAXPID);
#ifdef WEBIF
	  fprintf(fp, "webifsupport: yes\n");
#else
	  fprintf(fp, "webifsupport: no\n");
#endif
#ifdef HAVE_DVBAPI
	  fprintf(fp, "dvbapisupport: yes\n");
#else
	  fprintf(fp, "dvbapisupport: no\n");
#endif
#ifdef CS_WITH_GBOX
	  fprintf(fp, "gboxsupport: yes\n");
#else
	  fprintf(fp, "gboxsupport: no\n");
#endif
#ifdef CS_ANTICASC
	  fprintf(fp, "anticascsupport: yes\n");
#else
	  fprintf(fp, "anticascsupport: no\n");
#endif
#ifdef CS_WITH_DOUBLECHECK
	  fprintf(fp, "ECM doublecheck: yes\n");
#else
	  fprintf(fp, "ECM doublecheck: no\n");
#endif
	  fclose(fp);
  }
#endif


#ifdef AZBOX
  openxcas_debug_message_onoff(1);  // debug

  if (openxcas_open_with_smartcard("oscamCAS") < 0) {
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
	client[0].last=time((time_t *)0);

	//start_thread((void *) &cs_logger, "logger", 'l'); //97;

#ifdef WEBIF
  if(cfg->http_port == 0) 
    cs_log("http disabled"); 
  else 
    start_thread((void *) &http_srv, "http", 'h');
#endif

	init_cardreader();

	//cs_waitforcardinit();

#ifdef CS_LED
	cs_switch_led(LED1A, LED_OFF);
	cs_switch_led(LED1B, LED_ON);
#endif

#ifdef CS_ANTICASC
	if( !cfg->ac_enabled )
		cs_log("anti cascading disabled");
	else {
		init_ac();
		start_thread((void *) &start_anticascader, "anticascader", 'a'); // 96
		
	}
#endif

	for (i=0; i<CS_MAX_MOD; i++)
		if (ph[i].type & MOD_CONN_SERIAL)   // for now: oscam_ser only
			if (ph[i].s_handler)
				ph[i].s_handler(i);

	//cs_close_log();
	while (1) {
		fd_set fds;

		do {
			FD_ZERO(&fds);
			FD_SET(mfdr, &fds);
			for (i=0; i<CS_MAX_MOD; i++)
				if ( (ph[i].type & MOD_CONN_NET) && ph[i].ptab )
					for (j=0; j<ph[i].ptab->nports; j++)
						if (ph[i].ptab->ports[j].fd)
							FD_SET(ph[i].ptab->ports[j].fd, &fds);
			errno=0;
			select(gfd, &fds, 0, 0, 0);
		} while (errno==EINTR);

		client[0].last=time((time_t *)0);
		
		if (FD_ISSET(mfdr, &fds)) {
			process_master_pipe();
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

#ifdef AZBOX
  if (openxcas_close() < 0) {
    cs_log("openxcas: could not close");
  }
#endif

	cs_exit(1);
}

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
			//cs_log("Cannot open file \"%s\" (errno=%d)", ledfile, errno);
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
