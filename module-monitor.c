#include "globals.h"
#ifdef CS_WITH_GBOX
#  include "csgbox/gbox.h"
#  define CS_VERSION_X  CS_VERSION "-gbx-" GBXVERSION
#else
#  define CS_VERSION_X  CS_VERSION
#endif

static	int auth=0;

static void monitor_check_ip()
{
  int ok=0;
  struct s_ip *p_ip;

  if (auth) return;
  for (p_ip=cfg->mon_allowed; (p_ip) && (!ok); p_ip=p_ip->next)
    ok=((client[cs_idx].ip>=p_ip->ip[0]) && (client[cs_idx].ip<=p_ip->ip[1]));
  if (!ok)
  {
    cs_auth_client((struct s_auth *)0, "invalid ip");
    cs_exit(0);
  }
}

static void monitor_auth_client(char *usr, char *pwd)
{
  struct s_auth *account;

  if (auth) return;
  if ((!usr) || (!pwd))
  {
    cs_auth_client((struct s_auth *)0, NULL);
    cs_exit(0);
  }
  for (account=cfg->account, auth=0; (account) && (!auth);)
  {
    if (account->monlvl)
      auth=!(strcmp(usr, account->usr) | strcmp(pwd, account->pwd));
    if (!auth)
      account=account->next;
  }
  if (!auth)
  {
    cs_auth_client((struct s_auth *)0, "invalid account");
    cs_exit(0);
  }
  if (cs_auth_client(account, NULL))
    cs_exit(0);
}

static int secmon_auth_client(uchar *ucrc)
{
  ulong crc;
  struct s_auth *account;

  if (auth)
  {
    int s=memcmp(client[cs_idx].ucrc, ucrc, 4);
    if (s)
      cs_log("wrong user-crc or garbage !?");
    return(!s);
  }
  client[cs_idx].crypted=1;
  crc=(ucrc[0]<<24) | (ucrc[1]<<16) | (ucrc[2]<<8) | ucrc[3];
  for (account=cfg->account; (account) && (!auth); account=account->next)
    if ((account->monlvl) &&
       (crc==crc32(0L, MD5((unsigned char *)account->usr, strlen(account->usr), NULL), 16)))
    {
      memcpy(client[cs_idx].ucrc, ucrc, 4);
      aes_set_key((char *)MD5((unsigned char *)account->pwd, strlen(account->pwd), NULL));
      if (cs_auth_client(account, NULL))
        cs_exit(0);
      auth=1;
    }
  if (!auth)
  {
    cs_auth_client((struct s_auth *)0, "invalid user");
    cs_exit(0);
  }
  return(auth);
}

int monitor_send_idx(int idx, char *txt)
{
  int l;
  unsigned char buf[256+32];
  if (!client[idx].udp_fd)
    return(-1);
  usleep(500L);		// avoid lost udp-pakets ..
  if (!client[idx].crypted)
    return(sendto(client[idx].udp_fd, txt, strlen(txt), 0,
                 (struct sockaddr *)&client[idx].udp_sa,
                 sizeof(client[idx].udp_sa)));
  buf[0]='&';
  buf[9]=l=strlen(txt);
  l=boundary(4, l+5)+5;
  memcpy(buf+1, client[idx].ucrc, 4);
  strcpy((char *)buf+10, txt);
  memcpy(buf+5, i2b(4, crc32(0L, buf+10, l-10)), 4);
  aes_encrypt_idx(idx, buf+5, l-5);
  return(sendto(client[idx].udp_fd, buf, l, 0,
               (struct sockaddr *)&client[idx].udp_sa,
               sizeof(client[idx].udp_sa)));
}

#define monitor_send(t) monitor_send_idx(cs_idx, t)

static int monitor_recv(uchar *buf, int l)
{
  int n;
  uchar nbuf[3] = { 'U', 0, 0 };
  static int bpos=0;
  static uchar *bbuf=NULL;
  if (!bbuf)
  {
    bbuf=(uchar *)malloc(l);
    if (!bbuf)
    {
      cs_log("Cannot allocate memory (errno=%d)", errno);
      cs_exit(1);
    }
  }
  if (bpos)
    memcpy(buf, bbuf, n=bpos);
  else
    n=recv_from_udpipe(buf);
  bpos=0;
  if (!n) return(buf[0]=0);
  if (buf[0]=='&')
  {
    int bsize;
    if (n<21)	// 5+16 is minimum
    {
      cs_log("packet to short !");
      return(buf[0]=0);
    }
    if (!secmon_auth_client(buf+1))
      return(buf[0]=0);
    aes_decrypt(buf+5, 16);
    bsize=boundary(4, buf[9]+5)+5;
// cs_log("n=%d bsize=%d", n, bsize);
    if (n>bsize)
    {
// cs_log("DO >>>> copy-back");
      memcpy(bbuf, buf+bsize, bpos=n-bsize);
      n=bsize;
      if (!write(client[cs_idx].ufd, nbuf, sizeof(nbuf))) cs_exit(1);	// trigger new event
    }
    else if (n<bsize)
    {
      cs_log("packet-size mismatch !");
      return(buf[0]=0);
    }
    aes_decrypt(buf+21, n-21);
    if (memcmp(buf+5, i2b(4, crc32(0L, buf+10, n-10)), 4))
    {
      cs_log("CRC error ! wrong password ?");
      return(buf[0]=0);
    }
    n=buf[9];
    memmove(buf, buf+10, n);
  }
  else
  {
    uchar *p;
    monitor_check_ip();
    buf[n]='\0';
    if ((p=(uchar *)strchr((char *)buf, 10)) && (bpos=n-(p-buf)-1))
    {
      memcpy(bbuf, p+1, bpos);
      n=p-buf;
      if (!write(client[cs_idx].ufd, nbuf, sizeof(nbuf))) cs_exit(1);	// trigger new event
    }
  }
  buf[n]='\0';
  n=strlen(trim((char *)buf));
  if (n) client[cs_idx].last=time((time_t *) 0);
  return(n);
}

static void monitor_send_info(char *txt, int last)
{
  static int seq=0, counter=0;
  static char btxt[256] = {0};
  char buf[8];
  if (txt)
  {
    if (!btxt[0])
    {
      counter=0;
      txt[2]='B';
    }
    else
      counter++;
    sprintf(buf, "%03d", counter);
    memcpy(txt+4, buf, 3);
    txt[3]='0'+seq;
  }
  else
    if (!last)
      return;

  if (!last)
  {
    if (btxt[0]) monitor_send(btxt);
    strncpy(btxt, txt, sizeof(btxt));
    return;
  }

  if (txt && btxt[0])
  {
    monitor_send(btxt);
    txt[2]='E';
    strncpy(btxt, txt, sizeof(btxt));
  }
  else
  {
    if (txt)
      strncpy(btxt, txt, sizeof(btxt));
    btxt[2]=(btxt[2]=='B') ? 'S' : 'E';
  }

  if (btxt[0])
  {
    monitor_send(btxt);
    seq=(seq+1)%10;
  }
  btxt[0]=0;
}

static int cs_idx2ridx(int idx)
{
  int i;
  for (i=0; i<CS_MAXREADER; i++)
    if (reader[i].cs_idx==idx)
      return(i);
  return(-1);
}

static char *monitor_get_srvname(int id)
{
  struct s_srvid *this=cfg->srvid;
  static char name[83];
  for (name[0]=0; this && (!name[0]); this=this->next)
    if (this->srvid==id)
      strncpy(name, this->name, 32);
  if (!name[0]) sprintf(name, "[%04X]", id);
  if (!id) name[0]='\0';
  return(name);
}

static char *monitor_get_proto(int idx)
{
  int i;
  char *ctyp;
  switch(client[idx].typ)
  {
    case 's': ctyp="server"   ; break;
    case 'n': ctyp="resolver" ; break;
    case 'l': ctyp="logger"   ; break;
    case 'p':
    case 'r': if ((i=cs_idx2ridx(idx))<0)	// should never happen
                ctyp=(client[idx].typ=='p') ? "proxy" : "reader";
              else
              {
                switch(reader[i].typ)		// TODO like ph
                {
                  case R_MOUSE   : ctyp="mouse";    break;
                  case R_INTERNAL: ctyp="intern";   break;
                  case R_SMART   : ctyp="smartreader";    break;
                  case R_CAMD35  : ctyp="camd 3.5x";break;
                  case R_CAMD33  : ctyp="camd 3.3x";break;
                  case R_NEWCAMD : ctyp="newcamd";  break;
                  case R_RADEGAST: ctyp="radegast"; break;
                  case R_SERIAL  : ctyp="serial";   break;
                  case R_GBOX    : ctyp="gbox";     break;
                  default        : ctyp="unknown";  break;
                }
              }
              break;
    default : ctyp=ph[client[idx].ctyp].desc;
  }
  return(ctyp);
}

static char *monitor_client_info(char id, int i)
{
  static char sbuf[256];

  sbuf[0]='\0';
  if (client[i].pid)
  {
    char ldate[16], ltime[16], *usr;
    int lsec, isec, cnr, con, cau;
    time_t now;
    struct tm *lt;
    now=time((time_t)0);

    if ((cfg->mon_hideclient_to <= 0) ||
        (((now-client[i].lastecm)/60)<cfg->mon_hideclient_to) ||
        (((now-client[i].lastemm)/60)<cfg->mon_hideclient_to) ||
        (client[i].typ!='c'))
    {
      lsec=now-client[i].login;
      isec=now-client[i].last;
      usr=client[i].usr;
      if (((client[i].typ=='r') || (client[i].typ=='p')) &&
          (con=cs_idx2ridx(i))>=0)
        usr=reader[con].label;
      if (client[i].dup)
        con=2;
      else
        if ((client[i].tosleep) &&
            (now-client[i].lastswitch>client[i].tosleep))
          con=1;
        else
          con=0;
      if (i-cdiff>0)
        cnr=i-cdiff;
      else
        cnr=(i>1) ? i-1 : 0;
      if( (cau=client[i].au+1) )
        if ((now-client[i].lastemm)/60>cfg->mon_aulow)
          cau=-cau;
      lt=localtime(&client[i].login);
      sprintf(ldate, "%2d.%02d.%02d",
                     lt->tm_mday, lt->tm_mon+1, lt->tm_year % 100);
      sprintf(ltime, "%2d:%02d:%02d",
                     lt->tm_hour, lt->tm_min, lt->tm_sec);
      sprintf(sbuf, "[%c--CCC]%d|%c|%d|%s|%d|%d|%s|%d|%s|%s|%s|%d|%04X:%04X|%s|%d|%d\n",
              id, client[i].pid, client[i].typ, cnr, usr, cau, client[i].crypted,
              cs_inet_ntoa(client[i].ip), client[i].port, monitor_get_proto(i),
              ldate, ltime, lsec, client[i].last_caid, client[i].last_srvid,
              monitor_get_srvname(client[i].last_srvid), isec, con);
    }
  }
  return(sbuf);
}

static void monitor_process_info()
{
  int i;
  time_t now;

  now=time((time_t)0);
  for (i=0; i<CS_MAXPID; i++)
    if ((cfg->mon_hideclient_to <= 0) ||
        (((now-client[i].lastecm)/60)<cfg->mon_hideclient_to) ||
        (((now-client[i].lastemm)/60)<cfg->mon_hideclient_to) ||
        (client[i].typ!='c'))
      if (client[i].pid)
      {
        if ((client[cs_idx].monlvl<2) && (client[i].typ!='s'))
        {
          if ((strcmp(client[cs_idx].usr, client[i].usr)) ||
              ((client[i].typ!='c') && (client[i].typ!='m')))
            continue;
        }
        monitor_send_info(monitor_client_info('I', i), 0);
      }
  monitor_send_info(NULL, 1);
}

static void monitor_send_details(char *txt, int pid)
{
  char buf[256];
  snprintf(buf, 255, "[D-----]%d|%s\n", pid, txt);
  monitor_send_info(buf, 0);
}

static void monitor_send_details_version()
{
  char buf[256];
  sprintf(buf, "[A-0000]version=%s, build=%s, system=%s%s", CS_VERSION_X, CS_SVN_VERSION, cs_platform(buf+100), buf+200);
  monitor_send_info(buf, 1);
}

static void monitor_process_details_master(char *buf, int pid)
{
  if (cfg->nice!=99)
    sprintf(buf+200, ", nice=%d", cfg->nice);
  else
    buf[200]='\0';
  sprintf(buf, "version=%s#%s, system=%s%s", CS_VERSION_X, CS_SVN_VERSION, cs_platform(buf+100), buf+200);
  monitor_send_details(buf, pid);

  sprintf(buf, "max. clients=%d, client max. idle=%d sec", CS_MAXPID-2, cfg->cmaxidle);
  monitor_send_details(buf, pid);

  if( cfg->max_log_size )
    sprintf(buf+200, "%d Kb", cfg->max_log_size);
  else
    strcpy(buf+200, "unlimited");
  sprintf(buf, "max. logsize=%s", buf+200);
  monitor_send_details(buf, pid);

  sprintf(buf, "client timeout=%lu ms, cache delay=%ld ms", cfg->ctimeout, cfg->delay);
  monitor_send_details(buf, pid);

//#ifdef CS_NOSHM
//  sprintf(buf, "shared memory initialized (size=%d, fd=%d)", shmsize, shmid);
//#else
//  sprintf(buf, "shared memory initialized (size=%d, id=%d)", shmsize, shmid);
//#endif
//  monitor_send_details(buf, pid);
}

#ifdef CS_RDR_INIT_HIST
static void monitor_process_details_reader(int pid, int idx)
{
  int r_idx;
  char *p;
  if ((r_idx=cs_idx2ridx(idx))>=0)
    for (p=(char *)reader[r_idx].init_history; *p; p+=strlen(p)+1)
      monitor_send_details(p, pid);
  else
    monitor_send_details("Missing reader index !", pid);
}
#endif

static void monitor_process_details(char *arg)
{
  int pid, idx;
  char sbuf[256];
  if (!arg) return;
  if ((idx=idx_from_pid(pid=atoi(arg)))<0)
    monitor_send_details("Invalid PID", pid);
  else
  {
    monitor_send_info(monitor_client_info('D', idx), 0);
    switch(client[idx].typ)
    {
      case 's':
        monitor_process_details_master(sbuf, pid);
        break;
      case 'c': case 'm':
        break;
      case 'r':
#ifdef CS_RDR_INIT_HIST
        monitor_process_details_reader(pid, idx);
#endif
        break;
      case 'p':
        break;
    }
  }
  monitor_send_info(NULL, 1);
}

static void monitor_send_login(void)
{
  char buf[64];
  if (auth)
    sprintf(buf, "[A-0000]1|%s logged in\n", client[cs_idx].usr);
  else
    strcpy(buf, "[A-0000]0|not logged in\n");
  monitor_send_info(buf, 1);
}

static void monitor_login(char *usr)
{
  char *pwd=NULL;
  if ((usr) && (pwd=strchr(usr, ' ')))
    *pwd++=0;
  if (pwd)
    monitor_auth_client(trim(usr), trim(pwd));
  else
    monitor_auth_client(NULL, NULL);
  monitor_send_login();
}

static void monitor_logsend(char *flag)
{
#ifdef CS_LOGHISTORY
  int i;
#endif
  if (strcmp(flag, "on")) {
      if (strcmp(flag, "onwohist")) {
          client[cs_idx].log=0;
          return;
      }
  }

  if (client[cs_idx].log)	// already on
    return;
#ifdef CS_LOGHISTORY
   if (!strcmp(flag, "on")){
     for (i=(*loghistidx+3) % CS_MAXLOGHIST; i!=*loghistidx; i=(i+1) % CS_MAXLOGHIST)
     {
       char *p_usr, *p_txt;
       p_usr=(char *)(loghist+(i*CS_LOGHISTSIZE));
       p_txt=p_usr+32;
       if ((p_txt[0]) &&
          ((client[cs_idx].monlvl>1) || (!strcmp(p_usr, client[cs_idx].usr))))
       {
         char sbuf[8];
         sprintf(sbuf, "%03d", client[cs_idx].logcounter);
         client[cs_idx].logcounter=(client[cs_idx].logcounter+1) % 1000;
         memcpy(p_txt+4, sbuf, 3);
         monitor_send(p_txt);
       }
     }
   }
#endif
  client[cs_idx].log=1;
}
static void monitor_set_debuglevel(char *flag)
{
    cs_dblevel^=atoi(flag);
    kill(client[0].pid, SIGUSR1);
}

static int monitor_process_request(char *req)
{
  int i, rc;
  char *cmd[]={"login", "exit", "log", "status", "shutdown", "reload", "details", "version", "debug"};
  char *arg;
  if( (arg=strchr(req, ' ')) )
  {
    *arg++=0;
    trim(arg);
  }
  trim(req);
  if ((!auth) && (strcmp(req, cmd[0])))
    monitor_login(NULL);
  for (rc=1, i=0; i<9; i++)
    if (!strcmp(req, cmd[i]))
    {
      switch(i)
      {
        case  0: monitor_login(arg); break;             // login
        case  1: rc=0; break; // exit
        case  2: monitor_logsend(arg); break;           // log
        case  3: monitor_process_info(); break;         // status
        case  4: if (client[cs_idx].monlvl>3)
                   kill(client[0].pid, SIGQUIT);        // shutdown
                 break;
        case  5: if (client[cs_idx].monlvl>2)
                   kill(client[0].pid, SIGHUP);         // reload
                 break;
        case  6: monitor_process_details(arg); break;   // details
        case  7: monitor_send_details_version(); break;
	case  8: if (client[cs_idx].monlvl>3)
		  monitor_set_debuglevel(arg);          // debuglevel
		 break; 
        default: continue;
      }
      break;
    }
  return(rc);
}

static void monitor_server()
{
  int n;
  client[cs_idx].typ='m';
  while (((n=process_input(mbuf, sizeof(mbuf), cfg->cmaxidle))>=0) &&
           monitor_process_request((char *)mbuf));
  cs_disconnect_client();
}

void module_monitor(struct s_module *ph)
{
  static PTAB ptab;
  ptab.ports[0].s_port = cfg->mon_port;
  ph->ptab = &ptab;
  ph->ptab->nports = 1;

  if (cfg->mon_aulow<1)
    cfg->mon_aulow=30;
  strcpy(ph->desc, "monitor");
  ph->type=MOD_CONN_UDP;
  ph->multi=0;
  ph->watchdog=1;
  ph->s_ip=cfg->mon_srvip;
  ph->s_handler=monitor_server;
  ph->recv=monitor_recv;
//  ph->send_dcw=NULL;
}
