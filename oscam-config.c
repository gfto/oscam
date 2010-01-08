#include "globals.h"
#ifdef CS_WITH_BOXKEYS
#  include "oscam-boxkeys.np"
#endif

static char *cs_conf="oscam.conf";
static char *cs_user="oscam.user";
static char *cs_srvr="oscam.server";
static char *cs_srid="oscam.srvid";
static char *cs_l4ca="oscam.guess";
static char *cs_cert="oscam.cert";
static char *cs_sidt="oscam.services";
//static char *cs_ird="oscam.ird";
#ifdef CS_ANTICASC
static char *cs_ac="oscam.ac";
#endif

static char token[4096];

typedef enum cs_proto_type
{
  TAG_GLOBAL,   // must be first !
  TAG_MONITOR,  // monitor
  TAG_CAMD33,   // camd 3.3x
  TAG_CAMD35,   // camd 3.5x UDP
  TAG_NEWCAMD,  // newcamd
  TAG_RADEGAST, // radegast
  TAG_SERIAL,   // serial (static)
  TAG_CS357X,   // camd 3.5x UDP
  TAG_CS378X,    // camd 3.5x TCP
  TAG_GBOX, // gbox
  TAG_CCCAM,  // cccam
  TAG_DVBAPI
#ifdef CS_ANTICASC
  ,TAG_ANTICASC // anti-cascading
#endif
} cs_proto_type_t;

static char *cctag[]={"global", "monitor", "camd33", "camd35", 
                      "newcamd", "radegast", "serial", "cs357x", "cs378x", "gbox", "cccam", "dvbapi",
#ifdef CS_ANTICASC
                      "anticasc",
#endif
                       NULL};

#ifdef DEBUG_SIDTAB
static void show_sidtab(struct s_sidtab *sidtab)
{
  for (; sidtab; sidtab=sidtab->next)
  {
    int i;
    char buf[1024];
    cs_log("label=%s", sidtab->label);
    sprintf(buf, "caid(%d)=", sidtab->num_caid);
    for (i=0; i<sidtab->num_caid; i++)
      sprintf(buf+strlen(buf), "%04X ", sidtab->caid[i]);
    cs_log("%s", buf);
    sprintf(buf, "provider(%d)=", sidtab->num_provid);
    for (i=0; i<sidtab->num_provid; i++)
      sprintf(buf+strlen(buf), "%08X ", sidtab->provid[i]);
    cs_log("%s", buf);
    sprintf(buf, "services(%d)=", sidtab->num_srvid);
    for (i=0; i<sidtab->num_srvid; i++)
      sprintf(buf+strlen(buf), "%04X ", sidtab->srvid[i]);
    cs_log("%s", buf);
  }
}
#endif

void chk_iprange(char *value, struct s_ip **base)
{
  int i = 0;
  char *ptr1, *ptr2;
  struct s_ip *lip, *cip;

  for (cip=lip=*base; cip; cip=cip->next)
    lip=cip;
  if (!(cip=malloc(sizeof(struct s_ip))))
  {
    fprintf(stderr, "Error allocating memory (errno=%d)\n", errno);
    exit(1);
  }
  if (*base)
    lip->next=cip;
  else
    *base=cip;

  memset(cip, 0, sizeof(struct s_ip));
  for (ptr1=strtok(value, ","); ptr1; ptr1=strtok(NULL, ","))
  {
  	if (i == 0) ++i;
  	else {
  		if (!(cip=malloc(sizeof(struct s_ip)))){
    		fprintf(stderr, "Error allocating memory (errno=%d)\n", errno);
    		exit(1);
  		}
  		lip->next = cip;
  		memset(cip, 0, sizeof(struct s_ip));
  	}
    if( (ptr2=strchr(trim(ptr1), '-')) )
    {
      *ptr2++='\0';
      cip->ip[0]=cs_inet_addr(trim(ptr1));
      cip->ip[1]=cs_inet_addr(trim(ptr2));
    }
    else
      cip->ip[0]=cip->ip[1]=cs_inet_addr(ptr1);
    lip = cip;
  }
}

static void chk_caidtab(char *caidasc, CAIDTAB *ctab)
{
  int i;
  char *ptr1, *ptr2, *ptr3;
  for (i=0, ptr1=strtok(caidasc, ","); (i<CS_MAXCAIDTAB) && (ptr1); ptr1=strtok(NULL, ","))
  {
    ulong caid, mask, cmap;
    if( (ptr3=strchr(trim(ptr1), ':')) )
      *ptr3++='\0';
    else
      ptr3="";
    if( (ptr2=strchr(trim(ptr1), '&')) )
      *ptr2++='\0';
    else
      ptr2="";
    if (((caid=a2i(ptr1, 2))|(mask=a2i(ptr2,-2))|(cmap=a2i(ptr3, 2))) < 0x10000)
    {
      ctab->caid[i]=caid;
      ctab->mask[i]=mask;
      ctab->cmap[i++]=cmap;
    }
//    else
//      cs_log("WARNING: wrong CAID in %s -> ignored", cs_user);
  }
}

static void chk_tuntab(char *tunasc, TUNTAB *ttab)
{
  int i;
  char *ptr1, *ptr2, *ptr3;
  for (i=0, ptr1=strtok(tunasc, ","); (i<CS_MAXTUNTAB) && (ptr1); ptr1=strtok(NULL, ","))
  {
    ulong bt_caidfrom, bt_caidto, bt_srvid;
    if( (ptr3=strchr(trim(ptr1), ':')) )
      *ptr3++='\0';
    else
      ptr3="";
    if( (ptr2=strchr(trim(ptr1), '.')) )
      *ptr2++='\0';
    else
      ptr2="";
    if ((bt_caidfrom=a2i(ptr1, 2))|(bt_srvid=a2i(ptr2,-2))|(bt_caidto=a2i(ptr3, 2)))
    {
      ttab->bt_caidfrom[i]=bt_caidfrom;
      ttab->bt_caidto[i]=bt_caidto;
      ttab->bt_srvid[i++]=bt_srvid;
    }
//    else
//      cs_log("WARNING: wrong Betatunnel in %s -> ignored", cs_user);
  }
}

static void chk_services(char *labels, ulong *sidok, ulong *sidno)
{
  int i;
  char *ptr;
  SIDTAB *sidtab;
  *sidok=*sidno=0;
  for (ptr=strtok(labels, ","); ptr; ptr=strtok(NULL, ","))
    for (trim(ptr), i=0, sidtab=cfg->sidtab; sidtab; sidtab=sidtab->next, i++)
    {
      if (!strcmp(sidtab->label, ptr)) *sidok|=(1<<i);
      if ((ptr[0]=='!') && (!strcmp(sidtab->label, ptr+1))) *sidno|=(1<<i);
    }
}

static 
void chk_ftab(char *zFilterAsc, FTAB *ftab, const char *zType, const char *zName,
              const char *zFiltName)
{
  int i,j;
  char *ptr1,*ptr2,*ptr3;
  char *ptr[CS_MAXFILTERS] = {0};
  
  memset(ftab, 0, sizeof(FTAB));
  for( i=0, ptr1=strtok(zFilterAsc, ";"); (i<CS_MAXFILTERS) && (ptr1); ptr1=strtok(NULL, ";"), i++ )
  {
    //cs_log("ptr1=%s", ptr1);
    ptr[i] = ptr1;
    if( (ptr2=strchr(trim(ptr1), ':')) ) 
    {
      //cs_log("ptr2=%s", ptr2);
      *ptr2++='\0';
      //cs_log("ptr2=%s", ptr2);
      ftab->filts[i].caid = (ushort)a2i(ptr1, 4);
      //cs_log("caid=%04X", ftab->filts[i].caid);
      ptr[i] = ptr2;
    }
    else if (zFiltName && zFiltName[0]=='c')
    {
      cs_log("PANIC: CAID field not found in CHID parameter!");
      cs_exit(1);
    }
    ftab->nfilts++;
  }

  if( ftab->nfilts ) cs_debug("%s '%s' %s filter(s):", zType, zName, zFiltName);
  for( i=0; i<ftab->nfilts; i++ ) 
  {
    cs_debug("CAID #%d: %04X", i, ftab->filts[i].caid);
    for( j=0, ptr3=strtok(ptr[i], ","); (j<CS_MAXPROV) && (ptr3); ptr3=strtok(NULL, ","), j++ )
    {
      ftab->filts[i].prids[j] = a2i(ptr3,6);
      ftab->filts[i].nprids++;
      cs_debug("%s #%d: %06X", zFiltName, j, ftab->filts[i].prids[j]);
    }
  }
  //cs_log("exit chk_ftab");
}

static void chk_cltab(char *classasc, CLASSTAB *clstab)
{
  int i;
  char *ptr1;
  for( i=0, ptr1=strtok(classasc, ","); (i<CS_MAXCAIDTAB) && (ptr1); ptr1=strtok(NULL, ",") )
  {
    ptr1=trim(ptr1);
    if( ptr1[0] == '!' )
      clstab->bclass[clstab->bn++] = (uchar)a2i(ptr1+1, 2);
    else
      clstab->aclass[clstab->an++] = (uchar)a2i(ptr1, 2);
  }
}

static void chk_port_tab(char *portasc, PTAB *ptab)
{
  int i,j,nfilts,ifilt,iport;
  char *ptr1,*ptr2,*ptr3;
  char *ptr[CS_MAXPORTS] = {0};
  int  port[CS_MAXPORTS] = {0};
  int previous_nports = ptab->nports;

  for (nfilts=i=previous_nports, ptr1=strtok(portasc, ";"); (i<CS_MAXCAIDTAB) && (ptr1); ptr1=strtok(NULL, ";"), i++)
  {
    ptr[i] = ptr1;
    if( (ptr2=strchr(trim(ptr1), '@')) ) 
    {
      *ptr2++='\0';
      ptab->ports[i].s_port = atoi(ptr1);
      ptr[i] = ptr2;
      port[i] = ptab->ports[i].s_port;
      ptab->nports++;
    }
    nfilts++;
  }

  if( nfilts==1 && strlen(portasc)<6 && ptab->ports[0].s_port == 0 ) {
    ptab->ports[0].s_port = atoi(portasc);
    ptab->nports = 1;
  }

  iport=ifilt = previous_nports;
  for (i=previous_nports; i<nfilts; i++) 
  {
    if( port[i]!=0 ) iport = i;
    for (j=0, ptr3=strtok(ptr[i], ","); (j<CS_MAXPROV) && (ptr3); ptr3=strtok(NULL, ","), j++)
    {
      if( (ptr2=strchr(trim(ptr3), ':')) ) 
      {
        *ptr2++='\0';
        ptab->ports[iport].ftab.nfilts++;
        ifilt = ptab->ports[iport].ftab.nfilts-1;
        ptab->ports[iport].ftab.filts[ifilt].caid = (ushort)a2i(ptr3, 4);
        ptab->ports[iport].ftab.filts[ifilt].prids[j] = a2i(ptr2, 6);
      } else {
        ptab->ports[iport].ftab.filts[ifilt].prids[j] = a2i(ptr3, 6);
      }
      ptab->ports[iport].ftab.filts[ifilt].nprids++;
    }
  }
}

#ifdef NOTUSED
static void chk_srvip(char *value, in_addr_t *ip)
{
  int i;
  char *ptr;
  for (i=0, ptr=strtok(value, ","); ptr; ptr=strtok(NULL, ","))
    if (i<8) ip[i++]=inet_addr(ptr);
}
#endif

static void chk_t_global(char *token, char *value)
{
  if (!strcmp(token, "serverip")) { cfg->srvip=inet_addr(value); return; }
  if (!strcmp(token, "logfile")) { strncpy(logfile, value, sizeof(logfile)-1); return; }
  if (!strcmp(token, "pidfile")) { strncpy(cfg->pidfile, value, sizeof(cfg->pidfile)-1); return; }
  if (!strcmp(token, "usrfile")) { strncpy(cfg->usrfile, value, sizeof(cfg->usrfile)-1); return; }
  if (!strcmp(token, "cwlogdir")) { strncpy(cfg->cwlogdir, value, sizeof(cfg->cwlogdir)-1); return; }
  if (!strcmp(token, "clienttimeout")) 
  {
      cfg->ctimeout = atoi(value);
      if (cfg->ctimeout < 100)
          cfg->ctimeout *= 1000;
      return;
  }
  if (!strcmp(token, "fallbacktimeout")) 
  {
      cfg->ftimeout = atoi(value);
      if (cfg->ftimeout < 100)
          cfg->ftimeout *= 1000;
      return;
  }

  if (!strcmp(token, "clientmaxidle")) { cfg->cmaxidle=atoi(value); return; }
  if (!strcmp(token, "cachedelay")) { cfg->delay=atoi(value); return; }
  if (!strcmp(token, "bindwait")) { cfg->bindwait=atoi(value); return; }
  if (!strcmp(token, "netprio")) { cfg->netprio=atoi(value); return; }
  if (!strcmp(token, "resolvedelay")) { cfg->resolvedelay=atoi(value); return; }
  if (!strcmp(token, "sleep")) { cfg->tosleep=atoi(value); return; }
  if (!strcmp(token, "unlockparental")) { cfg->ulparent=atoi(value); return; }
  if (!strcmp(token, "nice"))
  {
    cfg->nice=atoi(value);
    if ((cfg->nice<-20) || (cfg->nice>20)) cfg->nice=99;
    if (cfg->nice!=99) cs_setpriority(cfg->nice);  // ignore errors
    return;
  }
  if (!strcmp(token, "serialreadertimeout")) 
  {
    if (cfg->srtimeout < 100)
      cfg->srtimeout = atoi(value) * 1000;
    else
      cfg->srtimeout = atoi(value);
    if( cfg->srtimeout <=0 )
      cfg->srtimeout=1500;
    return;
  }
  if (!strcmp(token, "maxlogsize")) 
  {
    cfg->max_log_size=atoi(value);
    if( cfg->max_log_size <=10 )
      cfg->max_log_size=10;
    return;
  }
  if( !strcmp(token, "showecmdw")) { cfg->show_ecm_dw = atoi(value); return; }
  if( !strcmp(token, "waitforcards")) { cfg->waitforcards = atoi(value); return; }
  if( !strcmp(token, "preferlocalcards")) { cfg->preferlocalcards = atoi(value); return; }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in global section not recognized\n",token);
}

#ifdef CS_ANTICASC
static void chk_t_ac(char *token, char *value)
{
  if (!strcmp(token, "enabled")) 
  {
    cfg->ac_enabled=atoi(value);
    if( cfg->ac_enabled<=0 ) cfg->ac_enabled=0;
    else cfg->ac_enabled=1;
    return;
  }

  if (!strcmp(token, "numusers")) 
  {
    cfg->ac_users=atoi(value);
    if( cfg->ac_users<0 ) cfg->ac_users=0;
    return;
  }
  if (!strcmp(token, "sampletime")) 
  {
    cfg->ac_stime=atoi(value);
    if( cfg->ac_stime<0 ) cfg->ac_stime=2;
    return;
  }
  if (!strcmp(token, "samples")) 
  {
    cfg->ac_samples=atoi(value);
    if( cfg->ac_samples<2 || cfg->ac_samples>10) cfg->ac_samples=10;
    return;
  }
  if (!strcmp(token, "penalty")) 
  {
    cfg->ac_penalty=atoi(value);
    if( cfg->ac_penalty<0 ) cfg->ac_penalty=0;
    return;
  }
  if (!strcmp(token, "aclogfile"))
  {
    strncpy(cfg->ac_logfile, value, sizeof(cfg->ac_logfile)-1);
    return;
  }
  if( !strcmp(token, "fakedelay") )
  {
    cfg->ac_fakedelay=atoi(value);
    if( cfg->ac_fakedelay<100 || cfg->ac_fakedelay>1000 )
      cfg->ac_fakedelay=1000;
    return;
  }
  if( !strcmp(token, "denysamples") )
  {
    cfg->ac_denysamples=atoi(value);
    if( cfg->ac_denysamples<2 || cfg->ac_denysamples>cfg->ac_samples-1 )
      cfg->ac_denysamples=cfg->ac_samples-1;
    return;
  }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in anticascading section not recognized\n",token);
//#endif moved this endif up two lines, I think this was erroneous - dingo35
}
#endif

static void chk_t_monitor(char *token, char *value)
{
  if (!strcmp(token, "port")) { cfg->mon_port=atoi(value); return; }
  if (!strcmp(token, "serverip")) { cfg->mon_srvip=inet_addr(value); return; }
  if (!strcmp(token, "nocrypt")) { chk_iprange(value, &cfg->mon_allowed); return; }
  if (!strcmp(token, "aulow")) { cfg->mon_aulow=atoi(value); return; }
  if (!strcmp(token, "monlevel")) { cfg->mon_level=atoi(value); return; }
  if (!strcmp(token, "hideclient_to")) { cfg->mon_hideclient_to=atoi(value); return; }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in monitor section not recognized\n",token);
}

static void chk_t_camd33(char *token, char *value)
{
  if (!strcmp(token, "port")) { cfg->c33_port=atoi(value); return; }
  if (!strcmp(token, "serverip")) { cfg->c33_srvip=inet_addr(value); return; }
  if (!strcmp(token, "nocrypt")) { chk_iprange(value, &cfg->c33_plain); return; }
  if (!strcmp(token, "passive")) { cfg->c33_passive=(value[0]!='0'); return; }
  if (!strcmp(token, "key"))
  {
    if (key_atob(value, cfg->c33_key))
    {
      fprintf(stderr, "Configuration camd3.3x: Error in Key\n");
      exit(1);
    }
    cfg->c33_crypted=1;
    return;
  }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in camd33 section not recognized\n",token);
}

static void chk_t_camd35(char *token, char *value)
{
  if (!strcmp(token, "port")) { cfg->c35_port=atoi(value); return; }
  if (!strcmp(token, "serverip")) { cfg->c35_tcp_srvip=inet_addr(value); return; }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in camd35 section not recognized\n",token);
}

static void chk_t_camd35_tcp(char *token, char *value)
{
  if (!strcmp(token, "port")) { chk_port_tab(value, &cfg->c35_tcp_ptab); return; }
  if (!strcmp(token, "serverip")) { cfg->c35_tcp_srvip=inet_addr(value); return; }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in camd35 tcp section not recognized\n",token);
}

static void chk_t_newcamd(char *token, char *value)
{
  if (!strcmp(token, "port")) { chk_port_tab(value, &cfg->ncd_ptab); return; }
  if (!strcmp(token, "serverip")) { cfg->ncd_srvip=inet_addr(value); return; }
  if (!strcmp(token, "key"))
  {
    if (key_atob14(value, cfg->ncd_key))
    {
      fprintf(stderr, "Configuration newcamd: Error in Key\n");
      exit(1);
    }
    return;
  }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in newcamd section not recognized\n",token);
}

static void chk_t_radegast(char *token, char *value)
{
  if (!strcmp(token, "port")) { cfg->rad_port=atoi(value); return; }
  if (!strcmp(token, "serverip")) { cfg->rad_srvip=inet_addr(value); return; }
  if (!strcmp(token, "allowed")) { chk_iprange(value, &cfg->rad_allowed); return; }
  if (!strcmp(token, "user")) { strncpy(cfg->rad_usr, value, sizeof(cfg->rad_usr)-1); return; }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in radegast section not recognized\n",token);
}

static void chk_t_serial(char *token, char *value)
{
  if (!strcmp(token, "device"))
  {
    int l;
    l=strlen(cfg->ser_device);
    if (l) cfg->ser_device[l++]=1;  // use ctrl-a as delimiter
    strncpy(cfg->ser_device+l, value, sizeof(cfg->ser_device)-1-l);
    return;
  }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in serial section not recognized\n",token);
}

static void chk_t_gbox(char *token, char *value)
{
//  if (!strcmp(token, "password")) strncpy(cfg->gbox_pwd, i2b(4, a2i(value, 4)), 4);
  if (!strcmp(token, "password")) { cs_atob(cfg->gbox_pwd, value, 4); return; }
  if (!strcmp(token, "maxdist")) { cfg->maxdist=atoi(value); return; }
  if (!strcmp(token, "ignorelist")) { strncpy((char *)cfg->ignorefile, value, sizeof(cfg->ignorefile)-1); return; }
  if (!strcmp(token, "onlineinfos")) { strncpy((char *)cfg->gbxShareOnl, value, sizeof(cfg->gbxShareOnl)-1); return; }
  if (!strcmp(token, "cardinfos")) { strncpy((char *)cfg->cardfile, value, sizeof(cfg->cardfile)-1); return; }
  if (!strcmp(token, "locals"))
  {
    char *ptr1;
    int n=0, i;
    for (i=0, ptr1=strtok(value, ","); (i<CS_MAXLOCALS) && (ptr1); ptr1=strtok(NULL, ","))
    {
      cfg->locals[n++]=a2i(ptr1, 8);
      //printf("%i %08X",n,cfg->locals[n-1]);
    }
    cfg->num_locals=n;
    return;
  }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in gbox section not recognized\n",token);
}

static void chk_t_cccam(char *token, char *value)
{
  // placeholder for ccam server support
  fprintf(stderr, "Warning: OSCam have no cccam server support yet. Parametr %s = %s\n", token, value);
}

#ifdef HAVE_DVBAPI
static void chk_t_dvbapi(char *token, char *value)
{
	if (!strcmp(token, "enabled")) 	{ cfg->dvbapi_enabled=atoi(value); return; }
	if (!strcmp(token, "au"))		{ cfg->dvbapi_au=atoi(value); return; }
	if (!strcmp(token, "boxtype")) 	{ strncpy(cfg->dvbapi_boxtype, value, sizeof(cfg->dvbapi_boxtype)-1); return; }
	if (!strcmp(token, "user")) 	{ strncpy(cfg->dvbapi_usr, value, sizeof(cfg->dvbapi_usr)-1); return; }
	
	if (token[0] != '#')
	    fprintf(stderr, "Warning: keyword '%s' in dvbapi section not recognized\n",token);
}
#endif

static void chk_token(char *token, char *value, int tag)
{
  switch(tag)
  {
    case TAG_GLOBAL  : chk_t_global(token, value); break;
    case TAG_MONITOR : chk_t_monitor(token, value); break;
    case TAG_CAMD33  : chk_t_camd33(token, value); break;
    case TAG_CAMD35  : 
    case TAG_CS357X  : chk_t_camd35(token, value); break;
    case TAG_NEWCAMD : chk_t_newcamd(token, value); break;
    case TAG_RADEGAST: chk_t_radegast(token, value); break;
    case TAG_SERIAL  : chk_t_serial(token, value); break;
    case TAG_CS378X  : chk_t_camd35_tcp(token, value); break;
    case TAG_GBOX    : chk_t_gbox(token, value); break;
    case TAG_CCCAM   : chk_t_cccam(token, value); break;
#ifdef HAVE_DVBAPI
    case TAG_DVBAPI  : chk_t_dvbapi(token, value); break;
#else
    case TAG_DVBAPI  : fprintf(stderr, "Warning: OSCam compiled without DVB API support.\n"); break;
#endif
#ifdef CS_ANTICASC
    case TAG_ANTICASC: chk_t_ac(token, value); break;
#endif
  }
}

void init_len4caid()
{
  int nr;
  FILE *fp;
  char *value;

  memset(len4caid, 0, sizeof(ushort)<<8);
  sprintf(token, "%s%s", cs_confdir, cs_l4ca);
  if (!(fp=fopen(token, "r")))
    return;
  for(nr=0; fgets(token, sizeof(token), fp);)
  {
    int i, c;
    char *ptr;
    if (!(value=strchr(token, ':'))) continue;
    *value++='\0';
    if( (ptr=strchr(value, '#')) )
      *ptr='\0';
    if (strlen(trim(token))!=2) continue;
    if (strlen(trim(value))!=4) continue;
    if ((i=byte_atob(token))<0) continue;
    if ((c=word_atob(value))<0) continue;
//printf("idx %02X = %04X\n", i, c); fflush(stdout);
    len4caid[i]=c;
    nr++;
  }
  fclose(fp);
  cs_log("%d lengths for caid guessing loaded", nr);
  return;
}

int search_boxkey(ushort caid, char *key)
{
  int i, rc=0;
  FILE *fp;
  char c_caid[512];

  sprintf(c_caid, "%s%s", cs_confdir, cs_cert);
  fp=fopen(c_caid, "r");
  if (fp)
  {
    for (; (!rc) && fgets(c_caid, sizeof(c_caid), fp);)
    {
      char *c_provid, *c_key;

      c_provid=strchr(c_caid, '#');
      if (c_provid) *c_provid='\0';
      if (!(c_provid=strchr(c_caid, ':'))) continue;
      *c_provid++='\0';
      if (!(c_key=strchr(c_provid, ':'))) continue;
      *c_key++='\0';
      if (word_atob(trim(c_caid))!=caid) continue;
      if ((i=(strlen(trim(c_key))>>1))>256) continue;
      if (cs_atob((uchar *)key, c_key, i)<0)
      {
        cs_log("wrong key in \"%s\"", cs_cert);
        continue;
      }
      rc=1;
    }
    fclose(fp);
  }
#ifdef OSCAM_INBUILD_KEYS
  for(i=0; (!rc) && (npkey[i].keylen); i++)
    if (rc=((caid==npkey[i].caid) && (npkey[i].provid==0)))
      memcpy(key, npkey[i].key, npkey[i].keylen);
#endif
  return(rc);
}

int init_config()
{
  int tag=TAG_GLOBAL;
  FILE *fp;
  char *value;

#ifndef CS_EMBEDDED
#ifdef PRIO_PROCESS
  errno=0;
  if ((cfg->nice=getpriority(PRIO_PROCESS, 0))==(-1))
    if (errno)
#endif
#endif
  cfg->nice=99;
  cfg->ctimeout=CS_CLIENT_TIMEOUT;
  cfg->ftimeout=CS_CLIENT_TIMEOUT / 2;
  cfg->cmaxidle=CS_CLIENT_MAXIDLE;
  cfg->delay=CS_DELAY;
  cfg->bindwait=CS_BIND_TIMEOUT;
  cfg->resolvedelay=CS_RESOLVE_DELAY;
  cfg->mon_level=2;
  cfg->mon_hideclient_to=0;
  cfg->srtimeout=1500;
  cfg->ulparent=0;
#ifdef CS_ANTICASC
  cfg->ac_enabled=0;
  cfg->ac_users=0;
  cfg->ac_stime=2;
  cfg->ac_samples=10;
  cfg->ac_denysamples=8;
  cfg->ac_fakedelay=1000;
  strcpy(cfg->ac_logfile, "./oscam_ac.log");
#endif
  sprintf(token, "%s%s", cs_confdir, cs_conf);
  if (!(fp=fopen(token, "r")))
  {
    fprintf(stderr, "Cannot open config file '%s' (errno=%d)\n", token, errno);
    exit(1);
  }
  while (fgets(token, sizeof(token), fp))
  {
    int i, l;
    //void *ptr;
    if ((l=strlen(trim(token)))<3) continue;
    if ((token[0]=='[') && (token[l-1]==']'))
    {
      for (token[l-1]=0, tag=-1, i=TAG_GLOBAL; cctag[i]; i++)
        if (!strcmp(cctag[i], strtolower(token+1)))
          tag=i;
      continue;
    }
    if (!(value=strchr(token, '='))) continue;
    *value++='\0';
    chk_token(trim(strtolower(token)), trim(value), tag);
  }
  fclose(fp);
  cs_init_log(logfile);
  if (cfg->ftimeout>=cfg->ctimeout)
  {
    cfg->ftimeout = cfg->ctimeout - 100;
    cs_log("WARNING: fallbacktimeout adjusted to %lu ms (must be smaller than clienttimeout (%lu ms))", cfg->ftimeout, cfg->ctimeout);
  }
  if(cfg->ftimeout < cfg->srtimeout)
  {
    cfg->ftimeout = cfg->srtimeout + 100;
    cs_log("WARNING: fallbacktimeout adjusted to %lu ms (must be greater than serialreadertimeout (%lu ms))", cfg->ftimeout, cfg->srtimeout);
  }
  if(cfg->ctimeout < cfg->srtimeout)
  {
    cfg->ctimeout = cfg->srtimeout + 100;
    cs_log("WARNING: clienttimeout adjusted to %lu ms (must be greater than serialreadertimeout (%lu ms))", cfg->ctimeout, cfg->srtimeout);
  }
#ifdef CS_ANTICASC
  if( cfg->ac_denysamples+1>cfg->ac_samples )
  {
    cfg->ac_denysamples=cfg->ac_samples-1;
    cs_log("WARNING: DenySamples adjusted to %d", cfg->ac_denysamples);
  }
#endif
  return 0;
}

static void chk_account(char *token, char *value, struct s_auth *account)
{
  int i;
  char *ptr1;//, *ptr2;
  if (!strcmp(token, "user")) { strncpy(account->usr, value, sizeof(account->usr)-1); return; }
  if (!strcmp(token, "pwd")) { strncpy(account->pwd, value, sizeof(account->pwd)-1); return; }
  if (!strcmp(token, "hostname")) { strncpy((char *)account->dyndns, value, sizeof(account->dyndns)-1); return; }
  if (!strcmp(token, "betatunnel")) { chk_tuntab(value, &account->ttab); return; }
  if (!strcmp(token, "uniq")) { account->uniq=atoi(value); return; }
  if (!strcmp(token, "sleep")) { account->tosleep=atoi(value); return; }
  if (!strcmp(token, "monlevel")) { account->monlvl=atoi(value); return; }
  if (!strcmp(token, "caid")) { chk_caidtab(value, &account->ctab); return; }
  /*
   *  case insensitive
   */
  strtolower(value);
  if (!strcmp(token, "au"))
  {
    if(value && value[0]=='1') account->autoau=1;
    for (i=0; i<CS_MAXREADER; i++)
      if ((reader[i].label[0]) &&
          (!strncmp(reader[i].label, value, strlen(reader[i].label))))
        account->au=i;
    return;
  }
  if (!strcmp(token, "group"))\
  {
    for (ptr1=strtok(value, ","); ptr1; ptr1=strtok(NULL, ","))
    {
      int g;
      g=atoi(ptr1);
      if ((g>0) && (g<33)) account->grp|=(1<<(g-1));
    }
    return;
  }
  if(!strcmp(token, "services")) { chk_services(value, &account->sidtabok, &account->sidtabno); return; }
  if(!strcmp(token, "ident")) { chk_ftab(value, &account->ftab, "user", account->usr, "provid"); return; }
  if(!strcmp(token, "class")) { chk_cltab(value, &account->cltab); return; }
  if(!strcmp(token, "chid")) {  chk_ftab(value, &account->fchid, "user", account->usr, "chid"); return; }

  if (!strcmp(token, "expdate"))
  {
    struct tm cstime;
    memset(&cstime,0,sizeof(cstime));
    for (i=0, ptr1=strtok(value, "-/"); (i<3)&&(ptr1); ptr1=strtok(NULL, "-/"), i++)
    {
      switch(i)
      {
        case 0: cstime.tm_year=atoi(ptr1)-1900; break;
        case 1: cstime.tm_mon =atoi(ptr1)-1;    break;
        case 2: cstime.tm_mday=atoi(ptr1);      break;
      }
    }	
    account->expirationdate=mktime(&cstime);
    return;
  }

#ifdef CS_ANTICASC
  if( !strcmp(token, "numusers") )
  {
    account->ac_users = atoi(value);
    return;
  }
  if( !strcmp(token, "penalty") ) 
  {
    account->ac_penalty = atoi(value);
    return;
  }
#endif
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in account section not recognized\n",token);

//  if (!strcmp(token, "caid"))
//  {
//    for (i=0, ptr1=strtok(value, ","); (i<CS_MAXCAIDTAB) && (ptr1); ptr1=strtok(NULL, ","))
//    {
//      ulong caid, mask;
//      if (ptr2=strchr(trim(ptr1), '&'))
//        *ptr2++='\0';
//      else
//        ptr2="";
//      if (((caid=a2i(ptr1, 2))|(mask=a2i(ptr2,-2))) < 0x10000)
//      {
//        account->caidtab[i][0]=caid;
//        account->caidtab[i++][1]=mask;
//      }
//      else
//        cs_log("WARNING: wrong CAID in %s -> ignored", cs_user);
//    }
//  }
}

int init_userdb()
{
  int tag=0, nr, nro, expired;
  //int first=1;
  FILE *fp;
  char *value;
  struct s_auth *ptr;
  /*static */struct s_auth *account=(struct s_auth *)0;

  sprintf(token, "%s%s", cs_confdir, cs_user);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("Cannot open file \"%s\" (errno=%d)", token, errno);
    return(1);
  }
  for (nro=0, ptr=cfg->account; ptr; nro++)
  {
    struct s_auth *ptr_next;
    ptr_next=ptr->next;
    free(ptr);
    ptr=ptr_next;
  }
  nr=0;
  while (fgets(token, sizeof(token), fp))
  {
    int i, l;
    void *ptr;
    if ((l=strlen(trim(token)))<3) continue;
    if ((token[0]=='[') && (token[l-1]==']'))
    {
      token[l-1]=0;
      tag=(!strcmp("account", strtolower(token+1)));
      if (!(ptr=malloc(sizeof(struct s_auth))))
      {
        cs_log("Error allocating memory (errno=%d)", errno);
        return(1);
      }
      if (account)
        account->next=ptr;
      else
        cfg->account=ptr;
      account=ptr;
      memset(account, 0, sizeof(struct s_auth));
      account->au=(-1);
      account->monlvl=cfg->mon_level;
      account->tosleep=cfg->tosleep;
      for (i=1; i<CS_MAXCAIDTAB; account->ctab.mask[i++]=0xffff);
      for (i=1; i<CS_MAXTUNTAB; account->ttab.bt_srvid[i++]=0x0000);
      nr++;
#ifdef CS_ANTICASC
      account->ac_users=cfg->ac_users;
      account->ac_penalty=cfg->ac_penalty;
      account->ac_idx = nr;
#endif
      continue;
    }
    if (!tag) continue;
    if (!(value=strchr(token, '='))) continue;
    *value++='\0';
    chk_account(trim(strtolower(token)), trim(value), account);
  }
  fclose(fp);

  for (expired=0, ptr=cfg->account; ptr;)
  {
    if(ptr->expirationdate && ptr->expirationdate<time(NULL)) expired++;
    ptr=ptr->next;
  }

  cs_log("userdb reloaded: %d accounts freed, %d accounts loaded, %d expired", nro, nr, expired);
  return(0);
}

static void chk_entry4sidtab(char *value, struct s_sidtab *sidtab, int what)
{
  int i, b;
  char *ptr;
  ushort *slist=(ushort *) 0;
  ulong *llist=(ulong *) 0;
  ulong caid;
  char buf[strlen(value) + 1];
  strncpy(buf, value, sizeof(buf));
  b=(what==1) ? sizeof(ulong) : sizeof(ushort);
  for (i=0, ptr=strtok(value, ","); ptr; ptr=strtok(NULL, ","))
  {
    caid=a2i(ptr, b);
    if (!errno) i++;
  }
  //if (!i) return(0);
  if (b==sizeof(ushort))
    slist=malloc(i*sizeof(ushort));
  else
    llist=malloc(i*sizeof(ulong));
  strcpy(value, buf);
  for (i=0, ptr=strtok(value, ","); ptr; ptr=strtok(NULL, ","))
  {
    caid=a2i(ptr, b);
    if (errno) continue;
    if (b==sizeof(ushort))
      slist[i++]=(ushort) caid;
    else
      llist[i++]=caid;
  }
  switch (what)
  {
    case 0: sidtab->caid=slist;
            sidtab->num_caid=i;
            break;
    case 1: sidtab->provid=llist;
            sidtab->num_provid=i;
            break;
    case 2: sidtab->srvid=slist;
            sidtab->num_srvid=i;
            break;
  }
}

static void chk_sidtab(char *token, char *value, struct s_sidtab *sidtab)
{
  if (!strcmp(token, "caid")) { chk_entry4sidtab(value, sidtab, 0); return; }
  if (!strcmp(token, "provid")) { chk_entry4sidtab(value, sidtab, 1); return; }
  if (!strcmp(token, "ident")) { chk_entry4sidtab(value, sidtab, 1); return; }
  if (!strcmp(token, "srvid")) { chk_entry4sidtab(value, sidtab, 2); return; }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in sidtab section not recognized\n",token);
}

int init_sidtab()
{
  int nr, nro;
  FILE *fp;
  char *value;
  struct s_sidtab *ptr;
  struct s_sidtab *sidtab=(struct s_sidtab *)0;

  sprintf(token, "%s%s", cs_confdir, cs_sidt);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("Cannot open file \"%s\" (errno=%d)", token, errno);
    return(1);
  }
  for (nro=0, ptr=cfg->sidtab; ptr; nro++)
  {
    struct s_sidtab *ptr_next;
    ptr_next=ptr->next;
    if (ptr->caid) free(ptr->caid);
    if (ptr->provid) free(ptr->provid);
    if (ptr->srvid) free(ptr->srvid);
    free(ptr);
    ptr=ptr_next;
  }
  nr=0;
  while (fgets(token, sizeof(token), fp))
  {
    int l;
    void *ptr;
    if ((l=strlen(trim(token)))<3) continue;
    if ((token[0]=='[') && (token[l-1]==']'))
    {
      token[l-1]=0;
      if (!(ptr=malloc(sizeof(struct s_sidtab))))
      {
        cs_log("Error allocating memory (errno=%d)", errno);
        return(1);
      }
      if (sidtab)
        sidtab->next=ptr;
      else
        cfg->sidtab=ptr;
      sidtab=ptr;
      nr++;
      memset(sidtab, 0, sizeof(struct s_sidtab));
      strncpy(sidtab->label, strtolower(token+1), sizeof(sidtab->label));
      continue;
    }
    if (!sidtab) continue;
    if (!(value=strchr(token, '='))) continue;
    *value++='\0';
    chk_sidtab(trim(strtolower(token)), trim(strtolower(value)), sidtab);
  }
  fclose(fp);

#ifdef DEBUG_SIDTAB
  show_sidtab(cfg->sidtab);
#endif
  cs_log("services reloaded: %d services freed, %d services loaded", nro, nr);
  return(0);
}

int init_srvid()
{
  int nr;
  FILE *fp;
  char *value;
  static struct s_srvid *srvid=(struct s_srvid *)0;

  sprintf(token, "%s%s", cs_confdir, cs_srid);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (err=%d), no service-id's loaded", 
           token, errno);
    return(0);
  }
  nr=0;
  while (fgets(token, sizeof(token), fp))
  {
    int l;
    void *ptr;
    if ((l=strlen(trim(token)))<6) continue;
    if (!(value=strchr(token, ':'))) continue;
    *value++='\0';
    if (strlen(token)!=4) continue;
    if (!(ptr=malloc(sizeof(struct s_srvid))))
    {
      cs_log("Error allocating memory (errno=%d)", errno);
      return(1);
    }
    if (srvid)
      srvid->next=ptr;
    else
      cfg->srvid=ptr;
    srvid=ptr;
    memset(srvid, 0, sizeof(struct s_srvid));
    srvid->srvid=word_atob(token);
    strncpy(srvid->name, value, sizeof(srvid->name)-1);
    nr++;
  }
  fclose(fp);
  cs_log("%d service-id's loaded", nr);
  return(0);
}

static void chk_reader(char *token, char *value, struct s_reader *rdr)
{
  int i;
  char *ptr;
  /*
   *  case sensitive first
   */
  if (!strcmp(token, "device"))
  {
    for (i=0, ptr=strtok(value, ","); (i<3)&&(ptr); ptr=strtok(NULL, ","), i++)
    {
      trim(ptr);
      switch(i)
      {
        case 0: strncpy(rdr->device, ptr, sizeof(rdr->device)-1); break;
        case 1: rdr->r_port=atoi(ptr); break;
        case 2: rdr->l_port=atoi(ptr); break;
      }
    }
    return;
  }
  if (!strcmp(token, "key"))
  {
    if (key_atob14(value, rdr->ncd_key))
    {
      fprintf(stderr, "Configuration newcamd: Error in Key\n");
      exit(1);
    }
    return;
  }
  if (!strcmp(token, "password")) { strncpy((char *)rdr->gbox_pwd, (const char *)i2b(4, a2i(value, 4)), 4); return; }
  if (!strcmp(token, "premium")) { rdr->gbox_prem=1; return; }
  if (!strcmp(token, "account"))
  {
    for (i=0, ptr=strtok(value, ","); (i<2)&&(ptr); ptr=strtok(NULL, ","), i++)
    {
      trim(ptr);
      switch(i)
      {
        case 0: strncpy(rdr->r_usr, ptr, sizeof(rdr->r_usr)-1); break;
        case 1: strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd)-1); break;
      }
    }
    return;
  }
  if( !strcmp(token, "pincode")) { strncpy(rdr->pincode, value, sizeof(rdr->pincode)-1); return; }
  if (!strcmp(token, "readnano")) { strncpy((char *)rdr->emmfile, value, sizeof(rdr->emmfile)-1); return; }
  /*
   *  case insensitive
   */
  strtolower(value);

  if (!strcmp(token, "services")) { chk_services(value, &rdr->sidtabok, &rdr->sidtabno); return; }
  if (!strcmp(token, "inactivitytimeout")) {   rdr->tcp_ito = atoi(value);  return; }
  if (!strcmp(token, "reconnecttimeout")) {    rdr->tcp_rto = atoi(value);  return; }
  if (!strcmp(token, "disableserverfilter")) { rdr->ncd_disable_server_filt = atoi(value);  return; }

  if (!strcmp(token, "label")) { strncpy(rdr->label, value, sizeof(rdr->label)-1); return; }
  if (!strcmp(token, "fallback")) { rdr->fallback=atoi(value) ? 1 : 0; return; }
  if (!strcmp(token, "logport")) { rdr->log_port=atoi(value); return; }
  if (!strcmp(token, "caid")) { chk_caidtab(value, &rdr->ctab); return; }
  if (!strcmp(token, "boxid")) { rdr->boxid=a2i(value,4); return; }
  if (!strcmp(token, "aeskey"))
  {
    if (key_atob(value, rdr->aes_key))
    {
      fprintf(stderr, "Configuration reader: Error in AES Key\n");
      exit(1);
    }
    return;
  }
  if (!strcmp(token, "n3_rsakey"))
  {
    rdr->nagra_native=1;
    if (key_atob_l(value, rdr->rsa_mod, 128))
    {
      fprintf(stderr, "Configuration reader: Error in n3_rsakey\n");
      exit(1);
    }
    return;
  }
  if (!strcmp(token, "tiger_rsakey"))
  {
    rdr->nagra_native=1;
    if (key_atob_l(value, rdr->rsa_mod, 240))
    {
      fprintf(stderr, "Configuration reader: Error in tiger_rsakey\n");
      exit(1);
    }
    return;
  }
  if (!strcmp(token, "n3_boxkey"))
  {
    if (key_atob_l(value, rdr->nagra_boxkey, 16))
    {
      fprintf(stderr, "Configuration reader: Error in Nagra Boxkey\n");
      exit(1);
    }
    return;
  }
  if (!strcmp(token, "tiger_ideakey"))
  {
    if (key_atob_l(value, rdr->nagra_boxkey, 32))
    {
      fprintf(stderr, "Configuration reader: Error in Nagra Boxkey\n");
      exit(1);
    }
    return;
  }
  if (!strcmp(token, "detect"))
  {
    for (i=0; RDR_CD_TXT[i]; i++)
    {
      if (!strcmp(value, RDR_CD_TXT[i]))
        rdr->detect=i;
      else
        if ((value[0]=='!') && (!strcmp(value+1, RDR_CD_TXT[i])))
          rdr->detect=i|0x80;
    }
    return;
  }
  if (!strcmp(token, "mhz")) { rdr->mhz=atoi(value); return; }
  if (!strcmp(token, "cardmhz")) { rdr->cardmhz=atoi(value); return; }
  if (!strcmp(token, "protocol"))
  {
    if (!strcmp(value, "mouse")) {      rdr->typ=R_MOUSE; return; }
    if (!strcmp(value, "smartreader")) {      rdr->typ=R_SMART; return; }
    if (!strcmp(value, "internal")) {   rdr->typ=R_INTERNAL; return; }
#ifdef HAVE_PCSC
    if (!strcmp(value, "pcsc")) {   rdr->typ=R_PCSC; return; }
#endif
    if (!strcmp(value, "serial")) {     rdr->typ=R_SERIAL; return; }
    if (!strcmp(value, "camd35")) {     rdr->typ=R_CAMD35; return; }
    if (!strcmp(value, "cs378x")) {     rdr->typ=R_CS378X; return; }
    if (!strcmp(value, "cs357x")) {     rdr->typ=R_CAMD35; return; }
    if (!strcmp(value, "gbox")) {       rdr->typ=R_GBOX; return; }
    if (!strcmp(value, "cccam")) {
      rdr->typ=R_CCCAM;
     // strcpy(value, "1");
     // chk_caidtab(value, &rdr->ctab); // this is a MAJOR hack for auto multiple caid support (not currently working due to ncd table issue)
      return;
    }
    if (!strcmp(value, "radegast")) {       rdr->typ=R_RADEGAST; return; }
    if (!strcmp(value, "newcamd") || 
        !strcmp(value, "newcamd525")) {rdr->typ=R_NEWCAMD; 
                                       rdr->ncd_proto=NCD_525; return; }
    if (!strcmp(value, "newcamd524")) {rdr->typ=R_NEWCAMD; 
                                       rdr->ncd_proto=NCD_524; return; }
    fprintf(stderr, "WARNING: value '%s' in protocol-line not recognized, assuming MOUSE\n",value);
    rdr->typ=R_MOUSE;
    return;
  }
  if (!strcmp(token, "ident")) { chk_ftab(value, &rdr->ftab,"reader",rdr->label,"provid"); return; }
  if (!strcmp(token, "class")) { chk_cltab(value, &rdr->cltab); return; }
  if (!strcmp(token, "chid")) {  chk_ftab(value, &rdr->fchid,"reader",rdr->label,"chid"); return; }
  if (!strcmp(token, "showcls")) { rdr->show_cls = atoi(value); return; }
  if (!strcmp(token, "maxqlen"))
  {
    rdr->maxqlen = atoi(value);
    if( rdr->maxqlen<0 || rdr->maxqlen>CS_MAXQLEN )
      rdr->maxqlen=CS_MAXQLEN;
    return;
  }
  if (!strcmp(token, "group"))
  {
    for (ptr=strtok(value, ","); ptr; ptr=strtok(NULL, ","))
    {
      int g;
      g=atoi(ptr);
      if ((g>0) && (g<33)) rdr->grp|=(1<<(g-1));
    }
    return;
  }
  if (!strcmp(token, "emmcache"))
  {
    for (i=0, ptr=strtok(value, ","); (i<3)&&(ptr); ptr=strtok(NULL, ","), i++)
      switch(i)
      {
        case 0: rdr->cachemm=atoi(ptr);   break;
        case 1: rdr->rewritemm=atoi(ptr); break;
        case 2: rdr->logemm=atoi(ptr);    break;
      }
    if (rdr->rewritemm <=0) {
      fprintf(stderr, "Notice: Setting EMMCACHE to %i,1,%i instead of %i,%i,%i. Zero or negative number of rewrites is silly\n", rdr->cachemm,rdr->logemm,rdr->cachemm,rdr->rewritemm,rdr->logemm);
      rdr->rewritemm = 1;
    }
    return;
  }

  if (!strcmp(token, "blocknano"))
  {
    if (!strcmp(value,"all")) //wildcard is used
      for (i=0 ; i<256; i++)
  rdr->b_nano[i] |= 0x01; //set all lsb's to block all nanos
    else
      for (ptr=strtok(value, ","); ptr; ptr=strtok(NULL, ","))
  if ((i=byte_atob(ptr))>=0)
    rdr->b_nano[i]|= 0x01; //lsb is set when to block nano
    return;
  }
  if (!strcmp(token, "savenano"))
  {
    if (!strcmp(value,"all")) //wildcard is used
      for (i=0 ; i<256; i++)
  rdr->b_nano[i] |= 0x02; //set all lsb+1 to save all nanos to file
    else
      for (ptr=strtok(value, ","); ptr; ptr=strtok(NULL, ","))
  if ((i=byte_atob(ptr))>=0)
    rdr->b_nano[i]|= 0x02; //lsb+1 is set when to save nano to file
    return;
  }
  if (!strcmp(token, "cccversion")) {  // cccam version
    if (strlen(value)>sizeof(rdr->cc_version)-1) {
      fprintf(stderr, "cccam config: version too long\n");
      exit(1);
    }
    bzero(rdr->cc_version, sizeof(rdr->cc_version));
    strncpy(rdr->cc_version, value, sizeof(rdr->cc_version)-1);
    return;
  }
  if (!strcmp(token, "cccbuild")) {  // cccam build number
    if (strlen(value)>sizeof(rdr->cc_build)-1) {
      fprintf(stderr, "cccam config build number too long\n");
      exit(1);
    }
    bzero(rdr->cc_build, sizeof(rdr->cc_build));
    strncpy(rdr->cc_build, value, sizeof(rdr->cc_build)-1);
    return;
  }
  if (!strcmp(token, "cccmaxhop")) {  // cccam max card distance
    rdr->cc_maxhop = atoi(value);
    return;
  }
  if (token[0] != '#')
    fprintf(stderr, "Warning: keyword '%s' in reader section not recognized\n",token);
}

int init_readerdb()
{
  int tag=0, nr;
  FILE *fp;
  char *value;

  sprintf(token, "%s%s", cs_confdir, cs_srvr);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (errno=%d)\n", token, errno);
    return(1);
  }
  nr=0;
  while (fgets(token, sizeof(token), fp))
  {
    int i, l;
    if ((l=strlen(trim(token)))<3) continue;
    if ((token[0]=='[') && (token[l-1]==']'))
    {
      token[l-1]=0;
      tag=(!strcmp("reader", strtolower(token+1)));
      if (reader[nr].label[0] && reader[nr].typ) nr++;
      memset(&reader[nr], 0, sizeof(struct s_reader));
      reader[nr].tcp_rto = 30;      
      reader[nr].show_cls = 10;
      reader[nr].maxqlen = CS_MAXQLEN;
      reader[nr].mhz = 357;
      reader[nr].cardmhz = 357;
      strcpy(reader[nr].pincode, "none");
      for (i=1; i<CS_MAXCAIDTAB; reader[nr].ctab.mask[i++]=0xffff);
      continue;
    }
    if (!tag) continue;
    if (!(value=strchr(token, '='))) continue;
    *value++='\0';
    chk_reader(trim(strtolower(token)), trim(value), &reader[nr]);
  }
  fclose(fp);
  return(0);
}

/*
int init_irdeto_guess_tab()
{
  int i, j, skip;
  int b47;
  FILE *fp;
  char token[128], *value, *ptr;
  char zSid[5];
  uchar b3;
  ushort caid, sid;
  struct s_irdeto_quess *ird_row, *head;

  memset(cfg->itab, 0, sizeof(cfg->itab));
  sprintf(token, "%s%s", cs_confdir, cs_ird);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (errno=%d) irdeto guessing not loaded", 
           token, errno);
    return(1);
  }
  while (fgets(token, sizeof(token), fp))
  {
    if( strlen(token)<20 ) continue;
    for( i=b3=b47=caid=sid=skip=0, ptr=strtok(token, ":"); (i<4)&&(ptr); ptr=strtok(NULL, ":"), i++ )
    {
      trim(ptr);
      if( *ptr==';' || *ptr=='#' || *ptr=='-' ) {
        skip=1;
        break;
      }
      switch(i)
      {
        case 0: b3   = a2i(ptr, 2); break;
        case 1: b47  = a2i(ptr, 8); break;
        case 2: caid = a2i(ptr, 4); break;
        case 3: 
          for( j=0; j<4; j++ )
            zSid[j]=ptr[j];
          zSid[4]=0;
          sid  = a2i(zSid, 4); 
          break;
      }
    }
    if( !skip ) 
    {
      if (!(ird_row=(struct s_irdeto_quess*)malloc(sizeof(struct s_irdeto_quess))))
      {
        cs_log("Error allocating memory (errno=%d)", errno);
        return;
      }
      ird_row->b47  = b47;
      ird_row->caid = caid;
      ird_row->sid  = sid;
      ird_row->next = 0;

      head = cfg->itab[b3];
      if( head ) {
        while( head->next )
          head=head->next;
        head->next=ird_row;
      }
      else
        cfg->itab[b3]=ird_row;

      //cs_debug("%02X:%08X:%04X:%04X", b3, b47, caid, sid);
    }
  }
  fclose(fp);

  for( i=0; i<0xff; i++ )
  {
    head=cfg->itab[i];
    while(head)
    {
      cs_debug("itab[%02X]: b47=%08X, caid=%04X, sid=%04X",
               i, head->b47, head->caid, head->sid);
      head=head->next;
    }
  }
  return(0);
}
*/

#ifdef CS_ANTICASC
void init_ac()
{
  int nr;
  FILE *fp;
  //char *value;

  sprintf(token, "%s%s", cs_confdir, cs_ac);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (errno=%d) anti-cascading table not loaded", 
            token, errno);
    return;
  }

  for(nr=0; fgets(token, sizeof(token), fp);)
  {
    int i, skip;
    ushort caid, sid, chid, dwtime;
    ulong  provid;
    char *ptr, *ptr1;
    struct s_cpmap *ptr_cpmap;
    static struct s_cpmap *cpmap=(struct s_cpmap *)0;

    if( strlen(token)<4 ) continue;

    caid=sid=chid=dwtime=0;
    provid=0;
    skip=0;
    ptr1=0;
    for( i=0, ptr=strtok(token, "="); (i<2)&&(ptr); ptr=strtok(NULL, "="), i++ )
    {
      trim(ptr);
      if( *ptr==';' || *ptr=='#' || *ptr=='-' ) {
        skip=1;
        break;
      }
      switch( i )
      {
        case 0:
          ptr1=ptr;
          break;
        case 1: 
          dwtime = atoi(ptr);
          break;
      }
    }

    if( !skip )
    {
      for( i=0, ptr=strtok(ptr1, ":"); (i<4)&&(ptr); ptr=strtok(NULL, ":"), i++ )
      {
        trim(ptr);
        switch( i )
        {
        case 0: 
          if( *ptr=='*' ) caid = 0;
          else caid = a2i(ptr, 4); 
          break;
        case 1: 
          if( *ptr=='*' ) provid = 0;
          else provid = a2i(ptr, 6); 
          break;
        case 2: 
          if( *ptr=='*' ) sid = 0;
          else sid = a2i(ptr, 4); 
          break;
        case 3: 
          if( *ptr=='*' ) chid = 0;
          else chid = a2i(ptr, 4); 
          break;
        }
      }
      if (!(ptr_cpmap=(struct s_cpmap*)malloc(sizeof(struct s_cpmap))))
      {
        cs_log("Error allocating memory (errno=%d)", errno);
        return;
      }
      if( cpmap )
        cpmap->next=ptr_cpmap;
      else
        cfg->cpmap=ptr_cpmap;
      cpmap=ptr_cpmap;

      cpmap->caid   = caid;
      cpmap->provid = provid;
      cpmap->sid    = sid;
      cpmap->chid   = chid;
      cpmap->dwtime = dwtime;
      cpmap->next   = 0;

      cs_debug("nr=%d, caid=%04X, provid=%06X, sid=%04X, chid=%04X, dwtime=%d", 
                nr, caid, provid, sid, chid, dwtime);
      nr++;
    }
  }
  fclose(fp);
  //cs_log("%d lengths for caid guessing loaded", nr);
  return;
}
#endif
