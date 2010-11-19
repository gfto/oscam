//FIXME Not checked on threadsafety yet; after checking please remove this line

#include "globals.h"
#ifdef CS_WITH_BOXKEYS
#  include "oscam-boxkeys.np"
#endif

#define CONFVARWIDTH 30

static const char *cs_conf="oscam.conf";
static const char *cs_user="oscam.user";
static const char *cs_srvr="oscam.server";
static const char *cs_srid="oscam.srvid";
static const char *cs_trid="oscam.tiers";
static const char *cs_l4ca="oscam.guess";
static const char *cs_cert="oscam.cert";
static const char *cs_sidt="oscam.services";
#ifdef CS_ANTICASC
static const char *cs_ac="oscam.ac";
#endif

//Todo #ifdef CCCAM
static const char *cs_provid="oscam.provid";

#ifdef IRDETO_GUESSING
static const char *cs_ird="oscam.ird";
#endif

static char token[4096];

typedef enum cs_proto_type
{
	TAG_GLOBAL,		// must be first !
	TAG_MONITOR,		// monitor
	TAG_CAMD33,		// camd 3.3x
	TAG_CAMD35,		// camd 3.5x UDP
	TAG_NEWCAMD,		// newcamd
	TAG_RADEGAST,		// radegast
	TAG_SERIAL,		// serial (static)
	TAG_CS357X,		// camd 3.5x UDP
	TAG_CS378X,		// camd 3.5x TCP
	TAG_GBOX,		// gbox
	TAG_CCCAM,		// cccam
	TAG_CONSTCW,		// constcw
	TAG_DVBAPI,		// dvbapi
	TAG_WEBIF,		// webif
	TAG_ANTICASC		// anti-cascading
} cs_proto_type_t;

static const char *cctag[]={"global", "monitor", "camd33", "camd35", "newcamd", "radegast", "serial",
		      "cs357x", "cs378x", "gbox", "cccam", "constcw", "dvbapi", "webif", "anticasc", NULL};

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
		lip = cip;
	if (!(cip=malloc(sizeof(struct s_ip)))) {
		fprintf(stderr, "Error allocating memory (errno=%d)\n", errno);
		exit(1);
	}
	if (*base)
		lip->next = cip;
	else
		*base = cip;

	memset(cip, 0, sizeof(struct s_ip));
	for (ptr1=strtok(value, ","); ptr1; ptr1=strtok(NULL, ",")) {
			if (i == 0)
				++i;
		else {
			if (!(cip=malloc(sizeof(struct s_ip)))) {
				fprintf(stderr, "Error allocating memory (errno=%d)\n", errno);
				exit(1);
			}
			lip->next = cip;
			memset(cip, 0, sizeof(struct s_ip));
		}

		if( (ptr2=strchr(trim(ptr1), '-')) ) {
			*ptr2++ ='\0';
			cip->ip[0]=cs_inet_addr(trim(ptr1));
			cip->ip[1]=cs_inet_addr(trim(ptr2));
		} else {
			cip->ip[0]=cip->ip[1]=cs_inet_addr(ptr1);
		}
		lip = cip;
	}
}

void chk_caidtab(char *caidasc, CAIDTAB *ctab)
{
	int i;
	char *ptr1, *ptr2, *ptr3;

	for (i = 0, ptr1 = strtok(caidasc, ","); (i < CS_MAXCAIDTAB) && (ptr1); ptr1 = strtok(NULL, ",")) {
		ulong caid, mask, cmap;
		if( (ptr3 = strchr(trim(ptr1), ':')) )
			*ptr3++ = '\0';
		else
			ptr3 = "";

		if( (ptr2 = strchr(trim(ptr1), '&')) )
			*ptr2++ = '\0';
		else
			ptr2 = "";

		if (((caid = a2i(ptr1, 2)) | (mask = a2i(ptr2,-2)) | (cmap = a2i(ptr3, 2))) < 0x10000) {
			ctab->caid[i] = caid;
			ctab->mask[i] = mask;
			ctab->cmap[i++] = cmap;
		}
	}
}

void chk_tuntab(char *tunasc, TUNTAB *ttab)
{
	int i;
	char *ptr1, *ptr2, *ptr3;

	for (i = 0, ptr1 = strtok(tunasc, ","); (i < CS_MAXTUNTAB) && (ptr1); ptr1 = strtok(NULL, ",")) {
		ulong bt_caidfrom, bt_caidto, bt_srvid;
		if( (ptr3 = strchr(trim(ptr1), ':')) )
			*ptr3++ = '\0';
		else
			ptr3 = "";

		if( (ptr2 = strchr(trim(ptr1), '.')) )
			*ptr2++ = '\0';
		else
			ptr2 = "";

		if ((bt_caidfrom = a2i(ptr1, 2)) | (bt_srvid = a2i(ptr2,-2)) | (bt_caidto = a2i(ptr3, 2))) {
			ttab->bt_caidfrom[i] = bt_caidfrom;
			ttab->bt_caidto[i] = bt_caidto;
			ttab->bt_srvid[i++] = bt_srvid;
		}
	}
}

void chk_services(char *labels, SIDTABBITS *sidok, SIDTABBITS *sidno)
{
	int i;
	char *ptr;
	SIDTAB *sidtab;
	*sidok = *sidno = 0;
	for (ptr=strtok(labels, ","); ptr; ptr=strtok(NULL, ",")) {
		for (trim(ptr), i = 0, sidtab = cfg->sidtab; sidtab; sidtab = sidtab->next, i++) {
			if (!strcmp(sidtab->label, ptr)) *sidok|=((SIDTABBITS)1<<i);
			if ((ptr[0]=='!') && (!strcmp(sidtab->label, ptr+1))) *sidno|=((SIDTABBITS)1<<i);
		}
	}
}

void chk_ftab(char *zFilterAsc, FTAB *ftab, const char *D_USE(zType), const char *D_USE(zName), const char *zFiltName)
{
	int i, j;
	char *ptr1, *ptr2, *ptr3;
	char *ptr[CS_MAXFILTERS] = {0};

	memset(ftab, 0, sizeof(FTAB));
	for( i = 0, ptr1 = strtok(zFilterAsc, ";"); (i < CS_MAXFILTERS) && (ptr1); ptr1 = strtok(NULL, ";"), i++ ) {
		ptr[i] = ptr1;
		if( (ptr2 = strchr(trim(ptr1), ':')) ) {
			*ptr2++ ='\0';
			ftab->filts[i].caid = (ushort)a2i(ptr1, 4);
			ptr[i] = ptr2;
		}
		else if (zFiltName && zFiltName[0] == 'c') {
			cs_log("PANIC: CAID field not found in CHID parameter!");
			cs_exit(1);
		}
		ftab->nfilts++;
	}

	if( ftab->nfilts ) {
	    cs_debug("%s '%s' %s filter(s):", zType, zName, zFiltName);
	}
	for( i = 0; i < ftab->nfilts; i++ ) {
		cs_debug("CAID #%d: %04X", i, ftab->filts[i].caid);
		for( j = 0, ptr3 = strtok(ptr[i], ","); (j < CS_MAXPROV) && (ptr3); ptr3 = strtok(NULL, ","), j++ ) {
			ftab->filts[i].prids[j] = a2i(ptr3,6);
			ftab->filts[i].nprids++;
			cs_debug("%s #%d: %06X", zFiltName, j, ftab->filts[i].prids[j]);
		}
	}
}

void chk_cltab(char *classasc, CLASSTAB *clstab)
{
	int i;
	char *ptr1;
	for( i = 0, ptr1 = strtok(classasc, ","); (i < CS_MAXCAIDTAB) && (ptr1); ptr1 = strtok(NULL, ",") ) {
		ptr1 = trim(ptr1);
		if( ptr1[0] == '!' )
			clstab->bclass[clstab->bn++] = (uchar)a2i(ptr1+1, 2);
		else
			clstab->aclass[clstab->an++] = (uchar)a2i(ptr1, 2);
	}
}

void chk_port_tab(char *portasc, PTAB *ptab)
{
	int i, j, nfilts, ifilt, iport;
	char *ptr1, *ptr2, *ptr3;
	char *ptr[CS_MAXPORTS] = {0};
	int  port[CS_MAXPORTS] = {0};
	int previous_nports = ptab->nports;

	for (nfilts = i = previous_nports, ptr1 = strtok(portasc, ";"); (i < CS_MAXCAIDTAB) && (ptr1); ptr1 = strtok(NULL, ";"), i++) {
		ptr[i] = ptr1;
		if( (ptr2=strchr(trim(ptr1), '@')) ) {
			*ptr2++ ='\0';
			ptab->ports[i].s_port = atoi(ptr1);

			//checking for des key for port
			ptab->ports[i].ncd_key_is_set = 0;   //default to 0
			if( (ptr3=strchr(trim(ptr1), '{')) ) {
				*ptr3++='\0';
				if (key_atob14(ptr3, ptab->ports[i].ncd_key))
					fprintf(stderr, "newcamd: error in DES Key for port %s -> ignored\n", ptr1);
				else
					ptab->ports[i].ncd_key_is_set = 1;
			}

			ptr[i] = ptr2;
			port[i] = ptab->ports[i].s_port;
			ptab->nports++;
		}
		nfilts++;
	}

	if( nfilts == 1 && strlen(portasc) < 6 && ptab->ports[0].s_port == 0 ) {
		ptab->ports[0].s_port = atoi(portasc);
		ptab->nports = 1;
	}

	iport = ifilt = previous_nports;
	for (i=previous_nports; i<nfilts; i++) {
		if( port[i] != 0 )
			iport = i;
		for (j = 0, ptr3 = strtok(ptr[i], ","); (j < CS_MAXPROV) && (ptr3); ptr3 = strtok(NULL, ","), j++) {
			if( (ptr2=strchr(trim(ptr3), ':')) ) {
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
		if (i<8) ip[i++] = inet_addr(ptr);
}
#endif

void chk_t_global(const char *token, char *value)
{

#ifdef QBOXHD_LED
	if (!strcmp(token, "disableqboxhdled")) {
		if (strlen(value) == 0) {
			cfg->disableqboxhdled = 0;
			return;
		} else {
			cfg->disableqboxhdled = atoi(value);
			return;
		}
	}
#endif

	if (!strcmp(token, "disablelog")) {
		if (strlen(value) == 0) {
			cfg->disablelog = 0;
			return;
		} else {
			cfg->disablelog = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "disableuserfile")) {
		if (strlen(value) == 0) {
			cfg->disableuserfile = 0;
			return;
		} else {
			cfg->disableuserfile = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if (strlen(value) == 0) {
			cfg->srvip = 0;
			return;
		} else {
			cfg->srvip=inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "logfile")) {
		NULLFREE(cfg->logfile);
		if (strlen(value) > 0) {
			if(asprintf(&(cfg->logfile), "%s", value) < 0)
				fprintf(stderr, "Error allocating string for cfg->logfile\n");
		}
		return;
	}

	if (!strcmp(token, "usrfile")) {
		NULLFREE(cfg->usrfile);
		if (strlen(value) > 0) {
			if(asprintf(&(cfg->usrfile), "%s", value) < 0)
				fprintf(stderr, "Error allocating string for cfg->usrfile\n");
		}
		return;
	}

	if (!strcmp(token, "cwlogdir")) {
		NULLFREE(cfg->cwlogdir);
		if (strlen(value) > 0) {
			if(asprintf(&(cfg->cwlogdir), "%s", value) < 0)
				fprintf(stderr, "Error allocating string for cfg->cwlogdir\n");
		}
		return;
	}

	if (!strcmp(token, "usrfileflag")) {
		if (strlen(value) == 0) {
			cfg->usrfileflag = 0;
			return;
		} else {
			cfg->usrfileflag = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "clienttimeout")) {
		if (strlen(value) == 0) {
			cfg->ctimeout = CS_CLIENT_TIMEOUT;
			return;
		} else {
			cfg->ctimeout = atoi(value);
			if (cfg->ctimeout < 100)
				cfg->ctimeout *= 1000;
			return;
		}
	}

	if (!strcmp(token, "fallbacktimeout")) {
		if (strlen(value) == 0) {
			cfg->ftimeout = CS_CLIENT_TIMEOUT;
			return;
		} else {
			cfg->ftimeout = atoi(value);
			if (cfg->ftimeout < 100)
				cfg->ftimeout *= 1000;
			return;
		}
	}

	if (!strcmp(token, "clientmaxidle")) {
		if (strlen(value) == 0) {
			cfg->cmaxidle = CS_CLIENT_MAXIDLE;
			return;
		} else {
			cfg->cmaxidle = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "cachedelay")) {
		if (strlen(value) == 0) {
			cfg->delay = CS_DELAY;
			return;
		} else {
			cfg->delay = atoi(value);
			return;
		}
		/*cfg->delay = CS_DELAY;
		fprintf(stderr, "Parameter %s is deprecated -> ignored\n", token);
		return;*/
	}

	if (!strcmp(token, "bindwait")) {
		if (strlen(value) == 0) {
			cfg->bindwait = CS_BIND_TIMEOUT;
			return;
		} else {
			cfg->bindwait = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "netprio")) {
		if (strlen(value) == 0) {
			cfg->netprio = 0;
			return;
		} else {
			cfg->netprio = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "resolvedelay")) {
		if (strlen(value) == 0) {
			cfg->resolvedelay = CS_RESOLVE_DELAY;
			return;
		} else {
			cfg->resolvedelay = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "clientdyndns")) {
		if (strlen(value) == 0) {
			cfg->clientdyndns = 0;
			return;
		} else {
			cfg->clientdyndns = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "sleep")) {
		if (strlen(value) == 0) {
			cfg->tosleep = 0;
			return;
		} else {
			cfg->tosleep = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "unlockparental")) {
		if (strlen(value) == 0) {
			cfg->ulparent = 0;
			return;
		} else {
			cfg->ulparent = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "nice")) {
		if (strlen(value) == 0) {
			cfg->nice = 99;
			return;
		} else {
			cfg->nice = atoi(value);
			if ((cfg->nice<-20) || (cfg->nice>20)) cfg->nice = 99;
			if (cfg->nice != 99) cs_setpriority(cfg->nice);  // ignore errors
			return;
		}
	}

	if (!strcmp(token, "serialreadertimeout")) {
		if (cfg->srtimeout < 100)
			cfg->srtimeout = atoi(value) * 1000;
		else
			cfg->srtimeout = atoi(value);
		if (cfg->srtimeout <= 0)
			cfg->srtimeout = 1500;
		return;
	}

	if (!strcmp(token, "maxlogsize")) {
		if (strlen(value) == 0) {
			cfg->max_log_size = 10;
			return;
		} else {
			cfg->max_log_size = atoi(value);
			if( cfg->max_log_size <= 10 )
				cfg->max_log_size = 10;
			return;
		}
	}

	if( !strcmp(token, "waitforcards")) {
		if (strlen(value) == 0) {
			cfg->waitforcards = 1;
			return;
		} else {
			cfg->waitforcards = atoi(value);
			return;
		}
	}

	if( !strcmp(token, "preferlocalcards")) {
		if (strlen(value) == 0) {
			cfg->preferlocalcards = 0;
			return;
		} else {
			cfg->preferlocalcards = atoi(value);
			return;
		}
	}

	if( !strcmp(token, "saveinithistory")) {
		if (strlen(value) == 0) {
			cfg->saveinithistory = 0;
			return;
		} else {
			cfg->saveinithistory = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "readerrestartseconds")) {
		if (strlen(value) == 0) {
			cfg->reader_restart_seconds = 5;
			return;
		} else {
			cfg->reader_restart_seconds = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "readerautoloadbalance") || !strcmp(token, "lb_mode")) {
		if (strlen(value) == 0) {
			cfg->lb_mode = 0;
			return;
		} else {
			cfg->lb_mode = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "readerautoloadbalance_save") || !strcmp(token, "lb_save")) {
		if (strlen(value) == 0) {
			cfg->lb_save = 0;
			return;
		} else {
			cfg->lb_save = atoi(value);
			return;
		}
	}
	
	if (!strcmp(token, "lb_nbest_readers")) {
		if (strlen(value))
			cfg->lb_nbest_readers = atoi(value);
		return;
	}

	if (!strcmp(token, "lb_nfb_readers")) {
		if (strlen(value))
			cfg->lb_nfb_readers = atoi(value);
		return;
	}

	if (!strcmp(token, "lb_min_ecmcount")) {
		if (strlen(value))
			cfg->lb_min_ecmcount = atoi(value);
		return;
	}

	if (!strcmp(token, "lb_max_ecmcount")) {
		if (strlen(value))
			cfg->lb_max_ecmcount = atoi(value);
		return;
	}

	if (!strcmp(token, "lb_reopen_seconds")) {
		if (strlen(value))
			cfg->lb_reopen_seconds = atoi(value);
		return;
	}

	if (!strcmp(token, "resolvegethostbyname")) {
		if (strlen(value) == 0) {
			cfg->resolve_gethostbyname = 0;
			return;
		} else {
			cfg->resolve_gethostbyname = atoi(value);
			return;
		}
	}
	
	if (!strcmp(token, "failbantime")) {
		if(strlen(value) == 0) {
			cfg->failbantime = 0;
			return;
		} else {
			cfg->failbantime = atoi(value);
			return;
		}
	}

#ifdef CS_WITH_DOUBLECHECK
	if (!strcmp(token, "double_check")) {
		if (strlen(value) == 0) {
			cfg->double_check = 0;
			return;
		} else {
			cfg->double_check = atoi(value);
			return;
		}
	}
#endif
    

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in global section not recognized\n", token);
}

#ifdef CS_ANTICASC
void chk_t_ac(char *token, char *value)
{
	if (!strcmp(token, "enabled")) {
		cfg->ac_enabled = atoi(value);
		if( cfg->ac_enabled <= 0 )
			cfg->ac_enabled = 0;
		else
			cfg->ac_enabled = 1;
	return;
	}

	if (!strcmp(token, "numusers")) {
		cfg->ac_users = atoi(value);
		if( cfg->ac_users < 0 )
			cfg->ac_users = 0;
		return;
	}

	if (!strcmp(token, "sampletime")) {
		cfg->ac_stime = atoi(value);
		if( cfg->ac_stime < 0 )
			cfg->ac_stime = 2;
		return;
	}

	if (!strcmp(token, "samples")) {
		cfg->ac_samples = atoi(value);
		if( cfg->ac_samples < 2 || cfg->ac_samples > 10)
			cfg->ac_samples = 10;
		return;
	}

	if (!strcmp(token, "penalty")) {
		cfg->ac_penalty = atoi(value);
		if( cfg->ac_penalty < 0 )
			cfg->ac_penalty = 0;
		return;
	}

	if (!strcmp(token, "aclogfile")) {
		cs_strncpy(cfg->ac_logfile, value, sizeof(cfg->ac_logfile));
		return;
	}

	if( !strcmp(token, "fakedelay") ) {
		cfg->ac_fakedelay = atoi(value);
		if( cfg->ac_fakedelay < 100 || cfg->ac_fakedelay > 1000 )
			cfg->ac_fakedelay = 1000;
		return;
	}

	if( !strcmp(token, "denysamples") ) {
		cfg->ac_denysamples = atoi(value);
		if( cfg->ac_denysamples < 2 || cfg->ac_denysamples > cfg->ac_samples - 1 )
			cfg->ac_denysamples=cfg->ac_samples-1;
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in anticascading section not recognized\n",token);
}
#endif

void chk_t_monitor(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			cfg->mon_port = 0;
			return;
		} else {
			cfg->mon_port=atoi(value);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg->mon_srvip = 0;
			return;
		} else {
			cfg->mon_srvip=inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "nocrypt")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg->mon_allowed);
			return;
		} else {
			chk_iprange(value, &cfg->mon_allowed);
			return;
		}
	}

	if (!strcmp(token, "aulow")) {
		if(strlen(value) == 0) {
			cfg->mon_aulow = 0;
			return;
		} else {
			cfg->mon_aulow = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "monlevel")) {
		if(strlen(value) == 0) {
			cfg->mon_level = 0;
			return;
		} else {
			cfg->mon_level = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "hideclient_to")) {
		if(strlen(value) == 0) {
			cfg->mon_hideclient_to = 0;
			return;
		} else {
			cfg->mon_hideclient_to = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "appendchaninfo")) {
		if(strlen(value) == 0) {
			cfg->mon_appendchaninfo = 0;
			return;
		} else {
			cfg->mon_appendchaninfo = atoi(value);
			return;
		}
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in monitor section not recognized\n",token);
}

#ifdef WEBIF
void chk_t_webif(char *token, char *value)
{
	if (!strcmp(token, "httpport")) {
		if(strlen(value) == 0) {
			cfg->http_port = 0;
			return;
		} else {
			if (value[0]=='+') {
#ifdef WITH_SSL
				cfg->http_use_ssl=1;
#endif
				cfg->http_port = atoi(value+1);
			} else {
				cfg->http_port = atoi(value);
			}
			return;
		}
	}

	if (!strcmp(token, "httpuser")) {
		cs_strncpy(cfg->http_user, value, sizeof(cfg->http_user));
		return;
	}

	if (!strcmp(token, "httppwd")) {
		cs_strncpy(cfg->http_pwd, value, sizeof(cfg->http_pwd));
		return;
	}

	if (!strcmp(token, "httpcss")) {
		cs_strncpy(cfg->http_css, value, sizeof(cfg->http_css));
		return;
	}

	if (!strcmp(token, "httpjscript")) {
		cs_strncpy(cfg->http_jscript, value, sizeof(cfg->http_jscript));
		return;
	}

	if (!strcmp(token, "httpscript")) {
		cs_strncpy(cfg->http_script, value, sizeof(cfg->http_script));
		return;
	}

	if (!strcmp(token, "httpcert")) {
		cs_strncpy(cfg->http_cert, value, sizeof(cfg->http_cert));
		return;
	}

	if (!strcmp(token, "httptpl")) {
		cfg->http_tpl[0] = '\0';
		cs_strncpy(cfg->http_tpl, value, sizeof(cfg->http_tpl));
		if(strlen(value) != 0) {
			if(strlen(cfg->http_tpl) < (sizeof(cfg->http_tpl)-2) && cfg->http_tpl[strlen(cfg->http_tpl)-1] != '/') {
				cfg->http_tpl[strlen(cfg->http_tpl)] = '/';
				cfg->http_tpl[strlen(cfg->http_tpl)] = '\0';
			}
		}
		return;
	}

	if (!strcmp(token, "httprefresh")) {
		if(strlen(value) == 0) {
			cfg->http_refresh = 0;
			return;
		} else {
			cfg->http_refresh = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "httphideidleclients")) {
		if(strlen(value) == 0) {
			cfg->http_hide_idle_clients = 0;
			return;
		} else {
			cfg->http_hide_idle_clients = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "httpallowed")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg->http_allowed);
			return;
		} else {
			chk_iprange(value, &cfg->http_allowed);
			return;
		}
	}

	if (!strcmp(token, "httpreadonly")) {
		if(strlen(value) == 0) {
			cfg->http_readonly = 0;
			return;
		} else {
			cfg->http_readonly = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "httpdyndns")) {
		cs_strncpy((char *)cfg->http_dyndns, value, sizeof(cfg->http_dyndns));
		return;
	}

	if (!strcmp(token, "httpsavefullcfg")) {
		if(strlen(value) == 0) {
			cfg->http_full_cfg = 0;
			return;
		} else {
			cfg->http_full_cfg = atoi(value);
			return;
		}
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in webif section not recognized\n",token);
}
#endif


void chk_t_camd33(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			cfg->c33_port = 0;
			return;
		} else {
			cfg->c33_port = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg->c33_srvip = 0;
			return;
		} else {
			cfg->c33_srvip = inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "nocrypt")) {
		if(strlen(value) == 0) {
			return;
		} else {
			chk_iprange(value, &cfg->c33_plain);
			return;
		}
	}

	if (!strcmp(token, "passive")) {
		cfg->c33_passive = (value[0]!='0');
		return;
	}

	if (!strcmp(token, "key")) {
		if(strlen(value) == 0) {
			cfg->c33_crypted = 0;
			return;
		}
		if (key_atob(value, cfg->c33_key)) {
			fprintf(stderr, "Configuration camd3.3x: Error in Key\n");
			exit(1);
		}
		cfg->c33_crypted=1;
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in camd33 section not recognized\n",token);
}

void chk_t_camd35(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			cfg->c35_port = 0;
			return;
		} else {
			cfg->c35_port = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg->c35_srvip = 0;
			return;
		} else {
			cfg->c35_srvip = inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "suppresscmd08")) {
		if(strlen(value) == 0) {
			cfg->c35_suppresscmd08 = 0;
			return;
		} else {
			cfg->c35_suppresscmd08=atoi(value);
			return;
		}
	}
	
	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in camd35 section not recognized\n", token);
}

void chk_t_camd35_tcp(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			clear_ptab(&cfg->c35_tcp_ptab);
			return;
		} else {
			chk_port_tab(value, &cfg->c35_tcp_ptab);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg->c35_tcp_srvip = 0;
			return;
		} else {
			cfg->c35_tcp_srvip = inet_addr(value);
			return;
		}
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in camd35 tcp section not recognized\n", token);
}

void chk_t_newcamd(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			clear_ptab(&cfg->ncd_ptab);
			return;
		} else {
			chk_port_tab(value, &cfg->ncd_ptab);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg->ncd_srvip = 0;
			return;
		} else {
			cfg->ncd_srvip = inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "allowed")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg->ncd_allowed);
			return;
		} else {
			chk_iprange(value, &cfg->ncd_allowed);
			return;
		}
	}

	if (!strcmp(token, "key")) {
		if(strlen(value) == 0)
			return;
		if (key_atob14(value, cfg->ncd_key)) {
			fprintf(stderr, "Configuration newcamd: Error in Key\n");
			exit(1);
		}
		return;
	}

	if (!strcmp(token, "keepalive")) {
		if(strlen(value) == 0) {
			cfg->ncd_keepalive = 1;
			return;
		} else {
			cfg->ncd_keepalive = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "mgclient")) {
		if(strlen(value) == 0) {
			cfg->ncd_mgclient = 0;
			return;
		} else {
			cfg->ncd_mgclient = atoi(value);
			return;
		}
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in newcamd section not recognized\n", token);
}

void chk_t_cccam(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			cfg->cc_port = 0;
			return;
		} else {
			cfg->cc_port = atoi(value);
			return;
		}
	}
	//if (!strcmp(token, "serverip")) { cfg->cc_srvip=inet_addr(value); return; }

	if (!strcmp(token, "reshare")) {
		if(strlen(value) == 0) {
			cfg->cc_reshare = 0;
			return;
		} else {
			cfg->cc_reshare=atoi(value);
			return;
		}
	}
	if (!strcmp(token, "ignorereshare")) {
		if(strlen(value) == 0) 
			cfg->cc_ignore_reshare = 0;
		else
			cfg->cc_ignore_reshare=atoi(value);
		return;
	}
	// cccam version
	if (!strcmp(token, "version")) {
		if (strlen(value) > sizeof(cfg->cc_version) - 1) {
			fprintf(stderr, "cccam config: version too long\n");
			exit(1);
		}
		memset(cfg->cc_version, 0, sizeof(cfg->cc_version));
		strncpy((char*)cfg->cc_version, value, sizeof(cfg->cc_version) - 1);
		return;
	}
	// cccam: Update cards interval
	if (!strcmp(token, "updateinterval")) {
	        if (strlen(value) == 0) 
	                cfg->cc_update_interval = 4*60; //4x60s = 4min
                else
                        cfg->cc_update_interval = atoi(value);
                return;
	}
	
	// cccam: Kind of card updates
	if (!strcmp(token, "minimizecards")) {
	        if (strlen(value) == 0)
	                cfg->cc_minimize_cards = 0;
                else
                        cfg->cc_minimize_cards = atoi(value);
                return;
	}

	// cccam: keep clients connected
	if (!strcmp(token, "keepconnected")) {
	        if (strlen(value) == 0)
	                cfg->cc_keep_connected = 1;
                else
                        cfg->cc_keep_connected = atoi(value);
                return;
	}


	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in cccam section not recognized\n",token);
}

void chk_t_radegast(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			cfg->rad_port = 0;
			return;
		} else {
			cfg->rad_port = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg->rad_srvip = 0;
			return;
		} else {
			cfg->rad_srvip = inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "allowed")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg->rad_allowed);
			return;
		} else {
			chk_iprange(value, &cfg->rad_allowed);
			return;
		}
	}

	if (!strcmp(token, "user")) {
		cs_strncpy(cfg->rad_usr, value, sizeof(cfg->rad_usr));
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in radegast section not recognized\n", token);
}

void chk_t_serial(char *token, char *value)
{
	if (!strcmp(token, "device")) {
		int l;
		l = strlen(cfg->ser_device);
		if (l)
			cfg->ser_device[l++]=1;  // use ctrl-a as delimiter
		cs_strncpy(cfg->ser_device+l, value, sizeof(cfg->ser_device)-l);
		return;
	}
	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in serial section not recognized\n", token);
}

#ifdef CS_WITH_GBOX
void chk_t_gbox(char *token, char *value)
{
	//if (!strcmp(token, "password")) strncpy(cfg->gbox_pwd, i2b(4, a2i(value, 4)), 4);
	if (!strcmp(token, "password")) {
		cs_atob(cfg->gbox_pwd, value, 4);
		return;
	}

	if (!strcmp(token, "maxdist")) {
		cfg->maxdist=atoi(value);
		return;
	}

	if (!strcmp(token, "ignorelist")) {
		cs_strncpy((char *)cfg->ignorefile, value, sizeof(cfg->ignorefile));
		return;
	}

	if (!strcmp(token, "onlineinfos")) {
		cs_strncpy((char *)cfg->gbxShareOnl, value, sizeof(cfg->gbxShareOnl));
		return;
	}

	if (!strcmp(token, "cardinfos")) {
		cs_strncpy((char *)cfg->cardfile, value, sizeof(cfg->cardfile));
		return;
	}

	if (!strcmp(token, "locals"))
	{
		char *ptr1;
		int n = 0, i;
		for (i = 0, ptr1 = strtok(value, ","); (i < CS_MAXLOCALS) && (ptr1); ptr1 = strtok(NULL, ",")) {
			cfg->locals[n++] = a2i(ptr1, 8);
			//printf("%i %08X",n,cfg->locals[n-1]);
		}
		cfg->num_locals = n;
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in gbox section not recognized\n",token);
}
#endif

#ifdef HAVE_DVBAPI
void chk_t_dvbapi(char *token, char *value)
{
	if (!strcmp(token, "enabled")) {
		if(strlen(value) == 0) {
			cfg->dvbapi_enabled = 0;
		} else {
			cfg->dvbapi_enabled = atoi(value);
		}
		return;
	}

	if (!strcmp(token, "au")) {
		if(strlen(value) == 0) {
			cfg->dvbapi_au = 0;
		} else {
			cfg->dvbapi_au = atoi(value);
		}
		return;
	}

	if (!strcmp(token, "pmt_mode")) {
		if(strlen(value) == 0) {
			cfg->dvbapi_pmtmode = 0;
		} else {
			cfg->dvbapi_pmtmode = atoi(value);
			if(cfg->dvbapi_pmtmode > 3)
				cfg->dvbapi_pmtmode = 3;
		}
		return;
	}

	if (!strcmp(token, "boxtype")) {
		int i;
		for (i=1;i<=BOXTYPES;i++) {
			if (strcmp(value, boxdesc[i])==0) {
				cfg->dvbapi_boxtype=i;
				return;
			}
		}

		cfg->dvbapi_boxtype=0;
		return;
	}

	if (!strcmp(token, "user")) {
		cs_strncpy(cfg->dvbapi_usr, value, sizeof(cfg->dvbapi_usr));
		return;
	}

	if(!strcmp(token, "services")) {
		chk_services(value, &cfg->dvbapi_sidtabok, &cfg->dvbapi_sidtabno);
		return;
	}

	//obsolete
	if (!strcmp(token, "priority")) {
		dvbapi_chk_caidtab(value, 'p');
		return;
	}

	if (!strcmp(token, "ignore")) {
		dvbapi_chk_caidtab(value, 'i');
		return;
	}

	if (!strcmp(token, "cw_delay")) {
		dvbapi_chk_caidtab(value, 'd');
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in dvbapi section not recognized\n",token);
}
#endif

static void chk_token(char *token, char *value, int tag)
{
	switch(tag) {
		case TAG_GLOBAL  : chk_t_global(token, value); break;
		case TAG_MONITOR : chk_t_monitor(token, value); break;
		case TAG_CAMD33  : chk_t_camd33(token, value); break;
		case TAG_CAMD35  :
		case TAG_CS357X  : chk_t_camd35(token, value); break;
		case TAG_NEWCAMD : chk_t_newcamd(token, value); break;
		case TAG_RADEGAST: chk_t_radegast(token, value); break;
		case TAG_SERIAL  : chk_t_serial(token, value); break;
		case TAG_CS378X  : chk_t_camd35_tcp(token, value); break;
		case TAG_CCCAM   : chk_t_cccam(token, value); break;

#ifdef CS_WITH_GBOX
		case TAG_GBOX    : chk_t_gbox(token, value); break;
#else
		case TAG_GBOX    : fprintf(stderr, "OSCam compiled without gbox support. Parameter %s ignored\n", token); break;
#endif


#ifdef HAVE_DVBAPI
		case TAG_DVBAPI  : chk_t_dvbapi(token, value); break;
#else
		case TAG_DVBAPI  : fprintf(stderr, "OSCam compiled without DVB API support. Parameter %s ignored\n", token); break;
#endif


#ifdef WEBIF
		case TAG_WEBIF   : chk_t_webif(token, value); break;
#else
		case TAG_WEBIF   : fprintf(stderr, "OSCam compiled without Webinterface support. Parameter %s ignored\n", token); break;
#endif


#ifdef CS_ANTICASC
		case TAG_ANTICASC: chk_t_ac(token, value); break;
#else
		case TAG_ANTICASC: fprintf(stderr, "OSCam compiled without Anticascading support. Parameter %s ignored\n", token); break;
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
	if (!(fp = fopen(token, "r")))
		return;
	for(nr = 0; fgets(token, sizeof(token), fp);) {
		int i, c;
		char *ptr;
		if (!(value=strchr(token, ':')))
			continue;
		*value++ ='\0';
		if( (ptr = strchr(value, '#')) )
			*ptr = '\0';
		if (strlen(trim(token)) != 2)
			continue;
		if (strlen(trim(value)) != 4)
			continue;
		if ((i = byte_atob(token)) < 0)
			continue;
		if ((c = word_atob(value)) < 0)
			continue;
		len4caid[i] = c;
		nr++;
	}
	fclose(fp);
	cs_log("%d lengths for caid guessing loaded", nr);
	return;
}

int search_boxkey(ushort caid, char *key)
{
	int i, rc = 0;
	FILE *fp;
	char c_caid[512];

	sprintf(c_caid, "%s%s", cs_confdir, cs_cert);
	fp = fopen(c_caid, "r");
	if (fp) {
		for (; (!rc) && fgets(c_caid, sizeof(c_caid), fp);) {
			char *c_provid, *c_key;

			c_provid = strchr(c_caid, '#');
			if (c_provid)
				*c_provid = '\0';
			if (!(c_provid = strchr(c_caid, ':')))
				continue;
			*c_provid++ ='\0';
			if (!(c_key = strchr(c_provid, ':')))
				continue;
			*c_key++ ='\0';
			if (word_atob(trim(c_caid))!=caid)
				continue;
			if ((i=(strlen(trim(c_key))>>1)) > 256)
				continue;
			if (cs_atob((uchar *)key, c_key, i) < 0) {
				cs_log("wrong key in \"%s\"", cs_cert);
				continue;
			}
			rc = 1;
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
	if ((cfg->nice = getpriority(PRIO_PROCESS, 0)) == (-1))
	if (errno)
#endif
#endif
	cfg->nice = 99;
	cfg->ctimeout = CS_CLIENT_TIMEOUT;
	cfg->ftimeout = CS_CLIENT_TIMEOUT / 2;
	cfg->cmaxidle = CS_CLIENT_MAXIDLE;
	cfg->delay = CS_DELAY;
	cfg->bindwait = CS_BIND_TIMEOUT;
	cfg->resolvedelay = CS_RESOLVE_DELAY;
	cfg->mon_level = 2;
	cfg->mon_hideclient_to = 0;
	cfg->srtimeout = 1500;
	cfg->ulparent = 0;
	cfg->logfile = NULL;
	cfg->usrfile = NULL;
	cfg->cwlogdir = NULL;
	cfg->reader_restart_seconds = 5;
	cfg->waitforcards = 1;
#ifdef QBOXHD_LED
    cfg->disableqboxhdled = 1;
#endif

#ifdef WEBIF
	strcpy(cfg->http_user, "");
	strcpy(cfg->http_pwd, "");
	strcpy(cfg->http_css, "");
	cfg->http_refresh = 0;
	cfg->http_hide_idle_clients = 0;
	strcpy(cfg->http_tpl, "");
#endif
	cfg->ncd_keepalive = 1;
#ifdef CS_ANTICASC
	cfg->ac_enabled = 0;
	cfg->ac_users = 0;
	cfg->ac_stime = 2;
	cfg->ac_samples = 10;
	cfg->ac_denysamples = 8;
	cfg->ac_fakedelay = 1000;
	strcpy(cfg->ac_logfile, "./oscam_ac.log");
#endif
#ifdef MODULE_CCCAM
	cfg->cc_update_interval = 240;
	cfg->cc_keep_connected = 1;
#endif  
	sprintf(token, "%s%s", cs_confdir, cs_conf);
	if (!(fp = fopen(token, "r"))) {
		fprintf(stderr, "Cannot open config file '%s' (errno=%d)\n", token, errno);
		exit(1);
	}
	while (fgets(token, sizeof(token), fp)) {
		int i, l;
		//void *ptr;
		if ((l = strlen(trim(token))) < 3)
			continue;
		if ((token[0] == '[') && (token[l-1] == ']')) {
			for (token[l-1] = 0, tag = -1, i = TAG_GLOBAL; cctag[i]; i++)
				if (!strcmp(cctag[i], strtolower(token+1)))
					tag = i;
			continue;
		}
		if (!(value=strchr(token, '=')))
			continue;
		*value++ ='\0';
		chk_token(trim(strtolower(token)), trim(value), tag);
	}
	fclose(fp);
#ifdef CS_LOGFILE
	if (cfg->logfile == NULL) {
		if(asprintf(&(cfg->logfile), "%s", CS_LOGFILE) < 0)
			fprintf(stderr, "Error allocating string for cfg->logfile\n");
	}
#endif
	cs_init_log();
	cs_init_statistics();
	if (cfg->ftimeout >= cfg->ctimeout) {
		cfg->ftimeout = cfg->ctimeout - 100;
		cs_log("WARNING: fallbacktimeout adjusted to %lu ms (must be smaller than clienttimeout (%lu ms))", cfg->ftimeout, cfg->ctimeout);
	}
	if(cfg->ftimeout < cfg->srtimeout) {
		cfg->ftimeout = cfg->srtimeout + 100;
		cs_log("WARNING: fallbacktimeout adjusted to %lu ms (must be greater than serialreadertimeout (%lu ms))", cfg->ftimeout, cfg->srtimeout);
	}
	if(cfg->ctimeout < cfg->srtimeout) {
		cfg->ctimeout = cfg->srtimeout + 100;
		cs_log("WARNING: clienttimeout adjusted to %lu ms (must be greater than serialreadertimeout (%lu ms))", cfg->ctimeout, cfg->srtimeout);
	}
#ifdef CS_ANTICASC
	if( cfg->ac_denysamples+1 > cfg->ac_samples ) {
		cfg->ac_denysamples = cfg->ac_samples - 1;
		cs_log("WARNING: DenySamples adjusted to %d", cfg->ac_denysamples);
	}
#endif
	return 0;
}

void chk_account(const char *token, char *value, struct s_auth *account)
{
	int i;
	char *ptr1;

	if (!strcmp(token, "user")) {
		cs_strncpy(account->usr, value, sizeof(account->usr));
		return;
	}

	if (!strcmp(token, "pwd")) {
		cs_strncpy(account->pwd, value, sizeof(account->pwd));
		return;
	}

	if (!strcmp(token, "hostname")) {
		cs_strncpy((char *)account->dyndns, value, sizeof(account->dyndns));
		return;
	}

	if (!strcmp(token, "betatunnel")) {
		if(strlen(value) == 0) {
			clear_tuntab(&account->ttab);
			return;
		} else {
			chk_tuntab(value, &account->ttab);
			return;
		}
	}

	if (!strcmp(token, "uniq")) {
		if(strlen(value) == 0) {
			account->uniq = 0;
			return;
		} else {
			account->uniq = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "sleep")) {
		if(strlen(value) == 0) {
			account->tosleep = 0;
			return;
		} else {
			account->tosleep = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "sleepsend")) {
		if(strlen(value) == 0) {
			account->c35_sleepsend = 0;
			return;
		} else {
			account->c35_sleepsend = atoi(value);
			if (account->c35_sleepsend > 0xFF)
				account->c35_sleepsend = 0xFF;
			return;
		}
	}

	if (!strcmp(token, "monlevel")) {
		if(strlen(value) == 0) {
			account->monlvl = 0;
			return;
		} else {
			account->monlvl = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "caid")) {
		if(strlen(value) == 0) {
			clear_caidtab(&account->ctab);
			return;
		} else {
			chk_caidtab(value, &account->ctab);
			return;
		}
	}

	if (!strcmp(token, "disabled")) {
		if(strlen(value) == 0) {
			account->disabled = 0;
			return;
		} else {
			account->disabled = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "suppresscmd08")) {
		if(strlen(value) == 0) {
			account->c35_suppresscmd08 = 0;
			return;
		} else {
			account->c35_suppresscmd08=atoi(value);
			return;
		}
	}

	if (!strcmp(token, "cccmaxhops")) {
		if (strlen(value) == 0) {
			account->cccmaxhops = 10;
			return;
		} else {
			account->cccmaxhops = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "cccreshare")) {
		if (strlen(value) == 0) {
			account->cccreshare = 0;
			return;
		} else {
			account->cccreshare = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "keepalive")) {
		if(strlen(value) == 0) {
			account->ncd_keepalive = 1;
			return;
		} else {
			account->ncd_keepalive = atoi(value);
			return;
		}
	}
	/*
	*  case insensitive
	*/
	strtolower(value);

	if (!strcmp(token, "au")) {
		//set default values for usage during runtime from Webif
		account->aureader = NULL;
		account->autoau=0;

		if(value && value[0] == '1')
			account->autoau = 1;
		struct s_reader *rdr;
		for (rdr=first_reader; rdr ; rdr=rdr->next)
			if ((rdr->label[0]) && (!strncmp(rdr->label, value, strlen(rdr->label))))
				account->aureader = rdr;
		return;
	}

	if (!strcmp(token, "group")) {
		account->grp = 0;
		for (ptr1=strtok(value, ","); ptr1; ptr1=strtok(NULL, ",")) {
			int g;
			g = atoi(ptr1);
			if ((g>0) && (g < 65)) account->grp|=(((uint64)1)<<(g-1));
		}
		return;
	}

	if(!strcmp(token, "services")) {
		chk_services(value, &account->sidtabok, &account->sidtabno);
		return;
	}

	if(!strcmp(token, "ident")) { /*ToDo ftab clear*/
		chk_ftab(value, &account->ftab, "user", account->usr, "provid");
		return;
	}

	if(!strcmp(token, "class")) {
		chk_cltab(value, &account->cltab);
		return;
	}

	if(!strcmp(token, "chid")) {
		chk_ftab(value, &account->fchid, "user", account->usr, "chid");
		return;
	}

	if (!strcmp(token, "expdate")) {
		if (!value[0]) {
			account->expirationdate=(time_t)NULL;
			return;
		}
		struct tm cstime;
		memset(&cstime,0,sizeof(cstime));
		for (i=0, ptr1=strtok(value, "-/"); (i<3)&&(ptr1); ptr1=strtok(NULL, "-/"), i++) {
			switch(i) {
				case 0: cstime.tm_year=atoi(ptr1)-1900; break;
				case 1: cstime.tm_mon =atoi(ptr1)-1;    break;
				case 2: cstime.tm_mday=atoi(ptr1);      break;
			}
		}
		account->expirationdate=mktime(&cstime);
		return;
	}

	if (!strcmp(token, "allowedtimeframe")) {
		if(strlen(value) == 0) {
			account->allowedtimeframe[0] = 0;
			account->allowedtimeframe[1] = 0;
		} else {
			int allowed[4];
			if (sscanf(value, "%d:%d-%d:%d", &allowed[0], &allowed[1], &allowed[2], &allowed[3]) != 4) {
				account->allowedtimeframe[0] = 0;
				account->allowedtimeframe[1] = 0;
				fprintf(stderr, "Warning: value '%s' is not valid for allowedtimeframe (hh:mm-hh:mm)\n", value);
			} else {
				account->allowedtimeframe[0] = (allowed[0]*60) + allowed[1];
				account->allowedtimeframe[1] = (allowed[2]*60) + allowed[3];
			}
		}
		return;
	}

	if (!strcmp(token, "failban")) {
		if(strlen(value) == 0) {
			account->failban = 0;
			return;
		} else {
			account->failban = atoi(value);
			return;
		}
	}

#ifdef CS_ANTICASC
	if( !strcmp(token, "numusers") ) {
		account->ac_users = atoi(value);
		return;
	}

	if( !strcmp(token, "penalty") ) {
		account->ac_penalty = atoi(value);
		return;
	}
#endif

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in account section not recognized\n",token);
}

int write_services()
{
	int i;
	FILE *f;
	struct s_sidtab *sidtab = cfg->sidtab;
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, 255,"%s%s", cs_confdir, cs_sidt);
	snprintf(tmpfile, 255, "%s%s.tmp", cs_confdir, cs_sidt);
	snprintf(bakfile, 255,"%s%s.bak", cs_confdir, cs_sidt);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d)", tmpfile, errno);
		return(1);
	}
	fprintf(f,"# oscam.services generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.gmc.to/oscam/browser/trunk/Distribution/doc/txt/oscam.services.txt\n\n");

	while(sidtab != NULL){
		fprintf(f,"[%s]\n", sidtab->label);
		fprintf_conf(f, CONFVARWIDTH, "caid", "");
		for (i=0; i<sidtab->num_caid; i++){
			if (i==0) fprintf(f,"%04X", sidtab->caid[i]);
			else fprintf(f,",%04X", sidtab->caid[i]);
		}
		fputc((int)'\n', f);
		fprintf_conf(f, CONFVARWIDTH, "provid", "");
		for (i=0; i<sidtab->num_provid; i++){
			if (i==0) fprintf(f,"%06lX", sidtab->provid[i]);
			else fprintf(f,",%06lX", sidtab->provid[i]);
		}
		fputc((int)'\n', f);
		fprintf_conf(f, CONFVARWIDTH, "srvid", "");
		for (i=0; i<sidtab->num_srvid; i++){
			if (i==0) fprintf(f,"%04X", sidtab->srvid[i]);
			else fprintf(f,",%04X", sidtab->srvid[i]);
		}
		fprintf(f,"\n\n");
		sidtab=sidtab->next;
	}

	fclose(f);
	return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

int write_config()
{
	int i,j;
	FILE *f;
	char *dot = "", *dot1 = "", *dot2 = ""; //flags for delimiters
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, 255,"%s%s", cs_confdir, cs_conf);
	snprintf(tmpfile, 255, "%s%s.tmp", cs_confdir, cs_conf);
	snprintf(bakfile, 255,"%s%s.bak", cs_confdir, cs_conf);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d)", tmpfile, errno);
		return(1);
	}
	fprintf(f,"# oscam.conf generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.gmc.to/oscam/browser/trunk/Distribution/doc/txt/oscam.conf.txt\n\n");

	/*global settings*/
	fprintf(f,"[global]\n");
	if (cfg->srvip != 0 || (cfg->srvip == 0 && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "serverip", "%s\n", inet_ntoa(*(struct in_addr *)&cfg->srvip));
	if (cfg->usrfile != NULL || (cfg->usrfile == NULL && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "usrfile", "%s\n", cfg->usrfile);
	if (cfg->logfile != NULL || (cfg->logfile == NULL && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "logfile", "%s\n", cfg->logfile);
	if (cfg->cwlogdir != NULL || (cfg->cwlogdir == NULL && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "cwlogdir", "%s\n", cfg->cwlogdir);
#ifdef QBOXHD_LED
	if (cfg->disableqboxhdled || (!cfg->disableqboxhdled && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "disableqboxhdled", "%d\n", cfg->disableqboxhdled);
#endif
    if (cfg->disablelog || (!cfg->disablelog && cfg->http_full_cfg))
    	fprintf_conf(f, CONFVARWIDTH, "disablelog", "%d\n", cfg->disablelog);
    if (cfg->disableuserfile || (!cfg->disableuserfile && cfg->http_full_cfg))
    	fprintf_conf(f, CONFVARWIDTH, "disableuserfile", "%d\n", cfg->disableuserfile);
    if (cfg->usrfileflag || (!cfg->usrfileflag && cfg->http_full_cfg))
    	fprintf_conf(f, CONFVARWIDTH, "usrfileflag", "%d\n", cfg->usrfileflag);
	if (cfg->ctimeout != CS_CLIENT_TIMEOUT || (cfg->ctimeout != CS_CLIENT_TIMEOUT && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "clienttimeout", "%ld\n", cfg->ctimeout);
	if (cfg->ftimeout || (!cfg->ftimeout && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "fallbacktimeout", "%ld\n", cfg->ftimeout);
	if (cfg->cmaxidle != CS_CLIENT_MAXIDLE || (cfg->cmaxidle == CS_CLIENT_MAXIDLE && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "clientmaxidle", "%d\n", cfg->cmaxidle);
	if (cfg->failbantime || (!cfg->failbantime && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "failbantime", "%d\n", cfg->failbantime);
	if (cfg->delay != CS_DELAY || (cfg->delay == CS_DELAY && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "cachedelay", "%ld\n", cfg->delay); //deprecated
	if (cfg->bindwait != CS_BIND_TIMEOUT || (cfg->bindwait != CS_BIND_TIMEOUT && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "bindwait", "%d\n", cfg->bindwait);
	if (cfg->netprio || (!cfg->netprio && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "netprio", "%ld\n", cfg->netprio);
	if (cfg->clientdyndns || (!cfg->clientdyndns && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "clientdyndns", "%d\n", cfg->clientdyndns);
	if (cfg->resolvedelay != CS_RESOLVE_DELAY || (cfg->resolvedelay == CS_RESOLVE_DELAY && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "resolvedelay", "%d\n", cfg->resolvedelay);
	if (cfg->tosleep ||(!cfg->tosleep && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "sleep", "%d\n", cfg->tosleep);
	if (cfg->ulparent ||(!cfg->ulparent && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "unlockparental", "%d\n", cfg->ulparent);
	if (cfg->nice != 99 || (cfg->nice == 99 && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "nice", "%d\n", cfg->nice);
	if (cfg->srtimeout != 1500 || (cfg->srtimeout == 1500 && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "serialreadertimeout", "%d\n", cfg->srtimeout);
	if (cfg->max_log_size != 10 || (cfg->max_log_size == 10 && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "maxlogsize", "%d\n", cfg->max_log_size);
	if (!cfg->waitforcards ||(cfg->waitforcards && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "waitforcards", "%d\n", cfg->waitforcards);
	if (cfg->preferlocalcards ||(!cfg->preferlocalcards && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "preferlocalcards", "%d\n", cfg->preferlocalcards);
	if (cfg->saveinithistory ||(!cfg->saveinithistory && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "saveinithistory", "%d\n", cfg->saveinithistory);
	if (cfg->reader_restart_seconds != 5 ||(cfg->reader_restart_seconds == 5 && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "readerrestartseconds", "%d\n", cfg->reader_restart_seconds);

	if (cfg->lb_mode ||(!cfg->lb_mode && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "lb_mode", "%d\n", cfg->lb_mode);
	if (cfg->lb_save ||(!cfg->lb_save && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "lb_save", "%d\n", cfg->lb_save);
	if (cfg->lb_nbest_readers != DEFAULT_NBEST ||(cfg->lb_nbest_readers == DEFAULT_NBEST && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "lb_nbest_readers", "%d\n", cfg->lb_nbest_readers);
	if (cfg->lb_nfb_readers != DEFAULT_NFB ||(cfg->lb_nfb_readers == DEFAULT_NFB  && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "lb_nfb_readers", "%d\n", cfg->lb_nfb_readers);
	if (cfg->lb_min_ecmcount != DEFAULT_MIN_ECM_COUNT ||(cfg->lb_min_ecmcount == DEFAULT_MIN_ECM_COUNT  && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "lb_min_ecmcount", "%d\n", cfg->lb_min_ecmcount);
	if (cfg->lb_max_ecmcount != DEFAULT_MAX_ECM_COUNT ||(cfg->lb_max_ecmcount == DEFAULT_MAX_ECM_COUNT  && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "lb_max_ecmcount", "%d\n", cfg->lb_max_ecmcount);
	if (cfg->lb_reopen_seconds != DEFAULT_REOPEN_SECONDS ||(cfg->lb_reopen_seconds == DEFAULT_REOPEN_SECONDS  && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "lb_reopen_seconds", "%d\n", cfg->lb_reopen_seconds);

	if (cfg->resolve_gethostbyname ||(!cfg->resolve_gethostbyname && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "resolvegethostbyname", "%d\n", cfg->resolve_gethostbyname);

#ifdef CS_WITH_DOUBLECHECK
	if (cfg->double_check ||(!cfg->double_check && cfg->http_full_cfg))
		fprintf_conf(f, CONFVARWIDTH, "double_check", "%d\n", cfg->double_check);
#endif

	fputc((int)'\n', f);

	/*monitor settings*/
	if(cfg->mon_port || cfg->mon_appendchaninfo || cfg->mon_hideclient_to) {
		fprintf(f,"[monitor]\n");
		fprintf_conf(f, CONFVARWIDTH, "port", "%d\n", cfg->mon_port);
		if (cfg->mon_srvip != 0)
			fprintf_conf(f, CONFVARWIDTH, "serverip", "%s\n", inet_ntoa(*(struct in_addr *)&cfg->mon_srvip));

		fprintf_conf(f, CONFVARWIDTH, "nocrypt", "");
		struct s_ip *cip;
		for (cip = cfg->mon_allowed; cip; cip = cip->next){
			fprintf(f,"%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1])	fprintf(f,"-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
		}
		fputc((int)'\n', f);
		fprintf_conf(f, CONFVARWIDTH, "aulow", "%d\n", cfg->mon_aulow);
		fprintf_conf(f, CONFVARWIDTH, "hideclient_to", "%d\n", cfg->mon_hideclient_to);
		fprintf_conf(f, CONFVARWIDTH, "monlevel", "%d\n", cfg->mon_level);
		fprintf_conf(f, CONFVARWIDTH, "appendchaninfo", "%d\n", cfg->mon_appendchaninfo);
		fputc((int)'\n', f);
	}

	/*newcamd*/
	if ((cfg->ncd_ptab.nports > 0) && (cfg->ncd_ptab.ports[0].s_port > 0)){
		fprintf(f,"[newcamd]\n");
		fprintf_conf(f, CONFVARWIDTH, "port", "");
		dot1 = "";
		for(i = 0; i < cfg->ncd_ptab.nports; ++i){
			fprintf(f,"%s%d", dot1, cfg->ncd_ptab.ports[i].s_port);

			// separate DES Key
			if(cfg->ncd_ptab.ports[i].ncd_key_is_set){
				int k;
				fprintf(f,"{");
				for (k = 0; k < 14; k++)
					fprintf(f,"%02X", cfg->ncd_ptab.ports[i].ncd_key[k]);
				fprintf(f,"}");
			}

			fprintf(f,"@%04X", cfg->ncd_ptab.ports[i].ftab.filts[0].caid);

			if (cfg->ncd_ptab.ports[i].ftab.filts[0].nprids > 0){
				fprintf(f,":");
				dot2 = "";
				for (j = 0; j < cfg->ncd_ptab.ports[i].ftab.filts[0].nprids; ++j){
					fprintf(f,"%s%06X", dot2, (int)cfg->ncd_ptab.ports[i].ftab.filts[0].prids[j]);
					dot2 = ",";
				}
			}
			dot1=";";
		}

		fputc((int)'\n', f);
		if (cfg->ncd_srvip != 0)
			fprintf_conf(f, CONFVARWIDTH, "serverip", "%s\n", inet_ntoa(*(struct in_addr *)&cfg->ncd_srvip));
		fprintf_conf(f, CONFVARWIDTH, "key", "");
		for (i = 0; i < 14; i++) fprintf(f,"%02X", cfg->ncd_key[i]);
		fprintf(f,"\n");
		fprintf_conf(f, CONFVARWIDTH, "allowed", "");
		struct s_ip *cip;
		dot="";
		for (cip = cfg->ncd_allowed; cip; cip = cip->next){
			fprintf(f,"%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1])	fprintf(f,"-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
		}
		fprintf(f,"\n");
		fprintf_conf(f, CONFVARWIDTH, "keepalive", "%d\n", cfg->ncd_keepalive);
		fprintf_conf(f, CONFVARWIDTH, "mgclient", "%d\n", cfg->ncd_mgclient);
		fprintf(f,"\n");
	}

	/*camd3.3*/
	if ( cfg->c33_port > 0) {
		fprintf(f,"[camd33]\n");
		fprintf_conf(f, CONFVARWIDTH, "port", "%d\n", cfg->c33_port);
		if (cfg->c33_srvip != 0)
			fprintf_conf(f, CONFVARWIDTH, "serverip", "%s\n", inet_ntoa(*(struct in_addr *)&cfg->c33_srvip));
		fprintf_conf(f, CONFVARWIDTH, "passive", "%d\n", cfg->c33_passive);
		fprintf_conf(f, CONFVARWIDTH, "key", ""); for (i = 0; i < (int) sizeof(cfg->c33_key); ++i) fprintf(f,"%02X", cfg->c33_key[i]); fputc((int)'\n', f);
		fprintf_conf(f, CONFVARWIDTH, "nocrypt", "");
		struct s_ip *cip;
		dot="";
		for (cip = cfg->c33_plain; cip; cip = cip->next){
			fprintf(f,"%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1])	fprintf(f,"-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
	  }
		fprintf(f,"\n\n");
	}

	/*camd3.5*/
	if ( cfg->c35_port > 0) {
		fprintf(f,"[cs357x]\n");
		fprintf_conf(f, CONFVARWIDTH, "port", "%d\n", cfg->c35_port);
		if (cfg->c35_srvip != 0)
			fprintf_conf(f, CONFVARWIDTH, "serverip", "%s\n", inet_ntoa(*(struct in_addr *)&cfg->c35_srvip));
		if (cfg->c35_suppresscmd08)
			fprintf_conf(f, CONFVARWIDTH, "suppresscmd08", "%d\n", cfg->c35_suppresscmd08);
		fprintf(f,"\n");
	}

	/*camd3.5 TCP*/
	if ((cfg->c35_tcp_ptab.nports > 0) && (cfg->c35_tcp_ptab.ports[0].s_port > 0)) {
		fprintf(f,"[cs378x]\n");
		fprintf_conf(f, CONFVARWIDTH, "port", "");
		dot1 = "";
		for(i = 0; i < cfg->c35_tcp_ptab.nports; ++i){
			fprintf(f,"%s%d@%04X", dot1, cfg->c35_tcp_ptab.ports[i].s_port, cfg->c35_tcp_ptab.ports[i].ftab.filts[0].caid);
			if (cfg->c35_tcp_ptab.ports[i].ftab.filts[0].nprids > 1){
				fprintf(f,":");
				dot2 = "";
				for (j = 0; j < cfg->c35_tcp_ptab.ports[i].ftab.filts[0].nprids; ++j){
					fprintf(f,"%s%lX", dot2, cfg->c35_tcp_ptab.ports[i].ftab.filts[0].prids[j]);
					dot2 = ",";
				}
			}
			dot1=";";
		}

		fputc((int)'\n', f);
		if (cfg->c35_tcp_srvip != 0)
			fprintf_conf(f, CONFVARWIDTH, "serverip", "%s\n", inet_ntoa(*(struct in_addr *)&cfg->c35_tcp_srvip));
		fputc((int)'\n', f);
	}

	/*Radegast*/
	if ( cfg->rad_port > 0) {
		fprintf(f,"[radegast]\n");
		fprintf_conf(f, CONFVARWIDTH, "port", "%d\n", cfg->rad_port);
		if (cfg->rad_srvip != 0)
			fprintf_conf(f, CONFVARWIDTH, "serverip", "%s\n", inet_ntoa(*(struct in_addr *)&cfg->rad_srvip));
		fprintf_conf(f, CONFVARWIDTH, "user", "%s\n", cfg->rad_usr);
		fprintf_conf(f, CONFVARWIDTH, "allowed", "");
		struct s_ip *cip;
		dot="";
		for (cip = cfg->rad_allowed; cip; cip = cip->next){
			fprintf(f,"%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1])
				fprintf(f,"-%s", cs_inet_ntoa(cip->ip[1]));
			dot=",";
		}
		fprintf(f,"\n\n");
	}

#ifdef CS_WITH_GBOX
	/*Gbox*/
	if ((cfg->gbox_pwd[0] > 0) || (cfg->gbox_pwd[1] > 0) || (cfg->gbox_pwd[2] > 0) || (cfg->gbox_pwd[3] > 0)){
		fprintf(f,"[gbox]\n");
		fprintf_conf(f, CONFVARWIDTH, "password", ""); for (i=0;i<4;i++) fprintf(f,"%02X", cfg->gbox_pwd[i]); fputc((int)'\n', f);;
		fprintf_conf(f, CONFVARWIDTH, "maxdist", "%d\n", cfg->maxdist);
		fprintf_conf(f, CONFVARWIDTH, "ignorelist", "%s\n", cfg->ignorefile);
		fprintf_conf(f, CONFVARWIDTH, "onlineinfos", "%s\n", cfg->gbxShareOnl);
		fprintf_conf(f, CONFVARWIDTH, "cardinfos", "%s\n", cfg->cardfile);
		fprintf_conf(f, CONFVARWIDTH, "locals", "");
		char *dot = "";
		for (i = 0; i < cfg->num_locals; i++){
			fprintf(f,"%s%06lX", dot, cfg->locals[i]);
			dot=";";
		}
		fprintf(f,"\n\n");
	}
#endif

	/*serial*/
	if (cfg->ser_device[0]){
		fprintf(f,"[serial]\n");
		char sdevice[512];
		cs_strncpy(sdevice, cfg->ser_device, sizeof(sdevice));
		char *ptr;
		char delimiter[2]; delimiter[0] = 1; delimiter[1] = '\0';

		ptr = strtok(sdevice, delimiter);
		while(ptr != NULL) {
			fprintf_conf(f, CONFVARWIDTH, "device", "%s\n", ptr);
			ptr = strtok(NULL, delimiter);
		}
		fprintf(f,"\n");
	}

	/*cccam*/
	if ( cfg->cc_port > 0) {
		fprintf(f,"[cccam]\n");
		fprintf_conf(f, CONFVARWIDTH, "port", "%d\n", cfg->cc_port);
		fprintf_conf(f, CONFVARWIDTH, "reshare", "%d\n", cfg->cc_reshare);
		fprintf_conf(f, CONFVARWIDTH, "ignorereshare", "%d\n", cfg->cc_ignore_reshare);
		fprintf_conf(f, CONFVARWIDTH, "version", "%s\n", cfg->cc_version);
		fprintf_conf(f, CONFVARWIDTH, "updateinterval", "%d\n", cfg->cc_update_interval);
		fprintf_conf(f, CONFVARWIDTH, "minimizecards", "%d\n", cfg->cc_minimize_cards);
		fprintf_conf(f, CONFVARWIDTH, "keepconnected", "%d\n", cfg->cc_keep_connected);
		fprintf(f,"\n");
	}

#ifdef HAVE_DVBAPI
	/*dvb-api*/
	if (cfg->dvbapi_enabled > 0) {
		fprintf(f,"[dvbapi]\n");
		fprintf_conf(f, CONFVARWIDTH, "enabled", "%d\n", cfg->dvbapi_enabled);
		fprintf_conf(f, CONFVARWIDTH, "au", "%d\n", cfg->dvbapi_au);
		fprintf_conf(f, CONFVARWIDTH, "boxtype", "%s\n", boxdesc[cfg->dvbapi_boxtype]);
		fprintf_conf(f, CONFVARWIDTH, "user", "%s\n", cfg->dvbapi_usr);
        	fprintf_conf(f, CONFVARWIDTH, "pmt_mode", "%d\n", cfg->dvbapi_pmtmode);

		fputc((int)'\n', f);
	}
#endif

#ifdef WEBIF
	/*webinterface*/
	if (cfg->http_port > 0) {
		fprintf(f,"[webif]\n");
		if (cfg->http_use_ssl) {
			fprintf_conf(f, CONFVARWIDTH, "httpport", "+%d\n", cfg->http_port);
		} else {
			fprintf_conf(f, CONFVARWIDTH, "httpport", "%d\n", cfg->http_port);
		}
		if(strlen(cfg->http_user) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httpuser", "%s\n", cfg->http_user);
		if(strlen(cfg->http_pwd) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httppwd", "%s\n", cfg->http_pwd);
		if(strlen(cfg->http_cert) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httpcert", "%s\n", cfg->http_cert);
		if(strlen(cfg->http_css) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httpcss", "%s\n", cfg->http_css);
		if(strlen(cfg->http_jscript) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httpjscript", "%s\n", cfg->http_jscript);
		if(strlen(cfg->http_tpl) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httptpl", "%s\n", cfg->http_tpl);
		if(strlen(cfg->http_script) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httpscript", "%s\n", cfg->http_script);
		fprintf_conf(f, CONFVARWIDTH, "httprefresh", "%d\n", cfg->http_refresh);
		fprintf_conf(f, CONFVARWIDTH, "httpallowed", "");
		struct s_ip *cip;
		dot = "";
		for (cip = cfg->http_allowed; cip; cip = cip->next){
			fprintf(f,"%s%s", dot, cs_inet_ntoa(cip->ip[0]));
			if (cip->ip[0] != cip->ip[1])	fprintf(f,"-%s", cs_inet_ntoa(cip->ip[1]));
			dot = ",";
		}
		fputc((int)'\n', f);
		if(strlen((const char *) (cfg->http_dyndns)) > 0)
			fprintf_conf(f, CONFVARWIDTH, "httpdyndns", "%s\n", cfg->http_dyndns);
		fprintf_conf(f, CONFVARWIDTH, "httphideidleclients", "%d\n", cfg->http_hide_idle_clients);
		fprintf_conf(f, CONFVARWIDTH, "httpreadonly", "%d\n", cfg->http_readonly);
		fprintf_conf(f, CONFVARWIDTH, "httpsavefullcfg", "%d\n", cfg->http_full_cfg);

		fputc((int)'\n', f);
	}
#endif

#ifdef CS_ANTICASC
	if(cfg->ac_enabled) {
		fprintf(f,"[anticasc]\n");
		fprintf_conf(f, CONFVARWIDTH, "enabled", "%d\n", cfg->ac_enabled);
		fprintf_conf(f, CONFVARWIDTH, "numusers", "%d\n", cfg->ac_users);
		fprintf_conf(f, CONFVARWIDTH, "sampletime", "%d\n", cfg->ac_stime);
		fprintf_conf(f, CONFVARWIDTH, "samples", "%d\n", cfg->ac_samples);
		fprintf_conf(f, CONFVARWIDTH, "penalty", "%d\n", cfg->ac_penalty);
		fprintf_conf(f, CONFVARWIDTH, "aclogfile", "%s\n", cfg->ac_logfile);
		fprintf_conf(f, CONFVARWIDTH, "denysamples", "%d\n", cfg->ac_denysamples);
		fprintf_conf(f, CONFVARWIDTH, "fakedelay", "%d\n", cfg->ac_fakedelay);
		fputc((int)'\n', f);
	}
#endif

	fclose(f);

	return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

int write_userdb(struct s_auth *authptr)
{
	int i;
	FILE *f;
	struct s_auth *account;
	char *value;
	char *dot = ""; //flag for comma
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, 255,"%s%s", cs_confdir, cs_user);
	snprintf(tmpfile, 255, "%s%s.tmp", cs_confdir, cs_user);
	snprintf(bakfile, 255,"%s%s.bak", cs_confdir, cs_user);

  if (!(f=fopen(tmpfile, "w"))){
    cs_log("Cannot open file \"%s\" (errno=%d)", tmpfile, errno);
    return(1);
  }
  fprintf(f,"# oscam.user generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
  fprintf(f,"# Read more: http://streamboard.gmc.to/oscam/browser/trunk/Distribution/doc/txt/oscam.user.txt\n\n");

  //each account
	for (account=authptr; (account) ; account=account->next){
		fprintf(f,"[account]\n");
		fprintf_conf(f, CONFVARWIDTH, "user", "%s\n", account->usr);
		fprintf_conf(f, CONFVARWIDTH, "pwd", "%s\n", account->pwd);

		if (account->disabled || (!account->disabled && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "disabled", "%d\n", account->disabled);

		if (account->expirationdate || (!account->expirationdate && cfg->http_full_cfg)) {
			struct tm * timeinfo = localtime (&account->expirationdate);
			char buf [80];
			strftime (buf,80,"%Y-%m-%d",timeinfo);
			if(strcmp(buf,"1970-01-01"))
				fprintf_conf(f, CONFVARWIDTH, "expdate", "%s\n", buf);
			else
				fprintf_conf(f, CONFVARWIDTH, "expdate", "\n");
		}


		if(account->allowedtimeframe[0] && account->allowedtimeframe[1]) {
			fprintf_conf(f, CONFVARWIDTH, "allowedtimeframe", "%02d:%02d-%02d:%02d\n",
					account->allowedtimeframe[0]/60,
					account->allowedtimeframe[0]%60,
					account->allowedtimeframe[1]/60,
					account->allowedtimeframe[1]%60 );
		} else {
			if (cfg->http_full_cfg)
				fprintf_conf(f, CONFVARWIDTH, "allowedtimeframe", "\n");
		}

		//group
		if (account->grp || (!account->grp && cfg->http_full_cfg)) {
			value = mk_t_group(account->grp);
			fprintf_conf(f, CONFVARWIDTH, "group", "%s\n", value);
			free(value);
		}

		if (account->dyndns[0] || (!account->dyndns[0] && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "hostname", "%s\n", account->dyndns);

		if (account->uniq || (!account->uniq && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "uniq", "%d\n", account->uniq);

		if (account->tosleep || (!account->tosleep && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "sleep", "%d\n", account->tosleep);

		if (account->monlvl || (!account->monlvl && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "monlevel", "%d\n", account->monlvl);

		if (account->aureader)
			fprintf_conf(f, CONFVARWIDTH, "au", "%s\n", account->aureader->label);
		if (account->autoau == 1)
			fprintf_conf(f, CONFVARWIDTH, "au", "1\n");

		if ((account->sidtabok + account->sidtabno > 0) || ((account->sidtabok + account->sidtabno == 0) && cfg->http_full_cfg)) {
			fprintf_conf(f, CONFVARWIDTH, "services", "");
			char sidok[MAX_SIDBITS+1]; sidtabbits2bitchar(account->sidtabok,sidok);
			char sidno[MAX_SIDBITS+1]; sidtabbits2bitchar(account->sidtabno,sidno);
			struct s_sidtab *sidtab = cfg->sidtab;
			i=0; dot = "";
			for (; sidtab; sidtab=sidtab->next){
				if(sidok[i]=='1')	{fprintf(f,"%s%s", dot, sidtab->label); dot = ",";}
				if(sidno[i]=='1') {fprintf(f,"%s!%s", dot, sidtab->label); dot = ",";}
				i++;
			}
			fputc((int)'\n', f);
		}

		//CAID
		if (account->ctab.caid[0] || (!account->ctab.caid[0] && cfg->http_full_cfg)) {
			value = mk_t_caidtab(&account->ctab);
			fprintf_conf(f, CONFVARWIDTH, "caid", "%s\n", value);
			free(value);
		}

		//betatunnel
		if (account->ttab.bt_caidfrom[0] || (!account->ttab.bt_caidfrom[0] && cfg->http_full_cfg)) {
			value = mk_t_tuntab(&account->ttab);
			fprintf_conf(f, CONFVARWIDTH, "betatunnel", "%s\n", value);
			free(value);
		}

		//ident
		if (account->ftab.nfilts || (!account->ftab.nfilts && cfg->http_full_cfg)) {
			value = mk_t_ftab(&account->ftab);
			fprintf_conf(f, CONFVARWIDTH, "ident", "%s\n", value);
			free(value);
		}

		//CHID
		if (account->fchid.nfilts || (!account->fchid.nfilts && cfg->http_full_cfg)) {
			value = mk_t_ftab(&account->fchid);
			fprintf_conf(f, CONFVARWIDTH, "chid", "%s\n", value);
			free(value);
		}

		if ((account->c35_suppresscmd08 != cfg->c35_suppresscmd08) || ((account->c35_suppresscmd08 == cfg->c35_suppresscmd08) && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "suppresscmd08", "%d\n", account->c35_suppresscmd08);
			
		if (account->cccmaxhops != 10 || ((account->cccmaxhops == 10) && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "cccmaxhops", "%d\n", account->cccmaxhops);

		if ((account->cccreshare != cfg->cc_reshare) || ((account->cccreshare == cfg->cc_reshare) && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "cccreshare", "%d\n", account->cccreshare);

		if (account->c35_sleepsend || (!account->c35_sleepsend && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "sleepsend", "%d\n", account->c35_sleepsend);

		if (account->failban || (!account->failban && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "failban", "%d\n", account->failban);

		if ((account->ncd_keepalive != cfg->ncd_keepalive) || ((account->ncd_keepalive == cfg->ncd_keepalive) && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "keepalive", "%d\n", account->ncd_keepalive);

#ifdef CS_ANTICASC
		if (account->ac_users || (!account->ac_users && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "numusers", "%d\n", account->ac_users);
		if (account->ac_penalty || (!account->ac_penalty && cfg->http_full_cfg))
			fprintf_conf(f, CONFVARWIDTH, "penalty", "%d\n", account->ac_penalty);
#endif
		fputc((int)'\n', f);
	}
  fclose(f);

  return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

int write_server()
{
	int j;
	char *value;
	FILE *f;

	char *dot = ""; //flag for comma
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, 255,"%s%s", cs_confdir, cs_srvr);
	snprintf(tmpfile, 255, "%s%s.tmp", cs_confdir, cs_srvr);
	snprintf(bakfile, 255,"%s%s.bak", cs_confdir, cs_srvr);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d)", tmpfile, errno);
		return(1);
	}
	fprintf(f,"# oscam.server generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.gmc.to/oscam/browser/trunk/Distribution/doc/txt/oscam.server.txt\n\n");

	struct s_reader *rdr;
	for (rdr=first_reader; rdr ; rdr=rdr->next) {
		if ( rdr->label[0] && !rdr->deleted) {
			fprintf(f,"[reader]\n");

			fprintf_conf(f, CONFVARWIDTH, "label", "%s\n", rdr->label);
			fprintf_conf(f, CONFVARWIDTH, "enable", "%d\n", rdr->enable);
			char *ctyp = reader_get_type_desc(rdr, 0);

			fprintf_conf(f, CONFVARWIDTH, "protocol", "%s\n", ctyp);

			fprintf_conf(f, CONFVARWIDTH, "device", "%s", rdr->device);
			if (rdr->r_port)
				fprintf(f, ",%d", rdr->r_port);
			if (rdr->l_port)
				fprintf(f, ",%d", rdr->l_port);
			fprintf(f, "\n");

#ifdef LIBUSB
			if (!(rdr->typ & R_IS_NETWORK))
				if (rdr->device_endpoint)
					fprintf_conf(f, CONFVARWIDTH, "device_out_endpoint", "0x%2X\n", rdr->device_endpoint);
#endif

			if (rdr->ncd_key[0] || rdr->ncd_key[13]) {
				fprintf_conf(f, CONFVARWIDTH, "key", "");
				for (j = 0; j < 14; j++) {
					fprintf(f, "%02X", rdr->ncd_key[j]);
				}
				fprintf(f, "\n");
			}

			int isphysical = (rdr->typ & R_IS_NETWORK)?0:1;
			if (rdr->r_usr[0] && !isphysical)
				fprintf_conf(f, CONFVARWIDTH, "account", "%s\n", rdr->r_usr);

#ifdef CS_WITH_GBOX
			if (rdr->typ == R_GBOX) {
				if (strlen(rdr->gbox_pwd) > 0)
					fprintf_conf(f, CONFVARWIDTH, "password", "%s\n", rdr->gbox_pwd);
				fprintf_conf(f, CONFVARWIDTH, "premium", "%d\n", rdr->gbox_prem);
			}
#endif

			if (strlen(rdr->r_pwd) > 0)
				fprintf_conf(f, CONFVARWIDTH, "password", "%s\n", rdr->r_pwd);

			if(strcmp(rdr->pincode, "none"))
				fprintf_conf(f, CONFVARWIDTH, "pincode", "%s\n", rdr->pincode);

			if (rdr->emmfile && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "readnano", "%s\n", rdr->emmfile);

			fprintf_conf(f, CONFVARWIDTH, "services", "");
			char sidok[MAX_SIDBITS+1]; sidtabbits2bitchar(rdr->sidtabok, sidok);
			char sidno[MAX_SIDBITS+1]; sidtabbits2bitchar(rdr->sidtabno, sidno);
			struct s_sidtab *sidtab = cfg->sidtab;
			j=0; dot = "";
			for (; sidtab; sidtab=sidtab->next){
				if(sidok[j]=='1')	{fprintf(f,"%s%s", dot, sidtab->label); dot = ",";}
				if(sidno[j]=='1') {fprintf(f,"%s!%s", dot, sidtab->label); dot = ",";}
				j++;
			}
			fputc((int)'\n', f);

			if (rdr->tcp_ito && !isphysical)
				fprintf_conf(f, CONFVARWIDTH, "inactivitytimeout", "%d\n", rdr->tcp_ito);

			if (rdr->tcp_rto && !isphysical )
				fprintf_conf(f, CONFVARWIDTH, "reconnecttimeout", "%d\n", rdr->tcp_rto);

			if (rdr->ncd_disable_server_filt && !isphysical)
				fprintf_conf(f, CONFVARWIDTH, "disableserverfilter", "%d\n", rdr->ncd_disable_server_filt);

			if (rdr->smargopatch && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "smargopatch", "%d\n", rdr->smargopatch);

			if (rdr->fallback)
				fprintf_conf(f, CONFVARWIDTH, "fallback", "%d\n", rdr->fallback);

			if (rdr->log_port)
				fprintf_conf(f, CONFVARWIDTH, "logport", "%d\n", rdr->log_port);

			value = mk_t_caidtab(&rdr->ctab);
			fprintf_conf(f, CONFVARWIDTH, "caid", "%s\n", value);
			free(value);

			if (rdr->boxid && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "boxid", "%08X\n", rdr->boxid);

			if (rdr->aes_key[0] && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "aeskey", "%s\n", cs_hexdump(0, rdr->aes_key, 16));


			//check for rsa
			for (j=0;j<64;j++) {
				if(rdr->rsa_mod[j] > 0) {
					rdr->has_rsa = 1;
					break;
				}
			}

			//check for tiger
			int tigerkey = 0;
			for (j=64;j<120;j++) {
				if(rdr->rsa_mod[j] > 0) {
					tigerkey = 1;
					break;
				}
			}

			//n3_rsakey
			if (rdr->has_rsa) {
				if (!tigerkey) {
					fprintf_conf(f, CONFVARWIDTH, "rsakey", "");
					for (j=0;j<64;j++) {
						fprintf(f, "%02X", rdr->rsa_mod[j]);
					}
					fprintf(f, "\n");
				}
				else  {
					//tiger_rsakey
					if (tigerkey) {
						fprintf_conf(f, CONFVARWIDTH, "tiger_rsakey", "");
						for (j=0;j<120;j++) {
							fprintf(f, "%02X", rdr->rsa_mod[j]);
						}
						fprintf(f, "\n");
					}
				}
			}

			if (rdr->force_irdeto && isphysical) {
				fprintf_conf(f, CONFVARWIDTH, "force_irdeto", "%d\n", rdr->force_irdeto);
			}

			if (rdr->nagra_boxkey[0] && isphysical) {
				fprintf_conf(f, CONFVARWIDTH, "boxkey", "");
				for (j=0;j<8;j++) {
					fprintf(f, "%02X", rdr->nagra_boxkey[j]);
				}
				fprintf(f, "\n");
			}

			if ( rdr->atr[0] && isphysical) {
				fprintf_conf(f, CONFVARWIDTH, "atr", "");
				for (j=0; j < rdr->atrlen/2; j++) {
					fprintf(f, "%02X", rdr->atr[j]);
				}
				fprintf(f, "\n");
			}

			if (isphysical) {
				if (rdr->detect&0x80)
					fprintf_conf(f, CONFVARWIDTH, "detect", "!%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
				else
					fprintf_conf(f, CONFVARWIDTH, "detect", "%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
			}

			if (rdr->nagra_read && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "nagra_read", "%d\n", rdr->nagra_read);

			if (rdr->mhz && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "mhz", "%d\n", rdr->mhz);

			if (rdr->cardmhz && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "cardmhz", "%d\n", rdr->cardmhz);

			value = mk_t_ftab(&rdr->ftab);
			fprintf_conf(f, CONFVARWIDTH, "ident", "%s\n", value);
			free(value);

			//Todo: write reader class

			value = mk_t_ftab(&rdr->fchid);
			if(value[0])
				fprintf_conf(f, CONFVARWIDTH, "chid", "%s\n", value);
			free(value);

			if (rdr->show_cls && !rdr->show_cls == 10)
				fprintf_conf(f, CONFVARWIDTH, "showcls", "%d\n", rdr->show_cls);

			if (rdr->maxqlen && !rdr->maxqlen == CS_MAXQLEN)
				fprintf_conf(f, CONFVARWIDTH, "maxqlen", "%d\n", rdr->maxqlen);

			value = mk_t_group(rdr->grp);
			fprintf_conf(f, CONFVARWIDTH, "group", "%s\n", value);
			free(value);

			if (rdr->cachemm)
				fprintf_conf(f, CONFVARWIDTH, "emmcache", "%d,%d,%d\n", rdr->cachemm, rdr->rewritemm, rdr->logemm);

			//Todo: write blocknano

			if (rdr->blockemm_unknown)
				fprintf_conf(f, CONFVARWIDTH, "blockemm-unknown", "%d\n", rdr->blockemm_unknown);

			if (rdr->blockemm_u)
				fprintf_conf(f, CONFVARWIDTH, "blockemm-u", "%d\n", rdr->blockemm_u);

			if (rdr->blockemm_s)
				fprintf_conf(f, CONFVARWIDTH, "blockemm-s", "%d\n", rdr->blockemm_s);

			if (rdr->blockemm_g)
				fprintf_conf(f, CONFVARWIDTH, "blockemm-g", "%d\n", rdr->blockemm_g);

			if (rdr->lb_weight)
				fprintf_conf(f, CONFVARWIDTH, "lb_weight", "%d\n", rdr->lb_weight);

			//Todo: write savenano

			if (rdr->typ == R_CCCAM) {
				if (rdr->cc_version[0])
					fprintf_conf(f, CONFVARWIDTH, "cccversion", "%s\n", rdr->cc_version);

				if (rdr->cc_maxhop)
					fprintf_conf(f, CONFVARWIDTH, "cccmaxhops", "%d\n", rdr->cc_maxhop);

				if (rdr->cc_want_emu)
					fprintf_conf(f, CONFVARWIDTH, "cccwantemu", "%d\n", rdr->cc_want_emu);

				if (rdr->cc_keepalive)
					fprintf_conf(f, CONFVARWIDTH, "ccckeepalive", "%d\n", rdr->cc_keepalive);
			}

			if (rdr->deprecated && isphysical)
				fprintf_conf(f, CONFVARWIDTH, "deprecated", "%d\n", rdr->deprecated);

			if (rdr->audisabled)
				fprintf_conf(f, CONFVARWIDTH, "audisabled", "%d\n", rdr->audisabled);

			if (rdr->auprovid)
				fprintf_conf(f, CONFVARWIDTH, "auprovid", "%06lX", rdr->auprovid);

                        if (rdr->ndsversion && isphysical)
                                fprintf_conf(f, CONFVARWIDTH, "ndsversion", "%d\n", rdr->ndsversion);

                        if (rdr->ratelimitecm && isphysical) {
                                fprintf_conf(f, CONFVARWIDTH, "ratelimitecm", "%d\n", rdr->ratelimitecm);
                                fprintf_conf(f, CONFVARWIDTH, "ratelimitseconds", "%d\n", rdr->ratelimitseconds);
			}
			fprintf(f, "\n\n");
		}
	}
	fclose(f);

	return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

void write_versionfile() {

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
	  fprintf(fp, "uxstarttime:    %d\n", (int)now);
	  fprintf(fp, "starttime:      %02d.%02d.%02d", st->tm_mday, st->tm_mon+1, st->tm_year%100);
	  fprintf(fp, " %02d:%02d:%02d\n", st->tm_hour, st->tm_min, st->tm_sec);
	  fprintf(fp, "version:        %s  Rev. %s\n", CS_VERSION, CS_SVN_VERSION);
	  fprintf(fp, "maxpid:         UNLIMITED\n\n\n");
	  fprintf(fp, "active modules:\n");

#ifdef WEBIF
	  fprintf(fp, "Webif support:    yes\n");
#else
	  fprintf(fp, "Webif support:    no\n");
#endif
#ifdef HAVE_DVBAPI
	  fprintf(fp, "Dvbapi support:   yes\n");
#else
	  fprintf(fp, "Dvbapi support:   no\n");
#endif
#ifdef CS_WITH_GBOX
	  fprintf(fp, "Gbox support:     yes\n");
#else
	  fprintf(fp, "Gbox support:     no\n");
#endif
#ifdef CS_ANTICASC
	  fprintf(fp, "Anticasc support: yes\n");
#else
	  fprintf(fp, "Anticasc support: no\n");
#endif
#ifdef CS_WITH_DOUBLECHECK
	  fprintf(fp, "ECM doublecheck:  yes\n");
#else
	  fprintf(fp, "ECM doublecheck:  no\n");
#endif
#ifdef IRDETO_GUESSING
	  fprintf(fp, "Irdeto guessing:  yes\n");
#else
	  fprintf(fp, "Irdeto guessing:  no\n");
#endif
#ifdef WITH_DEBUG
	  fprintf(fp, "Debug:            yes\n");
#else
	  fprintf(fp, "Debug:            no\n");
#endif
#ifdef CS_LED
	  fprintf(fp, "LED support:      yes\n");
#else
	  fprintf(fp, "LED support:      no\n");
#endif
#ifdef CS_LOGHISTORY
	  fprintf(fp, "Log history:      yes\n");
#else
	  fprintf(fp, "Log history:      no\n");
#endif
#ifdef MODULE_MONITOR
	  fprintf(fp, "Monitor:          yes\n");
#else
	  fprintf(fp, "Monitor:          no\n");
#endif
#ifdef MODULE_CAMD33
	  fprintf(fp, "Camd33:           yes\n");
#else
	  fprintf(fp, "Camd33:           no\n");
#endif
#ifdef MODULE_CAMD35
	  fprintf(fp, "Camd35 UDP:       yes\n");
#else
	  fprintf(fp, "Camd35 UDP:       no\n");
#endif
#ifdef MODULE_CAMD35_TCP
	  fprintf(fp, "Camd35 TCP:       yes\n");
#else
	  fprintf(fp, "Camd35 TCP:       no\n");
#endif
#ifdef MODULE_NEWCAMD
	  fprintf(fp, "Newcamd:          yes\n");
#else
	  fprintf(fp, "Newcamd:          no\n");
#endif
#ifdef MODULE_CCCAM
	  fprintf(fp, "Cccam:            yes\n");
#else
	  fprintf(fp, "Cccam:            no\n");
#endif
#ifdef MODULE_RADEGAST
	  fprintf(fp, "Radegast:         yes\n");
#else
	  fprintf(fp, "Radegast:         no\n");
#endif
#ifdef MODULE_SERIAL
	  fprintf(fp, "Serial:           yes\n");
#else
	  fprintf(fp, "Serial:           no\n");
#endif
#ifdef MODULE_CONSTCW
	  fprintf(fp, "ConstCW:          yes\n");
#else
	  fprintf(fp, "ConstCW:          no\n");
#endif
#ifdef WITH_CARDREADER
	  fprintf(fp, "Cardreader:       yes\n");

	#ifdef READER_NAGRA
		  fprintf(fp, "Nagra:            yes\n");
	#else
		  fprintf(fp, "Nagra:            no\n");
	#endif
	#ifdef READER_IRDETO
		  fprintf(fp, "Irdeto:           yes\n");
	#else
		  fprintf(fp, "Irdeto:           no\n");
	#endif
	#ifdef READER_CONAX
		  fprintf(fp, "Conax:            yes\n");
	#else
		  fprintf(fp, "Conax:            no\n");
	#endif
	#ifdef READER_CRYPTOWORKS
		  fprintf(fp, "Cryptoworks:      yes\n");
	#else
		  fprintf(fp, "Cryptoworks:      no\n");
	#endif
	#ifdef READER_SECA
		  fprintf(fp, "Seca:             yes\n");
	#else
		  fprintf(fp, "Seca:             no\n");
	#endif
	#ifdef READER_VIACCESS
		  fprintf(fp, "Viaccess:         yes\n");
	#else
		  fprintf(fp, "Viaccess:         no\n");
	#endif
	#ifdef READER_VIDEOGUARD
		  fprintf(fp, "Videoguard:       yes\n");
	#else
		  fprintf(fp, "Videoguard:       no\n");
	#endif
	#ifdef READER_DRE
		  fprintf(fp, "Dre:              yes\n");
	#else
		  fprintf(fp, "Dre:              no\n");
	#endif

	#ifdef READER_TONGFANG
		  fprintf(fp, "Tongfang:         yes\n");
	#else
		  fprintf(fp, "Tongfang:         no\n");
	#endif
#else
	  fprintf(fp, "Cardreader:       no\n");
#endif

	  fclose(fp);
  }
#endif

}

int init_userdb(struct s_auth **authptr_org)
{
	struct s_auth *authptr = *authptr_org;
	int tag = 0, nr, nro, expired, disabled;
	//int first=1;
	FILE *fp;
	char *value;
	struct s_auth *ptr;
	/*static */struct s_auth *account=(struct s_auth *)0;

	sprintf(token, "%s%s", cs_confdir, cs_user);
	if (!(fp = fopen(token, "r"))) {
		cs_log("Cannot open file \"%s\" (errno=%d)", token, errno);
		return(1);
	}

	for (nro = 0, ptr = authptr; ptr; nro++) {
		struct s_auth *ptr_next;
		ptr_next = ptr->next;
		free(ptr);
		ptr = ptr_next;
	}
	nr = 0;

	while (fgets(token, sizeof(token), fp)) {
		int i, l;
		void *ptr;

		if ((l=strlen(trim(token))) < 3)
			continue;

		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l - 1] = 0;
			tag = (!strcmp("account", strtolower(token + 1)));

			if (!(ptr=malloc(sizeof(struct s_auth)))) {
				cs_log("Error allocating memory (errno=%d)", errno);
				return(1);
			}

			if (account)
				account->next = ptr;
			else
				authptr = ptr;

			account = ptr;
			memset(account, 0, sizeof(struct s_auth));
			account->allowedtimeframe[0] = 0;
			account->allowedtimeframe[1] = 0;
			account->aureader = NULL;
			account->monlvl = cfg->mon_level;
			account->tosleep = cfg->tosleep;
			account->c35_suppresscmd08 = cfg->c35_suppresscmd08;
			account->cccmaxhops = 10;
			account->cccreshare = cfg->cc_reshare;
			account->ncd_keepalive = cfg->ncd_keepalive;
			for (i = 1; i < CS_MAXCAIDTAB; account->ctab.mask[i++] = 0xffff);
			for (i = 1; i < CS_MAXTUNTAB; account->ttab.bt_srvid[i++] = 0x0000);
			nr++;

#ifdef CS_ANTICASC
			account->ac_users = cfg->ac_users;
			account->ac_penalty = cfg->ac_penalty;
			account->ac_idx = nr;
#endif
			continue;
		}

		if (!tag)
			continue;

		if (!(value=strchr(token, '=')))
			continue;

		*value++ = '\0';
		chk_account(trim(strtolower(token)), trim(value), account);
	}

	fclose(fp);

	for (expired = 0, disabled = 0, ptr = authptr; ptr;) {

		if(ptr->expirationdate && ptr->expirationdate < time(NULL))
			expired++;

		if(ptr->disabled != 0)
			disabled++;

		ptr = ptr->next;
	}

	*authptr_org = authptr;

	cs_log("userdb reloaded: %d accounts freed, %d accounts loaded, %d expired, %d disabled", nro, nr, expired, disabled);
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
  cs_strncpy(buf, value, sizeof(buf));
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

void chk_sidtab(char *token, char *value, struct s_sidtab *sidtab)
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
    free(ptr->caid); //no need to check on NULL first, freeing NULL doesnt do anything
    free(ptr->provid);
    free(ptr->srvid);
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
      cs_strncpy(sidtab->label, strtolower(token+1), sizeof(sidtab->label));
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

//Todo #ifdef CCCAM
int init_provid() {
	int nr;
	FILE *fp;
	char *payload;
	static struct s_provid *provid=(struct s_provid *)0;
	sprintf(token, "%s%s", cs_confdir, cs_provid);

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d), no provids's loaded", token, errno);
		return(0);
	}
	nr=0;
	while (fgets(token, sizeof(token), fp)) {

		int l;
		void *ptr;
		char *tmp;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l = strlen(tmp)) < 11) continue;
		if (!(payload = strchr(token, '|'))) continue;
		*payload++ = '\0';

		if (!(ptr = malloc(sizeof(struct s_provid)))) {
			cs_log("Error allocating memory (errno=%d)", errno);
			return(1);
		}

		if (provid)
			provid->next = ptr;
		else
			cfg->provid = ptr;

		provid = ptr;
		memset(provid, 0, sizeof(struct s_provid));

		int i;
		char *ptr1;
		for (i = 0, ptr1 = strtok(payload, "|"); ptr1; ptr1 = strtok(NULL, "|"), i++){
			switch(i){
			case 0:
				cs_strncpy(provid->prov, trim(ptr1), sizeof(provid->prov));
				break;
			case 1:
				cs_strncpy(provid->sat, trim(ptr1), sizeof(provid->sat));
				break;
			case 2:
				cs_strncpy(provid->lang, trim(ptr1), sizeof(provid->lang));
				break;
			}
		}

		char *providasc = strchr(token, ':');
		*providasc++ = '\0';
		provid->provid = a2i(providasc, 3);
		provid->caid = a2i(token, 3);
		nr++;
	}

	fclose(fp);
	if (nr>0)
		cs_log("%d provid's loaded", nr);
	else{
		cs_log("oscam.provid loading failed, wrong format?");
	}
	return(0);
}

int init_srvid()
{
	int nr;
	FILE *fp;
	char *payload;
	static struct s_srvid *srvid=(struct s_srvid *)0;
	sprintf(token, "%s%s", cs_confdir, cs_srid);

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d), no service-id's loaded", token, errno);
		return(0);
	}

	nr=0;
	while (fgets(token, sizeof(token), fp)) {

		int l;
		void *ptr;
		char *tmp;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l=strlen(tmp)) < 6) continue;
		if (!(payload=strchr(token, '|'))) continue;
		*payload++ = '\0';

		if (!(ptr = malloc(sizeof(struct s_srvid)))) {
			cs_log("Error allocating memory (errno=%d)", errno);
			return(1);
		}

		if (srvid)
			srvid->next = ptr;
		else
			cfg->srvid = ptr;

		srvid = ptr;
		memset(srvid, 0, sizeof(struct s_srvid));

		int i;
		char *ptr1;
		for (i = 0, ptr1 = strtok(payload, "|"); ptr1; ptr1 = strtok(NULL, "|"), i++){
			switch(i){
			case 0:
				cs_strncpy(srvid->prov, trim(ptr1), sizeof(srvid->prov));
				break;
			case 1:
				cs_strncpy(srvid->name, trim(ptr1), sizeof(srvid->name));
				break;
			case 2:
				cs_strncpy(srvid->type, trim(ptr1), sizeof(srvid->type));
				break;
			case 3:
				cs_strncpy(srvid->desc, trim(ptr1), sizeof(srvid->desc));
				break;
			}
		}

		char *srvidasc = strchr(token, ':');
		*srvidasc++ = '\0';
		srvid->srvid = dyn_word_atob(srvidasc);
		//printf("srvid %s - %d\n",srvidasc,srvid->srvid );

		srvid->ncaid = 0;
		for (i = 0, ptr1 = strtok(token, ","); (ptr1) && (i < 10) ; ptr1 = strtok(NULL, ","), i++){
			srvid->caid[i] = dyn_word_atob(ptr1);
			srvid->ncaid = i+1;
			//cs_debug("ld caid: %04X srvid: %04X Prov: %s Chan: %s",srvid->caid[i],srvid->srvid,srvid->prov,srvid->name);
		}
		nr++;
	}

	fclose(fp);
	if (nr>0)
		cs_log("%d service-id's loaded", nr);
	else{
		cs_log("oscam.srvid loading failed, old format");
	}
	return(0);
}

int init_tierid()
{
	int nr;
	FILE *fp;
	char *payload;
	static struct s_tierid *tierid=(struct s_tierid *)0;
	sprintf(token, "%s%s", cs_confdir, cs_trid);

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d), no tier-id's loaded", token, errno);
		return(0);
	}

	nr=0;
	while (fgets(token, sizeof(token), fp)) {

		int l;
		void *ptr;
		char *tmp;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l=strlen(tmp)) < 6) continue;
		if (!(payload=strchr(token, '|'))) continue;
		*payload++ = '\0';

		if (!(ptr = malloc(sizeof(struct s_tierid)))) {
			cs_log("Error allocating memory (errno=%d)", errno);
			return(1);
		}

		if (tierid)
			tierid->next = ptr;
		else
			cfg->tierid = ptr;

		tierid = ptr;
		memset(tierid, 0, sizeof(struct s_tierid));

		int i;
		char *ptr1 = strtok(payload, "|");
		if (ptr1)
			cs_strncpy(tierid->name, trim(ptr1), sizeof(tierid->name));

		char *tieridasc = strchr(token, ':');
		*tieridasc++ = '\0';
		tierid->tierid = dyn_word_atob(tieridasc);
		//printf("tierid %s - %d\n",tieridasc,tierid->tierid );

		tierid->ncaid = 0;
		for (i = 0, ptr1 = strtok(token, ","); (ptr1) && (i < 10) ; ptr1 = strtok(NULL, ","), i++){
			tierid->caid[i] = dyn_word_atob(ptr1);
			tierid->ncaid = i+1;
			// cs_log("ld caid: %04X tierid: %04X name: %s",tierid->caid[i],tierid->tierid,tierid->name);
		}
		nr++;
	}

	fclose(fp);
	if (nr>0)
		cs_log("%d tier-id's loaded", nr);
	else{
		cs_log("%s loading failed", cs_trid);
	}
	return(0);
}

void chk_reader(char *token, char *value, struct s_reader *rdr)
{
	int i;
	char *ptr;
	/*
	 *  case sensitive first
	 */
	if (!strcmp(token, "device")) {
		for (i = 0, ptr = strtok(value, ","); (i < 3) && (ptr); ptr = strtok(NULL, ","), i++) {
			trim(ptr);
			switch(i) {
				case 0:
					cs_strncpy(rdr->device, ptr, sizeof(rdr->device));
					break;

				case 1:
					rdr->r_port = atoi(ptr);
					break;

				case 2:
					rdr->l_port = atoi(ptr);
					break;
			}
		}
		return;
	}

#ifdef LIBUSB
	if (!strcmp(token, "device_out_endpoint")) {
		if (strlen(value) > 0) {
			sscanf(value, "0x%2X", &i);
			rdr->device_endpoint = i;
		} else {
			rdr->device_endpoint = 0;
		}
		return;
	}
#endif

	if (!strcmp(token, "key")) {
		if (key_atob14(value, rdr->ncd_key)) {
			fprintf(stderr, "Configuration newcamd: Error in Key\n");
			exit(1);
		}
		return;
	}

	if (!strcmp(token, "password")) {
#ifdef CS_WITH_GBOX
		cs_strncpy((char *)rdr->gbox_pwd, (const char *)i2b(4, a2i(value, 4)), 4); 
#endif
		cs_strncpy(rdr->r_pwd, value, sizeof(rdr->r_pwd));
		return;
	}

#ifdef CS_WITH_GBOX
	if (!strcmp(token, "premium")) {
		rdr->gbox_prem = 1;
		return;
	}
#endif

	if (!strcmp(token, "account")) {
		if (strstr(value, ",")) {
			for (i = 0, ptr = strtok(value, ","); (i < 2) && (ptr); ptr = strtok(NULL, ","), i++) {
				trim(ptr);
				switch(i) {
					case 0:
						cs_strncpy(rdr->r_usr, ptr, sizeof(rdr->r_usr));
						break;

					case 1:
						cs_strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd));
						break;
				}
			}
		} else {
			cs_strncpy(rdr->r_usr, value, sizeof(rdr->r_usr));
		}
		return;
	}

	if (!strcmp(token, "pincode")) {
		strncpy(rdr->pincode, value, sizeof(rdr->pincode) - 1);
		return;
	}

	if (!strcmp(token, "readnano")) {
		NULLFREE(rdr->emmfile);
		if (strlen(value) > 0) {
			if(asprintf(&(rdr->emmfile), "%s", value) < 0)
				fprintf(stderr, "Error allocating string for rdr->emmfile\n");
		}
		return;
	}

	/*
	 *  case insensitive
	*/
	strtolower(value);

	if (!strcmp(token, "enable")) {
		if(strlen(value) == 0) {
			rdr->enable = 0;
			return;
		} else {
			rdr->enable = atoi(value) ? 1 : 0;
			return;
		}
	}

	if (!strcmp(token, "services")) {
		if(strlen(value) == 0) {
			rdr->sidtabok = 0;
			rdr->sidtabno = 0;
			return;
		} else {
			chk_services(value, &rdr->sidtabok, &rdr->sidtabno);
			return;
		}
	}

	if (!strcmp(token, "inactivitytimeout")) {
		if(strlen(value) == 0) {
			rdr->tcp_ito = 0;
			return;
		} else {
			rdr->tcp_ito = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "reconnecttimeout")) {
		if(strlen(value) == 0) {
			rdr->tcp_rto = 0;
			return;
		} else {
			rdr->tcp_rto = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "disableserverfilter")) {
		if(strlen(value) == 0) {
			rdr->ncd_disable_server_filt = 0;
			return;
		} else {
			rdr->ncd_disable_server_filt = atoi(value);
			return;
		}
	}

	//FIXME workaround for Smargo until native mode works
	if (!strcmp(token, "smargopatch")) {
		if(strlen(value) == 0) {
			rdr->smargopatch = 0;
			return;
		} else {
			rdr->smargopatch = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "label")) {
		int found = 0;
		for(i = 0; i < (int)strlen(value); i++) {
			if (value[i] == ' ') {
				value[i] = '_';
				found++;
			}
		}

		if (found) fprintf(stderr, "Configuration reader: corrected label to %s\n",value);
		cs_strncpy(rdr->label, value, sizeof(rdr->label));
		return;
	}

	if (!strcmp(token, "fallback")) {
		if(strlen(value) == 0) {
			rdr->fallback = 0;
			return;
		} else {
			rdr->fallback = atoi(value) ? 1 : 0;
			return;
		}
	}

	if (!strcmp(token, "logport")) {
		if(strlen(value) == 0) {
			rdr->log_port = 0;
			return;
		} else {
			rdr->log_port = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "caid")) {
		if(strlen(value) == 0) {
			clear_caidtab(&rdr->ctab);
			return;
		} else {
			chk_caidtab(value, &rdr->ctab);
			return;
		}
	}

	if (!strcmp(token, "boxid")) {
		if(strlen(value) == 0) {
			rdr->boxid = 0;
			return;
		} else {
			rdr->boxid = a2i(value, 4);
			return;
		}
	}

	if (!strcmp(token, "aeskey")) {
		if (key_atob(value, rdr->aes_key)) {
			fprintf(stderr, "Configuration reader: Error in AES Key\n");
			exit(1);
		}
		return;
	}

	if ((!strcmp(token, "n3_rsakey")) || (!strcmp(token, "rsakey"))) {
		if(strlen(value) == 0) {
			memset(rdr->rsa_mod, 0, 120);
			rdr->has_rsa = 0;
			return;
		} else {
			rdr->has_rsa = 1;
			if (key_atob_l(value, rdr->rsa_mod, 128)) {
				fprintf(stderr, "Configuration reader: Error in rsakey\n");
				exit(1);
			}
			return;
		}
	}

	if (!strcmp(token, "tiger_rsakey")) {
		if(strlen(value) == 0) {
			memset(rdr->rsa_mod, 0, 120);
			return;
		} else {
			if (key_atob_l(value, rdr->rsa_mod, 240)) {
				fprintf(stderr, "Configuration reader: Error in tiger_rsakey\n");
				exit(1);
			}
			return;
		}
	}

	if ((!strcmp(token, "n3_boxkey")) || (!strcmp(token, "boxkey"))) {
		if(strlen(value) == 0) {
			memset(rdr->nagra_boxkey, 0, 16);
			return;
		} else {
			if (key_atob_l(value, rdr->nagra_boxkey, 16)) {
				fprintf(stderr, "Configuration reader: Error in boxkey\n");
				exit(1);
			}
			return;
		}
	}

	if (!strcmp(token, "force_irdeto")) {
		if(strlen(value) == 0) {
			rdr->force_irdeto = 0;
			return;
		} else {
			rdr->force_irdeto = atoi(value);
			return;
		}
	}


	if ((!strcmp(token, "atr"))) {
		memset(rdr->atr, 0, 128);
		rdr->atrlen = strlen(value);
		if(rdr->atrlen == 0) {
			return;
		} else {
			key_atob_l(value, rdr->atr, rdr->atrlen);
			return;
		}
	}

	if (!strcmp(token, "detect")) {
		for (i = 0; RDR_CD_TXT[i]; i++) {
			if (!strcmp(value, RDR_CD_TXT[i])) {
				rdr->detect = i;
			}
			else {
				if ((value[0] == '!') && (!strcmp(value+1, RDR_CD_TXT[i])))
					rdr->detect = i|0x80;
			}
		}
		return;
	}

	if (!strcmp(token, "nagra_read")) {
		if(strlen(value) == 0) {
			rdr->nagra_read = 0;
			return;
		} else {
			rdr->nagra_read = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "mhz")) {
		if(strlen(value) == 0) {
			rdr->mhz = 0;
			return;
		} else {
			rdr->mhz = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "cardmhz")) {
		if(strlen(value) == 0) {
			rdr->cardmhz = 0;
			return;
		} else {
			rdr->cardmhz = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "protocol")) {

		if (!strcmp(value, "mp35")) {
			rdr->typ = R_MP35;
			return;
		}

		if (!strcmp(value, "mouse")) {
			rdr->typ = R_MOUSE;
			return;
		}

		if (!strcmp(value, "sc8in1")) {
			rdr->typ = R_SC8in1;
			return;
		}

		if (!strcmp(value, "smartreader")) {
			rdr->typ = R_SMART;
			return;
		}

		if (!strcmp(value, "internal")) {
			rdr->typ = R_INTERNAL;
			return;
		}

#ifdef HAVE_PCSC
		if (!strcmp(value, "pcsc")) {
			rdr->typ = R_PCSC;
			return;
		}
#endif

		if (!strcmp(value, "serial")) {
			rdr->typ = R_SERIAL;
			return;
		}

		if (!strcmp(value, "camd35")) {
			rdr->typ = R_CAMD35;
			return;
		}

		if (!strcmp(value, "cs378x")) {
			rdr->typ = R_CS378X;
			return;
		}

		if (!strcmp(value, "cs357x")) {
			rdr->typ = R_CAMD35;
			return;
		}

#ifdef CS_WITH_GBOX
		if (!strcmp(value, "gbox")) {
			rdr->typ = R_GBOX;
			return;
		}
#endif

		if (!strcmp(value, "cccam") || !strcmp(value, "cccam ext")) {
			rdr->typ = R_CCCAM;
			//strcpy(value, "1");
			//chk_caidtab(value, &rdr->ctab); 
			//this is a MAJOR hack for auto multiple caid support (not currently working due to ncd table issue)
			return;
		}

		if (!strcmp(value, "constcw")) {
			rdr->typ = R_CONSTCW;
			return;
		}

		if (!strcmp(value, "radegast")) {
			rdr->typ = R_RADEGAST;
			return;
		}

		if (!strcmp(value, "newcamd") || !strcmp(value, "newcamd525")) {
			rdr->typ = R_NEWCAMD;
			rdr->ncd_proto = NCD_525;
			return;
		}

		if (!strcmp(value, "newcamd524")) {
			rdr->typ = R_NEWCAMD;
			rdr->ncd_proto = NCD_524;
			return;
		}

		fprintf(stderr, "WARNING: value '%s' in protocol-line not recognized, assuming MOUSE\n",value);
		rdr->typ = R_MOUSE;
		return;
	}

	if (!strcmp(token, "ident")) {
		if(strlen(value) == 0) {
			clear_ftab(&rdr->ftab);
			return;
		} else {
			chk_ftab(value, &rdr->ftab,"reader",rdr->label,"provid");
			return;
		}
	}

	if (!strcmp(token, "class")) {
		chk_cltab(value, &rdr->cltab);
		return;
	}

	if (!strcmp(token, "chid")) {
		chk_ftab(value, &rdr->fchid,"reader",rdr->label,"chid");
		return;
	}

	if (!strcmp(token, "showcls")) {
		rdr->show_cls = atoi(value);
		return;
	}

	if (!strcmp(token, "maxqlen")) {
		rdr->maxqlen = atoi(value);
		if( rdr->maxqlen < 0 || rdr->maxqlen > CS_MAXQLEN) {
			rdr->maxqlen = CS_MAXQLEN;
		}
		return;
	}

	if (!strcmp(token, "group")) {
		if(strlen(value) == 0) {
			rdr->grp = 0;
			return;
		} else {
			for (ptr = strtok(value, ","); ptr; ptr = strtok(NULL, ",")) {
				int g;
				g = atoi(ptr);
				if ((g>0) && (g<65)) {
					rdr->grp |= (((uint64)1)<<(g-1));
				}
			}
			return;
		}
	}

	if (!strcmp(token, "emmcache")) {
		if(strlen(value) == 0) {
			rdr->cachemm = 0;
			rdr->rewritemm = 0;
			rdr->logemm = 0;
			return;
		} else {
			for (i = 0, ptr = strtok(value, ","); (i < 3) && (ptr); ptr = strtok(NULL, ","), i++) {
				switch(i)
				{
					case 0:
						rdr->cachemm = atoi(ptr);
						break;

					case 1:
						rdr->rewritemm = atoi(ptr);
						break;

					case 2: rdr->logemm = atoi(ptr);
						break;
				}
			}

			if (rdr->rewritemm <= 0) {
				fprintf(stderr, "Notice: Setting EMMCACHE to %i,1,%i instead of %i,%i,%i. ",
					rdr->cachemm, rdr->logemm,
					rdr->cachemm, rdr->rewritemm,
					rdr->logemm);

				fprintf(stderr, "Zero or negative number of rewrites is silly\n");
				rdr->rewritemm = 1;
			}
			return;
		}
	}

	if (!strcmp(token, "blocknano")) {
		//wildcard is used
		if (!strcmp(value,"all")) {
			for (i = 0 ; i < 256; i++) {
				rdr->b_nano[i] |= 0x01; //set all lsb's to block all nanos
			}
		}
		else {
			for (ptr = strtok(value, ","); ptr; ptr = strtok(NULL, ",")) {
				if ((i = byte_atob(ptr)) >= 0) {
					rdr->b_nano[i] |= 0x01; //lsb is set when to block nano
				}
			}
		}
		return;
	}

	if (!strcmp(token, "blockemm-unknown")) {
		if (strlen(value) == 0) {
			rdr->blockemm_unknown = 0;
			return;
		}
		else {
			rdr->blockemm_unknown = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "blockemm-u")) {
		if (strlen(value) == 0) {
			rdr->blockemm_u = 0;
			return;
		}
		else {
			rdr->blockemm_u = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "blockemm-s")) {
		if (strlen(value) == 0) {
			rdr->blockemm_s = 0;
			return;
		}
		else {
			rdr->blockemm_s = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "blockemm-g")) {
		if (strlen(value) == 0) {
			rdr->blockemm_g = 0;
			return;
		}
		else {
			rdr->blockemm_g = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "lb_weight")) {
		if(strlen(value) == 0) {
			rdr->lb_weight = 100;
			return;
		} else {
			rdr->lb_weight = atoi(value);
			if (rdr->lb_weight > 1000) rdr->lb_weight = 1000;
			else if (rdr->lb_weight <= 0) rdr->lb_weight = 100;
			return;
		}
	}

	if (!strcmp(token, "savenano")) {
		//wildcard is used
		if (!strcmp(value,"all")) {
			for (i = 0 ; i < 256; i++) {
				rdr->b_nano[i] |= 0x02; //set all lsb+1 to save all nanos to file
			}
		}
		else {
			for (ptr = strtok(value, ","); ptr; ptr = strtok(NULL, ",")) {
				if ((i = byte_atob(ptr)) >= 0) {
					rdr->b_nano[i] |= 0x02; //lsb+1 is set when to save nano to file
				}
			}
		}
		return;
	}

	if (!strcmp(token, "cccversion")) {
		// cccam version
		if (strlen(value) > sizeof(rdr->cc_version) - 1) {
			fprintf(stderr, "cccam config: version too long\n");
			exit(1);
		}
		memset(rdr->cc_version, 0, sizeof(rdr->cc_version));
		cs_strncpy(rdr->cc_version, value, sizeof(rdr->cc_version));
		return;
	}

	if (!strcmp(token, "cccmaxhop") || !strcmp(token, "cccmaxhops")) { //Schlocke: cccmaxhops is better!
		// cccam max card distance
		if (!strlen(value))
			rdr->cc_maxhop = 10;
		else
			rdr->cc_maxhop = atoi(value);
		return;
	}

	if (!strcmp(token, "cccwantemu")) {
		if (strlen(value) == 0) {
			rdr->cc_want_emu = 0;
			return;
		} else {
			rdr->cc_want_emu = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "ccckeepalive")) {
		if (strlen(value) == 0) {
			rdr->cc_keepalive = 0;
			return;
		} else {
			rdr->cc_keepalive = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "deprecated")) {
		if (strlen(value) == 0) {
			rdr->deprecated = 0;
			return;
		} else {
			rdr->deprecated = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "ccchopsaway") || !strcmp(token, "cccreshar")  || !strcmp(token, "cccreshare")) {
		rdr->cc_reshare = atoi(value);
		return;
	}

	if (!strcmp(token, "audisabled")) {
		if (strlen(value) == 0) {
			rdr->audisabled = 0;
			return;
		} else {
			rdr->audisabled = atoi(value);
			return;
		}
	}

	if (!strcmp(token, "auprovid")) {
		if (strlen(value) == 0) {
			rdr->auprovid = 0;
			return;
		} else {
			rdr->auprovid = a2i(value, 3);
			return;
		}
	}
    // new code for multiple aes key per reader
	if (!strcmp(token, "aeskeys")) {
        parse_aes_keys(rdr,value);
		return;
	}

        if (!strcmp(token, "ndsversion")) {
                if (strlen(value) == 0) {
                        rdr->ndsversion = 0;
                        return;
                } else {
                        rdr->ndsversion = atoi(value);
                        return;
                }
        }


#ifdef AZBOX
  if (!strcmp(token, "mode")) {
    if(strlen(value) == 0) {
      rdr->mode = -1;
      return;
    } else {
      rdr->mode = atoi(value);
      return;
    }
  }
#endif

	//ratelimit
        if (!strcmp(token, "ratelimitecm")) {
                if (strlen(value) == 0) {
                        rdr->ratelimitecm = 0;
                        return;
                } else {
                        rdr->ratelimitecm = atoi(value);
			int h;
			for (h=0;h<rdr->ratelimitecm;h++) rdr->rlecmh[h].last=-1;
                        return;
                }
        }
        if (!strcmp(token, "ratelimitseconds")) {
                if (strlen(value) == 0) {
			if (rdr->ratelimitecm>0) {
                        	rdr->ratelimitseconds = 10;
			} else {
                        	rdr->ratelimitseconds = 0;
			}
                        return;
                } else {
                        rdr->ratelimitseconds = atoi(value);
                        return;
                }
        }
	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in reader section not recognized\n",token);
}

#ifdef IRDETO_GUESSING
int init_irdeto_guess_tab()
{
  int i, j, skip;
  int b47;
  FILE *fp;
  char token[128], *ptr;
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
        return(1);
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
#endif

int init_readerdb()
{
	int tag = 0;
	FILE *fp;
	char *value;

	sprintf(token, "%s%s", cs_confdir, cs_srvr);
	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (errno=%d)\n", token, errno);
		return(1);
	}
	struct s_reader *rdr = first_reader = (struct s_reader*) malloc (sizeof(struct s_reader));
	memset(rdr, 0, sizeof(struct s_reader));
	while (fgets(token, sizeof(token), fp)) {
		int i, l;
		if ((l = strlen(trim(token))) < 3)
			continue;
		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l-1] = 0;
			tag = (!strcmp("reader", strtolower(token+1)));
			if (rdr->label[0] && rdr->typ) {
				struct s_reader *newreader = (struct s_reader*) malloc (sizeof(struct s_reader));
				rdr->next = newreader; //add reader to list
				rdr = newreader; //and advance to end of list
			}
			memset(rdr, 0, sizeof(struct s_reader));
			rdr->enable = 1;
			rdr->tcp_rto = 30;
			rdr->show_cls = 10;
			rdr->maxqlen = CS_MAXQLEN;
			rdr->nagra_read = 0;
			rdr->mhz = 357;
			rdr->cardmhz = 357;
			rdr->deprecated = 0;
			rdr->force_irdeto = 0;
			rdr->cc_reshare = cfg->cc_reshare; //set global value as init value
			rdr->cc_maxhop = 10;
			rdr->lb_weight = 100;
			strcpy(rdr->pincode, "none");
			rdr->ndsversion = 0;
			for (i=1; i<CS_MAXCAIDTAB; rdr->ctab.mask[i++]=0xffff);
			continue;
		}

		if (!tag)
			continue;
		if (!(value=strchr(token, '=')))
			continue;
		*value++ ='\0';
		chk_reader(trim(strtolower(token)), trim(value), rdr);
	}
	fclose(fp);
	return(0);
}

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

/*
 * makes a char ready to write a token into config or webIf
 */
char *mk_t_caidtab(CAIDTAB *ctab){
	int i = 0, needed = 1, pos = 0;
	while(ctab->caid[i]){
		if(ctab->mask[i]) needed += 10;
		else needed += 5;
		if(ctab->cmap[i]) needed += 5;
		++i;
	}
	char *value = (char *) malloc(needed * sizeof(char));
	i = 0;
	while(ctab->caid[i]) {
		if(i == 0) {
			sprintf(value + pos, "%04X", ctab->caid[i]);
			pos += 4;
		} else {
			sprintf(value + pos, ",%04X", ctab->caid[i]);
			pos += 5;
		}
		if((ctab->mask[i]) && (ctab->mask[i] != 0xFFFF)){
			sprintf(value + pos, "&%04X", ctab->mask[i]);
			pos += 5;
		}
		if(ctab->cmap[i]){
			sprintf(value + pos, ":%04X", ctab->cmap[i]);
			pos += 5;
		}
		++i;
	}
	value[pos] = '\0';
	return value;
}

/*
 * makes a char ready to write a token into config or webIf
 */
char *mk_t_tuntab(TUNTAB *ttab){
	int i = 0, needed = 1, pos = 0;
	while(ttab->bt_caidfrom[i]){
		if(ttab->bt_srvid[i]) needed += 10;
		else needed += 5;
		if(ttab->bt_caidto[i]) needed += 5;
		++i;
	}
	char *value = (char *) malloc(needed * sizeof(char));
	i = 0;
	while(ttab->bt_caidfrom[i]) {
		if(i == 0) {
			sprintf(value + pos, "%04X", ttab->bt_caidfrom[i]);
			pos += 4;
		} else {
			sprintf(value + pos, ",%04X", ttab->bt_caidfrom[i]);
			pos += 5;
		}
		if(ttab->bt_srvid[i]){
			sprintf(value + pos, ".%04X", ttab->bt_srvid[i]);
			pos += 5;
		}
		if(ttab->bt_caidto[i]){
			sprintf(value + pos, ":%04X", ttab->bt_caidto[i]);
			pos += 5;
		}
		++i;
	}
	value[pos] = '\0';
	return value;
}

/*
 * makes a char ready to write a token into config or webIf
 */
char *mk_t_group(uint64 grp){
	int i = 0, needed = 1, pos = 0, dot = 0;
	char grpbit[65];
	uint642bitchar(grp, grpbit);

	for(i = 0; i < 64; i++){
		if (grpbit[i] == '1'){
			needed += 2;
			if(i > 9) needed += 1;
		}
	}
	char *value = (char *) malloc(needed * sizeof(char));

	for(i = 0; i < 64; i++){
		if (grpbit[i] == '1'){
			if (dot == 0){
				sprintf(value + pos, "%d", i+1);
				if (i > 8)pos += 2;
				else pos += 1;
				dot = 1;
			} else {
				sprintf(value + pos, ",%d", i+1);
				if (i > 8)pos += 3;
				else pos += 2;
			}
		}
	}
	value[pos] = '\0';
	return value;
}

/*
 * makes a char ready to write a token into config or webIf
 */
char *mk_t_ftab(FTAB *ftab){
	int i = 0, j = 0, needed = 1, pos = 0;

	if (ftab->nfilts != 0) {
		needed = ftab->nfilts * 5;
		for (i = 0; i < ftab->nfilts; ++i)
			needed += ftab->filts[i].nprids * 7;
	}

	char *value = (char *) malloc(needed * sizeof(char));

	char *dot="";
	for (i = 0; i < ftab->nfilts; ++i){
		sprintf(value + pos, "%s%04X", dot, ftab->filts[i].caid);
		pos += 4;
		if (i > 0) pos += 1;
		dot=":";
		for (j = 0; j < ftab->filts[i].nprids; ++j) {
			sprintf(value + pos, "%s%06lX", dot, ftab->filts[i].prids[j]);
			pos += 7;
			dot=",";
		}
		dot=";";
	}

	value[pos] = '\0';
	return value;
}

