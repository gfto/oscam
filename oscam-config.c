//FIXME Not checked on threadsafety yet; after checking please remove this line

#include "globals.h"

#if defined OS_MACOSX || defined OS_FREEBSD
#include <net/if_dl.h>
#include <ifaddrs.h>
#elif defined OS_SOLARIS
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/sockio.h>
#else
#include <net/if.h>
#endif

#ifdef CS_WITH_BOXKEYS
#  include "oscam-boxkeys.np"
#endif

#define CONFVARWIDTH 30
#define MAXLINESIZE 1024

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

typedef enum cs_proto_type
{
	TAG_GLOBAL,	// must be first !
	TAG_MONITOR,	// monitor
	TAG_CAMD33,	// camd 3.3x
	TAG_CAMD35,	// camd 3.5x UDP
	TAG_NEWCAMD,	// newcamd
	TAG_RADEGAST,	// radegast
	TAG_SERIAL,	// serial (static)
	TAG_CS357X,	// camd 3.5x UDP
	TAG_CS378X,	// camd 3.5x TCP
	TAG_GBOX,	// gbox
#ifdef MODULE_CCCAM
	TAG_CCCAM,	// cccam
#endif
	TAG_CONSTCW,	// constcw
	TAG_DVBAPI,	// dvbapi
	TAG_WEBIF,	// webif
	TAG_ANTICASC,	// anti-cascading
	TAG_LCD		// LCD
} cs_proto_type_t;

static const char *cctag[]={"global", "monitor", "camd33", "camd35", "newcamd", "radegast", "serial",
		      "cs357x", "cs378x", "gbox",
#ifdef MODULE_CCCAM
		      "cccam",
#endif
		      "constcw", "dvbapi", "webif", "anticasc",
#ifdef LCDSUPPORT
		      "lcd",
#endif
		      NULL};


/* Returns the default value if string length is zero, otherwise atoi is called*/
static int32_t strToIntVal(char *value, int32_t defaultvalue){
	if (strlen(value) == 0) return defaultvalue;
	errno = 0; // errno should be set to 0 before calling strtol
	int32_t i = strtol(value, NULL, 10);
	return (errno == 0) ? i : defaultvalue;
}

/* Returns the default value if string length is zero, otherwise strtoul is called*/
static uint32_t strToUIntVal(char *value, uint32_t defaultvalue){
	if (strlen(value) == 0) return defaultvalue;
	errno = 0; // errno should be set to 0 before calling strtoul
	uint32_t i = strtoul(value, NULL, 10);
	return (errno == 0) ? i : defaultvalue;
}

 /* Replacement of fprintf which adds necessary whitespace to fill up the varname to a fixed width.
   If varname is longer than CONFVARWIDTH, no whitespace is added*/
static void fprintf_conf(FILE *f, const char *varname, const char *fmtstring, ...){
	int32_t varlen = strlen(varname);
	int32_t max = (varlen > CONFVARWIDTH) ? varlen : CONFVARWIDTH;
	char varnamebuf[max + 3];
	char *ptr = varnamebuf + varlen;
	va_list argptr;

	cs_strncpy(varnamebuf, varname, sizeof(varnamebuf));
	while(varlen < CONFVARWIDTH){
		ptr[0] = ' ';
		++ptr;
		++varlen;
	}
	cs_strncpy(ptr, "= ", sizeof(varnamebuf)-(ptr-varnamebuf));
	if (fwrite(varnamebuf, sizeof(char), strlen(varnamebuf), f)){
		if(strlen(fmtstring) > 0){
			va_start(argptr, fmtstring);
			vfprintf(f, fmtstring, argptr);
			va_end(argptr);
		}
	}
}


#ifdef DEBUG_SIDTAB
static void show_sidtab(struct s_sidtab *sidtab)
{
  for (; sidtab; sidtab=sidtab->next)
  {
    int32_t i;
    char buf[1024];
    char *saveptr = buf;
    cs_log("label=%s", sidtab->label);
    snprintf(buf, sizeof(buf), "caid(%d)=", sidtab->num_caid);
    for (i=0; i<sidtab->num_caid; i++)
      snprintf(buf+strlen(buf), 1024-(buf-saveptr), "%04X ", sidtab->caid[i]);
    cs_log("%s", buf);
    snprintf(buf, sizeof(buf), "provider(%d)=", sidtab->num_provid);
    for (i=0; i<sidtab->num_provid; i++)
      snprintf(buf+strlen(buf), 1024-(buf-saveptr), "%08X ", sidtab->provid[i]);
    cs_log("%s", buf);
    snprintf(buf, sizeof(buf), "services(%d)=", sidtab->num_srvid);
    for (i=0; i<sidtab->num_srvid; i++)
      snprintf(buf+strlen(buf), 1024-(buf-saveptr), "%04X ", sidtab->srvid[i]);
    cs_log("%s", buf);
  }
}
#endif

static void chk_iprange(char *value, struct s_ip **base)
{
	int32_t i = 0;
	char *ptr1, *ptr2, *saveptr1 = NULL;
	struct s_ip *fip, *lip, *cip;

	cs_malloc(&cip, sizeof(struct s_ip), SIGINT);
	fip = cip;

	for (ptr1=strtok_r(value, ",", &saveptr1); ptr1; ptr1=strtok_r(NULL, ",", &saveptr1)) {
			if (i == 0)
				++i;
		else {
			cs_malloc(&cip, sizeof(struct s_ip), SIGINT);
			lip->next = cip;
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
	lip = *base;
	*base = fip;
	clear_sip(&lip);
}

static void chk_caidtab(char *caidasc, CAIDTAB *ctab)
{
	int32_t i;
	char *ptr1, *ptr2, *ptr3, *saveptr1 = NULL;
	CAIDTAB newctab;
	memset(&newctab, 0, sizeof(CAIDTAB));
	for (i = 1; i < CS_MAXCAIDTAB; newctab.mask[i++] = 0xffff);

	for (i = 0, ptr1 = strtok_r(caidasc, ",", &saveptr1); (i < CS_MAXCAIDTAB) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1)) {
		uint32_t caid, mask, cmap;
		if( (ptr3 = strchr(trim(ptr1), ':')) )
			*ptr3++ = '\0';
		else
			ptr3 = "";

		if( (ptr2 = strchr(trim(ptr1), '&')) )
			*ptr2++ = '\0';
		else
			ptr2 = "";

		if (((caid = a2i(ptr1, 2)) | (mask = a2i(ptr2,-2)) | (cmap = a2i(ptr3, 2))) < 0x10000) {
			newctab.caid[i] = caid;
			newctab.mask[i] = mask;
			newctab.cmap[i++] = cmap;
		}
	}
	memcpy(ctab, &newctab, sizeof(CAIDTAB));
}

static void chk_caidvaluetab(char *lbrlt, CAIDVALUETAB *tab, int32_t minvalue)
{
		int32_t i;
		char *ptr1, *ptr2, *saveptr1 = NULL;
		CAIDVALUETAB newtab;
		memset(&newtab, 0, sizeof(CAIDVALUETAB));

		for (i = 0, ptr1 = strtok_r(lbrlt, ",", &saveptr1); (i < CS_MAX_CAIDVALUETAB) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1)) {
				int32_t caid, value;

				if( (ptr2 = strchr(trim(ptr1), ':')) )
						*ptr2++ = '\0';
				else
						ptr2 = "";

				if (((caid = a2i(ptr1, 2)) < 0xFFFF) | ((value = atoi(ptr2)) < 10000)) {
						newtab.caid[i] = caid;
						if (value < minvalue) value = minvalue;
						newtab.value[i] = value;
						newtab.n = ++i;
				}
		}
		memcpy(tab, &newtab, sizeof(CAIDVALUETAB));
}

static void chk_tuntab(char *tunasc, TUNTAB *ttab)
{
	int32_t i;
	char *ptr1, *ptr2, *ptr3, *saveptr1 = NULL;
	TUNTAB newttab;
	memset(&newttab, 0 , sizeof(TUNTAB));

	for (i = 0, ptr1 = strtok_r(tunasc, ",", &saveptr1); (i < CS_MAXTUNTAB) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1)) {
		uint32_t bt_caidfrom, bt_caidto, bt_srvid;
		if( (ptr3 = strchr(trim(ptr1), ':')) )
			*ptr3++ = '\0';
		else
			ptr3 = "";

		if( (ptr2 = strchr(trim(ptr1), '.')) )
			*ptr2++ = '\0';
		else
			ptr2 = "";

		if ((bt_caidfrom = a2i(ptr1, 2)) | (bt_srvid = a2i(ptr2,-2)) | (bt_caidto = a2i(ptr3, 2))) {
			newttab.bt_caidfrom[i] = bt_caidfrom;
			newttab.bt_caidto[i] = bt_caidto;
			newttab.bt_srvid[i++] = bt_srvid;
			newttab.n = i;
		}
	}
	memcpy(ttab, &newttab, sizeof(TUNTAB));
}

static void chk_services(char *labels, SIDTABBITS *sidok, SIDTABBITS *sidno)
{
	int32_t i;
	char *ptr, *saveptr1 = NULL;
	SIDTAB *sidtab;
	SIDTABBITS newsidok, newsidno;
	newsidok = newsidno = 0;
	for (ptr=strtok_r(labels, ",", &saveptr1); ptr; ptr=strtok_r(NULL, ",", &saveptr1)) {
		for (trim(ptr), i = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, i++) {
			if (!strcmp(sidtab->label, ptr)) newsidok|=((SIDTABBITS)1<<i);
			if ((ptr[0]=='!') && (!strcmp(sidtab->label, ptr+1))) newsidno|=((SIDTABBITS)1<<i);
		}
	}
	*sidok = newsidok;
	*sidno = newsidno;
}

static void chk_ftab(char *zFilterAsc, FTAB *ftab, const char *D_USE(zType), const char *D_USE(zName), const char *zFiltName)
{
	int32_t i, j;
	char *ptr1, *ptr2, *ptr3, *saveptr1 = NULL;
	char *ptr[CS_MAXFILTERS] = {0};
	FTAB newftab;
	memset(&newftab, 0, sizeof(FTAB));
	
	for( i = 0, ptr1 = strtok_r(zFilterAsc, ";", &saveptr1); (i < CS_MAXFILTERS) && (ptr1); ptr1 = strtok_r(NULL, ";", &saveptr1), i++ ) {
		ptr[i] = ptr1;
		if( (ptr2 = strchr(trim(ptr1), ':')) ) {
			*ptr2++ ='\0';
			newftab.filts[i].caid = (uint16_t)a2i(ptr1, 4);
			ptr[i] = ptr2;
		}
		else if (zFiltName && zFiltName[0] == 'c') {
			cs_log("PANIC: CAID field not found in CHID parameter!");
			return;
		}
		newftab.nfilts++;
	}

	if( newftab.nfilts ) {
	    cs_debug_mask(D_CLIENT, "%s '%s' %s filter(s):", zType, zName, zFiltName);
	}
	for( i = 0; i < newftab.nfilts; i++ ) {
		cs_debug_mask(D_CLIENT, "CAID #%d: %04X", i, newftab.filts[i].caid);
		for( j = 0, ptr3 = strtok_r(ptr[i], ",", &saveptr1); (j < CS_MAXPROV) && (ptr3); ptr3 = strtok_r(NULL, ",", &saveptr1), j++ ) {
			newftab.filts[i].prids[j] = a2i(ptr3,6);
			newftab.filts[i].nprids++;
			cs_debug_mask(D_CLIENT, "%s #%d: %06X", zFiltName, j, newftab.filts[i].prids[j]);
		}
	}
	memcpy(ftab, &newftab, sizeof(FTAB));
}

static void chk_cltab(char *classasc, CLASSTAB *clstab)
{
	int32_t i;
	char *ptr1, *saveptr1 = NULL;
	CLASSTAB newclstab;
	memset(&newclstab, 0, sizeof(newclstab));
	newclstab.an = newclstab.bn = 0;
	for( i = 0, ptr1 = strtok_r(classasc, ",", &saveptr1); (i < CS_MAXCAIDTAB) && (ptr1); ptr1 = strtok_r(NULL, ",", &saveptr1) ) {
		ptr1 = trim(ptr1);
		if( ptr1[0] == '!' )
			newclstab.bclass[newclstab.bn++] = (uchar)a2i(ptr1+1, 2);
		else
			newclstab.aclass[newclstab.an++] = (uchar)a2i(ptr1, 2);
	}
	memcpy(clstab, &newclstab, sizeof(CLASSTAB));
}

static void chk_port_tab(char *portasc, PTAB *ptab)
{
	int32_t i, j, nfilts, ifilt, iport;
	PTAB *newptab;
	char *ptr1, *ptr2, *ptr3, *saveptr1 = NULL;
	char *ptr[CS_MAXPORTS] = {0};
	int32_t port[CS_MAXPORTS] = {0};
	if(!cs_malloc(&newptab, sizeof(PTAB), -1)) return;

	for (nfilts = i = 0, ptr1 = strtok_r(portasc, ";", &saveptr1); (i < CS_MAXPORTS) && (ptr1); ptr1 = strtok_r(NULL, ";", &saveptr1), i++) {
		ptr[i] = ptr1;
		if( (ptr2=strchr(trim(ptr1), '@')) ) {
			*ptr2++ ='\0';
			newptab->ports[i].s_port = atoi(ptr1);

			//checking for des key for port
			newptab->ports[i].ncd_key_is_set = 0;   //default to 0
			if( (ptr3=strchr(trim(ptr1), '{')) ) {
				*ptr3++='\0';
				if (key_atob_l(ptr3, newptab->ports[i].ncd_key, 28))
					fprintf(stderr, "newcamd: error in DES Key for port %s -> ignored\n", ptr1);
				else
					newptab->ports[i].ncd_key_is_set = 1;
			}

			ptr[i] = ptr2;
			port[i] = newptab->ports[i].s_port;
			newptab->nports++;
		}
		nfilts++;
	}

	if( nfilts == 1 && strlen(portasc) < 6 && newptab->ports[0].s_port == 0 ) {
		newptab->ports[0].s_port = atoi(portasc);
		newptab->nports = 1;
	}

	iport = ifilt = 0;
	for (i=0; i<nfilts; i++) {
		if( port[i] != 0 )
			iport = i;
		for (j = 0, ptr3 = strtok_r(ptr[i], ",", &saveptr1); (j < CS_MAXPROV) && (ptr3); ptr3 = strtok_r(NULL, ",", &saveptr1), j++) {
			if( (ptr2=strchr(trim(ptr3), ':')) ) {
				*ptr2++='\0';
				newptab->ports[iport].ftab.nfilts++;
				ifilt = newptab->ports[iport].ftab.nfilts-1;
				newptab->ports[iport].ftab.filts[ifilt].caid = (uint16_t)a2i(ptr3, 4);
				newptab->ports[iport].ftab.filts[ifilt].prids[j] = a2i(ptr2, 6);
			} else {
				newptab->ports[iport].ftab.filts[ifilt].prids[j] = a2i(ptr3, 6);
			}
			newptab->ports[iport].ftab.filts[ifilt].nprids++;
		}
	}
	memcpy(ptab, newptab, sizeof(PTAB));
	free(newptab);
}

#ifdef MODULE_CCCAM
static void chk_cccam_ports(char *value)
{
	int32_t i;
	char *ptr, *saveptr1 = NULL;
	uint16_t newcc_port[CS_MAXPORTS];
	memset(newcc_port, 0, sizeof(newcc_port));

	for (i=0, ptr=strtok_r(value, ",", &saveptr1); ptr && i<CS_MAXPORTS; ptr=strtok_r(NULL, ",", &saveptr1)) {
		newcc_port[i] = atoi(ptr);
		if (newcc_port[i]) i++;
	}
	memcpy(cfg.cc_port, newcc_port, sizeof(cfg.cc_port));
}
#endif

#ifdef NOTUSED
static void chk_srvip(char *value, in_addr_t *ip)
{
	int32_t i;
	char *ptr, *saveptr1 = NULL;
	for (i=0, ptr=strtok_r(value, ",", &saveptr1); ptr; ptr=strtok_r(NULL, ",", &saveptr1))
		if (i<8) ip[i++] = inet_addr(ptr);
}
#endif

void chk_t_global(const char *token, char *value)
{
	char *saveptr1 = NULL;

#ifdef QBOXHD_LED
	if (!strcmp(token, "disableqboxhdled")) {
		cfg.disableqboxhdled = strToIntVal(value, 0);
		return;
	}
#endif

	if (!strcmp(token, "disablelog")) {
		cfg.disablelog = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "disableuserfile")) {
		cfg.disableuserfile = strToIntVal(value, 1);
		return;
	}

	if (!strcmp(token, "disablemail")) {
		cfg.disablemail = strToIntVal(value, 1);
		return;
	}

	if (!strcmp(token, "loghistorysize")) {
		uint32_t newsize = strToUIntVal(value, 4096);
		if (newsize < 1024) {
			fprintf(stderr, "WARNING: loghistorysize is too small, adjusted to 1024\n");
			newsize = 1024;
		}
		cs_reinit_loghist(newsize);
		return;
	}

	if (!strcmp(token, "serverip")) {
		if (strlen(value) == 0) {
			cfg.srvip = 0;
			return;
		} else {
			cfg.srvip=cs_inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "logfile")) {
		cfg.logtostdout = 0;
		cfg.logtosyslog = 0;
		NULLFREE(cfg.logfile);
		if (strlen(value) > 0) {
			char *pch;
			for(pch = strtok_r(value, ";", &saveptr1); pch != NULL; pch = strtok_r(NULL, ";", &saveptr1)){
				pch=trim(pch);
				if(!strcmp(pch, "stdout")) cfg.logtostdout = 1;
				else if(!strcmp(pch, "syslog")) cfg.logtosyslog = 1;
				else {
					NULLFREE(cfg.logfile);
					if(!cs_malloc(&(cfg.logfile), strlen(pch) + 1, -1)) continue;
					else memcpy(cfg.logfile, pch, strlen(pch) + 1);
				}
			}
		} else {
			if(cs_malloc(&(cfg.logfile), strlen(CS_LOGFILE) + 1, -1))
				memcpy(cfg.logfile, CS_LOGFILE, strlen(CS_LOGFILE) + 1);
			else cfg.logtostdout = 1;
		}
		return;
	}

	if (!strcmp(token, "usrfile")) {
		NULLFREE(cfg.usrfile);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(cfg.usrfile), strlen(value) + 1, -1)) return;
			memcpy(cfg.usrfile, value, strlen(value) + 1);
		} else cfg.disableuserfile = 1;
		return;
	}

	if (!strcmp(token, "mailfile")) {
		NULLFREE(cfg.mailfile);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(cfg.mailfile), strlen(value) + 1, -1)) return;
			memcpy(cfg.mailfile, value, strlen(value) + 1);
		} else cfg.disablemail = 1;
		return;
	}

	if (!strcmp(token, "cwlogdir")) {
		NULLFREE(cfg.cwlogdir);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(cfg.cwlogdir), strlen(value) + 1, -1)) return;
			memcpy(cfg.cwlogdir, value, strlen(value) + 1);
		}
		return;
	}

	if (!strcmp(token, "emmlogdir")) {
		NULLFREE(cfg.emmlogdir);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(cfg.emmlogdir), strlen(value) + 1, -1)) return;
			memcpy(cfg.emmlogdir, value, strlen(value) + 1);
		}
		return;
	}

	if (!strcmp(token, "usrfileflag")) {
		cfg.usrfileflag = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "clienttimeout")) {
		cfg.ctimeout = strToUIntVal(value, CS_CLIENT_TIMEOUT);
		if (cfg.ctimeout < 100) cfg.ctimeout *= 1000;
		return;
	}

	if (!strcmp(token, "fallbacktimeout")) {
		cfg.ftimeout = strToUIntVal(value, (CS_CLIENT_TIMEOUT / 2));
		if (cfg.ftimeout < 100) cfg.ftimeout *= 1000;
		return;
	}

	if (!strcmp(token, "clientmaxidle")) {
		cfg.cmaxidle = strToUIntVal(value, CS_CLIENT_MAXIDLE);
		return;
	}

	if (!strcmp(token, "cachedelay")) {
		cfg.delay = strToUIntVal(value, CS_DELAY);
		return;
	}

	if (!strcmp(token, "bindwait")) {
		cfg.bindwait = strToIntVal(value, CS_BIND_TIMEOUT);
		return;
	}

	if (!strcmp(token, "netprio")) {
		cfg.netprio = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "sleep")) {
		cfg.tosleep = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "unlockparental")) {
		cfg.ulparent = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "nice")) {
		if (strlen(value) == 0) {
			cfg.nice = 99;
			return;
		} else {
			cfg.nice = atoi(value);
			if ((cfg.nice<-20) || (cfg.nice>20)) cfg.nice = 99;
			if (cfg.nice != 99) cs_setpriority(cfg.nice);  // ignore errors
			return;
		}
	}

	if (!strcmp(token, "serialreadertimeout")) {
		if (cfg.srtimeout < 100)
			cfg.srtimeout = strtoul(value, NULL, 10) * 1000;
		else
			cfg.srtimeout = strtoul(value, NULL, 10);
		if (cfg.srtimeout <= 0)
			cfg.srtimeout = 1500;
		return;
	}

	if (!strcmp(token, "maxlogsize")) {
		cfg.max_log_size = strToIntVal(value, 10);
		if(cfg.max_log_size != 0 && cfg.max_log_size <= 10) cfg.max_log_size = 10;
		return;
	}

	if( !strcmp(token, "waitforcards")) {
		cfg.waitforcards = strToIntVal(value, 1);
		return;
	}

	if( !strcmp(token, "waitforcards_extra_delay")) {
		cfg.waitforcards_extra_delay = strToIntVal(value, 0);
		return;
	}

	if( !strcmp(token, "preferlocalcards")) {
		cfg.preferlocalcards = strToIntVal(value, 0);
		return;
	}

	if( !strcmp(token, "saveinithistory")) {
		cfg.saveinithistory = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "readerrestartseconds")) {
		cfg.reader_restart_seconds = strToIntVal(value, 5);
		return;
	}

	if (!strcmp(token, "dropdups")) {
		cfg.dropdups = strToIntVal(value, 0);
		return;
	}

#ifdef WITH_LB
	if (!strcmp(token, "readerautoloadbalance") || !strcmp(token, "lb_mode")) {
		cfg.lb_mode = strToIntVal(value, DEFAULT_LB_MODE);
		return;
	}

	if (!strcmp(token, "readerautoloadbalance_save") || !strcmp(token, "lb_save")) {
		cfg.lb_save = strToIntVal(value, 0);
		if (cfg.lb_save  > 0 && cfg.lb_save  < 100) {
			cfg.lb_save = 100;
			fprintf(stderr, "Warning: '%s' corrected to the minimum -> 100\n", token);
		}
		return;
	}

	if (!strcmp(token, "lb_nbest_readers")) {
		cfg.lb_nbest_readers = strToIntVal(value, DEFAULT_NBEST);
		if (cfg.lb_nbest_readers < 2)
			cfg.lb_nbest_readers = DEFAULT_NBEST;
		return;
	}

	if (!strcmp(token, "lb_nfb_readers")) {
		cfg.lb_nfb_readers = strToIntVal(value, DEFAULT_NFB);
		return;
	}

	if (!strcmp(token, "lb_min_ecmcount")) {
		cfg.lb_min_ecmcount = strToIntVal(value, DEFAULT_MIN_ECM_COUNT);
		return;
	}

	if (!strcmp(token, "lb_max_ecmcount")) {
		cfg.lb_max_ecmcount = strToIntVal(value, DEFAULT_MAX_ECM_COUNT);
		return;
	}

	if (!strcmp(token, "lb_reopen_seconds")) {
		cfg.lb_reopen_seconds = strToIntVal(value, DEFAULT_REOPEN_SECONDS);
		return;
	}

	if (!strcmp(token, "lb_retrylimit")) {
		cfg.lb_retrylimit = strToIntVal(value, DEFAULT_RETRYLIMIT);
		return;
	}

	if (!strcmp(token, "lb_retrylimits")) {
		chk_caidvaluetab(value, &cfg.lb_retrylimittab, 50);
		return;
	}

	if (!strcmp(token, "lb_nbest_percaid")) {
		chk_caidvaluetab(value, &cfg.lb_nbest_readers_tab, 1);
		return;
	}

	if (!strcmp(token, "lb_noproviderforcaid")) {
		if(strlen(value) == 0)
        	clear_caidtab(&cfg.lb_noproviderforcaid);
    	else
			chk_caidtab(value, &cfg.lb_noproviderforcaid);
        return;
    }

	if (!strcmp(token, "lb_savepath")) {
		NULLFREE(cfg.lb_savepath);
		cfg.lb_savepath = strnew(value);
		return;
	}

	if (!strcmp(token, "lb_stat_cleanup")) {
		cfg.lb_stat_cleanup = strToIntVal(value, DEFAULT_LB_STAT_CLEANUP);
		return;
	}

	if (!strcmp(token, "lb_use_locking")) {
		cfg.lb_use_locking = strToIntVal(value, DEFAULT_LB_USE_LOCKING);
		return;
	}

	if (!strcmp(token, "lb_reopen_mode")) {
		cfg.lb_reopen_mode = strToIntVal(value, DEFAULT_LB_REOPEN_MODE);
		return;
	}

	if (!strcmp(token, "lb_max_readers")) {
		cfg.lb_max_readers = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "lb_auto_betatunnel")) {
		cfg.lb_auto_betatunnel = strToIntVal(value, DEFAULT_LB_AUTO_BETATUNNEL);
		return;
	}
#endif

	if (!strcmp(token, "resolvegethostbyname")) {
		cfg.resolve_gethostbyname = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "failbantime")) {
		cfg.failbantime = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "failbancount")) {
		cfg.failbancount = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "suppresscmd08")) {
		cfg.c35_suppresscmd08 = strToIntVal(value, 0);
		return;
	}

#ifdef CS_WITH_DOUBLECHECK
	if (!strcmp(token, "double_check")) {
		cfg.double_check = strToIntVal(value, 0);
		return;
	}
#endif


	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in global section not recognized\n", token);
}

#ifdef CS_ANTICASC
void chk_t_ac(char *token, char *value)
{
	if (!strcmp(token, "enabled")) {
		cfg.ac_enabled = strToIntVal(value, 0);
		if( cfg.ac_enabled > 0 )
			cfg.ac_enabled = 1;
		return;
	}

	if (!strcmp(token, "numusers")) {
		cfg.ac_users = strToIntVal(value, 0);
		if ( cfg.ac_users < 0 )
			cfg.ac_users = 0;
		return;
	}

	if (!strcmp(token, "sampletime")) {
		cfg.ac_stime = strToIntVal(value, 2);
		if( cfg.ac_stime < 0 )
			cfg.ac_stime = 2;
		return;
	}

	if (!strcmp(token, "samples")) {
		cfg.ac_samples = strToIntVal(value, 10);
		if( cfg.ac_samples < 2 || cfg.ac_samples > 10)
			cfg.ac_samples = 10;
		return;
	}

	if (!strcmp(token, "penalty")) {
		cfg.ac_penalty = strToIntVal(value, 0);
		if( cfg.ac_penalty < 0  || cfg.ac_penalty > 3 )
			cfg.ac_penalty = 0;
		return;
	}

	if (!strcmp(token, "aclogfile")) {
		cs_strncpy(cfg.ac_logfile, value, sizeof(cfg.ac_logfile));
		return;
	}

	if( !strcmp(token, "fakedelay") ) {
		cfg.ac_fakedelay = strToIntVal(value, 1000);
		if( cfg.ac_fakedelay < 100 || cfg.ac_fakedelay > 1000 )
			cfg.ac_fakedelay = 1000;
		return;
	}

	if( !strcmp(token, "denysamples") ) {
		cfg.ac_denysamples = strToIntVal(value, 8);
		if( cfg.ac_denysamples < 2 || cfg.ac_denysamples > cfg.ac_samples - 1 )
			cfg.ac_denysamples=cfg.ac_samples-1;
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in anticascading section not recognized\n",token);
}
#endif

void chk_t_monitor(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		cfg.mon_port = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg.mon_srvip = 0;
			return;
		} else {
			cfg.mon_srvip=cs_inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "nocrypt")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg.mon_allowed);
			return;
		} else {
			chk_iprange(value, &cfg.mon_allowed);
			return;
		}
	}

	if (!strcmp(token, "aulow")) {
		cfg.mon_aulow = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "monlevel")) {
		cfg.mon_level = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "hideclient_to")) {
		cfg.mon_hideclient_to = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "appendchaninfo")) {
		cfg.mon_appendchaninfo = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in monitor section not recognized\n",token);
}

#ifdef WEBIF
void chk_t_webif(char *token, char *value)
{
	if (!strcmp(token, "httpport")) {
		if(strlen(value) == 0) {
			cfg.http_port = 0;
			return;
		} else {
			if (value[0]=='+') {
#ifdef WITH_SSL
				cfg.http_use_ssl=1;
#else
				fprintf(stderr, "Warning: OSCam compiled without SSL support.\n");
#endif
				cfg.http_port = atoi(value+1);
			} else {
				cfg.http_port = atoi(value);
			}
			return;
		}
	}

	if (!strcmp(token, "httpuser")) {
		cs_strncpy(cfg.http_user, value, sizeof(cfg.http_user));
		return;
	}

	if (!strcmp(token, "httppwd")) {
		cs_strncpy(cfg.http_pwd, value, sizeof(cfg.http_pwd));
		return;
	}

	if (!strcmp(token, "httpcss")) {
		cs_strncpy(cfg.http_css, value, sizeof(cfg.http_css));
		return;
	}

	if (!strcmp(token, "httpjscript")) {
		cs_strncpy(cfg.http_jscript, value, sizeof(cfg.http_jscript));
		return;
	}

	if (!strcmp(token, "httpscript")) {
		cs_strncpy(cfg.http_script, value, sizeof(cfg.http_script));
		return;
	}

	if (!strcmp(token, "httphelplang")) {
		cs_strncpy(cfg.http_help_lang, value, sizeof(cfg.http_help_lang));
		return;
	}

	if (!strcmp(token, "httpcert")) {
		cs_strncpy(cfg.http_cert, value, sizeof(cfg.http_cert));
		return;
	}

	if (!strcmp(token, "httptpl")) {
		cfg.http_tpl[0] = '\0';
		cs_strncpy(cfg.http_tpl, value, sizeof(cfg.http_tpl));
		if(strlen(value) != 0) {
			if(strlen(cfg.http_tpl) < (sizeof(cfg.http_tpl)-2) && cfg.http_tpl[strlen(cfg.http_tpl)-1] != '/') {
				cfg.http_tpl[strlen(cfg.http_tpl)] = '/';
				cfg.http_tpl[strlen(cfg.http_tpl)] = '\0';
			}
		}
		return;
	}

	if (!strcmp(token, "httprefresh")) {
		cfg.http_refresh = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "httphideidleclients")) {
		cfg.http_hide_idle_clients = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "httpallowed")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg.http_allowed);
			return;
		} else {
			chk_iprange(value, &cfg.http_allowed);
			return;
		}
	}

	if (!strcmp(token, "httpreadonly")) {
		cfg.http_readonly = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "httpdyndns")) {
		cs_strncpy((char *)cfg.http_dyndns, value, sizeof(cfg.http_dyndns));
		return;
	}

	if (!strcmp(token, "httpsavefullcfg")) {
		cfg.http_full_cfg = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in webif section not recognized\n",token);
}
#endif


void chk_t_camd33(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		cfg.c33_port = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg.c33_srvip = 0;
			return;
		} else {
			cfg.c33_srvip = cs_inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "nocrypt")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg.c33_plain);
			return;
		} else {
			chk_iprange(value, &cfg.c33_plain);
			return;
		}
	}

	if (!strcmp(token, "passive")) {
		cfg.c33_passive = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "key")) {
		if(strlen(value) == 0) {
			cfg.c33_crypted = 0;
			return;
		}
		if (key_atob_l(value, cfg.c33_key, 32)) {
			fprintf(stderr, "Configuration camd3.3x: Error in Key\n");
			cfg.c33_crypted = 0;
			memset(cfg.c33_key, 0, sizeof(cfg.c33_key));
			return;
		}
		cfg.c33_crypted=1;
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in camd33 section not recognized\n",token);
}

void chk_t_camd35(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		cfg.c35_port = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg.c35_srvip = 0;
			return;
		} else {
			cfg.c35_srvip = cs_inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "suppresscmd08")) {
		cfg.c35_udp_suppresscmd08 = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in camd35 section not recognized\n", token);
}

void chk_t_camd35_tcp(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			clear_ptab(&cfg.c35_tcp_ptab);
			return;
		} else {
			chk_port_tab(value, &cfg.c35_tcp_ptab);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg.c35_tcp_srvip = 0;
			return;
		} else {
			cfg.c35_tcp_srvip = cs_inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "suppresscmd08")) {
		cfg.c35_tcp_suppresscmd08 = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in camd35 tcp section not recognized\n", token);
}

void chk_t_newcamd(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		if(strlen(value) == 0) {
			clear_ptab(&cfg.ncd_ptab);
			return;
		} else {
			chk_port_tab(value, &cfg.ncd_ptab);
			return;
		}
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg.ncd_srvip = 0;
			return;
		} else {
			cfg.ncd_srvip = cs_inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "allowed")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg.ncd_allowed);
			return;
		} else {
			chk_iprange(value, &cfg.ncd_allowed);
			return;
		}
	}

	if (!strcmp(token, "key")) {
		if(strlen(value) == 0){
			memset(cfg.ncd_key, 0, sizeof(cfg.ncd_key));
			return;
		}
		if (key_atob_l(value, cfg.ncd_key, 28)) {
			fprintf(stderr, "Configuration newcamd: Error in Key\n");
			memset(cfg.ncd_key, 0, sizeof(cfg.ncd_key));
		}
		return;
	}

	if (!strcmp(token, "keepalive")) {
		cfg.ncd_keepalive = strToIntVal(value, DEFAULT_NCD_KEEPALIVE);
		return;
	}

	if (!strcmp(token, "mgclient")) {
		cfg.ncd_mgclient = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in newcamd section not recognized\n", token);
}

#ifdef MODULE_CCCAM
void chk_t_cccam(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		chk_cccam_ports(value);
		return;
	}
	//if (!strcmp(token, "serverip")) { cfg.cc_srvip=cs_inet_addr(value); return; }

	if (!strcmp(token, "reshare")) {
		cfg.cc_reshare = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "stealth")) {
		cfg.cc_stealth = strToIntVal(value, 1);
		return;
	}

	if (!strcmp(token, "nodeid")) {
		int8_t i, valid=0;
		memset(cfg.cc_fixed_nodeid, 0, 8);
		for (i=0;i<8 && value[i] != 0;i++) {
			cfg.cc_fixed_nodeid[i] = gethexval(value[i*2]) << 4 | gethexval(value[i*2+1]);
			if (cfg.cc_fixed_nodeid[i])
				valid=1;
		}
		cfg.cc_use_fixed_nodeid = valid && i == 8;
		return;
	}

	if (!strcmp(token, "reshare_mode")) {
		cfg.cc_reshare_services = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "ignorereshare")) {
		cfg.cc_ignore_reshare = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "forward_origin_card")) {
		cfg.cc_forward_origin_card = strToIntVal(value, 0);
		return;
	}

	// cccam version
	if (!strcmp(token, "version")) {
		memset(cfg.cc_version, 0, sizeof(cfg.cc_version));
		if (strlen(value) > sizeof(cfg.cc_version) - 1) {
			fprintf(stderr, "cccam config: version too long\n");
		} else
			cs_strncpy((char*)cfg.cc_version, value, sizeof(cfg.cc_version));
		return;
	}
	// cccam: Update cards interval
	if (!strcmp(token, "updateinterval")) {
		if (value[0] == '-')
			cfg.cc_update_interval = DEFAULT_UPDATEINTERVAL;
		else
			cfg.cc_update_interval = strToIntVal(value, DEFAULT_UPDATEINTERVAL);
		return;
	}

	// cccam: Kind of card updates
	if (!strcmp(token, "minimizecards")) {
		cfg.cc_minimize_cards = strToIntVal(value, 0);
		return;
	}

	// cccam: keep clients connected
	if (!strcmp(token, "keepconnected")) {
		cfg.cc_keep_connected = strToIntVal(value, 0);
		return;
	}


	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in cccam section not recognized\n",token);
}
#endif

void chk_t_radegast(char *token, char *value)
{
	if (!strcmp(token, "port")) {
		cfg.rad_port = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "serverip")) {
		if(strlen(value) == 0) {
			cfg.rad_srvip = 0;
			return;
		} else {
			cfg.rad_srvip = cs_inet_addr(value);
			return;
		}
	}

	if (!strcmp(token, "allowed")) {
		if(strlen(value) == 0) {
			clear_sip(&cfg.rad_allowed);
			return;
		} else {
			chk_iprange(value, &cfg.rad_allowed);
			return;
		}
	}

	if (!strcmp(token, "user")) {
		cs_strncpy(cfg.rad_usr, value, sizeof(cfg.rad_usr));
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in radegast section not recognized\n", token);
}

void chk_t_serial(char *token, char *value)
{
	if (!strcmp(token, "device")) {
		cs_strncpy(cfg.ser_device, value, sizeof(cfg.ser_device));
		return;
	}
	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in serial section not recognized\n", token);
}

void chk_t_gbox(char *token, char *value)
{
	if (!strcmp(token, "gsmsfile")) {
		memset(cfg.gbox_gsms_path, 0, sizeof(cfg.gbox_gsms_path));
		cs_strncpy(cfg.gbox_gsms_path, value, sizeof(cfg.gbox_gsms_path) - 1);
		return;
	}

	if (!strcmp(token, "hostname")) {
		memset(cfg.gbox_hostname, 0, sizeof(cfg.gbox_hostname));
		cs_strncpy(cfg.gbox_hostname, value, sizeof(cfg.gbox_hostname) - 1);
		return;
	}

	if (!strcmp(token, "password")) {
		memset(cfg.gbox_key, 0, sizeof(cfg.gbox_key));
		cs_strncpy(cfg.gbox_key, value, sizeof(cfg.gbox_key) - 1);
		return;
	}

	if (!strcmp(token, "port")) {
		cfg.gbox_port = strToIntVal(value, 0);
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in gbox section not recognized\n",token);
}

#ifdef HAVE_DVBAPI
void chk_t_dvbapi(char *token, char *value)
{
	if (!strcmp(token, "enabled")) {
		cfg.dvbapi_enabled = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "au")) {
		cfg.dvbapi_au = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "pmt_mode")) {
		cfg.dvbapi_pmtmode = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "request_mode")) {
		cfg.dvbapi_requestmode = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "boxtype")) {
		int32_t i;
		for (i=1;i<=BOXTYPES;i++) {
			if (strcmp(value, boxdesc[i])==0) {
				cfg.dvbapi_boxtype=i;
				return;
			}
		}

		cfg.dvbapi_boxtype=0;
		return;
	}

	if (!strcmp(token, "user")) {
		cs_strncpy(cfg.dvbapi_usr, value, sizeof(cfg.dvbapi_usr));
		return;
	}

	if(!strcmp(token, "services")) {
		chk_services(value, &cfg.dvbapi_sidtabok, &cfg.dvbapi_sidtabno);
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

#ifdef LCDSUPPORT
void chk_t_lcd(char *token, char *value)
{

	if (!strcmp(token, "lcd_outputpath")) {
		NULLFREE(cfg.lcd_output_path);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(cfg.lcd_output_path), strlen(value) + 1, -1)) return;
			memcpy(cfg.lcd_output_path, value, strlen(value) + 1);
		}
		return;
	}

	if (!strcmp(token, "lcd_hideidle")) {
		cfg.lcd_hide_idle = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "lcd_writeintervall")) {
		cfg.lcd_write_intervall = strToIntVal(value, 10);
		if (cfg.lcd_write_intervall < 5)
			cfg.lcd_write_intervall = 5;
		return;
	}

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in lcd section not recognized\n",token);
}
#endif

static void chk_token(char *token, char *value, int32_t tag)
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
#ifdef MODULE_CCCAM
		case TAG_CCCAM   : chk_t_cccam(token, value); break;
#endif
		case TAG_GBOX    : chk_t_gbox(token, value); break;

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

#ifdef LCDSUPPORT
		case TAG_LCD: chk_t_lcd(token, value); break;
#else
		case TAG_LCD: fprintf(stderr, "OSCam compiled without LCD support. Parameter %s ignored\n", token); break;
#endif

	}
}

void init_len4caid()
{
	int32_t nr;
	FILE *fp;
	char *value;
	char token[MAXLINESIZE];

	memset(len4caid, 0, sizeof(uint16_t)<<8);
	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_l4ca);
	if (!(fp = fopen(token, "r")))
		return;
	for(nr = 0; fgets(token, sizeof(token), fp);) {
		int32_t i, c;
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

int32_t search_boxkey(uint16_t caid, char *key)
{
	int32_t i, rc = 0;
	FILE *fp;
	char c_caid[512];

	snprintf(c_caid, sizeof(c_caid), "%s%s", cs_confdir, cs_cert);
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

int32_t init_config()
{
	int32_t tag=TAG_GLOBAL;
	FILE *fp;
	char *value=NULL;
	char token[MAXLINESIZE];

#ifndef CS_EMBEDDED
#ifdef PRIO_PROCESS
	errno=0;
	if ((cfg.nice = getpriority(PRIO_PROCESS, 0)) == (-1))
	if (errno)
#endif
#endif
	cfg.nice = 99;
	cfg.ctimeout = CS_CLIENT_TIMEOUT;
	cfg.ftimeout = CS_CLIENT_TIMEOUT / 2;
	cfg.cmaxidle = CS_CLIENT_MAXIDLE;
	cfg.delay = CS_DELAY;
	cfg.bindwait = CS_BIND_TIMEOUT;
	cfg.mon_level = 2;
	cfg.mon_hideclient_to = 0;
	cfg.srtimeout = 1500;
	cfg.ulparent = 0;
	cfg.logfile = NULL;
	cfg.usrfile = NULL;
	cfg.mailfile = NULL;
	cfg.max_log_size = 10;
	cfg.disableuserfile = 1;
	cfg.disablemail = 1;
#ifdef CS_LOGHISTORY
	cfg.loghistorysize = 0;
	cs_reinit_loghist(4096);
#endif
	cfg.cwlogdir = NULL;
	cfg.emmlogdir = NULL;
	cfg.reader_restart_seconds = 5;
	cfg.waitforcards = 1;
	cfg.waitforcards_extra_delay = 500;
#ifdef QBOXHD_LED
    cfg.disableqboxhdled = 1;
#endif

#ifdef WEBIF
	cs_strncpy(cfg.http_user, "", sizeof(cfg.http_user));
	cs_strncpy(cfg.http_pwd, "", sizeof(cfg.http_pwd));
	cs_strncpy(cfg.http_css, "", sizeof(cfg.http_css));
	cs_strncpy(cfg.http_help_lang, "en", sizeof(cfg.http_help_lang));
	cfg.http_refresh = 0;
	cfg.http_hide_idle_clients = 0;
	cfg.mon_hideclient_to = 15;
	cs_strncpy(cfg.http_tpl, "", sizeof(cfg.http_tpl));
#endif
	cfg.ncd_keepalive = DEFAULT_NCD_KEEPALIVE;
#ifdef CS_ANTICASC
	cfg.ac_enabled = 0;
	cfg.ac_users = 0;
	cfg.ac_stime = 2;
	cfg.ac_samples = 10;
	cfg.ac_denysamples = 8;
	cfg.ac_fakedelay = 1000;
	cs_strncpy(cfg.ac_logfile, "./oscam_ac.log", sizeof(cfg.ac_logfile));
#endif
#ifdef MODULE_CCCAM
	cfg.cc_update_interval = DEFAULT_UPDATEINTERVAL;
	cfg.cc_keep_connected = 1;
	cfg.cc_reshare = 10;
#endif

#ifdef WITH_LB
	//loadbalancer defaults:
	cfg.lb_mode = DEFAULT_LB_MODE;
	cfg.lb_nbest_readers = DEFAULT_NBEST;
	cfg.lb_nfb_readers = DEFAULT_NFB;
	cfg.lb_min_ecmcount = DEFAULT_MIN_ECM_COUNT;
	cfg.lb_max_ecmcount = DEFAULT_MAX_ECM_COUNT;
	cfg.lb_reopen_seconds = DEFAULT_REOPEN_SECONDS;
	cfg.lb_retrylimit = DEFAULT_RETRYLIMIT;
	cfg.lb_stat_cleanup = DEFAULT_LB_STAT_CLEANUP;
	cfg.lb_auto_betatunnel = DEFAULT_LB_AUTO_BETATUNNEL;
	//end loadbalancer defaults
#endif

#ifdef LCDSUPPORT
	cfg.lcd_hide_idle = 0;
	cfg.lcd_write_intervall = 10;
#endif

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_conf);
	if (!(fp = fopen(token, "r"))) {
		fprintf(stderr, "Cannot open config file '%s' (errno=%d %s)\n", token, errno, strerror(errno));
		exit(1);
	}
	while (fgets(token, sizeof(token), fp)) {
		int32_t i, l;
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

	if (cfg.logfile == NULL && cfg.logtostdout == 0 && cfg.logtosyslog == 0) {
		if(cs_malloc(&(cfg.logfile), strlen(CS_LOGFILE) + 1, -1))
			memcpy(cfg.logfile, CS_LOGFILE, strlen(CS_LOGFILE) + 1);
		else cfg.logtostdout = 1;
	}
	if(cfg.usrfile == NULL) cfg.disableuserfile = 1;
	if(cfg.mailfile == NULL) cfg.disablemail = 1;

	cs_init_log();
	cs_init_statistics();
	if (cfg.ftimeout >= cfg.ctimeout) {
		cfg.ftimeout = cfg.ctimeout - 100;
		cs_log("WARNING: fallbacktimeout adjusted to %u ms (must be smaller than clienttimeout (%u ms))", cfg.ftimeout, cfg.ctimeout);
	}
	if(cfg.ftimeout < cfg.srtimeout) {
		cfg.ftimeout = cfg.srtimeout + 100;
		cs_log("WARNING: fallbacktimeout adjusted to %u ms (must be greater than serialreadertimeout (%u ms))", cfg.ftimeout, cfg.srtimeout);
	}
	if(cfg.ctimeout < cfg.srtimeout) {
		cfg.ctimeout = cfg.srtimeout + 100;
		cs_log("WARNING: clienttimeout adjusted to %u ms (must be greater than serialreadertimeout (%u ms))", cfg.ctimeout, cfg.srtimeout);
	}
#ifdef CS_ANTICASC
	if( cfg.ac_denysamples+1 > cfg.ac_samples ) {
		cfg.ac_denysamples = cfg.ac_samples - 1;
		cs_log("WARNING: DenySamples adjusted to %d", cfg.ac_denysamples);
	}
#endif
	return 0;
}

void chk_account(const char *token, char *value, struct s_auth *account)
{
	int32_t i;
	char *ptr1, *saveptr1 = NULL;

	if (!strcmp(token, "user")) {
		cs_strncpy(account->usr, value, sizeof(account->usr));
		return;
	}

	if (!strcmp(token, "pwd")) {
		cs_strncpy(account->pwd, value, sizeof(account->pwd));
		return;
	}

	if (!strcmp(token, "allowedprotocols")) {
		account->allowedprotocols = 0;
		if(strlen(value) > 3) {
			char *ptr;
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++){
				if		(!strcmp(ptr, "camd33"))	account->allowedprotocols |= LIS_CAMD33TCP;
				else if (!strcmp(ptr, "camd35"))	account->allowedprotocols |= LIS_CAMD35UDP;
				else if (!strcmp(ptr, "cs357x"))	account->allowedprotocols |= LIS_CAMD35UDP;
				else if (!strcmp(ptr, "cs378x"))	account->allowedprotocols |= LIS_CAMD35TCP;
				else if (!strcmp(ptr, "newcamd"))	account->allowedprotocols |= LIS_NEWCAMD;
				else if (!strcmp(ptr, "cccam"))		account->allowedprotocols |= LIS_CCCAM;
				else if (!strcmp(ptr, "gbox"))		account->allowedprotocols |= LIS_GBOX;
				else if (!strcmp(ptr, "radegast"))	account->allowedprotocols |= LIS_RADEGAST;
				// these have no listener ports so it doesn't make sense
				else if (!strcmp(ptr, "dvbapi"))	account->allowedprotocols |= LIS_DVBAPI;
				else if (!strcmp(ptr, "constcw"))	account->allowedprotocols |= LIS_CONSTCW;
				else if (!strcmp(ptr, "serial"))	account->allowedprotocols |= LIS_SERIAL;
			}
		}
		return;
	}

#ifdef WEBIF
	if (!strcmp(token, "description")) {
		cs_strncpy(account->description, value, sizeof(account->description));
		return;
	}
#endif

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
		account->uniq = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "sleep")) {
		account->tosleep = strToIntVal(value, cfg.tosleep);
		return;
	}

	if (!strcmp(token, "sleepsend")) {
		uint32_t tmp = strToUIntVal(value, 0);
		if (tmp > 0xFF)
			account->c35_sleepsend = 0xFF;
		else account->c35_sleepsend = tmp;
		return;
	}

	if (!strcmp(token, "monlevel")) {
		account->monlvl = strToIntVal(value, 0);
		return;
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
		account->disabled = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "suppresscmd08")) {
		account->c35_suppresscmd08 = strToIntVal(value, 0);
		return;
	}

#ifdef MODULE_CCCAM
	if (!strcmp(token, "cccmaxhops")) {
		account->cccmaxhops = strToIntVal(value, DEFAULT_CC_MAXHOP);
		return;
	}

	if (!strcmp(token, "cccreshare")) {
		account->cccreshare = strToIntVal(value, DEFAULT_CC_RESHARE);
		return;
	}

	if (!strcmp(token, "cccignorereshare")) {
		account->cccignorereshare = strToIntVal(value, -1);
		if (account->cccignorereshare == cfg.cc_ignore_reshare)
			account->cccignorereshare = -1;
		return;
	}

	if (!strcmp(token, "cccstealth")) {
		account->cccstealth = strToIntVal(value, DEFAULT_CC_STEALTH);
		return;
	}
#endif

	if (!strcmp(token, "keepalive")) {
		account->ncd_keepalive = strToIntVal(value, DEFAULT_NCD_KEEPALIVE);
		return;
	}
	/*
	*  case insensitive
	*/
	strtolower(value);

	if (!strcmp(token, "au")) {

		// set default values for usage during runtime from Webif
		account->autoau = 0;

		if (!account->aureader_list)
			account->aureader_list = ll_create();

		if(value && value[0] == '1') {
			account->autoau = 1;
		}
		ll_clear(account->aureader_list);
		
		// exit if invalid or no value
		if ((strlen(value) == 0) || (value[0] == '0'))
			return;
			
		LL_ITER itr = ll_iter_create(configured_readers);		
		struct s_reader *rdr;
		char *pch;

		for (pch = strtok_r(value, ",", &saveptr1); pch != NULL; pch = strtok_r(NULL, ",", &saveptr1)) {
			ll_iter_reset(&itr);
			while ((rdr = ll_iter_next(&itr))) {
				if (((rdr->label[0]) && (!strcmp(rdr->label, pch))) || account->autoau) {
					ll_append(account->aureader_list, rdr);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "group")) {
		account->grp = 0;
		for (ptr1=strtok_r(value, ",", &saveptr1); ptr1; ptr1=strtok_r(NULL, ",", &saveptr1)) {
			int32_t g;
			g = atoi(ptr1);
			if ((g>0) && (g < 65)) account->grp|=(((uint64_t)1)<<(g-1));
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
		for (i=0, ptr1=strtok_r(value, "-/", &saveptr1); (i<3)&&(ptr1); ptr1=strtok_r(NULL, "-/", &saveptr1), i++) {
			switch(i) {
				case 0: cstime.tm_year=atoi(ptr1)-1900; break;
				case 1: cstime.tm_mon =atoi(ptr1)-1;    break;
				case 2: cstime.tm_mday=atoi(ptr1);      break;
			}
		}
		cstime.tm_hour=23;
		cstime.tm_min=59;
		cstime.tm_sec=59;
		cstime.tm_isdst=-1;
		account->expirationdate=mktime(&cstime);
		return;
	}

	if (!strcmp(token, "allowedtimeframe")) {
		if(strlen(value) == 0) {
			account->allowedtimeframe[0] = 0;
			account->allowedtimeframe[1] = 0;
		} else {
			int32_t allowed[4];
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
		account->failban = strToIntVal(value, 0);
		return;
	}

#ifdef CS_ANTICASC
	if( !strcmp(token, "numusers") ) {
		account->ac_users = strToIntVal(value, DEFAULT_AC_USERS);
		if ( account->ac_users < -1 )
			account->ac_users = DEFAULT_AC_USERS;
		return;
	}

	if( !strcmp(token, "penalty") ) {
		account->ac_penalty = strToIntVal(value, DEFAULT_AC_PENALTY);
		if ( account->ac_penalty < -1 )
			account->ac_penalty = DEFAULT_AC_PENALTY;
		return;
	}
#endif

	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in account section not recognized\n",token);
}

int32_t write_services()
{
	int32_t i;
	FILE *f;
	struct s_sidtab *sidtab = cfg.sidtab;
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];
	char *ptr;

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_sidt);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_sidt);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_sidt);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
		return(1);
	}
	fprintf(f,"# oscam.services generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.gmc.to/svn/oscam/trunk/Distribution/doc/txt/oscam.services.txt\n\n");

	while(sidtab != NULL){
		ptr = sidtab->label;
		while (*ptr) {
			if (*ptr == ' ') *ptr = '_';
			ptr++;
		}
		fprintf(f,"[%s]\n", sidtab->label);
		fprintf_conf(f, "caid", "");
		for (i=0; i<sidtab->num_caid; i++){
			if (i==0) fprintf(f,"%04X", sidtab->caid[i]);
			else fprintf(f,",%04X", sidtab->caid[i]);
		}
		fputc((int)'\n', f);
		fprintf_conf(f, "provid", "");
		for (i=0; i<sidtab->num_provid; i++){
			if (i==0) fprintf(f,"%06X", sidtab->provid[i]);
			else fprintf(f,",%06X", sidtab->provid[i]);
		}
		fputc((int)'\n', f);
		fprintf_conf(f, "srvid", "");
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

int32_t write_config()
{
	int32_t i;
	FILE *f;
	char *value, *saveptr1 = NULL;
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_conf);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_conf);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_conf);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
		return(1);
	}
	fprintf(f,"# oscam.conf generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.gmc.to/svn/oscam/trunk/Distribution/doc/txt/oscam.conf.txt\n\n");

	/*global settings*/
	fprintf(f,"[global]\n");
	if (cfg.srvip != 0 || cfg.http_full_cfg)
		fprintf_conf(f, "serverip", "%s\n", cs_inet_ntoa(cfg.srvip));
	if (cfg.usrfile != NULL || cfg.http_full_cfg)
		fprintf_conf(f, "usrfile", "%s\n", cfg.usrfile?cfg.usrfile:"");
	if (cfg.mailfile != NULL || cfg.http_full_cfg)
		fprintf_conf(f, "mailfile", "%s\n", cfg.mailfile?cfg.mailfile:"");
	if (cfg.logfile != NULL || cfg.logtostdout == 1 || cfg.logtosyslog == 1 || cfg.http_full_cfg){
		value = mk_t_logfile();
		fprintf_conf(f, "logfile", "%s\n", value);
		free_mk_t(value);
	}
	if (cfg.cwlogdir != NULL || cfg.http_full_cfg)
		fprintf_conf(f, "cwlogdir", "%s\n", cfg.cwlogdir?cfg.cwlogdir:"");
	if (cfg.emmlogdir != NULL || cfg.http_full_cfg)
		fprintf_conf(f, "emmlogdir", "%s\n", cfg.emmlogdir?cfg.emmlogdir:"");
#ifdef QBOXHD_LED
	if (cfg.disableqboxhdled || cfg.http_full_cfg)
		fprintf_conf(f, "disableqboxhdled", "%d\n", cfg.disableqboxhdled);
#endif
	if (cfg.disablelog || cfg.http_full_cfg)
		fprintf_conf(f, "disablelog", "%d\n", cfg.disablelog);
	if ((cfg.usrfile && cfg.disableuserfile == 0) || cfg.http_full_cfg)
		fprintf_conf(f, "disableuserfile", "%d\n", cfg.usrfile?cfg.disableuserfile:1);
	if ((cfg.mailfile && cfg.disablemail == 0) || cfg.http_full_cfg)
		fprintf_conf(f, "disablemail", "%d\n", cfg.mailfile?cfg.disablemail:1);
	if ((cfg.loghistorysize != 4096) || cfg.http_full_cfg)
		fprintf_conf(f, "loghistorysize", "%u\n", cfg.loghistorysize);
	if (cfg.usrfileflag || cfg.http_full_cfg)
		fprintf_conf(f, "usrfileflag", "%d\n", cfg.usrfileflag);
	if (cfg.ctimeout != CS_CLIENT_TIMEOUT || cfg.http_full_cfg)
		fprintf_conf(f, "clienttimeout", "%u\n", cfg.ctimeout);
	if ((cfg.ftimeout && cfg.ftimeout != (CS_CLIENT_TIMEOUT /2)) || cfg.http_full_cfg)
		fprintf_conf(f, "fallbacktimeout", "%u\n", cfg.ftimeout);
	if (cfg.cmaxidle != CS_CLIENT_MAXIDLE || cfg.http_full_cfg)
		fprintf_conf(f, "clientmaxidle", "%u\n", cfg.cmaxidle);
	if (cfg.failbantime || cfg.http_full_cfg)
		fprintf_conf(f, "failbantime", "%d\n", cfg.failbantime);
	if (cfg.failbancount || cfg.http_full_cfg)
		fprintf_conf(f, "failbancount", "%d\n", cfg.failbancount);
	if (cfg.delay != CS_DELAY || cfg.http_full_cfg)
		fprintf_conf(f, "cachedelay", "%u\n", cfg.delay); //deprecated
	if (cfg.bindwait != CS_BIND_TIMEOUT || cfg.http_full_cfg)
		fprintf_conf(f, "bindwait", "%d\n", cfg.bindwait);
	if (cfg.netprio || cfg.http_full_cfg)
		fprintf_conf(f, "netprio", "%ld\n", cfg.netprio);
	if (cfg.tosleep || cfg.http_full_cfg)
		fprintf_conf(f, "sleep", "%d\n", cfg.tosleep);
	if (cfg.ulparent || cfg.http_full_cfg)
		fprintf_conf(f, "unlockparental", "%d\n", cfg.ulparent);
	if (cfg.nice != 99 || cfg.http_full_cfg)
		fprintf_conf(f, "nice", "%d\n", cfg.nice);
	if (cfg.srtimeout != 1500 || cfg.http_full_cfg)
		fprintf_conf(f, "serialreadertimeout", "%u\n", cfg.srtimeout);
	if (cfg.c35_suppresscmd08 || cfg.http_full_cfg)
		fprintf_conf(f, "suppresscmd08", "%d\n", cfg.c35_suppresscmd08);
	if (cfg.max_log_size != 10 || cfg.http_full_cfg)
		fprintf_conf(f, "maxlogsize", "%d\n", cfg.max_log_size);
	if (!cfg.waitforcards || cfg.http_full_cfg)
		fprintf_conf(f, "waitforcards", "%d\n", cfg.waitforcards);
	if (cfg.waitforcards_extra_delay != 500 || cfg.http_full_cfg)
		fprintf_conf(f, "waitforcards_extra_delay", "%d\n", cfg.waitforcards_extra_delay);
	if (cfg.preferlocalcards || cfg.http_full_cfg)
		fprintf_conf(f, "preferlocalcards", "%d\n", cfg.preferlocalcards);
	if (cfg.saveinithistory || cfg.http_full_cfg)
		fprintf_conf(f, "saveinithistory", "%d\n", cfg.saveinithistory);
	if (cfg.reader_restart_seconds != 5 || cfg.http_full_cfg)
		fprintf_conf(f, "readerrestartseconds", "%d\n", cfg.reader_restart_seconds);
	if (cfg.dropdups || cfg.http_full_cfg)
		fprintf_conf(f, "dropdups", "%d\n", cfg.dropdups);

#ifdef WITH_LB
	if (cfg.lb_mode != DEFAULT_LB_MODE || cfg.http_full_cfg)
		fprintf_conf(f, "lb_mode", "%d\n", cfg.lb_mode);
	if (cfg.lb_save || cfg.http_full_cfg)
		fprintf_conf(f, "lb_save", "%d\n", cfg.lb_save);
	if (cfg.lb_nbest_readers != DEFAULT_NBEST || cfg.http_full_cfg)
		fprintf_conf(f, "lb_nbest_readers", "%d\n", cfg.lb_nbest_readers);
	if (cfg.lb_nfb_readers != DEFAULT_NFB || cfg.http_full_cfg)
		fprintf_conf(f, "lb_nfb_readers", "%d\n", cfg.lb_nfb_readers);
	if (cfg.lb_min_ecmcount != DEFAULT_MIN_ECM_COUNT || cfg.http_full_cfg)
		fprintf_conf(f, "lb_min_ecmcount", "%d\n", cfg.lb_min_ecmcount);
	if (cfg.lb_max_ecmcount != DEFAULT_MAX_ECM_COUNT || cfg.http_full_cfg)
		fprintf_conf(f, "lb_max_ecmcount", "%d\n", cfg.lb_max_ecmcount);
	if (cfg.lb_reopen_seconds != DEFAULT_REOPEN_SECONDS || cfg.http_full_cfg)
		fprintf_conf(f, "lb_reopen_seconds", "%d\n", cfg.lb_reopen_seconds);
	if (cfg.lb_retrylimit != DEFAULT_RETRYLIMIT || cfg.http_full_cfg)
		fprintf_conf(f, "lb_retrylimit", "%d\n", cfg.lb_retrylimit);
	if (cfg.lb_retrylimittab.n > 0 || cfg.http_full_cfg) {
		char *value = mk_t_caidvaluetab(&cfg.lb_retrylimittab);
		fprintf_conf(f, "lb_retrylimits", "%s\n", value);
		free_mk_t(value);
	}
	if (cfg.lb_nbest_readers_tab.n > 0 || cfg.http_full_cfg) {
		char *value = mk_t_caidvaluetab(&cfg.lb_nbest_readers_tab);
		fprintf_conf(f, "lb_nbest_percaid", "%s\n", value);
		free_mk_t(value);
	}

	if (cfg.lb_noproviderforcaid.caid[0] || cfg.http_full_cfg) {
		value = mk_t_caidtab(&cfg.lb_noproviderforcaid);
		fprintf_conf(f, "lb_noproviderforcaid", "%s\n", value);
		free_mk_t(value);
	}

	if (cfg.lb_savepath || cfg.http_full_cfg)
		fprintf_conf(f, "lb_savepath", "%s\n", cfg.lb_savepath?cfg.lb_savepath:"");
	if (cfg.lb_stat_cleanup != DEFAULT_LB_STAT_CLEANUP || cfg.http_full_cfg)
		fprintf_conf(f, "lb_stat_cleanup", "%d\n", cfg.lb_stat_cleanup);
	if (cfg.lb_use_locking != DEFAULT_LB_USE_LOCKING || cfg.http_full_cfg)
		fprintf_conf(f, "lb_use_locking", "%d\n", cfg.lb_use_locking);
	if (cfg.lb_reopen_mode != DEFAULT_LB_REOPEN_MODE || cfg.http_full_cfg)
		fprintf_conf(f, "lb_reopen_mode", "%d\n", cfg.lb_reopen_mode);
	if (cfg.lb_max_readers || cfg.http_full_cfg)
		fprintf_conf(f, "lb_max_readers", "%d\n", cfg.lb_max_readers);
	if (cfg.lb_auto_betatunnel != DEFAULT_LB_AUTO_BETATUNNEL || cfg.http_full_cfg)
		fprintf_conf(f, "lb_auto_betatunnel", "%d\n", cfg.lb_auto_betatunnel);
#endif

	if (cfg.resolve_gethostbyname || cfg.http_full_cfg)
		fprintf_conf(f, "resolvegethostbyname", "%d\n", cfg.resolve_gethostbyname);

#ifdef CS_WITH_DOUBLECHECK
	if (cfg.double_check ||(!cfg.double_check && cfg.http_full_cfg))
		fprintf_conf(f, "double_check", "%d\n", cfg.double_check);
#endif

	fputc((int)'\n', f);

	/*monitor settings*/
	if(cfg.mon_port || cfg.mon_appendchaninfo || cfg.mon_hideclient_to != 0 || cfg.mon_aulow != 30) {
		fprintf(f,"[monitor]\n");
		if (cfg.mon_port != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "port", "%d\n", cfg.mon_port);
		if (cfg.mon_srvip != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "serverip", "%s\n", cs_inet_ntoa(cfg.mon_srvip));
		value = mk_t_iprange(cfg.mon_allowed);
		if(strlen(value) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "nocrypt", "%s\n", value);
		free_mk_t(value);
		if(cfg.mon_aulow != 30 || cfg.http_full_cfg)
			fprintf_conf(f, "aulow", "%d\n", cfg.mon_aulow);
		if(cfg.mon_hideclient_to != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "hideclient_to", "%d\n", cfg.mon_hideclient_to);
		if(cfg.mon_level != 2 || cfg.http_full_cfg)
			fprintf_conf(f, "monlevel", "%d\n", cfg.mon_level);
		if(cfg.mon_appendchaninfo != 2 || cfg.http_full_cfg)
			fprintf_conf(f, "appendchaninfo", "%d\n", cfg.mon_appendchaninfo);
		fputc((int)'\n', f);
	}

	/*newcamd*/
	if ((cfg.ncd_ptab.nports > 0) && (cfg.ncd_ptab.ports[0].s_port > 0)){

		fprintf(f,"[newcamd]\n");

		value = mk_t_newcamd_port();
		fprintf_conf(f, "port", "%s\n", value);
		free_mk_t(value);

		if (cfg.ncd_srvip != 0)
			fprintf_conf(f, "serverip", "%s\n", cs_inet_ntoa(cfg.ncd_srvip));
		fprintf_conf(f, "key", "");
		for (i = 0; i < 14; i++) fprintf(f,"%02X", cfg.ncd_key[i]);
		fprintf(f,"\n");
		value = mk_t_iprange(cfg.ncd_allowed);
		if(strlen(value) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "allowed", "%s\n", value);
		free_mk_t(value);
		if(cfg.ncd_keepalive != DEFAULT_NCD_KEEPALIVE || cfg.http_full_cfg)
			fprintf_conf(f, "keepalive", "%d\n", cfg.ncd_keepalive);
		if(cfg.ncd_mgclient != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "mgclient", "%d\n", cfg.ncd_mgclient);
		fprintf(f,"\n");
	}

	/*camd3.3*/
	if ( cfg.c33_port > 0) {
		fprintf(f,"[camd33]\n");
		fprintf_conf(f, "port", "%d\n", cfg.c33_port);
		if (cfg.c33_srvip != 0)
			fprintf_conf(f, "serverip", "%s\n", cs_inet_ntoa(cfg.c33_srvip));
		if(cfg.c33_passive != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "passive", "%d\n", cfg.c33_passive);
		fprintf_conf(f, "key", ""); for (i = 0; i < (int) sizeof(cfg.c33_key); ++i) fprintf(f,"%02X", cfg.c33_key[i]); fputc((int)'\n', f);
		value = mk_t_iprange(cfg.c33_plain);
		if(strlen(value) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "nocrypt", "%s\n", value);
		free_mk_t(value);
		fprintf(f,"\n");
	}

	/*camd3.5*/
	if ( cfg.c35_port > 0) {
		fprintf(f,"[cs357x]\n");
		fprintf_conf(f, "port", "%d\n", cfg.c35_port);
		if (cfg.c35_srvip != 0)
			fprintf_conf(f, "serverip", "%s\n", cs_inet_ntoa(cfg.c35_srvip));
		if (cfg.c35_udp_suppresscmd08 || cfg.http_full_cfg)
			fprintf_conf(f, "suppresscmd08", "%d\n", cfg.c35_udp_suppresscmd08);
		fprintf(f,"\n");
	}

	/*camd3.5 TCP*/
	if ((cfg.c35_tcp_ptab.nports > 0) && (cfg.c35_tcp_ptab.ports[0].s_port > 0)) {
		fprintf(f,"[cs378x]\n");

		value = mk_t_camd35tcp_port();
		fprintf_conf(f, "port", "%s\n", value);
		free_mk_t(value);

		if (cfg.c35_tcp_srvip != 0)
			fprintf_conf(f, "serverip", "%s\n", cs_inet_ntoa(cfg.c35_tcp_srvip));
		if (cfg.c35_tcp_suppresscmd08 || cfg.http_full_cfg)
			fprintf_conf(f, "suppresscmd08", "%d\n", cfg.c35_tcp_suppresscmd08);
		fputc((int)'\n', f);
	}

	/*Radegast*/
	if ( cfg.rad_port > 0) {
		fprintf(f,"[radegast]\n");
		fprintf_conf(f, "port", "%d\n", cfg.rad_port);
		if (cfg.rad_srvip != 0)
			fprintf_conf(f, "serverip", "%s\n", cs_inet_ntoa(cfg.rad_srvip));
		fprintf_conf(f, "user", "%s\n", cfg.rad_usr);
		value = mk_t_iprange(cfg.rad_allowed);
		if(strlen(value) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "allowed", "%s\n", value);
		free_mk_t(value);
		fprintf(f,"\n");
	}

	/*serial*/
	if (cfg.ser_device[0]){
		fprintf(f,"[serial]\n");
		char sdevice[512];
		cs_strncpy(sdevice, cfg.ser_device, sizeof(sdevice));
		char *ptr;
		char delimiter[2]; delimiter[0] = 1; delimiter[1] = '\0';

		for(ptr = strtok_r(sdevice, delimiter, &saveptr1); ptr != NULL; ptr = strtok_r(NULL, delimiter, &saveptr1)) {
			fprintf_conf(f, "device", "%s\n", ptr);
		}
		fprintf(f,"\n");
	}

	/*gbox*/
	if ( cfg.gbox_port > 0) {
		fprintf(f,"[gbox]\n");
		fprintf_conf(f, "hostname", "%s\n", cfg.gbox_hostname);
		fprintf_conf(f, "port", "%d\n", cfg.gbox_port);
		fprintf_conf(f, "password", "%s\n", cfg.gbox_key);
		fprintf(f,"\n");
	}

#ifdef MODULE_CCCAM
	/*cccam*/
	if ( cfg.cc_port[0] > 0) {
		fprintf(f,"[cccam]\n");
		value = mk_t_cccam_port();
		fprintf_conf(f, "port", "%s\n", value);
		free_mk_t(value);

		if(cfg.cc_reshare != 10 || cfg.http_full_cfg)
			fprintf_conf(f, "reshare", "%d\n", cfg.cc_reshare);
		if(cfg.cc_ignore_reshare != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "ignorereshare", "%d\n", cfg.cc_ignore_reshare);
		if(cfg.cc_forward_origin_card != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "forward_origin_card", "%d\n", cfg.cc_forward_origin_card);
		if(cfg.cc_version || cfg.http_full_cfg)
			fprintf_conf(f, "version", "%s\n", cfg.cc_version);
		if(cfg.cc_update_interval != DEFAULT_UPDATEINTERVAL || cfg.http_full_cfg)
			fprintf_conf(f, "updateinterval", "%d\n", cfg.cc_update_interval);
		if(cfg.cc_minimize_cards != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "minimizecards", "%d\n", cfg.cc_minimize_cards);
		if(cfg.cc_keep_connected != 1 || cfg.http_full_cfg)
			fprintf_conf(f, "keepconnected", "%d\n", cfg.cc_keep_connected);
		if(cfg.cc_stealth != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "stealth", "%d\n", cfg.cc_stealth);
		if(cfg.cc_use_fixed_nodeid || cfg.http_full_cfg)
			fprintf_conf(f, "nodeid", "%02X%02X%02X%02X%02X%02X%02X%02X\n",
				cfg.cc_fixed_nodeid[0], cfg.cc_fixed_nodeid[1], cfg.cc_fixed_nodeid[2], cfg.cc_fixed_nodeid[3],
				cfg.cc_fixed_nodeid[4], cfg.cc_fixed_nodeid[5], cfg.cc_fixed_nodeid[6], cfg.cc_fixed_nodeid[7]);
		if(cfg.cc_reshare_services != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "reshare_mode", "%d\n", cfg.cc_reshare_services);
		fprintf(f,"\n");
	}
#endif

#ifdef HAVE_DVBAPI
	/*dvb-api*/
	if (cfg.dvbapi_enabled > 0) {
		fprintf(f,"[dvbapi]\n");
		fprintf_conf(f, "enabled", "%d\n", cfg.dvbapi_enabled);
		if(cfg.dvbapi_au != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "au", "%d\n", cfg.dvbapi_au);
		fprintf_conf(f, "boxtype", "%s\n", boxdesc[cfg.dvbapi_boxtype]);
		fprintf_conf(f, "user", "%s\n", cfg.dvbapi_usr);
		if(cfg.dvbapi_pmtmode != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "pmt_mode", "%d\n", cfg.dvbapi_pmtmode);
		if(cfg.dvbapi_requestmode != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "request_mode", "%d\n", cfg.dvbapi_requestmode);

		fputc((int)'\n', f);
	}
#endif

#ifdef WEBIF
	/*webinterface*/
	if (cfg.http_port > 0) {
		fprintf(f,"[webif]\n");
		if (cfg.http_use_ssl) {
			fprintf_conf(f, "httpport", "+%d\n", cfg.http_port);
		} else {
			fprintf_conf(f, "httpport", "%d\n", cfg.http_port);
		}

		if(strcmp(cfg.http_help_lang, "en") != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httphelplang", "%s\n", cfg.http_help_lang);
		if(strlen(cfg.http_user) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httpuser", "%s\n", cfg.http_user);
		if(strlen(cfg.http_pwd) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httppwd", "%s\n", cfg.http_pwd);
		if(strlen(cfg.http_cert) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httpcert", "%s\n", cfg.http_cert);
		if(strlen(cfg.http_css) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httpcss", "%s\n", cfg.http_css);
		if(strlen(cfg.http_jscript) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httpjscript", "%s\n", cfg.http_jscript);
		if(strlen(cfg.http_tpl) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httptpl", "%s\n", cfg.http_tpl);
		if(strlen(cfg.http_script) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httpscript", "%s\n", cfg.http_script);
		if(cfg.http_refresh > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httprefresh", "%d\n", cfg.http_refresh);
		value = mk_t_iprange(cfg.http_allowed);
		if(strlen(value) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httpallowed", "%s\n", value);
		free_mk_t(value);
		if(strlen((const char *) (cfg.http_dyndns)) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "httpdyndns", "%s\n", cfg.http_dyndns);
		if(cfg.http_hide_idle_clients || cfg.http_full_cfg)
			fprintf_conf(f, "httphideidleclients", "%d\n", cfg.http_hide_idle_clients);
		if(cfg.http_readonly || cfg.http_full_cfg)
			fprintf_conf(f, "httpreadonly", "%d\n", cfg.http_readonly);
		if(cfg.http_full_cfg)
			fprintf_conf(f, "httpsavefullcfg", "%d\n", cfg.http_full_cfg);

		fputc((int)'\n', f);
	}
#endif

#ifdef CS_ANTICASC
	if(cfg.ac_enabled) {
		fprintf(f,"[anticasc]\n");
		fprintf_conf(f, "enabled", "%d\n", cfg.ac_enabled);
		if(cfg.ac_users != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "numusers", "%d\n", cfg.ac_users);
		if(cfg.ac_stime != 2 || cfg.http_full_cfg)
			fprintf_conf(f, "sampletime", "%d\n", cfg.ac_stime);
		if(cfg.ac_samples != 10 || cfg.http_full_cfg)
			fprintf_conf(f, "samples", "%d\n", cfg.ac_samples);
		if(cfg.ac_penalty != 0 || cfg.http_full_cfg)
			fprintf_conf(f, "penalty", "%d\n", cfg.ac_penalty);
		if(cfg.ac_logfile || cfg.http_full_cfg)
			fprintf_conf(f, "aclogfile", "%s\n", cfg.ac_logfile);
		if(cfg.ac_denysamples != 8 || cfg.http_full_cfg)
			fprintf_conf(f, "denysamples", "%d\n", cfg.ac_denysamples);
		if(cfg.ac_fakedelay != 1000 || cfg.http_full_cfg)
			fprintf_conf(f, "fakedelay", "%d\n", cfg.ac_fakedelay);
		fputc((int)'\n', f);
	}
#endif

#ifdef LCDSUPPORT
	fprintf(f,"[lcd]\n");
	if(cfg.lcd_output_path != NULL) {
		if(strlen(cfg.lcd_output_path) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "lcd_outputpath", "%s\n", cfg.lcd_output_path);
	}
	if(cfg.lcd_hide_idle != 0 || cfg.http_full_cfg)
		fprintf_conf(f, "lcd_hideidle", "%d\n", cfg.lcd_hide_idle);
	if(cfg.lcd_write_intervall != 10 || cfg.http_full_cfg)
		fprintf_conf(f, "lcd_writeintervall", "%d\n", cfg.lcd_write_intervall);
#endif

	fclose(f);

	return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

int32_t write_userdb()
{
	FILE *f;
	struct s_auth *account;
	char *value;
	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_user);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_user);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_user);

  if (!(f=fopen(tmpfile, "w"))){
    cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
    return(1);
  }
  fprintf(f,"# oscam.user generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
  fprintf(f,"# Read more: http://streamboard.gmc.to/svn/oscam/trunk/Distribution/doc/txt/oscam.user.txt\n\n");

  //each account
	for (account=cfg.account; (account) ; account=account->next){
		fprintf(f,"[account]\n");
		fprintf_conf(f, "user", "%s\n", account->usr);
		fprintf_conf(f, "pwd", "%s\n", account->pwd);
#ifdef WEBIF
		if (account->description[0] || cfg.http_full_cfg)
			fprintf_conf(f, "description", "%s\n", account->description);
#endif
		if (account->disabled || cfg.http_full_cfg)
			fprintf_conf(f, "disabled", "%d\n", account->disabled);

		if (account->expirationdate || cfg.http_full_cfg) {
			struct tm timeinfo;
			localtime_r(&account->expirationdate, &timeinfo);
			char buf [80];
			strftime (buf,80,"%Y-%m-%d",&timeinfo);
			if(strcmp(buf,"1970-01-01"))
				fprintf_conf(f, "expdate", "%s\n", buf);
			else
				fprintf_conf(f, "expdate", "\n");
		}


		if(account->allowedtimeframe[0] && account->allowedtimeframe[1]) {
			fprintf_conf(f, "allowedtimeframe", "%02d:%02d-%02d:%02d\n",
					account->allowedtimeframe[0]/60,
					account->allowedtimeframe[0]%60,
					account->allowedtimeframe[1]/60,
					account->allowedtimeframe[1]%60 );
		} else {
			if (cfg.http_full_cfg)
				fprintf_conf(f, "allowedtimeframe", "\n");
		}

		//group
		if (account->grp || cfg.http_full_cfg) {
			value = mk_t_group(account->grp);
			fprintf_conf(f, "group", "%s\n", value);
			free_mk_t(value);
		}

		if (account->dyndns[0] || cfg.http_full_cfg)
			fprintf_conf(f, "hostname", "%s\n", account->dyndns);

		if (account->uniq || cfg.http_full_cfg)
			fprintf_conf(f, "uniq", "%d\n", account->uniq);

		if (account->tosleep != cfg.tosleep || cfg.http_full_cfg)
			fprintf_conf(f, "sleep", "%d\n", account->tosleep);

		if (account->monlvl != cfg.mon_level || cfg.http_full_cfg)
			fprintf_conf(f, "monlevel", "%d\n", account->monlvl);

		if (account->autoau == 1)
			fprintf_conf(f, "au", "1\n");
		else if (account->aureader_list) {

			value = mk_t_aureader(account);
			if (strlen(value) > 0)
				fprintf_conf(f, "au", "%s\n", value);
			free_mk_t(value);

		} else if (cfg.http_full_cfg) fprintf_conf(f, "au", "\n");

		value = mk_t_service((uint64_t)account->sidtabok, (uint64_t)account->sidtabno);
		if (strlen(value) > 0 || cfg.http_full_cfg)
			fprintf_conf(f, "services", "%s\n", value);
		free_mk_t(value);

		// allowed protocols
		if (account->allowedprotocols || cfg.http_full_cfg ){
			value = mk_t_allowedprotocols(account);
			fprintf_conf(f, "allowedprotocols", "%s\n", value);
			free_mk_t(value);
		}

		//CAID
		if (account->ctab.caid[0] || cfg.http_full_cfg) {
			value = mk_t_caidtab(&account->ctab);
			fprintf_conf(f, "caid", "%s\n", value);
			free_mk_t(value);
		}

		//betatunnel
		if (account->ttab.bt_caidfrom[0] || cfg.http_full_cfg) {
			value = mk_t_tuntab(&account->ttab);
			fprintf_conf(f, "betatunnel", "%s\n", value);
			free_mk_t(value);
		}

		//ident
		if (account->ftab.nfilts || cfg.http_full_cfg) {
			value = mk_t_ftab(&account->ftab);
			fprintf_conf(f, "ident", "%s\n", value);
			free_mk_t(value);
		}

		//CHID
		if (account->fchid.nfilts || cfg.http_full_cfg) {
			value = mk_t_ftab(&account->fchid);
			fprintf_conf(f, "chid", "%s\n", value);
			free_mk_t(value);
		}

		//class
		if ((account->cltab.bn > 0 || account->cltab.an > 0) || cfg.http_full_cfg) {
			value = mk_t_cltab(&account->cltab);
			fprintf_conf(f, "class", "%s\n", value);
			free_mk_t(value);
		}

		if ((account->c35_suppresscmd08 != cfg.c35_suppresscmd08) || cfg.http_full_cfg)
			fprintf_conf(f, "suppresscmd08", "%d\n", account->c35_suppresscmd08);

#ifdef MODULE_CCCAM
		if (account->cccmaxhops != DEFAULT_CC_MAXHOP || cfg.http_full_cfg)
			fprintf_conf(f, "cccmaxhops", "%d\n", account->cccmaxhops);

		if ((account->cccreshare != DEFAULT_CC_RESHARE) || cfg.http_full_cfg)
			fprintf_conf(f, "cccreshare", "%d\n", account->cccreshare);

		if ((account->cccignorereshare != cfg.cc_ignore_reshare && account->cccignorereshare != -1) || cfg.http_full_cfg)
			fprintf_conf(f, "cccignorereshare", "%d\n", account->cccignorereshare);

		if ((account->cccstealth != DEFAULT_CC_STEALTH) || cfg.http_full_cfg)
			fprintf_conf(f, "cccstealth", "%d\n", account->cccstealth);
#endif

		if (account->c35_sleepsend || cfg.http_full_cfg)
			fprintf_conf(f, "sleepsend", "%u\n", account->c35_sleepsend);

		if (account->failban || cfg.http_full_cfg)
			fprintf_conf(f, "failban", "%d\n", account->failban);

		if ((account->ncd_keepalive != DEFAULT_NCD_KEEPALIVE) || cfg.http_full_cfg)
			fprintf_conf(f, "keepalive", "%d\n", account->ncd_keepalive);

#ifdef CS_ANTICASC
		if (account->ac_users != DEFAULT_AC_USERS || cfg.http_full_cfg)
			fprintf_conf(f, "numusers", "%d\n", account->ac_users);
		if (account->ac_penalty != DEFAULT_AC_PENALTY || cfg.http_full_cfg)
			fprintf_conf(f, "penalty", "%d\n", account->ac_penalty);
#endif
		fputc((int)'\n', f);
	}
  fclose(f);

  return(safe_overwrite_with_bak(destfile, tmpfile, bakfile, 0));
}

int32_t write_server()
{
	int32_t j;
	char *value;
	FILE *f;

	char tmpfile[256];
	char destfile[256];
	char bakfile[256];

	snprintf(destfile, sizeof(destfile),"%s%s", cs_confdir, cs_srvr);
	snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", cs_confdir, cs_srvr);
	snprintf(bakfile, sizeof(bakfile),"%s%s.bak", cs_confdir, cs_srvr);

	if (!(f=fopen(tmpfile, "w"))){
		cs_log("Cannot open file \"%s\" (errno=%d %s)", tmpfile, errno, strerror(errno));
		return(1);
	}
	fprintf(f,"# oscam.server generated automatically by Streamboard OSCAM %s build #%s\n", CS_VERSION, CS_SVN_VERSION);
	fprintf(f,"# Read more: http://streamboard.gmc.to/svn/oscam/trunk/Distribution/doc/txt/oscam.server.txt\n\n");

	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) {
		if ( rdr->label[0]) {
			int32_t isphysical = (rdr->typ & R_IS_NETWORK)?0:1;
			char *ctyp = reader_get_type_desc(rdr, 0);

			fprintf(f,"[reader]\n");

			fprintf_conf(f, "label", "%s\n", rdr->label);

#ifdef WEBIF
			if (rdr->description[0] || cfg.http_full_cfg)
				fprintf_conf(f, "description", "%s\n", rdr->description);
#endif

			if (rdr->enable == 0 || cfg.http_full_cfg)
				fprintf_conf(f, "enable", "%d\n", rdr->enable);

			fprintf_conf(f, "protocol", "%s\n", ctyp);
			fprintf_conf(f, "device", "%s", rdr->device);

			if ((rdr->r_port || cfg.http_full_cfg) && !isphysical)
				fprintf(f, ",%d", rdr->r_port);
			if ((rdr->l_port || cfg.http_full_cfg) && !isphysical && strncmp(ctyp, "cccam", 5))
				fprintf(f, ",%d", rdr->l_port);
			if ((rdr->slot || cfg.http_full_cfg) && !strncmp(ctyp, "sc8in1", 6))
				fprintf(f, ":%d", rdr->slot);
			fprintf(f, "\n");

#ifdef LIBUSB
			if (!(rdr->typ & R_IS_NETWORK))
				if (rdr->device_endpoint || cfg.http_full_cfg)
					fprintf_conf(f, "device_out_endpoint", "0x%2X\n", rdr->device_endpoint);
#endif

			if (rdr->ncd_key[0] || rdr->ncd_key[13] || cfg.http_full_cfg) {
				fprintf_conf(f, "key", "");
				if(rdr->ncd_key[0] || rdr->ncd_key[13]){
					for (j = 0; j < 14; j++) {
						fprintf(f, "%02X", rdr->ncd_key[j]);
					}
				}
				fprintf(f, "\n");
			}

			if ((rdr->r_usr[0] || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "user", "%s\n", rdr->r_usr);

			if (strlen(rdr->r_pwd) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "password", "%s\n", rdr->r_pwd);

			if(strcmp(rdr->pincode, "none") || cfg.http_full_cfg)
				fprintf_conf(f, "pincode", "%s\n", rdr->pincode);

			if ((rdr->emmfile || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "readnano", "%s\n", rdr->emmfile?rdr->emmfile:"");

			value = mk_t_service((uint64_t)rdr->sidtabok, (uint64_t)rdr->sidtabno);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "services", "%s\n", value);
			free_mk_t(value);

			if ((rdr->tcp_ito || cfg.http_full_cfg) && !isphysical && rdr->typ != R_CCCAM)
				fprintf_conf(f, "inactivitytimeout", "%d\n", rdr->tcp_ito);

			if ((rdr->tcp_rto != DEFAULT_TCP_RECONNECT_TIMEOUT || cfg.http_full_cfg) && !isphysical)
				fprintf_conf(f, "reconnecttimeout", "%d\n", rdr->tcp_rto);

			if ((rdr->ncd_disable_server_filt || cfg.http_full_cfg) && rdr->typ == R_NEWCAMD)
				fprintf_conf(f, "disableserverfilter", "%d\n", rdr->ncd_disable_server_filt);

			if ((rdr->smargopatch || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "smargopatch", "%d\n", rdr->smargopatch);

			if ((rdr->show_cls != 10 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "showcls", "%d\n", rdr->show_cls);

			if (rdr->fallback || cfg.http_full_cfg)
				fprintf_conf(f, "fallback", "%d\n", rdr->fallback);

			if (rdr->log_port || cfg.http_full_cfg)
				fprintf_conf(f, "logport", "%d\n", rdr->log_port);

			value = mk_t_caidtab(&rdr->ctab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "caid", "%s\n", value);
			free_mk_t(value);

			if (rdr->boxid && isphysical)
				fprintf_conf(f, "boxid", "%08X\n", rdr->boxid);
			else if (cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "boxid", "\n");

			if((rdr->fix_9993 || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "fix9993", "%d\n", rdr->fix_9993);

			// rsakey
			int32_t len = check_filled(rdr->rsa_mod, 120);
			if (len > 0 && isphysical) {
				if(len > 64) len = 120;
				else len = 64;
				char tmp[len*2+1];
				fprintf_conf(f, "rsakey", "%s\n", cs_hexdump(0, rdr->rsa_mod, len, tmp, sizeof(tmp)));
			} else if(cfg.http_full_cfg && isphysical)
				fprintf_conf(f, "rsakey", "\n");

			if ((rdr->force_irdeto || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "force_irdeto", "%d\n", rdr->force_irdeto);
			}

			len = check_filled(rdr->nagra_boxkey, 8);
			if ((len > 0 || cfg.http_full_cfg) && isphysical){
				char tmp[17];
				fprintf_conf(f, "boxkey", "%s\n", len>0?cs_hexdump(0, rdr->nagra_boxkey, 8, tmp, sizeof(tmp)):"");
			}

			if ((rdr->atr[0] || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "atr", "");
				if(rdr->atr[0]){
					for (j=0; j < rdr->atrlen/2; j++) {
						fprintf(f, "%02X", rdr->atr[j]);
					}
				}
				fprintf(f, "\n");
			}

			value = mk_t_ecmwhitelist(rdr->ecmWhitelist);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ecmwhitelist", "%s\n", value);
			free_mk_t(value);

			if (isphysical) {
				if (rdr->detect&0x80)
					fprintf_conf(f, "detect", "!%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
				else
					fprintf_conf(f, "detect", "%s\n", RDR_CD_TXT[rdr->detect&0x7f]);
			}

			if ((rdr->nagra_read || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "nagra_read", "%d\n", rdr->nagra_read);

			if ((rdr->mhz || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "mhz", "%d\n", rdr->mhz);

			if ((rdr->cardmhz || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "cardmhz", "%d\n", rdr->cardmhz);

			value = mk_t_ftab(&rdr->ftab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ident", "%s\n", value);
			free_mk_t(value);

			//Todo: write reader class

			value = mk_t_ftab(&rdr->fchid);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "chid", "%s\n", value);
			free_mk_t(value);

			value = mk_t_cltab(&rdr->cltab);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "class", "%s\n", value);
			free_mk_t(value);

			value = mk_t_aeskeys(rdr);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "aeskeys", "%s\n", value);
			free_mk_t(value);

			if ((rdr->show_cls && !rdr->show_cls == 10) || cfg.http_full_cfg)
				fprintf_conf(f, "showcls", "%d\n", rdr->show_cls);

			value = mk_t_group(rdr->grp);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "group", "%s\n", value);
			free_mk_t(value);

			if (rdr->cachemm || cfg.http_full_cfg)
				fprintf_conf(f, "emmcache", "%d,%d,%d\n", rdr->cachemm, rdr->rewritemm, rdr->logemm);

			if ((rdr->blockemm & EMM_UNKNOWN) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-unknown", "%d\n", (rdr->blockemm & EMM_UNKNOWN) ? 1: 0);

			if ((rdr->blockemm & EMM_UNIQUE) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-u", "%d\n", (rdr->blockemm & EMM_UNIQUE) ? 1: 0);

			if ((rdr->blockemm & EMM_SHARED) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-s", "%d\n", (rdr->blockemm & EMM_SHARED) ? 1: 0);

			if ((rdr->blockemm & EMM_GLOBAL) || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-g", "%d\n", (rdr->blockemm & EMM_GLOBAL) ? 1: 0);

			value = mk_t_emmbylen(rdr);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "blockemm-bylen", "%s\n", value);
			free_mk_t(value);

#ifdef WITH_LB
			if (rdr->lb_weight != 100 || cfg.http_full_cfg)
				fprintf_conf(f, "lb_weight", "%d\n", rdr->lb_weight);
#endif

			//savenano
			value = mk_t_nano(rdr, 0x02);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "savenano", "%s\n", value);
			free_mk_t(value);

			//blocknano
			value = mk_t_nano(rdr, 0x01);
			if (strlen(value) > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "blocknano", "%s\n", value);
			free_mk_t(value);

			if (rdr->dropbadcws)
				fprintf_conf(f, "dropbadcws", "%d\n", rdr->dropbadcws);
				
#ifdef MODULE_CCCAM
			if (rdr->typ == R_CCCAM) {
				if (rdr->cc_version[0] || cfg.http_full_cfg)
					fprintf_conf(f, "cccversion", "%s\n", rdr->cc_version);

				if (rdr->cc_maxhop != DEFAULT_CC_MAXHOP || cfg.http_full_cfg)
					fprintf_conf(f, "cccmaxhops", "%d\n", rdr->cc_maxhop);

				if (rdr->cc_mindown > 0 || cfg.http_full_cfg)
					fprintf_conf(f, "cccmindown", "%d\n", rdr->cc_mindown);

				if (rdr->cc_want_emu || cfg.http_full_cfg)
					fprintf_conf(f, "cccwantemu", "%d\n", rdr->cc_want_emu);

				if (rdr->cc_keepalive != DEFAULT_CC_KEEPALIVE || cfg.http_full_cfg)
					fprintf_conf(f, "ccckeepalive", "%d\n", rdr->cc_keepalive);

				if (rdr->cc_reshare != DEFAULT_CC_RESHARE || cfg.http_full_cfg)
					fprintf_conf(f, "cccreshare", "%d\n", rdr->cc_reshare);
			}
			else if (rdr->cc_hop > 0 || cfg.http_full_cfg)
				fprintf_conf(f, "ccchop", "%d\n", rdr->cc_hop);
#endif

			if ((rdr->deprecated || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "deprecated", "%d\n", rdr->deprecated);

			if (rdr->audisabled || cfg.http_full_cfg)
				fprintf_conf(f, "audisabled", "%d\n", rdr->audisabled);

			if (rdr->auprovid)
				fprintf_conf(f, "auprovid", "%06lX\n", rdr->auprovid);
			else if (cfg.http_full_cfg)
				fprintf_conf(f, "auprovid", "\n");

			if ((rdr->ndsversion || cfg.http_full_cfg) && isphysical)
				fprintf_conf(f, "ndsversion", "%d\n", rdr->ndsversion);

			if ((rdr->ratelimitecm || cfg.http_full_cfg) && isphysical) {
				fprintf_conf(f, "ratelimitecm", "%d\n", rdr->ratelimitecm);
				fprintf_conf(f, "ratelimitseconds", "%d\n", rdr->ratelimitseconds);
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
  snprintf(targetfile, sizeof(targetfile),"%s%s", get_tmp_dir(), "/oscam.version");
  FILE *fp;

  if (!(fp=fopen(targetfile, "w"))) {
	  cs_log("Cannot open %s (errno=%d %s)", targetfile, errno, strerror(errno));
  } else {
	  time_t now = time((time_t)0);
	  struct tm st;
	  localtime_r(&now, &st);
	  fprintf(fp, "Unix starttime: %d\n", (int)now);
	  fprintf(fp, "Starttime:      %02d.%02d.%02d", st.tm_mday, st.tm_mon+1, st.tm_year%100);
	  fprintf(fp, " %02d:%02d:%02d\n", st.tm_hour, st.tm_min, st.tm_sec);
	  fprintf(fp, "Version:        %s  Rev. %s\n", CS_VERSION, CS_SVN_VERSION);
	  fprintf(fp, "Max PID:        unlimited\n\n\n");
	  fprintf(fp, "Active modules:\n");

#ifdef WEBIF
	  fprintf(fp, "Web interface support:      yes\n");
#else
	  fprintf(fp, "Web interface support:      no\n");
#endif
#ifdef WITH_SSL
	  fprintf(fp, "SSL support:                yes\n");
#else
	  fprintf(fp, "SSL support:                no\n");
#endif
#ifdef HAVE_DVBAPI
	  fprintf(fp, "DVB API support             yes\n");
#ifdef WITH_STAPI
	  fprintf(fp, "DVB API with STAPI support: yes\n");
#else
	  fprintf(fp, "DVB API with STAPI support: no\n");
#endif
#else
	  fprintf(fp, "DVB API support             no\n");
#endif
#ifdef CS_ANTICASC
	  fprintf(fp, "Anti-cascading support:     yes\n");
#else
	  fprintf(fp, "Anti-cascading support:     no\n");
#endif
#ifdef CS_WITH_DOUBLECHECK
	  fprintf(fp, "ECM doublecheck:            yes\n");
#else
	  fprintf(fp, "ECM doublecheck:            no\n");
#endif
#ifdef IRDETO_GUESSING
	  fprintf(fp, "Irdeto guessing:            yes\n");
#else
	  fprintf(fp, "Irdeto guessing:            no\n");
#endif
#ifdef WITH_DEBUG
	  fprintf(fp, "Debug mode:                 yes\n");
#else
	  fprintf(fp, "Debug mode:                 no\n");
#endif
#ifdef CS_LED
	  fprintf(fp, "LED support:                yes\n");
#else
	  fprintf(fp, "LED support:                no\n");
#endif
#ifdef QBOXHD_LED
	  fprintf(fp, "Q-Box HD LED support:       yes\n");
#else
	  fprintf(fp, "Q-Box HD LED support:       no\n");
#endif
#ifdef CS_LOGHISTORY
	  fprintf(fp, "Log history:                yes\n");
#else
	  fprintf(fp, "Log history:                no\n");
#endif
#ifdef MODULE_MONITOR
	  fprintf(fp, "Monitor:                    yes\n");
#else
	  fprintf(fp, "Monitor:                    no\n");
#endif
#ifdef WITH_LB
	  fprintf(fp, "Loadbalancing support:      yes\n");
#else
	  fprintf(fp, "Loadbalancing support:      no\n");
#endif
#ifdef LCDSUPPORT
	  fprintf(fp, "LCD support:                yes\n");
#else
	  fprintf(fp, "LCD support:                no\n");
#endif
#ifdef MODULE_CAMD33
	  fprintf(fp, "camd 3.3x:                  yes\n");
#else
	  fprintf(fp, "camd 3.3x:                  no\n");
#endif
#ifdef MODULE_CAMD35
	  fprintf(fp, "camd 3.5 UDP:               yes\n");
#else
	  fprintf(fp, "camd 3.5 UDP:               no\n");
#endif
#ifdef MODULE_CAMD35_TCP
	  fprintf(fp, "camd 3.5 TCP:               yes\n");
#else
	  fprintf(fp, "camd 3.5 TCP:               no\n");
#endif
#ifdef MODULE_NEWCAMD
	  fprintf(fp, "newcamd:                    yes\n");
#else
	  fprintf(fp, "newcamd:                    no\n");
#endif
#ifdef MODULE_CCCAM
	  fprintf(fp, "CCcam:                      yes\n");
#else
	  fprintf(fp, "CCcam:                      no\n");
#endif
#ifdef MODULE_GBOX
	  fprintf(fp, "gbox:                       yes\n");
#else
	  fprintf(fp, "gbox:                       no\n");
#endif
#ifdef MODULE_RADEGAST
	  fprintf(fp, "radegast:                   yes\n");
#else
	  fprintf(fp, "radegast:                   no\n");
#endif
#ifdef MODULE_SERIAL
	  fprintf(fp, "serial:                     yes\n");
#else
	  fprintf(fp, "serial:                     no\n");
#endif
#ifdef MODULE_CONSTCW
	  fprintf(fp, "constant CW:                yes\n");
#else
	  fprintf(fp, "constant CW:                no\n");
#endif
#ifdef WITH_CARDREADER
	  fprintf(fp, "Cardreader:                 yes\n");

	#ifdef READER_NAGRA
	  fprintf(fp, "Nagra:                      yes\n");
	#else
	  fprintf(fp, "Nagra:                      no\n");
	#endif
	#ifdef READER_IRDETO
	  fprintf(fp, "Irdeto:                     yes\n");
	#else
	  fprintf(fp, "Irdeto:                     no\n");
	#endif
	#ifdef READER_CONAX
	  fprintf(fp, "Conax:                      yes\n");
	#else
	  fprintf(fp, "Conax:                      no\n");
	#endif
	#ifdef READER_CRYPTOWORKS
	  fprintf(fp, "Cryptoworks:                yes\n");
	#else
	  fprintf(fp, "Cryptoworks:                no\n");
	#endif
	#ifdef READER_SECA
	  fprintf(fp, "Seca:                       yes\n");
	#else
	  fprintf(fp, "Seca:                       no\n");
	#endif
	#ifdef READER_VIACCESS
	  fprintf(fp, "Viaccess:                   yes\n");
	#else
	  fprintf(fp, "Viaccess:                   no\n");
	#endif
	#ifdef READER_VIDEOGUARD
	  fprintf(fp, "NDS Videoguard:             yes\n");
	#else
	  fprintf(fp, "NDS Videoguard:             no\n");
	#endif
	#ifdef READER_DRE
	  fprintf(fp, "DRE Crypt:                  yes\n");
	#else
	  fprintf(fp, "DRE Crypt:                  no\n");
	#endif

	#ifdef READER_TONGFANG
	  fprintf(fp, "TONGFANG:                   yes\n");
	#else
	  fprintf(fp, "TONGFANG:                   no\n");
	#endif
#else
	  fprintf(fp, "Cardreader:                 no\n");
#endif

	  fclose(fp);
  }
#endif

}

int32_t init_free_userdb(struct s_auth *ptr) {
	int32_t nro;
	for (nro = 0; ptr; nro++) {
		struct s_auth *ptr_next;
		ptr_next = ptr->next;
		ll_destroy(ptr->aureader_list);
		ptr->next = NULL;
		add_garbage(ptr);
		ptr = ptr_next;
	}
	cs_log("userdb %d accounts freed", nro);

	return nro;
}

struct s_auth *init_userdb()
{
	struct s_auth *authptr = NULL;
	int32_t tag = 0, nr = 0, expired = 0, disabled = 0;
	//int32_t first=1;
	FILE *fp;
	char *value;
	struct s_auth *account = NULL;
	struct s_auth *probe = NULL;
	char token[MAXLINESIZE];

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_user);
	if (!(fp = fopen(token, "r"))) {
		cs_log("Cannot open file \"%s\" (errno=%d %s)", token, errno, strerror(errno));
		return authptr;
	}

	while (fgets(token, sizeof(token), fp)) {
		int32_t i, l;
		void *ptr;

		if ((l=strlen(trim(token))) < 3)
			continue;

		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l - 1] = 0;
			tag = (!strcmp("account", strtolower(token + 1)));

			if(!cs_malloc(&ptr, sizeof(struct s_auth), -1)) return authptr;
			if (account)
				account->next = ptr;
			else
				authptr = ptr;

			account = ptr;
			account->allowedtimeframe[0] = 0;
			account->allowedtimeframe[1] = 0;
			account->aureader_list = NULL;
			account->monlvl = cfg.mon_level;
			account->tosleep = cfg.tosleep;
			account->c35_suppresscmd08 = cfg.c35_suppresscmd08;
			account->cccmaxhops = DEFAULT_CC_MAXHOP;
			account->cccreshare = DEFAULT_CC_RESHARE; // default: use global cfg
			account->cccignorereshare = -1;
			account->cccstealth = DEFAULT_CC_STEALTH; // default: use global cfg
			account->ncd_keepalive = cfg.ncd_keepalive;
			account->firstlogin = 0;
			for (i = 1; i < CS_MAXCAIDTAB; account->ctab.mask[i++] = 0xffff);
			for (i = 1; i < CS_MAXTUNTAB; account->ttab.bt_srvid[i++] = 0x0000);
			nr++;

#ifdef CS_ANTICASC
			account->ac_users   = DEFAULT_AC_USERS;   // use ac_users global value
			account->ac_penalty = DEFAULT_AC_PENALTY; // use ac_penalty global value
#endif
			continue;
		}

		if (!tag)
			continue;

		if (!(value=strchr(token, '=')))
			continue;

		*value++ = '\0';

		// check for duplicate useraccounts and make the name unique
		if (!strcmp(trim(strtolower(token)), "user")) {
			for(probe = authptr; probe; probe = probe->next){
				if (!strcmp(probe->usr, trim(value))){
					fprintf(stderr, "Warning: duplicate account '%s'\n", value);
					strncat(value, "_x", sizeof(probe->usr) - strlen(value) - 1);
				}
			}
		}

		chk_account(trim(strtolower(token)), trim(value), account);
	}

	fclose(fp);

	for(account = authptr; account; account = account->next){
		if(account->expirationdate && account->expirationdate < time(NULL))
			++expired;

		if(account->disabled)
			++disabled;
	}

	cs_log("userdb reloaded: %d accounts loaded, %d expired, %d disabled", nr, expired, disabled);
	return authptr;
}

void free_sidtab(struct s_sidtab *ptr)
{
		if (!ptr) return;
		add_garbage(ptr->caid); //no need to check on NULL first, freeing NULL doesnt do anything
		add_garbage(ptr->provid);
		add_garbage(ptr->srvid);
		add_garbage(ptr);
}

static void chk_entry4sidtab(char *value, struct s_sidtab *sidtab, int32_t what)
{
  int32_t i, b;
  char *ptr, *saveptr1 = NULL;
  uint16_t *slist=(uint16_t *) 0;
  uint32_t *llist=(uint32_t *) 0;
  uint32_t caid;
  char buf[strlen(value) + 1];
  cs_strncpy(buf, value, sizeof(buf));
  b=(what==1) ? sizeof(uint32_t) : sizeof(uint16_t);
  for (i=0, ptr=strtok_r(value, ",", &saveptr1); ptr; ptr=strtok_r(NULL, ",", &saveptr1))
  {
    caid=a2i(ptr, b);
    if (!errno) i++;
  }
  //if (!i) return(0);
  if (b==sizeof(uint16_t)){
    if(!cs_malloc(&slist, i*sizeof(uint16_t), -1)) return;
  } else {
  	if(!cs_malloc(&llist, i*sizeof(uint32_t), -1)) return;
  }
  cs_strncpy(value, buf, sizeof(buf));
  for (i=0, ptr=strtok_r(value, ",", &saveptr1); ptr; ptr=strtok_r(NULL, ",", &saveptr1))
  {
    caid=a2i(ptr, b);
    if (errno) continue;
    if (b==sizeof(uint16_t))
      slist[i++]=(uint16_t) caid;
    else
      llist[i++]=caid;
  }
  switch (what)
  {
    case 0: add_garbage(sidtab->caid);
    		sidtab->caid=slist;
            sidtab->num_caid=i;
            break;
    case 1: add_garbage(sidtab->provid);
    		sidtab->provid=llist;
            sidtab->num_provid=i;
            break;
    case 2: add_garbage(sidtab->srvid);
    		sidtab->srvid=slist;
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

void init_free_sidtab() {
		struct s_sidtab *nxt, *ptr = cfg.sidtab;
		while (ptr) {
				nxt = ptr->next;
				free_sidtab(ptr);
				ptr = nxt;
		}
		cfg.sidtab = NULL;
}

int32_t init_sidtab() {
	int32_t nr, nro, nrr;
	FILE *fp;
	char *value;
	char token[MAXLINESIZE];
	struct s_sidtab *ptr;
	struct s_sidtab *sidtab=(struct s_sidtab *)0;

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_sidt);
	if (!(fp=fopen(token, "r")))
	{
		cs_log("Cannot open file \"%s\" (errno=%d %s)", token, errno, strerror(errno));
		return(1);
	}
	for (nro=0, ptr=cfg.sidtab; ptr; nro++)
	{
		struct s_sidtab *ptr_next;
		ptr_next=ptr->next;
		free_sidtab(ptr);
		ptr=ptr_next;
	}
	nr = 0; nrr = 0;
	while (fgets(token, sizeof(token), fp))
	{
		int32_t l;
		void *ptr;
		if ((l=strlen(trim(token)))<3) continue;
		if ((token[0]=='[') && (token[l-1]==']'))
		{
			token[l-1]=0;
			if(nr > MAX_SIDBITS){
				fprintf(stderr, "Warning: Service No.%d - '%s' ignored. Max allowed Services %d\n", nr, strtolower(token+1), MAX_SIDBITS);
				nr++;
				nrr++;
			} else {
				if (!cs_malloc(&ptr, sizeof(struct s_sidtab), -1)) return(1);
				if (sidtab)
					sidtab->next=ptr;
				else
					cfg.sidtab=ptr;
				sidtab=ptr;
				nr++;
				cs_strncpy(sidtab->label, strtolower(token+1), sizeof(sidtab->label));
				continue;
			}
		}
		if (!sidtab) continue;
		if (!(value=strchr(token, '='))) continue;
		*value++='\0';
		chk_sidtab(trim(strtolower(token)), trim(strtolower(value)), sidtab);
	}
	fclose(fp);

#ifdef DEBUG_SIDTAB
	show_sidtab(cfg.sidtab);
#endif
	cs_log("services reloaded: %d services freed, %d services loaded, rejected %d", nro, nr, nrr);
	return(0);
}

//Todo #ifdef CCCAM
int32_t init_provid() {
	int32_t nr;
	FILE *fp;
	char *payload, *saveptr1 = NULL;
	char token[MAXLINESIZE];
	static struct s_provid *provid=(struct s_provid *)0;
	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_provid);

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d %s), no provids's loaded", token, errno, strerror(errno));
		return(0);
	}
	nr=0;
	while (fgets(token, sizeof(token), fp)) {

		int32_t l;
		void *ptr;
		char *tmp;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l = strlen(tmp)) < 11) continue;
		if (!(payload = strchr(token, '|'))) continue;
		*payload++ = '\0';

		if (!cs_malloc(&ptr, sizeof(struct s_provid), -1)) return(1);
		if (provid)
			provid->next = ptr;
		else
			cfg.provid = ptr;

		provid = ptr;

		int32_t i;
		char *ptr1;
		for (i = 0, ptr1 = strtok_r(payload, "|", &saveptr1); ptr1; ptr1 = strtok_r(NULL, "|", &saveptr1), i++){
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

int32_t init_srvid()
{
	int32_t nr = 0, i;
	FILE *fp;
	char *payload, *tmp, *saveptr1 = NULL;
	char token[MAXLINESIZE];
	struct s_srvid *srvid=NULL, *new_cfg_srvid[16], *last_srvid[16];
	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_srid);
	// A cache for strings within srvids. A checksum is calculated which is the start point in the array (some kind of primitive hash algo).
	// From this point, a sequential search is done. This greatly reduces the amount of string comparisons.
	char **stringcache[1024];
	int32_t allocated[1024] = { 0 };
	int32_t used[1024] = { 0 };
	struct timeb ts, te;
  cs_ftime(&ts);

	memset(last_srvid, 0, sizeof(last_srvid));
	memset(new_cfg_srvid, 0, sizeof(new_cfg_srvid));

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d %s), no service-id's loaded", token, errno, strerror(errno));
		return(0);
	}

	while (fgets(token, sizeof(token), fp)) {
		int32_t l, j, len=0, len2, srvidtmp;
		uint32_t pos;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l=strlen(tmp)) < 6) continue;
		if (!(payload=strchr(token, '|'))) continue;
		*payload++ = '\0';

		if (!cs_malloc(&srvid, sizeof(struct s_srvid), -1)) return(1);

		char tmptxt[128];

		int32_t offset[4] = { -1, -1, -1, -1 };
		char *ptr1, *searchptr[4] = { NULL, NULL, NULL, NULL };
		char **ptrs[4] = { &srvid->prov, &srvid->name, &srvid->type, &srvid->desc };

		for (i = 0, ptr1 = strtok_r(payload, "|", &saveptr1); ptr1 && (i < 4) ; ptr1 = strtok_r(NULL, "|", &saveptr1), ++i){
			// check if string is in cache
			len2 = strlen(ptr1);
			pos = 0;
			for(j = 0; j < len2; ++j) pos += (uint8_t)ptr1[j];
			pos = pos%1024;
			for(j = 0; j < used[pos]; ++j){
				if (!strcmp(stringcache[pos][j], ptr1)){
					searchptr[i]=stringcache[pos][j];
					break;
				}
			}
			if (searchptr[i]) continue;

			offset[i]=len;
			cs_strncpy(tmptxt+len, trim(ptr1), sizeof(tmptxt)-len);
			len+=strlen(ptr1)+1;
		}

		char *tmpptr;
		if (!cs_malloc(&tmpptr, len, 0))
			continue;

		srvid->data=tmpptr;
		memcpy(tmpptr, tmptxt, len);

		for (i=0;i<4;i++) {
			if (searchptr[i]) {
				*ptrs[i] = searchptr[i];
				continue;
			}
			if (offset[i]>-1){
				*ptrs[i] = tmpptr + offset[i];
				// store string in stringcache
				tmp = *ptrs[i];
				len2 = strlen(tmp);
				pos = 0;
				for(j = 0; j < len2; ++j) pos += (uint8_t)tmp[j];
				pos = pos%1024;
				if(used[pos] >= allocated[pos]){
					if(allocated[pos] == 0) cs_malloc(&stringcache[pos], 16 * sizeof(char*), SIGINT);
					else cs_realloc(&stringcache[pos], (allocated[pos] + 16) * sizeof(char*), SIGINT);
					allocated[pos] += 16;
				}
				stringcache[pos][used[pos]] = tmp;
				used[pos] += 1;
			}
		}

		char *srvidasc = strchr(token, ':');
		*srvidasc++ = '\0';
		srvidtmp = dyn_word_atob(srvidasc) & 0xFFFF;
		//printf("srvid %s - %d\n",srvidasc,srvid->srvid );

		if (srvidtmp<0) {
			free(tmpptr);
			free(srvid);
			continue;
		} else srvid->srvid = srvidtmp;

		srvid->ncaid = 0;
		for (i = 0, ptr1 = strtok_r(token, ",", &saveptr1); (ptr1) && (i < 10) ; ptr1 = strtok_r(NULL, ",", &saveptr1), i++){
			srvid->caid[i] = dyn_word_atob(ptr1);
			srvid->ncaid = i+1;
			//cs_debug_mask(D_CLIENT, "ld caid: %04X srvid: %04X Prov: %s Chan: %s",srvid->caid[i],srvid->srvid,srvid->prov,srvid->name);
		}
		nr++;

		if (new_cfg_srvid[srvid->srvid>>12])
			last_srvid[srvid->srvid>>12]->next = srvid;
		else
			new_cfg_srvid[srvid->srvid>>12] = srvid;

		last_srvid[srvid->srvid>>12] = srvid;
	}
	for(i = 0; i < 1024; ++i){
		if(allocated[i] > 0) free(stringcache[i]);
	}

	cs_ftime(&te);
	int32_t time = 1000*(te.time-ts.time)+te.millitm-ts.millitm;

	fclose(fp);
	if (nr > 0) {
		cs_log("%d service-id's loaded in %dms", nr, time);
		if (nr > 2000) {
			cs_log("WARNING: You risk high CPU load and high ECM times with more than 2000 service-id´s!");
			cs_log("HINT: --> use optimized lists from http://streamboard.gmc.to/wiki/index.php/Srvid");
		}
	} else {
		cs_log("oscam.srvid loading failed, old format");
	}

	//this allows reloading of srvids, so cleanup of old data is needed:
	memcpy(last_srvid, cfg.srvid, sizeof(last_srvid));	//old data
	memcpy(cfg.srvid, new_cfg_srvid, sizeof(last_srvid));	//assign after loading, so everything is in memory

	struct s_client *cl;
	for (cl=first_client->next; cl ; cl=cl->next)
		cl->last_srvidptr=NULL;

	struct s_srvid *ptr;
	for (i=0; i<16; i++) {
		while (last_srvid[i]) { //cleanup old data:
			ptr = last_srvid[i]->next;
			free(last_srvid[i]->data);
			free(last_srvid[i]);
			last_srvid[i] = ptr;
		}
	}

	return(0);
}

int32_t init_tierid()
{
	int32_t nr;
	FILE *fp;
	char *payload, *saveptr1 = NULL;
	char token[MAXLINESIZE];
	static struct s_tierid *tierid=NULL, *new_cfg_tierid=NULL;
	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_trid);

	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (err=%d %s), no tier-id's loaded", token, errno, strerror(errno));
		return(0);
	}

	nr=0;
	while (fgets(token, sizeof(token), fp)) {

		int32_t l;
		void *ptr;
		char *tmp;
		tmp = trim(token);

		if (tmp[0] == '#') continue;
		if ((l=strlen(tmp)) < 6) continue;
		if (!(payload=strchr(token, '|'))) continue;
		*payload++ = '\0';

		if (!cs_malloc(&ptr,sizeof(struct s_tierid), -1)) return(1);
		if (tierid)
			tierid->next = ptr;
		else
			new_cfg_tierid = ptr;

		tierid = ptr;

		int32_t i;
		char *ptr1 = strtok_r(payload, "|", &saveptr1);
		if (ptr1)
			cs_strncpy(tierid->name, trim(ptr1), sizeof(tierid->name));

		char *tieridasc = strchr(token, ':');
		*tieridasc++ = '\0';
		tierid->tierid = dyn_word_atob(tieridasc);
		//printf("tierid %s - %d\n",tieridasc,tierid->tierid );

		tierid->ncaid = 0;
		for (i = 0, ptr1 = strtok_r(token, ",", &saveptr1); (ptr1) && (i < 10) ; ptr1 = strtok_r(NULL, ",", &saveptr1), i++){
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

	//reload function:
	tierid = cfg.tierid;
	cfg.tierid = new_cfg_tierid;
	struct s_tierid *ptr;
	while (tierid) {
		ptr = tierid->next;
		free(tierid);
		tierid = ptr;
	}

	return(0);
}

void chk_reader(char *token, char *value, struct s_reader *rdr)
{
	int32_t i;
	char *ptr, *ptr2, *ptr3, *saveptr1 = NULL;
	/*
	 *  case sensitive first
	 */
	if (!strcmp(token, "device")) {
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
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
		if (strlen(value) == 0){
			return;
		} else if (key_atob_l(value, rdr->ncd_key, 28)) {
			fprintf(stderr, "Configuration newcamd: Error in Key\n");
			memset(rdr->ncd_key, 0, sizeof(rdr->ncd_key));
		}
		return;
	}

	if (!strcmp(token, "password")) {
		cs_strncpy(rdr->r_pwd, value, sizeof(rdr->r_pwd));
		return;
	}

	if (!strcmp(token, "user")) {
		cs_strncpy(rdr->r_usr, value, sizeof(rdr->r_usr));
		return;
	}

#ifdef WEBIF
	if (!strcmp(token, "description")) {
		cs_strncpy(rdr->description, value, sizeof(rdr->description));
		return;
	}
#endif

  if (!strcmp(token, "mg-encrypted")) {
    uchar key[16];
    uchar mac[6];
    tmp_dbg(13);
    uchar *buf = NULL;
    int32_t len = 0;

    memset(&key, 0, 16);
    memset(&mac, 0, 6);

    for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
      trim(ptr);
      switch(i) {
        case 0:
          len = strlen(ptr) / 2 + (16 - (strlen(ptr) / 2) % 16);
          if(!cs_malloc(&buf,len, -1)) return;
          key_atob_l(ptr, buf, strlen(ptr));
          cs_log("enc %d: %s", len, ptr);
          break;

        case 1:
          key_atob_l(ptr, mac, 12);
          cs_log("mac: %s", ptr);
          break;
      }
    }

    if (!memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6)) {
#if defined OS_MACOSX || defined OS_FREEBSD
      // no mac address specified so use mac of en0 on local box
      struct ifaddrs *ifs, *current;

      if (getifaddrs(&ifs) == 0)
      {
         for (current = ifs; current != 0; current = current->ifa_next)
         {
            if (current->ifa_addr->sa_family == AF_LINK && strcmp(current->ifa_name, "en0") == 0)
            {
               struct sockaddr_dl *sdl = (struct sockaddr_dl *)current->ifa_addr;
               memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
               break;
            }
         }
         freeifaddrs(ifs);
      }
#elif defined OS_SOLARIS
			// no mac address specified so use first filled mac
			int32_t j, sock, niccount;
			struct ifreq nicnumber[16];
			struct ifconf ifconf;
			struct arpreq arpreq;

			if ((sock=socket(AF_INET,SOCK_DGRAM,0)) > -1){
				ifconf.ifc_buf = (caddr_t)nicnumber;
				ifconf.ifc_len = sizeof(nicnumber);
				if (!ioctl(sock,SIOCGIFCONF,(char*)&ifconf)){
					niccount = ifconf.ifc_len/(sizeof(struct ifreq));
					for(i = 0; i < niccount, ++i){
						memset(&arpreq, 0, sizeof(arpreq));
						((struct sockaddr_in*)&arpreq.arp_pa)->sin_addr.s_addr = ((struct sockaddr_in*)&nicnumber[i].ifr_addr)->sin_addr.s_addr;
						if (!(ioctl(sock,SIOCGARP,(char*)&arpreq))){
							for (j = 0; j < 6; ++j)
								mac[j] = (unsigned char)arpreq.arp_ha.sa_data[j];
							if(check_filled(mac, 6) > 0) break;
						}
					}
				}
				close(sock);
			}
#else
      // no mac address specified so use mac of eth0 on local box
      int32_t fd = socket(PF_INET, SOCK_STREAM, 0);

      struct ifreq ifreq;
      memset(&ifreq, 0, sizeof(ifreq));
      snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "eth0");

      ioctl(fd, SIOCGIFHWADDR, &ifreq);
      memcpy(mac, ifreq.ifr_ifru.ifru_hwaddr.sa_data, 6);

      close(fd);
#endif
			cs_debug_mask(D_TRACE, "Determined local mac address for mg-encrypted as %s", cs_hexdump(1, mac, 6, tmp_dbg, sizeof(tmp_dbg)));
    }

    // decrypt encrypted mgcamd gbox line
    for (i = 0; i < 6; i++)
      key[i * 2] = mac[i];

    AES_KEY aeskey;
    AES_set_decrypt_key(key, 128, &aeskey);
    for (i = 0; i < len; i+=16)
      AES_decrypt(buf + i,buf + i, &aeskey);

    // parse d-line
    for (i = 0, ptr = strtok_r((char *)buf, " {", &saveptr1); (i < 5) && (ptr); ptr = strtok_r(NULL, " {", &saveptr1), i++) {
      trim(ptr);
      switch(i) {
        case 1:    // hostname
          cs_strncpy(rdr->device, ptr, sizeof(rdr->device));
          break;
        case 2:   // local port
          cfg.gbox_port = atoi(ptr);  // ***WARNING CHANGE OF GLOBAL LISTEN PORT FROM WITHIN READER!!!***
          break;
        case 3:   // remote port
          rdr->r_port = atoi(ptr);
          break;
        case 4:   // password
          cs_strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd));
          break;
      }
    }

    free(buf);
    return;
  }

	//legacy parameter containing account=user,pass
	if (!strcmp(token, "account")) {
		if (strstr(value, ",")) {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
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
		cs_strncpy(rdr->pincode, value, sizeof(rdr->pincode));
		return;
	}

	if (!strcmp(token, "readnano")) {
		NULLFREE(rdr->emmfile);
		if (strlen(value) > 0) {
			if(!cs_malloc(&(rdr->emmfile), strlen(value) + 1, -1)) return;
			memcpy(rdr->emmfile, value, strlen(value) + 1);
		}
		return;
	}

	/*
	 *  case insensitive
	 */
	strtolower(value);

	if (!strcmp(token, "enable")) {
		rdr->enable  = strToIntVal(value, 0);
		return;
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
		rdr->tcp_ito  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "reconnecttimeout")) {
		rdr->tcp_rto  = strToIntVal(value, DEFAULT_TCP_RECONNECT_TIMEOUT);
		return;
	}

	if (!strcmp(token, "disableserverfilter")) {
		rdr->ncd_disable_server_filt  = strToIntVal(value, 0);
		return;
	}

	//FIXME workaround for Smargo until native mode works
	if (!strcmp(token, "smargopatch")) {
		rdr->smargopatch  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "label")) {
		int32_t found = 0;
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
		rdr->fallback  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "logport")) {
		rdr->log_port  = strToIntVal(value, 0);
		return;
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

  if (!strcmp(token, "fix9993")) {
    rdr->fix_9993 = strToIntVal(value, 0);
    return;
  }

	if (!strcmp(token, "rsakey")) {
		int32_t len = strlen(value);
		if(len != 128 && len != 240) {
			memset(rdr->rsa_mod, 0, 120);
			return;
		} else {
			if (key_atob_l(value, rdr->rsa_mod, len)) {
				fprintf(stderr, "Configuration reader: Error in rsakey\n");
				memset(rdr->rsa_mod, 0, sizeof(rdr->rsa_mod));
			}
			return;
		}
	}

	if (!strcmp(token, "boxkey")) {
		if(strlen(value) != 16 ) {
			memset(rdr->nagra_boxkey, 0, 16);
			return;
		} else {
			if (key_atob_l(value, rdr->nagra_boxkey, 16)) {
				fprintf(stderr, "Configuration reader: Error in boxkey\n");
				memset(rdr->nagra_boxkey, 0, sizeof(rdr->nagra_boxkey));
			}
			return;
		}
	}

	if (!strcmp(token, "force_irdeto")) {
		rdr->force_irdeto  = strToIntVal(value, 0);
		return;
	}


	if ((!strcmp(token, "atr"))) {
		memset(rdr->atr, 0, sizeof(rdr->atr));
		rdr->atrlen = strlen(value);
		if(rdr->atrlen == 0) {
			return;
		} else {
			if(rdr->atrlen > (int32_t)sizeof(rdr->atr) * 2)
				rdr->atrlen = (int32_t)sizeof(rdr->atr) * 2;
			key_atob_l(value, rdr->atr, rdr->atrlen);
			return;
		}
	}

	if (!strcmp(token, "ecmwhitelist")) {
		struct s_ecmWhitelist *tmp, *last;
		struct s_ecmWhitelistIdent *tmpIdent, *lastIdent;
		struct s_ecmWhitelistLen *tmpLen, *lastLen;
		for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
			for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
				for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
					add_garbage(tmpLen);
				}
				add_garbage(tmpIdent);
			}
			add_garbage(tmp);
		}
		rdr->ecmWhitelist = NULL;
		if(strlen(value) > 0){
			char *saveptr1=NULL, *saveptr2 = NULL;
			for (ptr = strtok_r(value, ";", &saveptr1); ptr; ptr = strtok_r(NULL, ";", &saveptr1)) {
				int16_t caid = 0, len;
				uint32_t ident = 0;
				ptr2=strchr(ptr,':');
				if(ptr2 != NULL){
					ptr2[0] = '\0';
					++ptr2;
					ptr3=strchr(ptr,'@');
					if(ptr3 != NULL){
						ptr3[0] = '\0';
						++ptr3;
						ident = (uint32_t)a2i(ptr3, 6);
					}
					caid = (int16_t)dyn_word_atob(ptr);
				} else ptr2 = ptr;
				for (ptr2 = strtok_r(ptr2, ",", &saveptr2); ptr2; ptr2 = strtok_r(NULL, ",", &saveptr2)) {
					len = (int16_t)dyn_word_atob(ptr2);
					last = NULL, tmpIdent = NULL, lastIdent = NULL, tmpLen = NULL, lastLen = NULL;
					for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
						last = tmp;
						if(tmp->caid == caid){
							for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
								lastIdent = tmpIdent;
								if(tmpIdent->ident == ident){
									for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
										lastLen = tmpLen;
										if(tmpLen->len == len) break;
									}
									break;
								}
							}
						}
					}
					if(tmp == NULL){
						if (cs_malloc(&tmp, sizeof(struct s_ecmWhitelist), -1)) {
							tmp->caid = caid;
							tmp->idents = NULL;
							tmp->next = NULL;
							if(last == NULL){
								rdr->ecmWhitelist = tmp;
							} else {
								last->next = tmp;
							}
						}
					}
					if(tmp != NULL && tmpIdent == NULL){
						if (cs_malloc(&tmpIdent, sizeof(struct s_ecmWhitelistIdent), -1)) {
							tmpIdent->ident = ident;
							tmpIdent->lengths = NULL;
							tmpIdent->next = NULL;
							if(lastIdent == NULL){
								tmp->idents = tmpIdent;
							} else {
								lastIdent->next = tmpIdent;
							}
						}
					}
					if(tmp != NULL && tmpIdent != NULL && tmpLen == NULL){
						if (cs_malloc(&tmpLen, sizeof(struct s_ecmWhitelistLen), -1)) {
							tmpLen->len = len;
							tmpLen->next = NULL;
							if(lastLen == NULL){
								tmpIdent->lengths = tmpLen;
							} else {
								lastLen->next = tmpLen;
							}
						}
					}
				}
			}
		}
		return;
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
		rdr->nagra_read  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "mhz")) {
		rdr->mhz  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cardmhz")) {
		rdr->cardmhz  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "protocol")) {

		for (i=0; i<CS_MAX_MOD; i++) {
			if (!strcmp(value, cardreader[i].desc)) {
				rdr->crdr = cardreader[i];
				rdr->crdr.active = 1;
				rdr->typ = cardreader[i].typ; //FIXME
				return;
			}
		}

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

		if (!strcmp(value, "gbox")) {
			rdr->typ = R_GBOX;
			return;
		}

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
		rdr->show_cls  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "group")) {
		rdr->grp = 0;
		for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
			int32_t g;
			g = atoi(ptr);
			if ((g>0) && (g<65)) {
				rdr->grp |= (((uint64_t)1)<<(g-1));
			}
		}
		return;
	}

	if (!strcmp(token, "emmcache")) {
		if(strlen(value) == 0) {
			rdr->cachemm = 0;
			rdr->rewritemm = 0;
			rdr->logemm = 0;
			return;
		} else {
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 3) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
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
		rdr->b_nano = 0;
		if (strlen(value) > 0) {
			if (!strcmp(value,"all")) {
				rdr->b_nano = 0xFFFF;
			} else {
				for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
					i = (byte_atob(ptr) % 0x80);
					if (i >= 0 && i <= 16)
						rdr->b_nano |= (1 << i);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "savenano")) {
		rdr->s_nano = 0;
		if (strlen(value) > 0) {
			if (!strcmp(value,"all")) {
				rdr->s_nano = 0xFFFF;
			} else {
				for (ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1)) {
					i = (byte_atob(ptr) % 0x80);
					if (i >= 0 && i <= 16)
						rdr->s_nano |= (1 << i);
				}
			}
		}
		return;
	}

	if (!strcmp(token, "blockemm-unknown")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_UNKNOWN))
			rdr->blockemm -= EMM_UNKNOWN;
		if (i)
			rdr->blockemm |= EMM_UNKNOWN;
		return;
	}

	if (!strcmp(token, "blockemm-u")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_UNIQUE))
			rdr->blockemm -= EMM_UNIQUE;
		if (i)
			rdr->blockemm |= EMM_UNIQUE;
		return;
	}

	if (!strcmp(token, "blockemm-s")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_SHARED))
			rdr->blockemm -= EMM_SHARED;
		if (i)
			rdr->blockemm |= EMM_SHARED;
		return;
	}

	if (!strcmp(token, "blockemm-g")) {
		i=atoi(value);
		if (!i && (rdr->blockemm & EMM_GLOBAL))
			rdr->blockemm -= EMM_GLOBAL;
		if (i)
			rdr->blockemm |= EMM_GLOBAL;
		return;
	}

	if (!strcmp(token, "blockemm-bylen")) {
		for (i = 0; i < CS_MAXEMMBLOCKBYLEN; i++)
			rdr->blockemmbylen[i] = 0;
		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < CS_MAXEMMBLOCKBYLEN) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++)
			rdr->blockemmbylen[i] = atoi(ptr);

		return;
	}

#ifdef WITH_LB
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
#endif

#ifdef MODULE_CCCAM
	if (!strcmp(token, "cccversion")) {
		// cccam version
		memset(rdr->cc_version, 0, sizeof(rdr->cc_version));
		if (strlen(value) > sizeof(rdr->cc_version) - 1) {
			fprintf(stderr, "cccam config: version too long.\n");
		}	else	
			cs_strncpy(rdr->cc_version, value, sizeof(rdr->cc_version));
		return;
	}

	if (!strcmp(token, "cccmaxhop") || !strcmp(token, "cccmaxhops")) { //Schlocke: cccmaxhops is better!
		// cccam max card distance
		rdr->cc_maxhop  = strToIntVal(value, DEFAULT_CC_MAXHOP);
		return;
	}

	if (!strcmp(token, "cccmindown") ) {
		// cccam min downhops
		rdr->cc_mindown  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "cccwantemu")) {
		rdr->cc_want_emu  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "ccckeepalive")) {
		rdr->cc_keepalive  = strToIntVal(value, DEFAULT_CC_KEEPALIVE);
		return;
	}

	if (!strcmp(token, "ccchopsaway") || !strcmp(token, "cccreshar")  || !strcmp(token, "cccreshare")) {
		rdr->cc_reshare = strToIntVal(value, DEFAULT_CC_RESHARE);
		return;
	}

	if (!strcmp(token, "ccchop")) {
		rdr->cc_hop = strToIntVal(value, 0);
		return;
	}
#endif

	if (!strcmp(token, "deprecated")) {
		rdr->deprecated  = strToIntVal(value, 0);
		return;
	}

	if (!strcmp(token, "audisabled")) {
		rdr->audisabled  = strToIntVal(value, 0);
		return;
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
		rdr->ndsversion = strToIntVal(value, 0);
		return;
	}


#ifdef AZBOX
	if (!strcmp(token, "mode")) {
		rdr->mode = strToIntVal(value, -1);
		return;
	}
#endif

	//ratelimit
	if (!strcmp(token, "ratelimitecm")) {
		if (strlen(value) == 0) {
			rdr->ratelimitecm = 0;
			return;
		} else {
			rdr->ratelimitecm = atoi(value);
			int32_t h;
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
	
	if (!strcmp(token, "dropbadcws")) {
		rdr->dropbadcws = strToIntVal(value, 0);
		return;
	}
	
	if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in reader section not recognized\n",token);
}

#ifdef IRDETO_GUESSING
int32_t init_irdeto_guess_tab()
{
  int32_t i, j, skip;
  int32_t b47;
  FILE *fp;
  char token[128], *ptr, *saveptr1 = NULL;
  char zSid[5];
  uchar b3;
  uint16_t caid, sid;
  struct s_irdeto_quess *ird_row, *head;

  memset(cfg.itab, 0, sizeof(cfg.itab));
  snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_ird);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (errno=%d %s) irdeto guessing not loaded",
           token, errno, strerror(errno));
    return(1);
  }
  while (fgets(token, sizeof(token), fp))
  {
    if( strlen(token)<20 ) continue;
    for( i=b3=b47=caid=sid=skip=0, ptr=strtok_r(token, ":", &saveptr1); (i<4)&&(ptr); ptr=strtok_r(NULL, ":", &saveptr1), i++ )
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
      if (!cs_malloc(&ird_row, sizeof(struct s_irdeto_quess), -1)) return(1);
      ird_row->b47  = b47;
      ird_row->caid = caid;
      ird_row->sid  = sid;
      ird_row->next = 0;

      head = cfg.itab[b3];
      if( head ) {
        while( head->next )
          head=head->next;
        head->next=ird_row;
      }
      else
        cfg.itab[b3]=ird_row;
        //cs_debug_mask(D_CLIENT, "%02X:%08X:%04X:%04X", b3, b47, caid, sid);
    }
  }
  fclose(fp);

  for( i=0; i<0xff; i++ )
  {
    head=cfg.itab[i];
    while(head)
    {
      cs_debug_mask(D_CLIENT, "itab[%02X]: b47=%08X, caid=%04X, sid=%04X",
               i, head->b47, head->caid, head->sid);
      head=head->next;
    }
  }
  return(0);
}
#endif

/**
 * frees a reader
 **/
void free_reader(struct s_reader *rdr)
{
	NULLFREE(rdr->emmfile);

	struct s_ecmWhitelist *tmp;
	struct s_ecmWhitelistIdent *tmpIdent;
	struct s_ecmWhitelistLen *tmpLen;
	for(tmp = rdr->ecmWhitelist; tmp; tmp=tmp->next){
		for(tmpIdent = tmp->idents; tmpIdent; tmpIdent=tmpIdent->next){
			for(tmpLen = tmpIdent->lengths; tmpLen; tmpLen=tmpLen->next){
				add_garbage(tmpLen);
			}
			add_garbage(tmpIdent);
		}
		add_garbage(tmp);
	}
	rdr->ecmWhitelist = NULL;

	clear_ftab(&rdr->ftab);

#ifdef WITH_LB
	ll_destroy_data(rdr->lb_stat);
#endif
	add_garbage(rdr);
}

int32_t init_readerdb()
{
	int32_t tag = 0;
	FILE *fp;
	char *value;
	char token[MAXLINESIZE];
	configured_readers = ll_create();

	snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_srvr);
	if (!(fp=fopen(token, "r"))) {
		cs_log("can't open file \"%s\" (errno=%d %s)\n", token, errno, strerror(errno));
		return(1);
	}
	struct s_reader *rdr;
	cs_malloc(&rdr, sizeof(struct s_reader), SIGINT);

	ll_append(configured_readers, rdr);
	while (fgets(token, sizeof(token), fp)) {
		int32_t i, l;
		if ((l = strlen(trim(token))) < 3)
			continue;
		if ((token[0] == '[') && (token[l-1] == ']')) {
			token[l-1] = 0;
			tag = (!strcmp("reader", strtolower(token+1)));
			if (rdr->label[0] && rdr->typ) {
				struct s_reader *newreader;
				if(cs_malloc(&newreader, sizeof(struct s_reader), -1)){
					ll_append(configured_readers, newreader);
					rdr = newreader;
				}
			}
			memset(rdr->hexserial, 0, sizeof(rdr->hexserial));
			memset(rdr->rom, 0, sizeof(rdr->rom));
			rdr->enable = 1;
			rdr->tcp_rto = DEFAULT_TCP_RECONNECT_TIMEOUT;
			rdr->show_cls = 10;
			rdr->nagra_read = 0;
			rdr->mhz = 357;
			rdr->cardmhz = 357;
			rdr->deprecated = 0;
			rdr->force_irdeto = 0;
#ifdef MODULE_CCCAM
			rdr->cc_reshare = DEFAULT_CC_RESHARE;
			rdr->cc_maxhop  = DEFAULT_CC_MAXHOP;
			rdr->cc_mindown = 0;
#endif
#ifdef WITH_LB
			rdr->lb_weight = 100;
#endif
			cs_strncpy(rdr->pincode, "none", sizeof(rdr->pincode));
			rdr->ndsversion = 0;
			rdr->ecmWhitelist = NULL;
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
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr))) { //build active readers list
		int32_t i;
		if (rdr->device[0] && (rdr->typ & R_IS_CASCADING)) {
			for (i=0; i<CS_MAX_MOD; i++) {
				if (ph[i].num && rdr->typ==ph[i].num) {
					rdr->ph=ph[i];
					rdr->ph.active=1;
				}
			}
		}
	}
	fclose(fp);
	return(0);
}

#ifdef CS_ANTICASC
void init_ac()
{
  int32_t nr;
  FILE *fp;
  char *saveptr1 = NULL;
  char token[MAXLINESIZE];

  snprintf(token, sizeof(token), "%s%s", cs_confdir, cs_ac);
  if (!(fp=fopen(token, "r")))
  {
    cs_log("can't open file \"%s\" (errno=%d %s) anti-cascading table not loaded",
            token, errno, strerror(errno));
    return;
  }
  
  struct s_cpmap *cur_cpmap, *first_cpmap = NULL, *last_cpmap = NULL;

  for(nr=0; fgets(token, sizeof(token), fp);)
  {
    int32_t i, skip;
    uint16_t caid, sid, chid, dwtime;
    uint32_t  provid;
    char *ptr, *ptr1;

    if( strlen(token)<4 ) continue;

    caid=sid=chid=dwtime=0;
    provid=0;
    skip=0;
    ptr1=0;
    for( i=0, ptr=strtok_r(token, "=", &saveptr1); (i<2)&&(ptr); ptr=strtok_r(NULL, "=", &saveptr1), i++ )
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
      for( i=0, ptr=strtok_r(ptr1, ":", &saveptr1); (i<4)&&(ptr); ptr=strtok_r(NULL, ":", &saveptr1), i++ )
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
      if (!cs_malloc(&cur_cpmap, sizeof(struct s_cpmap), -1)){
      	for(cur_cpmap = first_cpmap; cur_cpmap; cur_cpmap = cur_cpmap->next)
      		free(cur_cpmap);
      	return;
      }
      if(last_cpmap)
        last_cpmap->next=cur_cpmap;
      else
        first_cpmap=cur_cpmap;
      last_cpmap=cur_cpmap;

      cur_cpmap->caid   = caid;
      cur_cpmap->provid = provid;
      cur_cpmap->sid    = sid;
      cur_cpmap->chid   = chid;
      cur_cpmap->dwtime = dwtime;
      cur_cpmap->next   = 0;

      cs_debug_mask(D_CLIENT, "nr=%d, caid=%04X, provid=%06X, sid=%04X, chid=%04X, dwtime=%d",
                nr, caid, provid, sid, chid, dwtime);
      nr++;
    }
  }
  fclose(fp);
  
  last_cpmap = cfg.cpmap;
  cfg.cpmap = first_cpmap;
  for(cur_cpmap = last_cpmap; cur_cpmap; cur_cpmap = cur_cpmap->next)
    add_garbage(cur_cpmap);
  //cs_log("%d lengths for caid guessing loaded", nr);
  return;
}
#endif

/*
 * Creates a string ready to write as a token into config or WebIf for CAIDs. You must free the returned value through free_mk_t().
 */
char *mk_t_caidtab(CAIDTAB *ctab){
	int32_t i = 0, needed = 1, pos = 0;
	while(ctab->caid[i]){
		if(ctab->mask[i]) needed += 10;
		else needed += 5;
		if(ctab->cmap[i]) needed += 5;
		++i;
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed * sizeof(char), -1)) return "";
	char *saveptr = value;
	i = 0;
	while(ctab->caid[i]) {
	
		if (ctab->caid[i] < 0x0100) { //for "ignore provider for" option, caid-shortcut, just first 2 bytes:
			if(i == 0) {
				snprintf(value + pos, needed-(value-saveptr), "%02X", ctab->caid[i]);
				pos += 2;
			} else {
				snprintf(value + pos, needed-(value-saveptr), ",%02X", ctab->caid[i]);
				pos += 3;
			}
		} else {
			if(i == 0) {
				snprintf(value + pos, needed-(value-saveptr), "%04X", ctab->caid[i]);
				pos += 4;
			} else {
				snprintf(value + pos, needed-(value-saveptr), ",%04X", ctab->caid[i]);
				pos += 5;
			}
		}
		
		if((ctab->mask[i]) && (ctab->mask[i] != 0xFFFF)){
			snprintf(value + pos, needed-(value-saveptr), "&%04X", ctab->mask[i]);
			pos += 5;
		}
		if(ctab->cmap[i]){
			snprintf(value + pos, needed-(value-saveptr), ":%04X", ctab->cmap[i]);
			pos += 5;
		}
		++i;
	}
	value[pos] = '\0';
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for TunTabs. You must free the returned value through free_mk_t().
 */
char *mk_t_tuntab(TUNTAB *ttab){
	int32_t i, needed = 1, pos = 0;
	for (i=0; i<ttab->n; i++) {
		if(ttab->bt_srvid[i]) needed += 10;
		else needed += 5;
		if(ttab->bt_caidto[i]) needed += 5;
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed * sizeof(char), -1)) return "";
	char *saveptr = value;
	for (i=0; i<ttab->n; i++) {
		if(i == 0) {
			snprintf(value + pos, needed-(value-saveptr), "%04X", ttab->bt_caidfrom[i]);
			pos += 4;
		} else {
			snprintf(value + pos, needed-(value-saveptr), ",%04X", ttab->bt_caidfrom[i]);
			pos += 5;
		}
		if(ttab->bt_srvid[i]){
			snprintf(value + pos, needed-(value-saveptr), ".%04X", ttab->bt_srvid[i]);
			pos += 5;
		}
		if(ttab->bt_caidto[i]){
			snprintf(value + pos, needed-(value-saveptr), ":%04X", ttab->bt_caidto[i]);
			pos += 5;
		}
	}
	value[pos] = '\0';
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for groups. You must free the returned value through free_mk_t().
 */
char *mk_t_group(uint64_t grp){
	int32_t i = 0, needed = 1, pos = 0, dot = 0;

	for(i = 0; i < 64; i++){
		if (grp&((uint64_t)1<<i)){
			needed += 2;
			if(i > 9) needed += 1;
		}
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed * sizeof(char), -1)) return "";
	char * saveptr = value;
	for(i = 0; i < 64; i++){
		if (grp&((uint64_t)1<<i)){
			if (dot == 0){
				snprintf(value + pos, needed-(value-saveptr), "%d", i+1);
				if (i > 8)pos += 2;
				else pos += 1;
				dot = 1;
			} else {
				snprintf(value + pos, needed-(value-saveptr), ",%d", i+1);
				if (i > 8)pos += 3;
				else pos += 2;
			}
		}
	}
	value[pos] = '\0';
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for FTabs (CHID, Ident). You must free the returned value through free_mk_t().
 */
char *mk_t_ftab(FTAB *ftab){
	int32_t i = 0, j = 0, needed = 1, pos = 0;

	if (ftab->nfilts != 0) {
		needed = ftab->nfilts * 5;
		for (i = 0; i < ftab->nfilts; ++i)
			needed += ftab->filts[i].nprids * 7;
	}

	char *value;
	if(needed == 1 || !cs_malloc(&value, needed * sizeof(char), -1)) return "";
	char *saveptr = value;
	char *dot="";
	for (i = 0; i < ftab->nfilts; ++i){
		snprintf(value + pos, needed-(value-saveptr), "%s%04X", dot, ftab->filts[i].caid);
		pos += 4;
		if (i > 0) pos += 1;
		dot=":";
		for (j = 0; j < ftab->filts[i].nprids; ++j) {
			snprintf(value + pos, needed-(value-saveptr), "%s%06X", dot, ftab->filts[i].prids[j]);
			pos += 7;
			dot=",";
		}
		dot=";";
	}

	value[pos] = '\0';
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the camd35 tcp ports. You must free the returned value through free_mk_t().
 */
char *mk_t_camd35tcp_port(){
	int32_t i, j, pos = 0, needed = 1;

	/* Precheck to determine how long the resulting string will maximally be (might be a little bit smaller but that shouldn't hurt) */
	for(i = 0; i < cfg.c35_tcp_ptab.nports; ++i) {
		/* Port is maximally 5 chars long, plus the @caid, plus the ";" between ports */
		needed += 11;
		if (cfg.c35_tcp_ptab.ports[i].ftab.filts[0].nprids > 1){
			needed += cfg.c35_tcp_ptab.ports[i].ftab.filts[0].nprids * 7;
		}
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed * sizeof(char), -1)) return "";
	char *saveptr = value;
	char *dot1 = "", *dot2;
	for(i = 0; i < cfg.c35_tcp_ptab.nports; ++i) {

		if (cfg.c35_tcp_ptab.ports[i].ftab.filts[0].caid){
			pos += snprintf(value + pos, needed-(value-saveptr), "%s%d@%04X", dot1,
					cfg.c35_tcp_ptab.ports[i].s_port,
					cfg.c35_tcp_ptab.ports[i].ftab.filts[0].caid);

			if (cfg.c35_tcp_ptab.ports[i].ftab.filts[0].nprids > 1) {
				dot2 = ":";
				for (j = 0; j < cfg.c35_tcp_ptab.ports[i].ftab.filts[0].nprids; ++j) {
					pos += snprintf(value + pos, needed-(value-saveptr), "%s%X", dot2, cfg.c35_tcp_ptab.ports[i].ftab.filts[0].prids[j]);
					dot2 = ",";
				}
			}
			dot1=";";
		} else {
			pos += snprintf(value + pos, needed-(value-saveptr), "%d", cfg.c35_tcp_ptab.ports[i].s_port);
		}
	}
	return value;
}

#ifdef MODULE_CCCAM
/*
 * Creates a string ready to write as a token into config or WebIf for the cccam tcp ports. You must free the returned value through free_mk_t().
 */
char *mk_t_cccam_port(){
	int32_t i, pos = 0, needed = CS_MAXPORTS*6+8;

	char *value;
	if(!cs_malloc(&value, needed * sizeof(char), -1)) return "";
	char *dot = "";
	for(i = 0; i < CS_MAXPORTS; i++) {
		if (!cfg.cc_port[i]) break;

		pos += snprintf(value + pos, needed-pos, "%s%d", dot, cfg.cc_port[i]);
		dot=",";
	}
	return value;
}
#endif


/*
 * Creates a string ready to write as a token into config or WebIf for AESKeys. You must free the returned value through free_mk_t().
 */
char *mk_t_aeskeys(struct s_reader *rdr){
	AES_ENTRY *current = rdr->aes_list;
	int32_t i, pos = 0, needed = 1, prevKeyid = 0, prevCaid = 0;
	uint32_t prevIdent = 0;

	/* Precheck for the approximate size that we will need; it's a bit overestimated but we correct that at the end of the function */
	while(current) {
		/* The caid, ident, "@" and the trailing ";" need to be output when they are changing */
		if(prevCaid != current->caid || prevIdent != current->ident) needed += 12 + (current->keyid * 2);
		/* "0" keys are not saved so we need to check for gaps */
		else if(prevKeyid != current->keyid + 1) needed += (current->keyid - prevKeyid - 1) * 2;
		/* The 32 byte key plus either the (heading) ":" or "," */
		needed += 33;
		prevCaid = current->caid;
		prevIdent = current->ident;
		prevKeyid = current->keyid;
		current = current->next;
	}

	/* Set everything back and now create the string */
	current = rdr->aes_list;
	prevCaid = 0;
	prevIdent = 0;
	prevKeyid = 0;
	char tmp[needed];
	char dot;
	if(needed == 1) tmp[0] = '\0';
	char tmpkey[33];
	while(current) {
		/* A change in the ident or caid means that we need to output caid and ident */
		if(prevCaid != current->caid || prevIdent != current->ident){
			if(pos > 0) {
				tmp[pos] = ';';
				++pos;
			}
			pos += snprintf(tmp+pos, sizeof(tmp)-pos, "%04X@%06X", current->caid, current->ident);
			prevKeyid = -1;
			dot = ':';
		} else dot = ',';
		/* "0" keys are not saved so we need to check for gaps and output them! */
		for (i = prevKeyid + 1; i < current->keyid; ++i) {
			pos += snprintf(tmp+pos, sizeof(tmp)-pos, "%c0", dot);
			dot = ',';
		}
		tmp[pos] = dot;
		++pos;
		for (i = 0; i < 16; ++i) snprintf(tmpkey + (i*2), sizeof(tmpkey) - (i*2), "%02X", current->plainkey[i]);
		/* A key consisting of only FFs has a special meaning (just return what the card outputted) and can be specified more compact */
		if(strcmp(tmpkey, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0) pos += snprintf(tmp+pos, sizeof(tmp)-pos, "FF");
		else pos += snprintf(tmp+pos, sizeof(tmp)-pos, "%s", tmpkey);
		prevCaid = current->caid;
		prevIdent = current->ident;
		prevKeyid = current->keyid;
		current = current->next;
	}

	/* copy to result array of correct size */
	char *value;
	if(pos == 0 || !cs_malloc(&value, (pos + 1) * sizeof(char), -1)) return "";
	memcpy(value, tmp, pos + 1);
	return(value);
}

/*
 * Creates a string ready to write as a token into config or WebIf for the Newcamd Port. You must free the returned value through free_mk_t().
 */
char *mk_t_newcamd_port(){
	int32_t i, j, k, pos = 0, needed = 1;

	/* Precheck to determine how long the resulting string will maximally be (might be a little bit smaller but that shouldn't hurt) */
	for(i = 0; i < cfg.ncd_ptab.nports; ++i){
		/* Port is maximally 5 chars long, plus the @caid, plus the ";" between ports */
		needed += 11;
		if(cfg.ncd_ptab.ports[i].ncd_key_is_set) needed += 30;
		if (cfg.ncd_ptab.ports[i].ftab.filts[0].nprids > 0){
			needed += cfg.ncd_ptab.ports[i].ftab.filts[0].nprids * 7;
		}
	}
	char *value;
	if(needed == 1 || !cs_malloc(&value, needed * sizeof(char), -1)) return "";
	char *dot1 = "", *dot2;

	for(i = 0; i < cfg.ncd_ptab.nports; ++i){
		pos += snprintf(value + pos, needed-pos,  "%s%d", dot1, cfg.ncd_ptab.ports[i].s_port);

		// separate DES Key for this port
		if(cfg.ncd_ptab.ports[i].ncd_key_is_set){
			pos += snprintf(value + pos, needed-pos, "{");
			for (k = 0; k < 14; k++)
				pos += snprintf(value + pos, needed-pos, "%02X", cfg.ncd_ptab.ports[i].ncd_key[k]);
			pos += snprintf(value + pos, needed-pos, "}");
		}

		pos += snprintf(value + pos, needed-pos, "@%04X", cfg.ncd_ptab.ports[i].ftab.filts[0].caid);

		if (cfg.ncd_ptab.ports[i].ftab.filts[0].nprids > 0){
			dot2 = ":";
			for (j = 0; j < cfg.ncd_ptab.ports[i].ftab.filts[0].nprids; ++j){
				pos += snprintf(value + pos, needed-pos, "%s%06X", dot2, (int)cfg.ncd_ptab.ports[i].ftab.filts[0].prids[j]);
				dot2 = ",";
			}
		}
		dot1=";";
	}
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for au readers. You must free the returned value through free_mk_t().
 */
char *mk_t_aureader(struct s_auth *account){
	int32_t pos = 0;
	char *dot = "";

	char *value;
	if(ll_count(account->aureader_list) == 0 || !cs_malloc(&value, 256 * sizeof(char), -1)) return "";
	value[0] = '\0';

	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(account->aureader_list);
	while ((rdr = ll_iter_next(&itr))) {
		pos += snprintf(value + pos, 256-pos, "%s%s", dot, rdr->label);
		dot = ",";
	}

	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for blocknano and savenano. You must free the returned value through free_mk_t().
 * flag 0x01 for blocknano or 0x02 for savenano
 */
char *mk_t_nano(struct s_reader *rdr, uchar flag){
	int32_t i, pos = 0, needed = 0;
	uint16_t nano = 0;

	if (flag==0x01)
		nano=rdr->b_nano;
	else
		nano=rdr->s_nano;

	for (i=0; i<16; i++)
		if ((1 << i) & nano)
			needed++;

	char *value;
	if (nano == 0xFFFF) {
		if(!cs_malloc(&value, (3 * sizeof(char)) + 1, -1)) return "";
		snprintf(value, 4, "all");
	} else {
		if(needed == 0 || !cs_malloc(&value, (needed * 3 * sizeof(char)) + 1, -1)) return "";
		value[0] = '\0';
		for (i=0; i<16; i++) {
			if ((1 << i) & nano)
				pos += snprintf(value + pos, (needed*3)+1-pos, "%s%02x", pos ? "," : "", (i+0x80));
		}
	}
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the sidtab. You must free the returned value through free_mk_t().
 */
char *mk_t_service( uint64_t sidtabok, uint64_t sidtabno){
	int32_t i, pos;
	char *dot;
	char *value;
	struct s_sidtab *sidtab = cfg.sidtab;
	if(!sidtab || (!sidtabok && !sidtabno) || !cs_malloc(&value, 1024, -1)) return "";
	value[0] = '\0';

	for (i=pos=0,dot=""; sidtab; sidtab=sidtab->next,i++){
		if (sidtabok&((SIDTABBITS)1<<i)) {
			pos += snprintf(value + pos, 1024 - pos, "%s%s", dot, sidtab->label);
			dot = ",";
		}
		if (sidtabno&((SIDTABBITS)1<<i)) {
			pos += snprintf(value + pos, 1024 - pos, "%s!%s", dot, sidtab->label);
			dot = ",";
		}
	}
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the logfile parameter. You must free the returned value through free_mk_t().
 */
char *mk_t_logfile(){
	int32_t pos = 0, needed = 1;
	char *value, *dot = "";

	if(cfg.logtostdout == 1) needed += 7;
	if(cfg.logtosyslog == 1) needed += 7;
	if(cfg.logfile != NULL) needed += strlen(cfg.logfile);
	if(needed == 1 || !cs_malloc(&value, needed * sizeof(char), -1)) return "";

	if(cfg.logtostdout == 1){
		pos += snprintf(value + pos, needed - pos, "stdout");
		dot = ";";
	}
	if(cfg.logtosyslog == 1){
		pos += snprintf(value + pos, needed - pos, "%ssyslog", dot);
		dot = ";";
	}
	if(cfg.logfile != NULL){
		pos += snprintf(value + pos, needed - pos, "%s%s", dot, cfg.logfile);
	}
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the ecm whitelist. You must free the returned value through free_mk_t().
 */
char *mk_t_ecmwhitelist(struct s_ecmWhitelist *whitelist){
	int32_t needed = 1, pos = 0;
	struct s_ecmWhitelist *cip;
	struct s_ecmWhitelistIdent *cip2;
	struct s_ecmWhitelistLen *cip3;
	char *value, *dot = "", *dot2 = "";
	for (cip = whitelist; cip; cip = cip->next){
		needed += 7;
		for (cip2 = cip->idents; cip2; cip2 = cip2->next){
			needed +=7;
			for (cip3 = cip2->lengths; cip3; cip3 = cip3->next) needed +=3;
		}
	}

	char tmp[needed];

	for (cip = whitelist; cip; cip = cip->next){
		for (cip2 = cip->idents; cip2; cip2 = cip2->next){
			if(cip2->lengths != NULL){
				if(cip->caid != 0){
					if(cip2->ident == 0)
						pos += snprintf(tmp + pos, needed - pos, "%s%04X:", dot, cip->caid);
					else
						pos += snprintf(tmp + pos, needed - pos, "%s%04X@%06X:", dot, cip->caid, cip2->ident);
				} else pos += snprintf(tmp + pos, needed - pos, "%s", dot);
			}
			dot2="";
			for (cip3 = cip2->lengths; cip3; cip3 = cip3->next){
				pos += snprintf(tmp + pos, needed - pos, "%s%02X", dot2, cip3->len);
				dot2=",";
			}
			dot=";";
		}
	}
	if(pos == 0 || !cs_malloc(&value, (pos + 1) * sizeof(char), -1)) return "";
	memcpy(value, tmp, pos + 1);
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for an iprange. You must free the returned value through free_mk_t().
 */
char *mk_t_iprange(struct s_ip *range){
	struct s_ip *cip;
	char *value, *dot = "";
	int32_t needed = 1, pos = 0;
	for (cip = range; cip; cip = cip->next) needed += 32;

	char tmp[needed];

	for (cip = range; cip; cip = cip->next){
		pos += snprintf(tmp + pos, needed - pos, "%s%s", dot, cs_inet_ntoa(cip->ip[0]));
		if (cip->ip[0] != cip->ip[1])	pos += snprintf(tmp + pos, needed - pos, "-%s", cs_inet_ntoa(cip->ip[1]));
		dot=",";
	}
	if(pos == 0 || !cs_malloc(&value, (pos + 1) * sizeof(char), -1)) return "";
	memcpy(value, tmp, pos + 1);
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf for the class attribute. You must free the returned value through free_mk_t().
 */
char *mk_t_cltab(CLASSTAB *clstab){
	char *value, *dot = "";
	int32_t i, needed = 1, pos = 0;
	for(i = 0; i < clstab->an; ++i) needed += 3;
	for(i = 0; i < clstab->bn; ++i) needed += 4;

	char tmp[needed];

	for(i = 0; i < clstab->an; ++i) {
		pos += snprintf(tmp + pos, needed - pos, "%s%02x", dot, (int32_t)clstab->aclass[i]);
		dot=",";
	}
	for(i = 0; i < clstab->bn; ++i) {
		pos += snprintf(tmp + pos, needed - pos, "%s!%02x", dot, (int32_t)clstab->bclass[i]);
		dot=",";
	}

	if(pos == 0 || !cs_malloc(&value, (pos + 1) * sizeof(char), -1)) return "";
	memcpy(value, tmp, pos + 1);
	return value;
}

/*
 * Creates a string ready to write as a token into config or WebIf. You must free the returned value through free_mk_t().
 */
char *mk_t_caidvaluetab(CAIDVALUETAB *tab)
{
		if (!tab->n) return "";
		int32_t i, size = 2 + tab->n * (4 + 1 + 5 + 1); //caid + ":" + time + ","
		char *buf = cs_malloc(&buf, size, SIGINT);
		char *ptr = buf;

		for (i = 0; i < tab->n; i++) {
			if (tab->caid[i] < 0x0100) //Do not format 0D as 000D, its a shortcut for 0Dxx:
				ptr += snprintf(ptr, size-(ptr-buf), "%s%02X:%d", i?",":"", tab->caid[i], tab->value[i]);
			else
				ptr += snprintf(ptr, size-(ptr-buf), "%s%04X:%d", i?",":"", tab->caid[i], tab->value[i]);
		}
		*ptr = 0;
		return buf;
}

/*
 * returns string of comma separated values
 */
char *mk_t_emmbylen(struct s_reader *rdr) {

	char *value, *dot = "";
	int32_t pos = 0, needed = 0;
	int8_t i;

	needed = (CS_MAXEMMBLOCKBYLEN * 4) +1;

	if (!cs_malloc(&value, needed, -1)) return "";

	for( i = 0; i < CS_MAXEMMBLOCKBYLEN; i++ ) {
		if(rdr->blockemmbylen[i] != 0) {
			pos += snprintf(value + pos, needed, "%s%d", dot, rdr->blockemmbylen[i]);
			dot = ",";
		}
	}
	return value;
}

/*
 * makes string from binary structure
 */
char *mk_t_allowedprotocols(struct s_auth *account) {

	if (!account->allowedprotocols)
		return "";

	int16_t i, tmp = 1, pos = 0, needed = 255, tagcnt;
	char *tag[] = {"camd33", "camd35", "cs378x", "newcamd", "cccam", "gbox", "radegast", "dvbapi", "constcw", "serial"};
	char *value, *dot = "";

	if (!cs_malloc(&value, needed, -1))
		return "";

	tagcnt = sizeof(tag)/sizeof(char *);
	for (i = 0; i < tagcnt; i++) {
		if ((account->allowedprotocols & tmp) == tmp) {
			pos += snprintf(value + pos, needed, "%s%s", dot, tag[i]);
			dot = ",";
		}
		tmp = tmp << 1;
	}
	return value;
}

/*
 * mk_t-functions give back a constant empty string when allocation fails or when the result is an empty string.
 * This function thus checks the stringlength and only frees if necessary.
 */
void free_mk_t(char *value){
	if(strlen(value) > 0) free(value);
}
