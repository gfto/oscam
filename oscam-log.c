#include "globals.h"
#include <syslog.h>
#include <stdlib.h>

char *LOG_LIST = "log_list";

static FILE *fp=(FILE *)0;
static FILE *fps=(FILE *)0;
#ifdef CS_ANTICASC
static FILE *fpa=(FILE *)0;
#endif
static int8_t logStarted = 0;
static int8_t logThreadRunning = 0;
LLIST *log_list;
char *vbuf;

struct s_log {
	char *txt;
	int8_t header_len;
	int8_t direct_log;
	int8_t cl_typ;
	char *cl_usr;
	char *cl_text;
};

#if defined(WEBIF) || defined(MODULE_MONITOR)
CS_MUTEX_LOCK loghistory_lock;
#endif

#define LOG_BUF_SIZE 512

static void switch_log(char* file, FILE **f, int32_t (*pfinit)(void))
{
	if(cfg.max_log_size && file)	//only 1 thread needs to switch the log; even if anticasc, statistics and normal log are running
					//at the same time, it is ok to have the other logs switching 1 entry later
	{
		if(*f != NULL && ftell(*f) >= cfg.max_log_size*1024) {
			int32_t rc;
			char prev_log[strlen(file) + 6];
			snprintf(prev_log, sizeof(prev_log), "%s-prev", file);
			fprintf(*f, "switch log file\n");
			fflush(*f);
			fclose(*f);
			*f = (FILE *)0;
			rc = rename(file, prev_log);
			if( rc!=0 ) {
				fprintf(stderr, "rename(%s, %s) failed (errno=%d %s)\n", file, prev_log, errno, strerror(errno));
			}
			else
				if( pfinit()){
					fprintf(stderr, "Initialisation of log file failed, continuing without logging thread %8X. Log will be output to stdout!", (unsigned int)pthread_self());
					cfg.logtostdout = 1;
				}
		}
	}
}

static void cs_write_log(char *txt, int8_t do_flush)
{
	// filter out entries with leading 's' and forward to statistics
	if(txt[0] == 's') {
		if (fps) {
			switch_log(cfg.usrfile, &fps, cs_init_statistics);
			if (fps) {
					fputs(txt + 1, fps); // remove the leading 's' and write to file
					if (do_flush) fflush(fps);
			}
		}
	} else {
		if(!cfg.disablelog){
			if (fp){
				switch_log(cfg.logfile, &fp, cs_open_logfiles);		// only call the switch code if lock = 1 is specified as otherwise we are calling it internally
				if (fp) {
						fputs(txt, fp);
						if (do_flush) fflush(fp);
				}
			}
			if(cfg.logtostdout){
				fputs(txt+11, stdout);
				if (do_flush) fflush(stdout);
			}
		}
	}
}

static void cs_write_log_int(char *txt)
{
	if(exit_oscam == 1) {
		cs_write_log(txt, 1);
	} else {
		struct s_log * log = cs_malloc(&log, sizeof(struct s_log), 0);
		log->txt = strnew(txt);
		log->header_len = 0;
		log->direct_log = 1;
		ll_append(log_list, log);
	}
}

int32_t cs_open_logfiles(void)
{
	char *starttext;
	if(logStarted) starttext = "log switched";
	else starttext = "started";
	if (!fp && cfg.logfile) {	//log to file
		if ((fp = fopen(cfg.logfile, "a+")) <= (FILE *)0) {
			fp = (FILE *)0;
			fprintf(stderr, "couldn't open logfile: %s (errno %d %s)\n", cfg.logfile, errno, strerror(errno));
		} else {
			setvbuf(fp, NULL, _IOFBF, 8*1024);
			time_t t;
			char line[80];
			memset(line, '-', sizeof(line));
			line[(sizeof(line)/sizeof(char)) - 1] = '\0';
			time(&t);
			if (!cfg.disablelog){
				char buf[28];
				cs_ctime_r(&t, buf);
				fprintf(fp, "\n%s\n>> OSCam <<  cardserver %s at %s%s\n", line, starttext, buf, line);
			}
		}
	}
	// according to syslog docu: calling closelog is not necessary and calling openlog multiple times is safe
	// We use openlog to set the default syslog settings so that it's possible to allow switching syslog on and off
	openlog("oscam", LOG_NDELAY, LOG_DAEMON);

	cs_log_nolock(">> OSCam <<  cardserver %s, version " CS_VERSION ", build #" CS_SVN_VERSION " (" CS_TARGET ")", starttext);
	cs_log_config();
	return(fp <= (FILE *)0);
}

#ifdef CS_ANTICASC
int32_t ac_init_log(void){
	FILE *tmp = fpa;
	fpa=(FILE *)0;
	if(tmp)
		fclose(tmp);

	if(cfg.ac_logfile[0]) {
		if( (fpa=fopen(cfg.ac_logfile, "a+"))<=(FILE *)0 ) {
			fpa=(FILE *)0;
			fprintf(stderr, "can't open anti-cascading logfile: %s\n", cfg.ac_logfile);
		} else
			cs_log("anti-cascading log initialized");
	}

	return(fpa<=(FILE *)0);
}
#endif

#if defined(WEBIF) || defined(MODULE_MONITOR)
/*
 This function allows to reinit the in-memory loghistory with a new size.
*/
void cs_reinit_loghist(uint32_t size)
{
	char *tmp = NULL, *tmp2;
	if(size != cfg.loghistorysize){
		if(size == 0 || cs_malloc(&tmp, size, -1)){
			cs_writelock(&loghistory_lock);
			tmp2 = loghist;
			// On shrinking, the log is not copied and the order is reversed
			if(size < cfg.loghistorysize){
				cfg.loghistorysize = size;
				cs_sleepms(20);	// Monitor or webif may be currently outputting the loghistory but don't use locking so we sleep a bit...
				loghistptr = tmp;
				loghist = tmp;
			} else {
				if(loghist){
					memcpy(tmp, loghist, cfg.loghistorysize);
					loghistptr = tmp + (loghistptr - loghist);
				} else loghistptr = tmp;
				loghist = tmp;
				cs_sleepms(20);	// Monitor or webif may be currently outputting the loghistory but don't use locking so we sleep a bit...
				cfg.loghistorysize = size;
			}
			cs_writeunlock(&loghistory_lock);
			if(tmp2 != NULL) add_garbage(tmp2);
		}
	}
}
#endif

static int32_t get_log_header(int32_t m, char *txt)
{
	struct s_client *cl = cur_client();
	time_t t;
	struct tm lt;
	int32_t pos;

	time(&t);
	localtime_r(&t, &lt);

	pos = snprintf(txt, LOG_BUF_SIZE,  "[LOG000]%4d/%02d/%02d %02d:%02d:%02d ", lt.tm_year+1900, lt.tm_mon+1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec);

	if(m)
		return pos + snprintf(txt+pos, LOG_BUF_SIZE-pos, "%8X %c ", cl?cl->tid:0, cl?cl->typ:' ');
	else
		return pos + snprintf(txt+pos, LOG_BUF_SIZE-pos, "%8X%-3.3s ", cl?cl->tid:0, "");
}

static void write_to_log(char *txt, struct s_log *log, int8_t do_flush)
{
	char sbuf[16];

#ifdef CS_ANTICASC
	if (!strncmp(txt + log->header_len, "acasc:", 6)) {
		strcat(txt, "\n");
		switch_log(cfg.ac_logfile, &fpa, ac_init_log);
		if (fpa) {
			fputs(txt + 8, fpa);
			if (do_flush) fflush(fpa);
		}
	} else
#endif
	{
		if (cfg.logtosyslog)
			syslog(LOG_INFO, "%s", txt+24);
		strcat(txt, "\n");
	}
	cs_write_log(txt + 8, do_flush);

#if defined(WEBIF) || defined(MODULE_MONITOR)
	if (loghist && exit_oscam != 1) {
		char *usrtxt = log->cl_text;
		char *target_ptr = NULL;
		int32_t target_len = strlen(usrtxt) + (strlen(txt) - 8) + 1;

		cs_writelock(&loghistory_lock);
		char *lastpos = loghist + (cfg.loghistorysize) - 1;
		if(loghist + target_len + 1 >= lastpos){
			strncpy(txt + 39, "Log entry too long!", strlen(txt) - 39);	// we can assume that the min loghistorysize is always 1024 so we don't need to check if this new string fits into it!
			target_len = strlen(usrtxt) + (strlen(txt) - 8) + 1;
		}
		if (!loghistptr)
			loghistptr = loghist;

		if (loghistptr + target_len + 1 > lastpos) {
			*loghistptr='\0';
			loghistptr=loghist + target_len + 1;
			*loghistptr='\0';
			target_ptr=loghist;
		} else {
			target_ptr = loghistptr;
			loghistptr=loghistptr + target_len + 1;
			*loghistptr='\0';
		}
		cs_writeunlock(&loghistory_lock);

		snprintf(target_ptr, target_len + 1, "%s\t%s", usrtxt, txt + 8);
	}
#endif

	struct s_client *cl;
	for (cl=first_client; cl ; cl=cl->next) {
		if ((cl->typ == 'm') && (cl->monlvl>0) && cl->log) //this variable is only initialized for cl->typ = 'm'
		{
			if (cl->monlvl<2) {
				if (log->cl_typ != 'c' && log->cl_typ != 'm')
					continue;
				if (log->cl_usr && cl->account && strcmp(log->cl_usr, cl->account->usr))
					continue;
			}
			snprintf(sbuf, sizeof(sbuf), "%03d", cl->logcounter);
			cl->logcounter = (cl->logcounter+1) % 1000;
			memcpy(txt + 4, sbuf, 3);
#ifdef MODULE_MONITOR
			monitor_send_idx(cl, txt);
#endif
		}
	}
}

static void write_to_log_int(char *txt, int8_t header_len)
{
#if !defined(WEBIF) && !defined(MODULE_MONITOR)
	if (cfg.disablelog) return;
#endif

	struct s_log *log = cs_malloc(&log, sizeof(struct s_log), 0);
	log->txt = strnew(txt);
	log->header_len = header_len;
	log->direct_log = 0;
	struct s_client *cl = cur_client();
	log->cl_usr = "";
	if (!cl){
		log->cl_text = "undef";
		log->cl_typ = ' ';
	} else {
		switch(cl->typ) {
			case 'c':
			case 'm':
				if(cl->account) {
					log->cl_text = cl->account->usr;
					log->cl_usr = cl->account->usr;
				} else log->cl_text = "";
				break;
			case 'p':
			case 'r':
				log->cl_text = cl->reader ? cl->reader->label : "";
				break;
			default:
				log->cl_text = "server";
				break;
		}
		log->cl_typ = cl->typ;
	}

	if(exit_oscam == 1 || cfg.disablelog){ //Exit or log disabled. if disabled, just display on webif/monitor
		char buf[LOG_BUF_SIZE];
		cs_strncpy(buf, log->txt, LOG_BUF_SIZE);
		write_to_log(buf, log, 1);
		free(log->txt);
		free(log);
	} else
		ll_append(log_list, log);
}

void cs_log_int(uint16_t mask, int8_t lock __attribute__((unused)), const uchar *buf, int32_t n, const char *fmt, ...)
{
	va_list params;

	char log_txt[LOG_BUF_SIZE];
	int32_t i, len = 0;
	if (((mask & cs_dblevel) || !mask) && (fmt))
	{
		va_start(params, fmt);
		len = get_log_header(1, log_txt);
		vsnprintf(log_txt + len, sizeof(log_txt) - len, fmt, params);
		write_to_log_int(log_txt, len);
		va_end(params);
	}
	if (buf && ((mask & cs_dblevel) || !mask))
	{
		for (i=0; i<n; i+=16)
		{
			len = get_log_header(0, log_txt);
			cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i, log_txt + len, sizeof(log_txt) - len);
			write_to_log_int(log_txt, len);
		}
	}
}

void cs_close_log(void)
{
	if (!fp) return;

	//Wait for log close:
	int8_t i = 2;
	while (ll_count(log_list) > 0 && i) {
		cs_sleepms(500);
		i--;
	}

	fclose(fp);
	fp=(FILE *)0;
}

void log_emm_request(struct s_reader *rdr){
	cs_log("%s emm-request sent (reader=%s, caid=%04X, auprovid=%06X)",
			username(cur_client()), rdr->label, rdr->caid,
			rdr->auprovid ? rdr->auprovid : b2i(4, rdr->prid[0]));
}

/*
 * This function writes the current CW from ECM struct to a cwl file.
 * The filename is re-calculated and file re-opened every time.
 * This will consume a bit cpu time, but nothing has to be stored between
 * each call. If not file exists, a header is prepended
 */
void logCWtoFile(ECM_REQUEST *er, uchar *cw){
	FILE *pfCWL;
	char srvname[128];
	/* %s / %s   _I  %04X  _  %s  .cwl  */
	char buf[256 + sizeof(srvname)];
	char date[9];
	unsigned char  i, parity, writeheader = 0;
	time_t t;
	struct tm timeinfo;

	/*
	* search service name for that id and change characters
	* causing problems in file name
	*/

	get_servicename(cur_client(), er->srvid, er->caid, srvname);

	for (i = 0; srvname[i]; i++)
		if (srvname[i] == ' ') srvname[i] = '_';

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
			for the moment do not print32_t to log on every ecm
			cs_log(""error opening cw logfile for writing: %s (errno=%d %s)", buf, errno, strerror(errno)); */
		return;
	}
	if (writeheader) {
		/* no global macro for cardserver name :( */
		fprintf(pfCWL, "# OSCam cardserver v%s - http://streamboard.gmc.to/oscam/\n", CS_VERSION);
		fprintf(pfCWL, "# control word log file for use with tsdec offline decrypter\n");
		strftime(buf, sizeof(buf),"DATE %Y-%m-%d, TIME %H:%M:%S, TZ %Z\n", &timeinfo);
		fprintf(pfCWL, "# %s", buf);
		fprintf(pfCWL, "# CAID 0x%04X, SID 0x%04X, SERVICE \"%s\"\n", er->caid, er->srvid, srvname);
	}

	parity = er->ecm[0]&1;
	fprintf(pfCWL, "%d ", parity);
	for (i = parity * 8; i < 8 + parity * 8; i++)
		fprintf(pfCWL, "%02X ", cw[i]);
	/* better use incoming time er->tps rather than current time? */
	strftime(buf,sizeof(buf),"%H:%M:%S\n", &timeinfo);
	fprintf(pfCWL, "# %s", buf);
	fflush(pfCWL);
	fclose(pfCWL);
}

void cs_log_config(void)
{
  uchar buf[20];

  if (cfg.nice!=99)
    snprintf((char *)buf, sizeof(buf), ", nice=%d", cfg.nice);
  else
    buf[0]='\0';
  cs_log_nolock("version=%s, build #%s, system=%s%s", CS_VERSION, CS_SVN_VERSION, CS_TARGET, buf);
  cs_log_nolock("client max. idle=%d sec, debug level=%d, filter_sensitive=%d", cfg.cmaxidle, cs_dblevel, log_remove_sensitive);

  if( cfg.max_log_size )
    snprintf((char *)buf, sizeof(buf), "%d Kb", cfg.max_log_size);
  else
    cs_strncpy((char *)buf, "unlimited", sizeof(buf));
#if defined(WEBIF) || defined(MODULE_MONITOR)
  cs_log_nolock("max. logsize=%s, loghistorysize=%d bytes", buf, cfg.loghistorysize);
#else
	cs_log_nolock("max. logsize=%s bytes", buf);
#endif
  cs_log_nolock("client timeout=%u ms, fallback timeout=%u ms, cache delay=%d ms",
         cfg.ctimeout, cfg.ftimeout, cfg.delay);
}

int32_t cs_init_statistics(void)
{
	if ((!fps) && (cfg.usrfile != NULL))
	{
		if ((fps=fopen(cfg.usrfile, "a+"))<=(FILE *)0)
		{
			fps=(FILE *)0;
			cs_log("couldn't open statistics file: %s", cfg.usrfile);
		}
	}
	return(fps<=(FILE *)0);
}

void cs_statistics(struct s_client * client)
{
	if (!cfg.disableuserfile){
		time_t t;
		struct tm lt;
		char buf[LOG_BUF_SIZE];

		float cwps;

		time(&t);
		localtime_r(&t, &lt);
		if (client->cwfound+client->cwnot>0)
		{
			cwps=client->last-client->login;
			cwps/=client->cwfound+client->cwnot;
		}
		else
			cwps=0;

		char channame[32];
		if(cfg.mon_appendchaninfo)
			get_servicename(client, client->last_srvid,client->last_caid, channame);
		else
			channame[0] = '\0';

		int32_t lsec;
		if ((client->last_caid == 0xFFFF) && (client->last_srvid == 0xFFFF))
			lsec = client->last - client->login; //client leave calc total duration
		else
			lsec = client->last - client->lastswitch;

		int32_t secs = 0, fullmins = 0, mins = 0, fullhours = 0;

		if((lsec > 0) && (lsec < 1000000)) {
			secs = lsec % 60;
			if (lsec > 60) {
				fullmins = lsec / 60;
				mins = fullmins % 60;
				if(fullmins > 60) {
					fullhours = fullmins / 60;
				}
			}
		}

		/* statistics entry start with 's' to filter it out on other end of pipe
		 * so we can use the same Pipe as Log
		 */
		snprintf(buf, sizeof(buf), "s%02d.%02d.%02d %02d:%02d:%02d %3.1f %s %s %d %d %d %d %d %d %d %ld %ld %02d:%02d:%02d %s %04X:%04X %s\n",
				lt.tm_mday, lt.tm_mon+1, lt.tm_year%100,
				lt.tm_hour, lt.tm_min, lt.tm_sec, cwps,
				client->account->usr,
				cs_inet_ntoa(client->ip),
				client->port,
				client->cwfound,
				client->cwcache,
				client->cwnot,
				client->cwignored,
				client->cwtout,
				client->cwtun,
				client->login,
				client->last,
				fullhours, mins, secs,
				ph[client->ctyp].desc,
				client->last_caid,
				client->last_srvid,
				channame);

		cs_write_log_int(buf);
	}
}

void log_list_thread(void)
{
	char buf[LOG_BUF_SIZE];
	logThreadRunning = 1;
	int last_count=ll_count(log_list), count, grow_count=0, write_count;
	do {
		LL_ITER it = ll_iter_create(log_list);
		struct s_log *log;
		write_count = 0;
		while ((log=ll_iter_next_remove(&it))) {
			int8_t do_flush = ll_count(log_list) == 0; //flush on writing last element

			cs_strncpy(buf, log->txt, LOG_BUF_SIZE);
			if (log->direct_log)
				cs_write_log(buf, do_flush);
			else
				write_to_log(buf, log, do_flush);
			free(log->txt);
			free(log);

			//If list is faster growing than we could write to file, drop list:
			write_count++;
			if (write_count%10000 == 0) { //check every 10000 writes:
				count = ll_count(log_list);
				if (count > last_count) {
					grow_count++;
					if (grow_count > 5) { //5 times still growing
						cs_write_log("------------->logging temporary disabled (30s) - too much data!\n", 1);
						cfg.disablelog = 1;
						ll_iter_reset(&it);
						while ((log=ll_iter_next_remove(&it))) { //clear log
							free(log->txt);
							free(log);
						}
						cs_sleepms(30*1000);
						cfg.disablelog = 0;

						grow_count = 0;
						last_count = 0;
						break;
					}
				}
				else
					grow_count = 0;
				last_count = count;
			}
		}

		cs_sleepms(250);
	} while(!cfg.disablelog);
	logThreadRunning = 0;
}

int32_t cs_init_log(void)
{
	if(logStarted == 0){
#if defined(WEBIF) || defined(MODULE_MONITOR)
		cs_lock_create(&loghistory_lock, 5, "loghistory_lock");
#endif

		log_list = ll_create(LOG_LIST);
		start_thread((void*)&log_list_thread, "log_list_thread");
	}
	int32_t rc = cs_open_logfiles();
	logStarted = 1;
	return rc;
}

void cs_disable_log(int8_t disabled)
{
	if (cfg.disablelog != disabled) {
		cfg.disablelog = disabled;
		if (disabled) {
			if (logStarted) {
				while(logThreadRunning == 1){
					cs_sleepms(5);
				}
				if(ll_count(log_list) > 0) log_list_thread(); //Clean log
				cs_close_log();
			}
		} else {
			if(logStarted == 0){
				cs_init_log();
			} else {
				cs_open_logfiles();
				if(logThreadRunning == 0){
					start_thread((void*)&log_list_thread, "log_list_thread");
				}
			}
		}
	}
}

