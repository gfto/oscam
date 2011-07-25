#include "globals.h"
#include <syslog.h>
#include <stdlib.h>

static FILE *fp=(FILE *)0;
static FILE *fps=(FILE *)0;
#ifdef CS_ANTICASC
static FILE *fpa=(FILE *)0;
#endif
static int8_t logStarted = 0;

CS_MUTEX_LOCK log_lock;
CS_MUTEX_LOCK ac_lock;
CS_MUTEX_LOCK user_lock;
CS_MUTEX_LOCK stdout_lock;
CS_MUTEX_LOCK loghistory_lock;

#define LOG_BUF_SIZE 512

static void switch_log(char* file, FILE **f, int32_t (*pfinit)(void))
{
	if(cfg.max_log_size)	//only 1 thread needs to switch the log; even if anticasc, statistics and normal log are running
					//at the same time, it is ok to have the other logs switching 1 entry later
	{
		struct stat stlog;

		if( stat(file, &stlog)!=0 )
		{
			fprintf(stderr, "stat('%s',..) failed (errno=%d %s)\n", file, errno, strerror(errno));
			return;
		}

		if(stlog.st_size >= cfg.max_log_size*1024 && *f != NULL) {
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

static void cs_write_log(char *txt, int8_t lock)
{
	// filter out entries with leading 's' and forward to statistics
	if(txt[0] == 's') {
		if (fps) {
			if(lock) cs_writelock(&user_lock);
			switch_log(cfg.usrfile, &fps, cs_init_statistics);
			if (fps) {
					fputs(txt + 1, fps); // remove the leading 's' and write to file
					fflush(fps);
			}
			if(lock) cs_writeunlock(&user_lock);
		}
	} else {
		if(!cfg.disablelog){
			if (fp){
				if(lock){
					cs_writelock(&log_lock);
					switch_log(cfg.logfile, &fp, cs_open_logfiles);		// only call the switch code if lock = 1 is specified as otherwise we are calling it internally
				}
				if (fp) {
						fputs(txt, fp);
						fflush(fp);
				}
				if(lock) cs_writeunlock(&log_lock);	
			}
			if(cfg.logtostdout){
				if(lock) cs_writelock(&stdout_lock);
				fputs(txt+11, stdout);
				fflush(stdout);
				if(lock) cs_writeunlock(&stdout_lock);	
			}
		}
	}
}

int32_t cs_open_logfiles()
{
	char *starttext;
	if(logStarted) starttext = "log switched";
	else starttext = "started";
	if (!fp && cfg.logfile != NULL) {	//log to file
		if ((fp = fopen(cfg.logfile, "a+")) <= (FILE *)0) {
			fp = (FILE *)0;
			fprintf(stderr, "couldn't open logfile: %s (errno %d %s)\n", cfg.logfile, errno, strerror(errno));
		} else {
			time_t t;
			char line[80];
			memset(line, '-', sizeof(line));
			line[(sizeof(line)/sizeof(char)) - 1] = '\0';
			time(&t);
			if (!cfg.disablelog)
				fprintf(fp, "\n%s\n>> OSCam <<  cardserver %s at %s%s\n", line, starttext, ctime(&t), line);
		}
	}
	// according to syslog docu: calling closelog is not necessary and calling openlog multiple times is safe
	// We use openlog to set the default syslog settings so that it's possible to allow switching syslog on and off
	openlog("oscam", LOG_NDELAY, LOG_DAEMON);
	
	cs_log_nolock(">> OSCam <<  cardserver %s, version " CS_VERSION ", build #" CS_SVN_VERSION " (" CS_OSTYPE ")", starttext);
	cs_log_config();
	return(fp <= (FILE *)0);
}

int32_t cs_init_log(void)
{
	if(logStarted == 0){
		cs_lock_create(&log_lock, 5, "log_lock");
		cs_lock_create(&ac_lock, 5, "ac_lock");
		cs_lock_create(&user_lock, 5, "user_lock");
		cs_lock_create(&stdout_lock, 5, "stdout_lock");
		cs_lock_create(&loghistory_lock, 5, "loghistory_lock");
	}
	int32_t rc = cs_open_logfiles();
	logStarted = 1;
	return rc;
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

/* 
 This function allows to reinit the in-memory loghistory with a new size.
*/
void cs_reinit_loghist(uint32_t size)
{
	char *tmp, *tmp2;
	if(size != cfg.loghistorysize){
		if(cs_malloc(&tmp, size, -1)){
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

static int32_t get_log_header(int32_t m, char *txt)
{
	struct s_client *cl = cur_client();
	time_t t;
	struct tm lt;
	int32_t pos;

	time(&t);
	localtime_r(&t, &lt);

	pos = snprintf(txt, LOG_BUF_SIZE,  "[LOG000]%4d/%02d/%02d %2d:%02d:%02d ", lt.tm_year+1900, lt.tm_mon+1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec);

	if(m)
		return pos + snprintf(txt+pos, LOG_BUF_SIZE-pos, "%8X %c ",(unsigned int) cl, cl?cl->typ:' ');
	else
		return pos + snprintf(txt+pos, LOG_BUF_SIZE-pos, "%8X%-3.3s ",(unsigned int) cl, "");
}

static void write_to_log(char *txt, int8_t lock, int32_t header_len)
{
	char sbuf[16];
	struct s_client *cur_cl = cur_client();

#ifdef CS_ANTICASC
	if (!strncmp(txt + header_len, "acasc:", 6)) {
		strcat(txt, "\n");
		if(lock) cs_writelock(&ac_lock);
		switch_log(cfg.ac_logfile, &fpa, ac_init_log);
		if (fpa) {
			fputs(txt + 8, fpa);
			fflush(fpa);
		}
		if(lock) cs_writeunlock(&ac_lock);
	} else
#endif
	{
		if (cfg.logtosyslog)
			syslog(LOG_INFO, "%s", txt+24);
		strcat(txt, "\n");
	}
	cs_write_log(txt + 8, lock);

	if (loghist) {
		char *usrtxt = NULL;

		if (!cur_cl)
			usrtxt = "undef";
		else {
			switch(cur_cl->typ) {
				case 'c':
				case 'm':
					usrtxt = cur_cl->account ? cur_cl->account->usr : "";
					break;
				case 'p':
				case 'r':
					usrtxt = cur_cl->reader ? cur_cl->reader->label : "";
					break;
				default:
					usrtxt = "server";
					break;
			}
		}

		char *target_ptr = NULL;
		int32_t target_len = strlen(usrtxt) + (strlen(txt) - 8) + 1;
		
		if(lock) cs_writelock(&loghistory_lock);
		char *lastpos = loghist + (cfg.loghistorysize) - 1;		
		if (!loghistptr)
			loghistptr = loghist;

		if (loghistptr+target_len > lastpos - 1) {
			*loghistptr='\0';
			loghistptr=loghist + target_len + 1;
			*loghistptr='\0';
			target_ptr=loghist;
		} else {
			target_ptr = loghistptr;
			loghistptr=loghistptr + target_len + 1;
			*loghistptr='\0';
		}
		if(lock) cs_writeunlock(&loghistory_lock);

		snprintf(target_ptr, target_len + 1, "%s\t%s", usrtxt, txt + 8);
	}

	struct s_client *cl;
	for (cl=first_client; cl ; cl=cl->next) {
		if ((cl->typ == 'm') && (cl->monlvl>0) && cl->log) //this variable is only initialized for cl->typ = 'm' 
		{
			if (cl->monlvl<2) {
				if (cur_cl && (cur_cl->typ != 'c') && (cur_cl->typ != 'm'))
					continue;
				if (cur_cl && cur_cl->account && cl->account && strcmp(cur_cl->account->usr, cl->account->usr))
					continue;
			}
			snprintf(sbuf, sizeof(sbuf), "%03d", cl->logcounter);
			cl->logcounter = (cl->logcounter+1) % 1000;
			memcpy(txt + 4, sbuf, 3);
			monitor_send_idx(cl, txt);
		}
	}
}

__attribute__ ((noinline)) void cs_log_int(uint16_t mask, int8_t lock, const uchar *buf, int32_t n, const char *fmt, ...)
{
	va_list params;

	char log_txt[LOG_BUF_SIZE];
	int32_t i, len = 0;
	if (((mask & cs_dblevel) || !mask) && (fmt))
	{
		va_start(params, fmt);
		len = get_log_header(1, log_txt);
		vsnprintf(log_txt + len, sizeof(log_txt) - len, fmt, params);
		write_to_log(log_txt, lock, len);
		va_end(params);
	}
	if (buf && (mask & cs_dblevel || !mask))
	{
		for (i=0; i<n; i+=16)
		{
			len = get_log_header(0, log_txt);
			cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i, log_txt + len, sizeof(log_txt) - len);
			write_to_log(log_txt, lock, len);
		}
	}
}

void cs_close_log(void)
{
	if (!fp) return;
	fclose(fp);
	fp=(FILE *)0;
}

void log_emm_request(struct s_reader *rdr){
	cs_log("%s emm-request sent (reader=%s, caid=%04X, auprovid=%06lX)",
			username(cur_client()), rdr->label, rdr->caid,
			rdr->auprovid ? rdr->auprovid : b2i(4, rdr->prid[0]));
}

/*
 * This function writes the current CW from ECM struct to a cwl file.
 * The filename is re-calculated and file re-opened every time.
 * This will consume a bit cpu time, but nothing has to be stored between
 * each call. If not file exists, a header is prepended
 */
void logCWtoFile(ECM_REQUEST *er){
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
		fprintf(pfCWL, "%02X ", er->cw[i]);
	/* better use incoming time er->tps rather than current time? */
	strftime(buf,sizeof(buf),"%H:%M:%S\n", &timeinfo);
	fprintf(pfCWL, "# %s", buf);
	fflush(pfCWL);
	fclose(pfCWL);
}

void cs_log_config()
{
  uchar buf[20];

  if (cfg.nice!=99)
    snprintf((char *)buf, sizeof(buf), ", nice=%d", cfg.nice);
  else
    buf[0]='\0';
  cs_log_nolock("version=%s, build #%s, system=%s-%s-%s%s", CS_VERSION, CS_SVN_VERSION, CS_OS_CPU, CS_OS_HW, CS_OS_SYS, buf);
  cs_log_nolock("client max. idle=%d sec, debug level=%d", cfg.cmaxidle, cs_dblevel);

  if( cfg.max_log_size )
    snprintf((char *)buf, sizeof(buf), "%d Kb", cfg.max_log_size);
  else
    cs_strncpy((char *)buf, "unlimited", sizeof(buf));
  cs_log_nolock("max. logsize=%s, loghistorysize=%d bytes", buf, cfg.loghistorysize);
  cs_log_nolock("client timeout=%lu ms, fallback timeout=%lu ms, cache delay=%d ms",
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

		cs_write_log(buf, 1);
	}
}
