#include "globals.h"
#include <syslog.h>
#include "module-anticasc.h"
#include "module-monitor.h"
#include "oscam-client.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-log.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"

// Do not allow log_list to grow bigger than that many entries
#define MAX_LOG_LIST_BACKLOG 10000

extern char *syslog_ident;
extern int32_t exit_oscam;

char *LOG_LIST = "log_list";
int8_t logStarted = 0;

static FILE *fp;
static FILE *fps;
static LLIST *log_list;
static bool log_running;
static int log_list_queued;
static pthread_t log_thread;
static pthread_cond_t log_thread_sleep_cond;
static pthread_mutex_t log_thread_sleep_cond_mutex;
static int32_t syslog_socket = -1;
static struct sockaddr_in syslog_addr;


struct s_log
{
	char *txt;
	uint8_t header_len;
	uint8_t header_logcount_offset;
	uint8_t header_date_offset;
	uint8_t header_time_offset;
	uint8_t header_info_offset;
	int8_t direct_log;
	int8_t cl_typ;
	char *cl_usr;
	char *cl_text;
};

#define LOG_BUF_SIZE 512

static void switch_log(char *file, FILE **f, int32_t (*pfinit)(void))
{
	if(cfg.max_log_size && file)    //only 1 thread needs to switch the log; even if anticasc, statistics and normal log are running
		//at the same time, it is ok to have the other logs switching 1 entry later
	{
		if(*f != NULL && ftell(*f) >= cfg.max_log_size * 1024)
		{
			int32_t rc;
			char prev_log[strlen(file) + 6];
			snprintf(prev_log, sizeof(prev_log), "%s-prev", file);
			fprintf(*f, "switch log file\n");
			fflush(*f);
			fclose(*f);
			*f = (FILE *)0;
			rc = rename(file, prev_log);
			if(rc != 0)
			{
				fprintf(stderr, "rename(%s, %s) failed (errno=%d %s)\n", file, prev_log, errno, strerror(errno));
			}
			else if(pfinit())
			{
				fprintf(stderr, "Initialisation of log file failed, continuing without logging thread %8lX. Log will be output to stdout!", (unsigned long)pthread_self());
				cfg.logtostdout = 1;
			}
		}
	}
}

void cs_reopen_log(void)
{
	if(cfg.logfile)
	{
		if(fp)
		{
			fprintf(fp, "flush and re-open log file\n");
			fflush(fp);
			fclose(fp);
			fp = NULL;
		}
		if(cs_open_logfiles())
		{
			fprintf(stderr, "Initialisation of log file failed, continuing without logging thread %8luX. Log will be output to stdout!", (unsigned long)pthread_self());
			cfg.logtostdout = 1;
		}
	}
	if(cfg.usrfile)
	{
		if(fps)
		{
			fprintf(fps, "flush and re-open user log file\n");
			fflush(fps);
			fclose(fps);
			fps = NULL;
		}
		if(cs_init_statistics())
		{
			fprintf(stderr, "Initialisation of user log file failed, continuing without logging thread %8luX.", (unsigned long)pthread_self());
		}
	}
}

static void cs_write_log(char *txt, int8_t do_flush, uint8_t hdr_date_offset, uint8_t hdr_time_offset)
{
	// filter out entries with leading 's' and forward to statistics
	if(txt[hdr_date_offset] == 's')
	{
		if(fps)
		{
			switch_log(cfg.usrfile, &fps, cs_init_statistics);
			if(fps)
			{
				fputs(txt + hdr_date_offset + 1, fps); // remove the leading 's' and write to file
				if(do_flush) { fflush(fps); }
			}
		}
	}
	else
	{
		if(!cfg.disablelog)
		{
			if(fp)
			{
				switch_log(cfg.logfile, &fp, cs_open_logfiles);     // only call the switch code if lock = 1 is specified as otherwise we are calling it internally
				if(fp)
				{
					fputs(txt + hdr_date_offset, fp);
					if(do_flush) { fflush(fp); }
				}
			}
			if(cfg.logtostdout)
			{
				fputs(txt + hdr_time_offset, stdout);
				if(do_flush) { fflush(stdout); }
			}
		}
	}
}

static void log_list_flush(void)
{
	if(logStarted == 0)
		{ return; }
	
	SAFE_COND_SIGNAL_NOLOG(&log_thread_sleep_cond);
	int32_t i = 0;
	while(ll_count(log_list) > 0 && i < 200)
	{
		cs_sleepms(5);
		++i;
	}
}

static void log_list_add(struct s_log *log)
{
	if(logStarted == 0)
		{ return; }
	
	int32_t count = ll_count(log_list);
	log_list_queued++;
	if(count < MAX_LOG_LIST_BACKLOG)
	{
		ll_append(log_list, log);
	}
	else     // We have too much backlog
	{
		NULLFREE(log->txt);
		NULLFREE(log);
		cs_write_log("-------------> Too much data in log_list, dropping log message.\n", 1, 0, 0);
	}
	SAFE_COND_SIGNAL_NOLOG(&log_thread_sleep_cond);
}

static void cs_write_log_int(char *txt)
{
	if(exit_oscam == 1)
	{
		cs_write_log(txt, 1, 0, 0);
	}
	else
	{
		char *newtxt = cs_strdup(txt);
		if(!newtxt)
			{ return; }
		struct s_log *log;
		if(!cs_malloc(&log, sizeof(struct s_log)))
		{
			NULLFREE(newtxt);
			return;
		}
		log->txt = newtxt;
		log->header_len = 0;
		log->direct_log = 1;
		log_list_add(log);
	}
}

int32_t cs_open_logfiles(void)
{
	char *starttext;
	if(logStarted) { starttext = "log switched"; }
	else { starttext = "started"; }
	if(!fp && cfg.logfile)      //log to file
	{
		if((fp = fopen(cfg.logfile, "a+")) <= (FILE *)0)
		{
			fp = (FILE *)0;
			fprintf(stderr, "couldn't open logfile: %s (errno %d %s)\n", cfg.logfile, errno, strerror(errno));
		}
		else
		{
			char line[80];
			memset(line, '-', sizeof(line));
			line[(sizeof(line) / sizeof(char)) - 1] = '\0';
			time_t walltime = cs_time();
			if(!cfg.disablelog)
			{
				char buf[28];
				cs_ctime_r(&walltime, buf);
				fprintf(fp, "\n%s\n>> OSCam <<  cardserver %s at %s%s\n", line, starttext, buf, line);
			}
		}
	}
	// according to syslog docu: calling closelog is not necessary and calling openlog multiple times is safe
	// We use openlog to set the default syslog settings so that it's possible to allow switching syslog on and off
	openlog(syslog_ident, LOG_NDELAY | LOG_PID, LOG_DAEMON);
	cs_log(">> OSCam <<  cardserver %s, version " CS_VERSION ", build r" CS_SVN_VERSION " (" CS_TARGET ")", starttext);

	return (fp <= (FILE *)0);
}

#if defined(WEBIF) || defined(MODULE_MONITOR)
static uint64_t counter = 0;
CS_MUTEX_LOCK loghistory_lock;
// These are accessed in module-monitor and module-webif
char *loghist = NULL;     // ptr of log-history
char *loghistid = NULL;
char *loghistptr = NULL;

/*
 This function allows to reinit the in-memory loghistory with a new size.
*/
void cs_reinit_loghist(uint32_t size)
{
	char *tmp = NULL, *tmp2, *tmp3 = NULL, *tmp4;
	if(size != cfg.loghistorysize)
	{
		if(cs_malloc(&tmp, size) && cs_malloc(&tmp3, size/3+8))
		{
			if(logStarted)
				{ cs_writelock_nolog(__func__, &loghistory_lock); }
			
			tmp2 = loghist;
			tmp4 = loghistid;
			// On shrinking, the log is not copied and the order is reversed
			if(size < cfg.loghistorysize)
			{
				cfg.loghistorysize = size;
				loghistptr = tmp;
				loghist = tmp;
				loghistid = tmp3;
			}
			else
			{
				if(loghist)
				{
					memcpy(tmp, loghist, cfg.loghistorysize);
					loghistptr = tmp + (loghistptr - loghist);
					memcpy(tmp3, loghistid, cfg.loghistorysize/3);
				} else { 
					loghistptr = tmp;
				}
				loghist = tmp;
				loghistid = tmp3;
				cfg.loghistorysize = size;
			}
			if(logStarted)
				{ cs_writeunlock_nolog(__func__, &loghistory_lock); }
			
			if(tmp2 != NULL) { add_garbage(tmp2); }
			if(tmp4 != NULL) { add_garbage(tmp4); }
		}
	}
}
#endif

static struct timeb log_ts;

static uint8_t get_log_header(char *txt, int32_t txt_size, uint8_t* hdr_logcount_offset,
								uint8_t* hdr_date_offset, uint8_t* hdr_time_offset, uint8_t* hdr_info_offset)
{
	struct s_client *cl = cur_client();
	struct tm lt;
	int32_t tmp;
		
	cs_ftime(&log_ts);
	time_t walltime = cs_walltime(&log_ts);
	localtime_r(&walltime, &lt);

	tmp = snprintf(txt, txt_size,  "[LOG000]%04d/%02d/%02d %02d:%02d:%02d %08X %c ",
		lt.tm_year + 1900,
		lt.tm_mon + 1,
		lt.tm_mday,
		lt.tm_hour,
		lt.tm_min,
		lt.tm_sec,
		cl ? cl->tid : 0,
		cl ? cl->typ : ' '
	);
	
	if(tmp == 39)
	{
		if(hdr_logcount_offset != NULL)
		{
			// depends on snprintf(...) format
			(*hdr_logcount_offset) = 4;
		}
		if(hdr_date_offset != NULL)
		{
			// depends on snprintf(...) format
			(*hdr_date_offset) = *hdr_logcount_offset + 4;
		}
		if(hdr_time_offset != NULL)
		{
			// depends on snprintf(...) format
			(*hdr_time_offset) = *hdr_date_offset + 11;
		}
		if(hdr_info_offset != NULL)
		{
			// depends on snprintf(...) format
			(*hdr_info_offset) = *hdr_time_offset + 9;
		}
		
		return (uint8_t)tmp;
	}
	
	if(hdr_logcount_offset != NULL)
	{
		(*hdr_logcount_offset) = 0;
	}	
	if(hdr_date_offset != NULL)
	{
		(*hdr_date_offset) = 0;
	}
	if(hdr_time_offset != NULL)
	{
		(*hdr_time_offset) = 0;
	}
	if(hdr_info_offset != NULL)
	{
		(*hdr_info_offset) = 0;
	}	
	
	return 0;
}

static void write_to_log(char *txt, struct s_log *log, int8_t do_flush)
{
	if(logStarted == 0)
		{ return; }
	
	(void)log; // Prevent warning when WEBIF, MODULE_MONITOR and CS_ANTICASC are disabled

	// anticascading messages go to their own log
	if (!anticasc_logging(txt + log->header_date_offset))
	{
		if(cfg.logtosyslog)
		{
			syslog(LOG_INFO, "%s", txt + log->header_info_offset);
		}
			
		if (cfg.sysloghost != NULL && syslog_socket != -1)
		{	
			char tmp[128+LOG_BUF_SIZE];			
			static char hostname[64];
			static uint8_t have_hostname = 0;
			time_t walltime;
			struct tm lt;
			char timebuf[32];
						
			if(!have_hostname)
			{
				if(gethostname(hostname, 64) != 0)
				{
					cs_strncpy(hostname, "unknown", 64);
				}
				
				have_hostname = 1;
			}
										
			walltime = cs_time();
			localtime_r(&walltime, &lt);

			if(strftime(timebuf, 32, "%b %d %H:%M:%S", &lt) == 0)
			{
				cs_strncpy(timebuf, "unknown", 32);
			}			
			
			snprintf(tmp, sizeof(tmp), "%s %s oscam[%u]: %s", timebuf, hostname, getpid(), txt + log->header_info_offset);
			sendto(syslog_socket, tmp, strlen(tmp), 0, (struct sockaddr*) &syslog_addr, sizeof(syslog_addr));
		}
	}
	
	strcat(txt, "\n");
	cs_write_log(txt, do_flush, log->header_date_offset, log->header_time_offset);

#if defined(WEBIF) || defined(MODULE_MONITOR)
	if(loghist && !exit_oscam && cfg.loghistorysize)
	{
		char *usrtxt = log->cl_text;
		char *target_ptr = NULL;
		int32_t target_len = strlen(usrtxt) + strlen(txt+log->header_date_offset) + 1;

		cs_writelock_nolog(__func__, &loghistory_lock);
		char *lastpos = loghist + (cfg.loghistorysize) - 1;
		if(loghist + target_len + 1 >= lastpos)
		{
			// we can assume that the min loghistorysize is always 1024 so we don't need to check if this new string fits into it!
			strncpy(txt + log->header_len, "Log entry too long!", strlen(txt) - log->header_len);
			target_len = strlen(usrtxt) + strlen(txt+log->header_date_offset) + 1;
		}
		if(!loghistptr)
			{ loghistptr = loghist;	}

		if(loghistptr + target_len + 1 > lastpos)
		{
			*loghistptr = '\0';
			loghistptr = loghist + target_len + 1;
			*loghistptr = '\0';
			target_ptr = loghist;
		}
		else
		{
			target_ptr = loghistptr;
			loghistptr = loghistptr + target_len + 1;
			*loghistptr = '\0';
		}
		++counter;
		
		snprintf(target_ptr, target_len + 1, "%s\t%s", usrtxt, txt + log->header_date_offset);
		ull2b_buf(counter, (uchar *)(loghistid + ((target_ptr-loghist)/3)));
		
		cs_writeunlock_nolog(__func__, &loghistory_lock);
	}
#endif

#if defined(MODULE_MONITOR)
	char sbuf[16];
	struct s_client *cl;
	for(cl = first_client; cl ; cl = cl->next)
	{
		if((cl->typ == 'm') && (cl->monlvl > 0) && cl->log)  //this variable is only initialized for cl->typ = 'm'
		{
			if(cl->monlvl < 2)
			{
				if(log->cl_typ != 'c' && log->cl_typ != 'm')
					{ continue; }
				if(log->cl_usr && cl->account && strcmp(log->cl_usr, cl->account->usr))
					{ continue; }
			}
			
			if(log->header_len > 0)
			{
				snprintf(sbuf, sizeof(sbuf), "%03d", cl->logcounter);
				cl->logcounter = (cl->logcounter + 1) % 1000;
				memcpy(txt + log->header_logcount_offset, sbuf, 3);
				monitor_send_idx(cl, txt);
			}
			else
			{
				char tmp_log[8+LOG_BUF_SIZE];
				snprintf(tmp_log, sizeof(tmp_log), "[LOG%03d]%s", cl->logcounter, txt);
				cl->logcounter = (cl->logcounter + 1) % 1000;
				monitor_send_idx(cl, tmp_log);
			}
		}
	}
#endif
}

static void write_to_log_int(char *txt, uint8_t header_len, uint8_t hdr_logcount_offset, uint8_t hdr_date_offset, uint8_t hdr_time_offset, uint8_t hdr_info_offset)
{
#if !defined(WEBIF) && !defined(MODULE_MONITOR)
	if(cfg.disablelog) { return; }
#endif
	char *newtxt = cs_strdup(txt);
	if(!newtxt)
		{ return; }
	struct s_log *log;
	if(!cs_malloc(&log, sizeof(struct s_log)))
	{
		NULLFREE(newtxt);
		return;
	}
	log->txt = newtxt;
	log->header_len = header_len;
	log->header_logcount_offset = hdr_logcount_offset;
	log->header_date_offset = hdr_date_offset;
	log->header_time_offset = hdr_time_offset;
	log->header_info_offset = hdr_info_offset;		
	log->direct_log = 0;
	struct s_client *cl = cur_client();
	log->cl_usr = "";
	if(!cl)
	{
		log->cl_text = "undef";
		log->cl_typ = ' ';
	}
	else
	{
		switch(cl->typ)
		{
		case 'c':
		case 'm':
			if(cl->account)
			{
				log->cl_text = cl->account->usr;
				log->cl_usr = cl->account->usr;
			}
			else { log->cl_text = ""; }
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

	if(exit_oscam == 1 || cfg.disablelog)  //Exit or log disabled. if disabled, just display on webif/monitor
	{
		char buf[LOG_BUF_SIZE];
		cs_strncpy(buf, log->txt, LOG_BUF_SIZE);
		write_to_log(buf, log, 1);
		NULLFREE(log->txt);
		NULLFREE(log);
	}
	else
		{ log_list_add(log); }
}

static pthread_mutex_t log_mutex;
static char log_txt[LOG_BUF_SIZE];
static char dupl[LOG_BUF_SIZE / 4];
static char last_log_txt[LOG_BUF_SIZE];
static struct timeb last_log_ts;
static unsigned int last_log_duplicates;

static void __cs_log_check_duplicates(uint8_t hdr_len, uint8_t hdr_logcount_offset, uint8_t hdr_date_offset, uint8_t hdr_time_offset, uint8_t hdr_info_offset)
{
	bool repeated_line = strcmp(last_log_txt, log_txt + hdr_len) == 0;
	if (last_log_duplicates > 0)
	{
		if (!cs_valid_time(&last_log_ts))  // Must be initialized once
			last_log_ts = log_ts;
		// Report duplicated lines when the new log line is different
		// than the old or 60 seconds have passed.
		int64_t gone = comp_timeb(&log_ts, &last_log_ts);
		if (!repeated_line || gone >= 60*1000)
		{
			uint8_t dupl_hdr_logcount_offset = 0, dupl_hdr_date_offset = 0, dupl_hdr_time_offset = 0, dupl_hdr_info_offset = 0;
			uint8_t dupl_header_len = get_log_header(dupl, sizeof(dupl), &dupl_hdr_logcount_offset, &dupl_hdr_date_offset, &dupl_hdr_time_offset, &dupl_hdr_info_offset);
			snprintf(dupl + dupl_header_len - 1, sizeof(dupl) - dupl_header_len, "        (-) -- Skipped %u duplicated log lines --", last_log_duplicates);
			write_to_log_int(dupl, dupl_header_len, dupl_hdr_logcount_offset, dupl_hdr_date_offset, dupl_hdr_time_offset, dupl_hdr_info_offset);
			last_log_duplicates = 0;
			last_log_ts = log_ts;
		}
	}
	if (!repeated_line)
	{
		memcpy(last_log_txt, log_txt + hdr_len, LOG_BUF_SIZE - hdr_len);
		write_to_log_int(log_txt, hdr_len, hdr_logcount_offset, hdr_date_offset, hdr_time_offset, hdr_info_offset);
	} else {
		last_log_duplicates++;
	}
}

#define __init_log_prefix(fmt) \
	uint8_t hdr_logcount_offset = 0, hdr_date_offset = 0, hdr_time_offset = 0, hdr_info_offset = 0; \
	uint8_t hdr_len = get_log_header(log_txt, sizeof(log_txt), &hdr_logcount_offset, &hdr_date_offset, &hdr_time_offset, &hdr_info_offset); \
	int32_t log_prefix_len = 0; \
	do { \
		if (log_prefix) { \
			char _lp[16]; \
			snprintf(_lp, sizeof(_lp), "(%s)", log_prefix); \
			log_prefix_len = snprintf(log_txt + hdr_len, sizeof(log_txt) - hdr_len, fmt, _lp); \
		} \
	} while(0)

#define __do_log() \
	do { \
		va_list params; \
		va_start(params, fmt); \
		__init_log_prefix("%10s "); \
		vsnprintf(log_txt + hdr_len + log_prefix_len, sizeof(log_txt) - (hdr_len + log_prefix_len), fmt, params); \
		va_end(params); \
		if (cfg.logduplicatelines) \
		{ \
			memcpy(last_log_txt, log_txt + hdr_len, LOG_BUF_SIZE - hdr_len); \
			write_to_log_int(log_txt, hdr_len, hdr_logcount_offset, hdr_date_offset, hdr_time_offset, hdr_info_offset); \
		} else { \
			__cs_log_check_duplicates(hdr_len, hdr_logcount_offset, hdr_date_offset, hdr_time_offset, hdr_info_offset); \
		} \
	} while(0)

void cs_log_txt(const char *log_prefix, const char *fmt, ...)
{
	if(logStarted == 0)
		{ return; }
	
	SAFE_MUTEX_LOCK_NOLOG(&log_mutex);
	__do_log();
	SAFE_MUTEX_UNLOCK_NOLOG(&log_mutex);
}

void cs_log_hex(const char *log_prefix, const uint8_t *buf, int32_t n, const char *fmt, ...)
{
	if(logStarted == 0)
		{ return; }
	
	SAFE_MUTEX_LOCK_NOLOG(&log_mutex);
	__do_log();
	if(buf)
	{
		int32_t i;
		__init_log_prefix("%10s   ");
		for(i = 0; i < n; i += 16)
		{
			cs_hexdump(1, buf + i, (n - i > 16) ? 16 : n - i, log_txt + hdr_len + log_prefix_len, sizeof(log_txt) - (hdr_len + log_prefix_len));
			write_to_log_int(log_txt, hdr_len, hdr_logcount_offset, hdr_date_offset, hdr_time_offset, hdr_info_offset);
		}
	}
	SAFE_MUTEX_UNLOCK_NOLOG(&log_mutex);
}

static void cs_close_log(void)
{
	log_list_flush();
	if(fp)
	{
		fclose(fp);
		fp = (FILE *)0;
	}
}

int32_t cs_init_statistics(void)
{
	if((!fps) && (cfg.usrfile != NULL))
	{
		if((fps = fopen(cfg.usrfile, "a+")) <= (FILE *)0)
		{
			fps = (FILE *)0;
			cs_log("couldn't open statistics file: %s", cfg.usrfile);
		}
	}
	return (fps <= (FILE *)0);
}

void cs_statistics(struct s_client *client)
{
	if(!cfg.disableuserfile)
	{
		struct tm lt;
		char buf[LOG_BUF_SIZE];

		float cwps;

		time_t walltime = cs_time();
		localtime_r(&walltime, &lt);
		if(client->cwfound + client->cwnot > 0)
		{
			cwps = client->last - client->login;
			cwps /= client->cwfound + client->cwnot;
		}
		else
			{ cwps = 0; }

		char channame[CS_SERVICENAME_SIZE];
		get_servicename(client, client->last_srvid, client->last_provid, client->last_caid, channame, sizeof(channame));

		int32_t lsec;
		if((client->last_caid == NO_CAID_VALUE) && (client->last_srvid == NO_SRVID_VALUE))
			{ lsec = client->last - client->login; } //client leave calc total duration
		else
			{ lsec = client->last - client->lastswitch; }

		int32_t secs = 0, fullmins = 0, mins = 0, fullhours = 0;

		if((lsec > 0) && (lsec < 1000000))
		{
			secs = lsec % 60;
			if(lsec > 60)
			{
				fullmins = lsec / 60;
				mins = fullmins % 60;
				if(fullmins > 60)
				{
					fullhours = fullmins / 60;
				}
			}
		}

		/* statistics entry start with 's' to filter it out on other end of pipe
		 * so we can use the same Pipe as Log
		 */
		snprintf(buf, sizeof(buf), "s%02d.%02d.%02d %02d:%02d:%02d %3.1f %s %s %d %d %d %d %d %d %d %ld %ld %02d:%02d:%02d %s %04X@%06X:%04X %s\n",
				 lt.tm_mday, lt.tm_mon + 1, lt.tm_year % 100,
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
				 get_module(client)->desc,
				 client->last_caid,
				 client->last_provid,
				 client->last_srvid,
				 channame);

		cs_write_log_int(buf);
	}
}

void log_list_thread(void)
{
	char buf[LOG_BUF_SIZE];
	log_running = 1;
	set_thread_name(__func__);
	do
	{
		log_list_queued = 0;
		LL_ITER it = ll_iter_create(log_list);
		struct s_log *log;
		while((log = ll_iter_next_remove(&it)))
		{
			int8_t do_flush = ll_count(log_list) == 0; //flush on writing last element

			cs_strncpy(buf, log->txt, LOG_BUF_SIZE);
			if(log->direct_log)
				{ cs_write_log(buf, do_flush, log->header_date_offset, log->header_time_offset); }
			else
				{ write_to_log(buf, log, do_flush); }
			NULLFREE(log->txt);
			NULLFREE(log);
		}
		if(!log_list_queued)  // The list is empty, sleep until new data comes in and we are woken up
			sleepms_on_cond(__func__, &log_thread_sleep_cond_mutex, &log_thread_sleep_cond, 60 * 1000);
	}
	while(log_running);
	ll_destroy(&log_list);
}

static void init_syslog_socket(void)
{
	if(cfg.sysloghost != NULL && syslog_socket == -1)
	{	
		IN_ADDR_T in_addr;
		
		if ((syslog_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		{
			perror("Socket create error!");
		}
		
		memset((char *) &syslog_addr, 0, sizeof(syslog_addr));
		syslog_addr.sin_family = AF_INET;
		syslog_addr.sin_port = htons(cfg.syslogport);
		cs_resolve(cfg.sysloghost, &in_addr, NULL, NULL);
		SIN_GET_ADDR(syslog_addr) = in_addr;
	}		
}

int32_t cs_init_log(void)
{	
	if(logStarted == 0)
	{
		init_syslog_socket();
		SAFE_MUTEX_INIT_NOLOG(&log_mutex, NULL);

		cs_pthread_cond_init_nolog(__func__, &log_thread_sleep_cond_mutex, &log_thread_sleep_cond);

#if defined(WEBIF) || defined(MODULE_MONITOR)
		cs_lock_create_nolog(__func__, &loghistory_lock, "loghistory_lock", 5000);
#endif

		log_list = ll_create(LOG_LIST);

		int32_t ret = start_thread_nolog("logging", (void *)&log_list_thread, NULL, &log_thread, 0);
		if(ret)
		{
			cs_exit(1);
		}
		
		logStarted = 1;
	}
	int32_t rc = 0;
	if(!cfg.disablelog) { rc = cs_open_logfiles(); }
	logStarted = 1;
	
	if(cfg.initial_debuglevel > 0) 
	{ 
		cs_dblevel = cfg.initial_debuglevel;
		cs_log("debug_level=%d", cs_dblevel);
	}
	
	return rc;
}

void cs_disable_log(int8_t disabled)
{
	if(cfg.disablelog != disabled)
	{
		if(disabled && logStarted)
		{
			cs_log("Stopping log...");
			log_list_flush();
		}
		cfg.disablelog = disabled;
		if(disabled)
		{
			if(logStarted)
			{
				if(syslog_socket != -1)
				{
					close(syslog_socket);
					syslog_socket = -1;					
				}
				
				cs_sleepms(20);
				cs_close_log();
			}
		}
		else
		{
			init_syslog_socket();
			cs_open_logfiles();
		}
	}
}

void log_free(void)
{
	if(syslog_socket != -1)
	{
		close(syslog_socket);
		syslog_socket = -1;
	}
	cs_close_log();
	log_running = 0;
	SAFE_COND_SIGNAL_NOLOG(&log_thread_sleep_cond);
	SAFE_THREAD_JOIN_NOLOG(log_thread, NULL);
#if defined(WEBIF) || defined(MODULE_MONITOR)
	NULLFREE(loghist);
	NULLFREE(loghistid);
	loghist = loghistptr = loghistid = NULL;
#endif
}
