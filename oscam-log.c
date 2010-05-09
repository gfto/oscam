#include "globals.h"
#include <syslog.h>
#include <stdlib.h>
#include <pthread.h>

int number_of_chars_printed = 0;

static FILE *fp=(FILE *)0;
static FILE *fps=(FILE *)0;
static int use_syslog=0;
static int use_stdout=0;
static pthread_mutex_t log_lock;
static char *log_txt;
static char *log_buf;

#ifdef CS_ANTICASC
FILE *fpa=(FILE *)0;
int use_ac_log=0;
#endif

static void switch_log(char* file, FILE **f, int (*pfinit)(char*))
{
	if( cfg->max_log_size && mcl)
	{
		struct stat stlog;
		if( stat(file, &stlog)!=0 )
		{
			fprintf(stderr, "stat('%s',..) failed (errno=%d)\n", file, errno);
			return;
		}

		if( stlog.st_size >= cfg->max_log_size*1024 ) {
			int rc;
			char prev_log[128];
			sprintf(prev_log, "%s-prev", file);
			fprintf(*f, "switch log file\n");
			fflush(*f);
			fclose(*f);
			*f = (FILE *)0;
			rc = rename(file, prev_log);
			if( rc!=0 ) {
				fprintf(stderr, "rename(%s, %s) failed (errno=%d)\n",
						file, prev_log, errno);
			}
			else if( pfinit(file))
				cs_exit(0);
		}
	}
}

void cs_write_log(char *txt)
{
#ifdef CS_ANTICASC
	if( use_ac_log && fpa ) {
		switch_log(cfg->ac_logfile, &fpa, ac_init_log);
		fprintf(fpa, "%s", txt);
		fflush(fpa);
	}
	else
#endif
		// filter out entries with leading 's' and forward to statistics
		if(txt[0] == 's') {
			if (fps) {
				switch_log(cfg->usrfile, &fps, cs_init_statistics);
				fprintf(fps, "%s", txt + 1); // remove the leading 's' and write to file
				fflush(fps);
			}
		} else {
			if (fp || use_stdout) {
				if( !use_stdout && !use_syslog)
					switch_log(cfg->logfile, &fp, cs_init_log);
				if (!cfg->disablelog){
					fprintf(fp, "%s", txt);
					fflush(fp);
				}
			}
		}
}

int cs_init_log(char *file)
{
	static char *head = ">> OSCam <<  cardserver started version " CS_VERSION ", build #" CS_SVN_VERSION " (" CS_OSTYPE ")";

	pthread_mutex_init(&log_lock, NULL);
	log_txt = malloc(512);
	log_buf = malloc(700);

	if (!strcmp(file, "stdout")) {
		use_stdout = 1;
		fp = stdout;
		cs_log(head);
		cs_log_config();
		return(0);
	}
	if (strcmp(file, "syslog")) {
		if (!fp) {
			if ((fp = fopen(file, "a+")) <= (FILE *)0) {
				fp = (FILE *)0;
				fprintf(stderr, "couldn't open logfile: %s (errno %d)\n", file, errno);
			} else {
				time_t t;
				char line[80];
				memset(line, '-', sizeof(line));
				line[(sizeof(line)/sizeof(char)) - 1] = '\0';
				time(&t);
				if (!cfg->disablelog)
					fprintf(fp, "\n%s\n>> OSCam <<  cardserver started at %s%s\n", line, ctime(&t), line);
				cs_log_config();
			}
		}
		return(fp <= (FILE *)0);
	} else {
		openlog("oscam", LOG_NDELAY, LOG_DAEMON);
		use_syslog = 1;
		cs_log(head);
		cs_log_config();
		return(0);
	}
}

static char *get_log_header(int m, char *txt)
{
	if(m) {
		sprintf(txt, "%6d ", getpid());
		if (cs_idx) {
			switch (client[cs_idx].typ) {
				case 'r':
				case 'p':	sprintf(txt+7, "%c%02d ", client[cs_idx].typ, cs_idx - 1);
							break;
				case 'm':
				case 'c':	sprintf(txt+7, "%c%02d ", client[cs_idx].typ, cs_idx - cdiff);
							break;
#ifdef CS_ANTICASC
				case 'a':
#endif
				case 'l':
#ifdef WEBIF
				case 'h':
#endif
				case 'n':	sprintf(txt+7, "%c   "  , client[cs_idx].typ);
							break;
			}
		} else {
			strcpy(txt+7, "s   ");
		}
	} else {
		sprintf(txt, "%-11.11s", "");
	}
	return(txt);
}

static void write_to_log(int flag, char *txt)
{
	//flag = -1 is old behaviour, before implementation of debug_nolf (=debug no line feed)
	//
	int i;
	time_t t;
	struct tm *lt;
	char sbuf[16];

	//  get_log_header(flag, sbuf);
	//  memcpy(txt, sbuf, 11);

#ifdef CS_ANTICASC
	if (use_syslog && !use_ac_log) // system-logfile
#else
	if (use_syslog) // system-logfile
#endif
		syslog(LOG_INFO, "%s", txt);

	time(&t);
	lt=localtime(&t);

	switch(flag) {
		case -1:
		sprintf(log_buf, "[LOG000]%4d/%02d/%02d %2d:%02d:%02d %s\n",
				lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday,
				lt->tm_hour, lt->tm_min, lt->tm_sec, txt);
		break;
		case 1:
			sprintf(log_buf, "[LOG000]%4d/%02d/%02d %2d:%02d:%02d            %s",
					lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday,
					lt->tm_hour, lt->tm_min, lt->tm_sec, txt);
			break;
		case 16:
			number_of_chars_printed = 0;
			sprintf(log_buf, "[LOG000]%s\n", txt);
			break;
		default:
			sprintf(log_buf, "[LOG000]%s", txt);
	}

	if ((*log_fd) && (client[cs_idx].typ != 'l') && (client[cs_idx].typ != 'a'))
		write_to_pipe(*log_fd, PIP_ID_LOG, (uchar *) log_buf+8, strlen(log_buf+8));
	else
		cs_write_log(log_buf + 8);

	store_logentry(log_buf);

	for (i = 0; i < CS_MAXPID; i++)	// monitor-clients
	{
		if ((client[i].pid) && (client[i].log))
		{
			if (client[i].monlvl<2)
			{
				if ((client[cs_idx].typ != 'c') && (client[cs_idx].typ != 'm'))
					continue;
				if (strcmp(client[cs_idx].usr, client[i].usr))
					continue;
			}
			sprintf(sbuf, "%03d", client[i].logcounter);
			client[i].logcounter = (client[i].logcounter+1) % 1000;
			memcpy(log_buf + 4, sbuf, 3);
			monitor_send_idx(i, log_buf);
		}
	}
}

void cs_log(char *fmt,...)
{
	if (!log_txt)
		return;
	pthread_mutex_lock(&log_lock);
	get_log_header(1, log_txt);
	va_list params;
	va_start(params, fmt);
	vsprintf(log_txt+11, fmt, params);
	va_end(params);
	write_to_log(-1, log_txt);
	pthread_mutex_unlock(&log_lock);
}

void cs_close_log(void)
{
	if (log_txt) {
		cs_log("LOG CLOSED");
		pthread_mutex_destroy(&log_lock);
		free(log_buf);
		free(log_txt);
		log_txt = NULL;
		log_buf = NULL;
	}
	if (use_stdout || use_syslog || !fp) return;
	fclose(fp);
	fp=(FILE *)0;
}

void cs_debug(char *fmt,...)
{
	//  cs_log("cs_debug called, cs_ptyp=%d, cs_dblevel=%d, %d", cs_ptyp, client[cs_idx].dbglvl ,cs_ptyp & client[cs_idx].dbglvl);
	if (log_txt && client[cs_idx].dbglvl & cs_ptyp)
	{
		pthread_mutex_lock(&log_lock);
		get_log_header(1, log_txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(log_txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, log_txt);
		pthread_mutex_unlock(&log_lock);
	}
}

void cs_debug_mask(unsigned short mask, char *fmt,...)
{
	if (log_txt && client[cs_idx].dbglvl & mask)
	{
		pthread_mutex_lock(&log_lock);
		get_log_header(1, log_txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(log_txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, log_txt);
		pthread_mutex_unlock(&log_lock);
	}
}

void cs_debug_nolf(char *fmt,...)
{
	if (log_txt && client[cs_idx].dbglvl & cs_ptyp)
	{
		pthread_mutex_lock(&log_lock);
		va_list params;
		va_start(params, fmt);
		vsprintf(log_txt, fmt, params);
		va_end(params);
		if(!memcmp(log_txt,"\n", 1)) {
			number_of_chars_printed = 0;
		}
		else
			number_of_chars_printed++;
		write_to_log(number_of_chars_printed, log_txt);
		pthread_mutex_unlock(&log_lock);
	}
}

void cs_dump(uchar *buf, int n, char *fmt, ...)
{
	if (!log_txt)
		return;
	pthread_mutex_lock(&log_lock);
	int i;

	if( fmt )
	{
		get_log_header(1, log_txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(log_txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, log_txt);
		//printf("LOG: %s\n", txt); fflush(stdout);
	}

	for( i=0; i<n; i+=16 )
	{
		get_log_header(0, log_txt);
		sprintf(log_txt+11, "%s", cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i));
		write_to_log(-1, log_txt);
	}
	pthread_mutex_unlock(&log_lock);
}

void cs_ddump(uchar *buf, int n, char *fmt, ...)
{
	if (!log_txt)
		return;
	pthread_mutex_lock(&log_lock);
	int i;

	//if (((cs_ptyp & client[cs_idx].dbglvl)==cs_ptyp) && (fmt))
	if ((cs_ptyp & client[cs_idx].dbglvl) && (fmt))
	{
		get_log_header(1, log_txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(log_txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, log_txt);
		//printf("LOG: %s\n", txt); fflush(stdout);
	}
	//if (((cs_ptyp | D_DUMP) & client[cs_idx].dbglvl)==(cs_ptyp | D_DUMP))
	if (cs_ptyp & client[cs_idx].dbglvl)
	{
		for (i=0; i<n; i+=16)
		{
			get_log_header(0, log_txt);
			sprintf(log_txt+11, "%s", cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i));
			write_to_log(-1, log_txt);
		}
	}
	pthread_mutex_unlock(&log_lock);
}

void cs_ddump_mask(unsigned short mask, uchar *buf, int n, char *fmt, ...)
{
	if(!log_txt)
		return;
	pthread_mutex_lock(&log_lock);
	int i;

	//if (((cs_ptyp & client[cs_idx].dbglvl)==cs_ptyp) && (fmt))
	if ((mask & client[cs_idx].dbglvl) && (fmt))
	{
		get_log_header(1, log_txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(log_txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, log_txt);
		//printf("LOG: %s\n", txt); fflush(stdout);
	}
	//if (((cs_ptyp | D_DUMP) & client[cs_idx].dbglvl)==(cs_ptyp | D_DUMP))
	if (mask & client[cs_idx].dbglvl)
	{
		for (i=0; i<n; i+=16)
		{
			get_log_header(0, log_txt);
			sprintf(log_txt+11, "%s", cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i));
			write_to_log(-1, log_txt);
		}
	}
	pthread_mutex_unlock(&log_lock);
}

int cs_init_statistics(char *file) 
{
	if ((!fps) && (file != NULL))
	{
		if ((fps=fopen(file, "a+"))<=(FILE *)0)
		{
			fps=(FILE *)0;
			cs_log("couldn't open statistics file: %s", file);
		}
	}
	return(fps<=(FILE *)0);
}

void cs_statistics(int idx)
{
	if (!cfg->disableuserfile){
		time_t t;
		struct tm *lt;
		char buf[512];

		float cwps;

		time(&t);
		lt=localtime(&t);
		if (client[idx].cwfound+client[idx].cwnot>0)
		{
			cwps=client[idx].last-client[idx].login;
			cwps/=client[idx].cwfound+client[idx].cwnot;
		}
		else
			cwps=0;

		char *channel ="";
		if(cfg->mon_appendchaninfo)
			channel = get_servicename(client[idx].last_srvid,client[idx].last_caid);

		int lsec;
		if ((client[idx].last_caid == 0xFFFF) && (client[idx].last_srvid == 0xFFFF))
			lsec = client[idx].last - client[idx].login; //client leave calc total duration
		else
			lsec = client[idx].last - client[idx].lastswitch;

		int secs = 0, fullmins = 0, mins = 0, fullhours = 0;

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
		sprintf(buf, "s%02d.%02d.%02d %02d:%02d:%02d %3.1f %s %s %d %d %d %d %d %d %d %ld %ld %02d:%02d:%02d %s %04X:%04X %s\n",
				lt->tm_mday, lt->tm_mon+1, lt->tm_year%100,
				lt->tm_hour, lt->tm_min, lt->tm_sec, cwps,
				client[idx].usr[0] ? client[idx].usr : "-",
				cs_inet_ntoa(client[idx].ip),
				client[idx].port,
				client[idx].cwfound,
				client[idx].cwcache,
				client[idx].cwnot,
				client[idx].cwignored,
				client[idx].cwtout,
				client[idx].cwtun,
				client[idx].login,
				client[idx].last,
				fullhours, mins, secs,
				ph[client[idx].ctyp].desc,
				client[idx].last_caid,
				client[idx].last_srvid,
				channel);

		if ((*log_fd) && (client[cs_idx].typ != 'l') && (client[cs_idx].typ != 'a'))
			write_to_pipe(*log_fd, PIP_ID_LOG, (uchar *) buf, strlen(buf));
		else
			cs_write_log(buf);
	}
}
