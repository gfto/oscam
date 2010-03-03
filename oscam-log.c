#include "globals.h"
#include <syslog.h>

int number_of_chars_printed = 0;

static FILE *fp=(FILE *)0;
static FILE *fps=(FILE *)0;
static int use_syslog=0;
static int use_stdout=0;

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
			*f=(FILE *)0;
			rc=rename(file, prev_log);
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
		if (fp || use_stdout) {
			if( !use_stdout && !use_syslog)
				switch_log(cfg->logfile, &fp, cs_init_log);
			if (!cfg->disablelog){
				fprintf(fp, "%s", txt);
				fflush(fp);
			}
		}
}

int cs_init_log(char *file)
{
	static char *head = ">> OSCam <<  cardserver started version " CS_VERSION ", build #" CS_SVN_VERSION " (" CS_OSTYPE ")";

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
	char buf[512], sbuf[16];

	//  get_log_header(flag, sbuf);
	//  memcpy(txt, sbuf, 11);


	time(&t);
	lt=localtime(&t);
	sprintf(buf, "[LOG000]%4d/%02d/%02d %2d:%02d:%02d %s\n",
			lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday,
			lt->tm_hour, lt->tm_min, lt->tm_sec, txt);

	if (use_syslog && !use_ac_log)		// system-logfile
		syslog(LOG_INFO, "%s", txt);

	time(&t);
	lt=localtime(&t);

	switch(flag) {
		case -1:
		sprintf(buf, "[LOG000]%4d/%02d/%02d %2d:%02d:%02d %s\n",
				lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday,
				lt->tm_hour, lt->tm_min, lt->tm_sec, txt);
		break;
		case 1:
			sprintf(buf, "[LOG000]%4d/%02d/%02d %2d:%02d:%02d            %s",
					lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday,
					lt->tm_hour, lt->tm_min, lt->tm_sec, txt);
			break;
		case 16:
			number_of_chars_printed = 0;
			sprintf(buf, "[LOG000]%s\n", txt);
			break;
		default:
			sprintf(buf, "[LOG000]%s", txt);
	}

	if ((*log_fd) && (client[cs_idx].typ != 'l') && (client[cs_idx].typ != 'a'))
		write_to_pipe(*log_fd, PIP_ID_LOG, (uchar *) buf+8, strlen(buf+8));
	else
		cs_write_log(buf + 8);

	store_logentry(buf);

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
			memcpy(buf + 4, sbuf, 3);
			monitor_send_idx(i, buf);
		}
	}
}

void cs_log(char *fmt,...)
{
	char txt[256+11];

	get_log_header(1, txt);
	va_list params;
	va_start(params, fmt);
	vsprintf(txt+11, fmt, params);
	va_end(params);
	write_to_log(-1, txt);
}

void cs_close_log(void)
{
	if (use_stdout || use_syslog || !fp) return;
	fclose(fp);
	fp=(FILE *)0;
}

void cs_debug(char *fmt,...)
{
	char txt[256];

	//  cs_log("cs_debug called, cs_ptyp=%d, cs_dblevel=%d, %d", cs_ptyp, client[cs_idx].dbglvl ,cs_ptyp & client[cs_idx].dbglvl);
	if (client[cs_idx].dbglvl & cs_ptyp)
	{
		get_log_header(1, txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, txt);
	}
}

void cs_debug_mask(unsigned short mask, char *fmt,...)
{
	char txt[256];
	if (client[cs_idx].dbglvl & mask)
	{
		get_log_header(1, txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, txt);
	}
}

void cs_debug_nolf(char *fmt,...)
{
	char txt[256];

	if (client[cs_idx].dbglvl & cs_ptyp)
	{
		va_list params;
		va_start(params, fmt);
		vsprintf(txt, fmt, params);
		va_end(params);
		if(!memcmp(txt,"\n", 1)) {
			number_of_chars_printed = 0;
		}
		else
			number_of_chars_printed++;
		write_to_log(number_of_chars_printed, txt);
	}
}

void cs_dump(uchar *buf, int n, char *fmt, ...)
{
	int i;
	char txt[512];

	if( fmt )
		cs_log(fmt);

	for( i=0; i<n; i+=16 )
	{
		get_log_header(0, txt);
		sprintf(txt+11, "%s", cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i));
		write_to_log(-1, txt);
	}
}

void cs_ddump(uchar *buf, int n, char *fmt, ...)
{
	int i;
	char txt[512];

	//if (((cs_ptyp & client[cs_idx].dbglvl)==cs_ptyp) && (fmt))
	if ((cs_ptyp & client[cs_idx].dbglvl) && (fmt))
	{
		get_log_header(1, txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, txt);
		//printf("LOG: %s\n", txt); fflush(stdout);
	}
	//if (((cs_ptyp | D_DUMP) & client[cs_idx].dbglvl)==(cs_ptyp | D_DUMP))
	if (cs_ptyp & client[cs_idx].dbglvl)
	{
		for (i=0; i<n; i+=16)
		{
			get_log_header(0, txt);
			sprintf(txt+11, "%s", cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i));
			write_to_log(-1, txt);
		}
	}
}

void cs_ddump_mask(unsigned short mask, uchar *buf, int n, char *fmt, ...)
{
	int i;
	char txt[512];

	//if (((cs_ptyp & client[cs_idx].dbglvl)==cs_ptyp) && (fmt))
	if ((mask & client[cs_idx].dbglvl) && (fmt))
	{
		get_log_header(1, txt);
		va_list params;
		va_start(params, fmt);
		vsprintf(txt+11, fmt, params);
		va_end(params);
		write_to_log(-1, txt);
		//printf("LOG: %s\n", txt); fflush(stdout);
	}
	//if (((cs_ptyp | D_DUMP) & client[cs_idx].dbglvl)==(cs_ptyp | D_DUMP))
	if (mask & client[cs_idx].dbglvl)
	{
		for (i=0; i<n; i+=16)
		{
			get_log_header(0, txt);
			sprintf(txt+11, "%s", cs_hexdump(1, buf+i, (n-i>16) ? 16 : n-i));
			write_to_log(-1, txt);
		}
	}
}

int cs_init_statistics(char *file) 
{
	if ((!fps) && (file != NULL))
	{
		if ((fps=fopen(file, "a"))<=(FILE *)0)
		{
			fps=(FILE *)0;
			cs_log("couldn't open statistics file: %s", file);
		}
	}
	return(fps<=(FILE *)0);
}

void cs_statistics(int idx)
{
	time_t t;
	struct tm *lt;

	if (fps)
	{
		float cwps;

		switch_log(cfg->usrfile, &fps, cs_init_statistics);
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
		if(!cfg->mon_appendchaninfo)
			channel = monitor_get_srvname(client[idx].last_srvid,client[idx].last_caid);

		if(!cfg->disableuserfile) {
			fprintf(fps, "%02d.%02d.%02d %02d:%02d:%02d %3.1f %s %s %d %d %d %d %d %d %d %ld %ld %s %04X:%04X %s\n",
					lt->tm_mday, lt->tm_mon+1, lt->tm_year%100,
					lt->tm_hour, lt->tm_min, lt->tm_sec, cwps,
					client[idx].usr[0] ? client[idx].usr : "-",
					cs_inet_ntoa(client[idx].ip), client[idx].port,
					client[idx].cwfound, client[idx].cwcache, client[idx].cwnot, client[idx].cwignored,
					client[idx].cwtout, client[idx].cwtun, client[idx].login, client[idx].last,
					ph[client[idx].ctyp].desc,client[idx].last_caid,client[idx].last_srvid,
					channel);

			fflush(fps);
		}
	}
}
