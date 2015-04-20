#define MODULE_LOG_PREFIX "webif"

#include "globals.h"

#ifdef WEBIF
#include "cscrypt/md5.h"
#include "module-webif-lib.h"
#include "module-webif-tpl.h"
#include "oscam-config.h"
#include "oscam-files.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-net.h"
#if defined(__linux__)
	#include <sys/sysinfo.h>
#elif defined(__APPLE__)
	#include <sys/sysctl.h>
#endif

extern int32_t ssl_active;
extern pthread_key_t getkeepalive;
extern pthread_key_t getssl;
extern CS_MUTEX_LOCK *lock_cs;
extern char noncekey[33];

static struct s_nonce *nonce_first[AUTHNONCEHASHBUCKETS];
static CS_MUTEX_LOCK nonce_lock[AUTHNONCEHASHBUCKETS];

/* Parses a value in an authentication string by removing all quotes/whitespace. Note that the original array is modified. */
static char *parse_auth_value(char *value)
{
	char *pch = value;
	char *pch2;
	value = strstr(value, "=");
	if(value != NULL)
	{
		do
		{
			++value;
		}
		while(value[0] == ' ' || value[0] == '"');
		pch = value;
		for(pch2 = value + strlen(value) - 1; pch2 >= value && (pch2[0] == ' ' || pch2[0] == '"' || pch2[0] == '\r' || pch2[0] == '\n'); --pch2) { pch2[0] = '\0'; }
	}
	return pch;
}

/* Parses the date out of a "If-Modified-Since"-header. Note that the original string is modified. */
time_t parse_modifiedsince(char *value)
{
	int32_t day = -1, month = -1, year = -1, hour = -1, minutes = -1, seconds = -1;
	char months[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	char *str, *saveptr1 = NULL;
	time_t modifiedheader = 0;
	value += 18;
	// Parse over weekday at beginning...
	while(value[0] == ' ' && value[0] != '\0') { ++value; }
	while(value[0] != ' ' && value[0] != '\0') { ++value; }
	// According to http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3.1 three different timeformats are allowed so we need a bit logic to parse all of them...
	if(value[0] != '\0')
	{
		++value;
		for(month = 0; month < 12; ++month)
		{
			if(strstr(value, months[month])) { break; }
		}
		if(month > 11) { month = -1; }
		for(str = strtok_r(value, " ", &saveptr1); str; str = strtok_r(NULL, " ", &saveptr1))
		{
			switch(strlen(str))
			{
			case 1:
			case 2:
				day = atoi(str);
				break;

			case 4:
				if(str[0] != 'G')
					{ year = atoi(str); }
				break;

			case 8:
				if(str[2] == ':' && str[5] == ':')
				{
					hour = atoi(str);
					minutes = atoi(str + 3);
					seconds = atoi(str + 6);
				}
				break;

			case 9:
				if(str[2] == '-' && str[6] == '-')
				{
					day = atoi(str);
					year = atoi(str + 7) + 2000;
				}
				break;
			}
		}
		if(day > 0 && day < 32 && month > 0 && year > 0 && year < 9999 && hour > -1 && hour < 24 && minutes > -1 && minutes < 60 && seconds > -1 && seconds < 60)
		{
			struct tm timeinfo;
			memset(&timeinfo, 0, sizeof(timeinfo));
			timeinfo.tm_mday = day;
			timeinfo.tm_mon = month;
			timeinfo.tm_year = year - 1900;
			timeinfo.tm_hour = hour;
			timeinfo.tm_min = minutes;
			timeinfo.tm_sec = seconds;
			modifiedheader = cs_timegm(&timeinfo);
		}
	}
	return modifiedheader;
}

/* Calculates a new opaque value. Please note that opaque needs to be at least (MD5_DIGEST_LENGTH * 2) + 1 large. */
void calculate_opaque(IN_ADDR_T addr, char *opaque)
{
	char noncetmp[128];
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	snprintf(noncetmp, sizeof(noncetmp), "%d:%s:%d", (int32_t)time(NULL), cs_inet_ntoa(addr), (int16_t)rand());
	char_to_hex(MD5((unsigned char *)noncetmp, strlen(noncetmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char *)opaque);
}

void init_noncelocks(void)
{
	int32_t i;
	for(i = 0; i < AUTHNONCEHASHBUCKETS; ++i)
	{
		cs_lock_create(&nonce_lock[i], "nonce_lock", 5000);
		nonce_first[i] = NULL;
	}
}

/* Calculates the currently valid nonce value and copies it to result. Please note that nonce (may be NULL), opaque and result needs to be at least (MD5_DIGEST_LENGTH * 2) + 1 large. */
void calculate_nonce(char *nonce, char *result, char *opaque)
{
	struct s_nonce *noncelist, *prev, *foundnonce = NULL, *foundopaque = NULL, *foundexpired = NULL;
	int32_t bucket = opaque[0] % AUTHNONCEHASHBUCKETS;
	time_t now = time(NULL);
	cs_writelock(&nonce_lock[bucket]);
	for(noncelist = nonce_first[bucket], prev = NULL; noncelist; prev = noncelist, noncelist = noncelist->next)
	{
		if(now > noncelist->expirationdate)
		{
			if(prev) { prev->next = NULL; }
			else
			{
				nonce_first[bucket] = NULL;
			}
			foundexpired = noncelist;
			break;
		}
		if(nonce && !memcmp(noncelist->nonce, nonce, (MD5_DIGEST_LENGTH * 2) + 1))
		{
			memcpy(result, noncelist->nonce, (MD5_DIGEST_LENGTH * 2) + 1);
			foundnonce = noncelist;
			if(!noncelist->firstuse) { noncelist->firstuse = now; }
			else if(now - foundnonce->firstuse > AUTHNONCEVALIDSECS)
			{
				if(prev) { prev->next = noncelist->next; }
				else
				{
					nonce_first[bucket] = noncelist->next;
				}
			}
			break;
		}
		else if(!noncelist->firstuse && !memcmp(noncelist->opaque, opaque, (MD5_DIGEST_LENGTH * 2) + 1))
		{
			foundopaque = noncelist;
		}
	}
	if(foundnonce && now - foundnonce->firstuse > AUTHNONCEVALIDSECS)
	{
		NULLFREE(foundnonce);
		foundnonce = NULL;
	}
	if(!foundnonce && foundopaque)
		{ memcpy(result, foundopaque->nonce, (MD5_DIGEST_LENGTH * 2) + 1); }
	if(!foundnonce && !foundopaque)
	{
		char noncetmp[128], randstr[16];
		unsigned char md5tmp[MD5_DIGEST_LENGTH];
		get_random_bytes((uint8_t *)randstr, sizeof(randstr) - 1);
		randstr[sizeof(randstr) - 1] = '\0';
		snprintf(noncetmp, sizeof(noncetmp), "%d:%s:%s", (int32_t)now, randstr, noncekey);
		char_to_hex(MD5((unsigned char *)noncetmp, strlen(noncetmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char *)result);
		if(cs_malloc(&noncelist, sizeof(struct s_nonce)))
		{
			noncelist->expirationdate = now + AUTHNONCEEXPIRATION;
			memcpy(noncelist->nonce, result, (MD5_DIGEST_LENGTH * 2) + 1);
			memcpy(noncelist->opaque, opaque, (MD5_DIGEST_LENGTH * 2) + 1);
			noncelist->next = nonce_first[bucket];
			nonce_first[bucket] = noncelist;
		}
	}
	cs_writeunlock(&nonce_lock[bucket]);
	while(foundexpired)
	{
		prev = foundexpired;
		foundexpired = foundexpired->next;
		NULLFREE(prev);
	}
}

/* Checks if authentication is correct. Returns -1 if not correct, 1 if correct and 2 if nonce isn't valid anymore.
   Note that authstring will be modified. */
int32_t check_auth(char *authstring, char *method, char *path, IN_ADDR_T addr, char *expectednonce, char *opaque)
{
	int32_t authok = 0, uriok = 0;
	char authnonce[(MD5_DIGEST_LENGTH * 2) + 1];
	memset(authnonce, 0, sizeof(authnonce));
	char *authnc = "";
	char *authcnonce = "";
	char *authresponse = "";
	char *uri = "";
	char *username = "";
	char *expectedPassword = cfg.http_pwd;
	char *pch = authstring + 22;
	char *pch2;
	char *saveptr1 = NULL;
	memset(opaque, 0, (MD5_DIGEST_LENGTH * 2) + 1);

	for(pch = strtok_r(pch, ",", &saveptr1); pch; pch = strtok_r(NULL, ",", &saveptr1))
	{
		pch2 = pch;
		while(pch2[0] == ' ' && pch2[0] != '\0') { ++pch2; }
		if(strncmp(pch2, "nonce", 5) == 0)
		{
			cs_strncpy(authnonce, parse_auth_value(pch2), sizeof(authnonce));
		}
		else if(strncmp(pch2, "nc", 2) == 0)
		{
			authnc = parse_auth_value(pch2);
		}
		else if(strncmp(pch2, "cnonce", 6) == 0)
		{
			authcnonce = parse_auth_value(pch2);
		}
		else if(strncmp(pch2, "response", 8) == 0)
		{
			authresponse = parse_auth_value(pch2);
		}
		else if(strncmp(pch2, "uri", 3) == 0)
		{
			uri = parse_auth_value(pch2);
		}
		else if(strncmp(pch2, "username", 8) == 0)
		{
			username = parse_auth_value(pch2);
		}
		else if(strncmp(pch2, "opaque", 6) == 0)
		{
			char *tmp = parse_auth_value(pch2);
			cs_strncpy(opaque, tmp, (MD5_DIGEST_LENGTH * 2) + 1);
		}
	}

	if(strncmp(uri, path, strlen(path)) == 0) { uriok = 1; }
	else
	{
		pch2 = uri;
		for(pch = uri; pch[0] != '\0'; ++pch)
		{
			if(pch[0] == '/') { pch2 = pch; }
			if(strncmp(pch2, path, strlen(path)) == 0) { uriok = 1; }
		}
	}
	if(uriok == 1 && streq(username, cfg.http_user))
	{
		char A1tmp[3 + strlen(username) + strlen(AUTHREALM) + strlen(expectedPassword)];
		char A1[(MD5_DIGEST_LENGTH * 2) + 1], A2[(MD5_DIGEST_LENGTH * 2) + 1], A3[(MD5_DIGEST_LENGTH * 2) + 1];
		unsigned char md5tmp[MD5_DIGEST_LENGTH];
		snprintf(A1tmp, sizeof(A1tmp), "%s:%s:%s", username, AUTHREALM, expectedPassword);
		char_to_hex(MD5((unsigned char *)A1tmp, strlen(A1tmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char *)A1);

		char A2tmp[2 + strlen(method) + strlen(uri)];
		snprintf(A2tmp, sizeof(A2tmp), "%s:%s", method, uri);
		char_to_hex(MD5((unsigned char *)A2tmp, strlen(A2tmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char *)A2);

		char A3tmp[10 + strlen(A1) + strlen(A2) + strlen(authnonce) + strlen(authnc) + strlen(authcnonce)];
		snprintf(A3tmp, sizeof(A3tmp), "%s:%s:%s:%s:auth:%s", A1, authnonce, authnc, authcnonce, A2);
		char_to_hex(MD5((unsigned char *)A3tmp, strlen(A3tmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char *)A3);

		if(strcmp(A3, authresponse) == 0)
		{
			if(strlen(opaque) != MD5_DIGEST_LENGTH * 2) { calculate_opaque(addr, opaque); }
			calculate_nonce(authnonce, expectednonce, opaque);
			if(strcmp(expectednonce, authnonce) == 0) { authok = 1; }
			else
			{
				authok = 2;
				cs_log_dbg(D_TRACE, "WebIf: Received stale header from %s (nonce=%s, expectednonce=%s, opaque=%s).", cs_inet_ntoa(addr), authnonce, expectednonce, opaque);
			}
		}
	}
	return authok;
}

int32_t webif_write_raw(char *buf, FILE *f, int32_t len)
{
	errno = 0;
#ifdef WITH_SSL
	if(ssl_active)
	{
		return SSL_write((SSL *)f, buf, len);
	}
	else
#endif
		return fwrite(buf, 1, len, f);
}

int32_t webif_write(char *buf, FILE *f)
{
	return webif_write_raw(buf, f, strlen(buf));
}

int32_t webif_read(char *buf, int32_t num, FILE *f)
{
	errno = 0;
#ifdef WITH_SSL
	if(ssl_active)
	{
		return SSL_read((SSL *)f, buf, num);
	}
	else
#endif
		return read(fileno(f), buf, num);
}

void send_headers(FILE *f, int32_t status, char *title, char *extra, char *mime, int32_t cache, int32_t length, char *content, int8_t forcePlain)
{
	time_t now;
	char timebuf[32];
	char buf[sizeof(PROTOCOL) + sizeof(SERVER) + strlen(title) + (extra == NULL ? 0 : strlen(extra) + 2) + (mime == NULL ? 0 : strlen(mime) + 2) + 350];
	char *pos = buf;
	struct tm timeinfo;

	pos += snprintf(pos, sizeof(buf) - (pos - buf), "%s %d %s\r\n", PROTOCOL, status, title);
	pos += snprintf(pos, sizeof(buf) - (pos - buf), "Server: %s\r\n", SERVER);

	now = time(NULL);
	cs_gmtime_r(&now, &timeinfo);
	strftime(timebuf, sizeof(timebuf), RFC1123FMT, &timeinfo);
	pos += snprintf(pos, sizeof(buf) - (pos - buf), "Date: %s\r\n", timebuf);

	if(extra)
		{ pos += snprintf(pos, sizeof(buf) - (pos - buf), "%s\r\n", extra); }

	if(mime)
		{ pos += snprintf(pos, sizeof(buf) - (pos - buf), "Content-Type: %s\r\n", mime); }

	if(status != 304)
	{
		if(!cache)
		{
			pos += snprintf(pos, sizeof(buf) - (pos - buf), "Cache-Control: no-store, no-cache, must-revalidate\r\n");
			pos += snprintf(pos, sizeof(buf) - (pos - buf), "Expires: Sat, 10 Jan 2000 05:00:00 GMT\r\n");
		}
		else
		{
			pos += snprintf(pos, sizeof(buf) - (pos - buf), "Cache-Control: public, max-age=7200\r\n");
		}
		pos += snprintf(pos, sizeof(buf) - (pos - buf), "Content-Length: %d\r\n", length);
		pos += snprintf(pos, sizeof(buf) - (pos - buf), "Last-Modified: %s\r\n", timebuf);
		if(content)
		{
			uint32_t checksum = (uint32_t)crc32(0L, (uchar *)content, length);
			pos += snprintf(pos, sizeof(buf) - (pos - buf), "ETag: \"%u\"\r\n", checksum == 0 ? 1 : checksum);
		}
	}
	if(*(int8_t *)pthread_getspecific(getkeepalive))
		{ pos += snprintf(pos, sizeof(buf) - (pos - buf), "Connection: Keep-Alive\r\n"); }
	else
		{ pos += snprintf(pos, sizeof(buf) - (pos - buf), "Connection: close\r\n"); }
	snprintf(pos, sizeof(buf) - (pos - buf), "\r\n");
	if(forcePlain == 1) { fwrite(buf, 1, strlen(buf), f); }
	else { webif_write(buf, f); }
}

void send_error(FILE *f, int32_t status, char *title, char *extra, char *text, int8_t forcePlain)
{
	char buf[(2 * strlen(title)) + strlen(text) + 128];
	char *pos = buf;
	pos += snprintf(pos, sizeof(buf) - (pos - buf), "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\r\n", status, title);
	pos += snprintf(pos, sizeof(buf) - (pos - buf), "<BODY><H4>%d %s</H4>\r\n", status, title);
	pos += snprintf(pos, sizeof(buf) - (pos - buf), "%s\r\n", text);
	snprintf(pos, sizeof(buf) - (pos - buf), "</BODY></HTML>\r\n");
	send_headers(f, status, title, extra, "text/html", 0, strlen(buf), NULL, forcePlain);
	if(forcePlain == 1) { fwrite(buf, 1, strlen(buf), f); }
	else { webif_write(buf, f); }
}

void send_error500(FILE *f)
{
	send_error(f, 500, "Internal Server Error", NULL, "The server encountered an internal error that prevented it from fulfilling this request.", 0);
}

void send_header304(FILE *f, char *extraheader)
{
	send_headers(f, 304, "Not Modified", extraheader, NULL, 1, 0, NULL, 0);
}

/*
 * function for sending files.
 */
void send_file(FILE *f, char *filename, char *subdir, time_t modifiedheader, uint32_t etagheader, char *extraheader)
{
	int8_t filen = 0;
	int32_t size = 0;
	char *mimetype = "", *result = " ", *allocated = NULL;
	time_t moddate;
	char path[255];
	char *CSS = NULL;
	char *JSCRIPT = NULL;
	char *JQUERY = NULL;
	char *TOUCH_CSS = NULL;
	char *TOUCH_JSCRIPT = NULL;

	if(!strcmp(filename, "CSS"))
	{
		filename = cfg.http_css ? cfg.http_css : "";
		if(subdir && strlen(subdir) > 0)
		{
			filename = tpl_getFilePathInSubdir(cfg.http_tpl ? cfg.http_tpl : "", subdir, "site", ".css", path, 255);
		}
		mimetype = "text/css";
		filen = 1;
	}
	else if(!strcmp(filename, "JS"))
	{
		filename = cfg.http_jscript ? cfg.http_jscript : "";
		if(subdir && strlen(subdir) > 0)
		{
			filename = tpl_getFilePathInSubdir(cfg.http_tpl ? cfg.http_tpl : "", subdir, "oscam", ".js", path, 255);
		}
		mimetype = "text/javascript";
		filen = 2;
	}
	else if(!strcmp(filename, "JQ"))
	{
		if(subdir && strlen(subdir) > 0)
		{
			filename = tpl_getFilePathInSubdir(cfg.http_tpl ? cfg.http_tpl : "", subdir, "jquery", ".js", path, 255);
		}
		mimetype = "text/javascript";
		filen = 3;
	}

	if(strlen(filename) > 0 && file_exists(filename))
	{
		struct stat st;
		stat(filename, &st);
		moddate = st.st_mtime;
		// We need at least size 1 or keepalive gets problems on some browsers...
		if(st.st_size > 0)
		{
			FILE *fp;
			int32_t readen;
			if((fp = fopen(filename, "r")) == NULL) { return; }
			if(!cs_malloc(&allocated, st.st_size + 1))
			{
				send_error500(f);
				fclose(fp);
				return;
			}
			if((readen = fread(allocated, 1, st.st_size, fp)) == st.st_size)
			{
				allocated[readen] = '\0';
			}
			fclose(fp);
		}

		if(filen == 1 && cfg.http_prepend_embedded_css)    // Prepend Embedded CSS
		{
			char separator [255];
			snprintf(separator, 255, "\n/* Beginn embedded CSS File: %s */\n", cfg.http_css);
			char *oldallocated = allocated;
			CSS = tpl_getUnparsedTpl("CSS", 1, "");
			int32_t newsize = strlen(CSS) + strlen(separator) + 2;
			if(oldallocated) { newsize += strlen(oldallocated) + 1; }
			if(!cs_malloc(&allocated, newsize))
			{
				if(oldallocated) { NULLFREE(oldallocated); }
				NULLFREE(CSS);
				send_error500(f);
				return;
			}
			if (CSS){
				snprintf(allocated, newsize, "%s\n%s\n%s", CSS, separator, (oldallocated != NULL ? oldallocated : ""));
			}
			if(oldallocated) { NULLFREE(oldallocated); }
		}

		if(allocated) { result = allocated; }

	}
	else
	{
		CSS = tpl_getUnparsedTpl("CSS", 1, "");
		JSCRIPT = tpl_getUnparsedTpl("JSCRIPT", 1, "");
		JQUERY = tpl_getUnparsedTpl("JQUERY", 1, "");
#ifdef TOUCH
		TOUCH_CSS = tpl_getUnparsedTpl("TOUCH_CSS", 1, "");
		TOUCH_JSCRIPT = tpl_getUnparsedTpl("TOUCH_JSCRIPT", 1, "");

		if(!subdir || strcmp(subdir, TOUCH_SUBDIR)) {
			if( filen == 1 && strlen(CSS)){ result = CSS; }
			else if ( filen == 2 && strlen(JSCRIPT)){ result = JSCRIPT; }
			else if ( filen == 3 && strlen(JQUERY)){ result = JQUERY; }
		} else {
			if( filen == 1 && strlen(TOUCH_CSS)){ result = TOUCH_CSS; }
			else if ( filen == 2 && strlen(TOUCH_JSCRIPT)){ result = TOUCH_JSCRIPT; }
			else if ( filen == 3 && strlen(JQUERY)){ result = JQUERY; }
		}
#else
		if(filen == 1 && strlen(CSS) > 0){ result = CSS;}
		else if(filen == 2 && strlen(JSCRIPT) > 0){result = JSCRIPT;}
		else if(filen == 3 && strlen(JQUERY) > 0){result = JQUERY;}
#endif
		moddate = first_client->login;
	}

	size = strlen(result);

	if((etagheader == 0 && moddate < modifiedheader) || (etagheader > 0 && (uint32_t)crc32(0L, (uchar *)result, size) == etagheader))
	{
		send_header304(f, extraheader);
	}
	else
	{
		send_headers(f, 200, "OK", NULL, mimetype, 1, size, result, 0);
		webif_write(result, f);
	}
	if(allocated) { NULLFREE(allocated); }
	NULLFREE(CSS);
	NULLFREE(JSCRIPT);
	NULLFREE(JQUERY);
	NULLFREE(TOUCH_CSS);
	NULLFREE(TOUCH_JSCRIPT);
}

/* Parse url parameters and save them to params array. The pch pointer is increased to the position where parsing stopped. */
void parseParams(struct uriparams *params, char *pch)
{
	char *pch2;
	// parsemode = 1 means parsing next param, parsemode = -1 parsing next
	//value; pch2 points to the beginning of the currently parsed string, pch is the current position
	int32_t parsemode = 1;

	pch2 = pch;
	while(pch[0] != '\0')
	{
		if((parsemode == 1 && pch[0] == '=') || (parsemode == -1 && pch[0] == '&'))
		{
			pch[0] = '\0';
			urldecode(pch2);
			if(parsemode == 1)
			{
				if(params->paramcount >= MAXGETPARAMS) { break; }
				++params->paramcount;
				params->params[params->paramcount - 1] = pch2;
			}
			else
			{
				params->values[params->paramcount - 1] = pch2;
			}
			parsemode = -parsemode;
			pch2 = pch + 1;
		}
		++pch;
	}
	/* last value wasn't processed in the loop yet... */
	if(parsemode == -1 && params->paramcount <= MAXGETPARAMS)
	{
		urldecode(pch2);
		params->values[params->paramcount - 1] = pch2;
	}
}

/* Returns the value of the parameter called name or an empty string if it doesn't exist. */
char *getParam(struct uriparams *params, char *name)
{
	int32_t i;
	for(i = (*params).paramcount - 1; i >= 0; --i)
	{
		if(strcmp((*params).params[i], name) == 0) { return (*params).values[i]; }
	}
	return "";
}

/*
 * returns uptime in sec on success, -1 on error
*/
int32_t oscam_get_uptime(void)
{
#if defined(__linux__)
	struct sysinfo uptime;
	if(!sysinfo(&uptime)){
		return (int32_t)uptime.uptime;
	}
	else{
		return -1;
	}
#elif defined(__APPLE__)
	struct timeval boottime;
	size_t len = sizeof(boottime);
	int mib[2] = { CTL_KERN, KERN_BOOTTIME };
	if(sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 ){
		return -1;
	}
	time_t bsec = boottime.tv_sec, csec = time(NULL);

	return difftime(csec, bsec);
#else
	return -1;
#endif
}

#if defined(__linux__)
/*
 * read /proc data into the passed struct pstat
 * returns 0 on success, -1 on error
*/
int8_t get_stats_linux(const pid_t pid, struct pstat* result)
{
	// convert pid to string
	char pid_s[20];
	snprintf(pid_s, sizeof(pid_s), "%d", pid);
	char stat_filepath[30] = "/proc/"; strncat(stat_filepath, pid_s,
			sizeof(stat_filepath) - strlen(stat_filepath) -1);
	strncat(stat_filepath, "/stat", sizeof(stat_filepath) -
			strlen(stat_filepath) -1);

	FILE *f_pstat = fopen(stat_filepath, "r");
	if (f_pstat == NULL) {
		cs_log("FOPEN ERROR %s",stat_filepath);
		return -1;
	}

	FILE *f_stat = fopen("/proc/stat", "r");
	if (!f_stat) {
		fclose(f_pstat);
		cs_log("ERROR: Can't open /proc/stat for reading: %s", strerror(errno));
		return -1;
	}

	// read values from /proc/pid/stat
	uint64_t rss;
	if (fscanf(f_pstat, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %" SCNd64
				"%" SCNd64 "%" SCNd64 "%" SCNd64 "%*d %*d %*d %*d %*u %" SCNu64 "%" SCNu64,
				&result->utime_ticks,&result->stime_ticks,
				&result->cutime_ticks,&result->cstime_ticks,&result->vsize,
				&rss) == EOF)
	{
		fclose(f_pstat);
		fclose(f_stat);
		return -1;
	}
	fclose(f_pstat);
	result->rss = rss * getpagesize();

	// read+calc cpu total time from /proc/stat
	int64_t cpu_time[10] = {0,0,0,0,0,0,0,0,0,0};
	if (fscanf(f_stat, "%*s %" SCNd64 "%" SCNd64 "%" SCNd64 "%" SCNd64 "%" SCNd64 "%" SCNd64 "%" SCNd64 "%" SCNd64 "%" SCNd64 "%" SCNd64,
				&cpu_time[0], &cpu_time[1], &cpu_time[2], &cpu_time[3],
				&cpu_time[4], &cpu_time[5], &cpu_time[6], &cpu_time[7],
				&cpu_time[8], &cpu_time[9]) == EOF)
	{
		fclose(f_stat);
		return -1;
	}
	fclose(f_stat);
	int8_t i;
	result->cpu_total_time = 0;
	// FIXME: On 32 Bit platforms, the single cpu times can overflow quite easily (clock_t from /proc/stat normally refers to a int32 here) resulting in useless calculation results!
	for(i = 0; i < 10; i++) {
		result->cpu_total_time += cpu_time[i];
	}

	// read cached from /proc/meminfo
	uint64_t meminfo_cached = 0;
	FILE *fd = fopen("/proc/meminfo", "r");
	if (fd ) {
		char line[256];
		while(fgets(line, sizeof(line), fd)) {
			if(sscanf(line, "Cached: %" PRId64" \n kB", &meminfo_cached) == 1){
				break;
			}
		}
	}
	fclose(fd);

	// read processes from /proc
	uint info_procs = 0;
	DIR *hdir;
	if((hdir = opendir("/proc")) != NULL){
		struct dirent entry;
		struct dirent *dirresult;
		while(cs_readdir_r(hdir, &entry, &dirresult) == 0 && dirresult != NULL)
		{
			if (entry.d_name[0] > '0' && entry.d_name[0] <= '9') { info_procs++; }
		}
		closedir(hdir);
	}

	// read cpu/meminfo from sysinfo()
	struct sysinfo info;
	float shiftfloat = (float)(1 << SI_LOAD_SHIFT);
	if (!sysinfo(&info)) {
		// processes
		result->info_procs = info_procs;
		// cpu load
		result->cpu_avg[0] = (float) info.loads[0] / shiftfloat;
		result->cpu_avg[1] = (float) info.loads[1] / shiftfloat;
		result->cpu_avg[2] = (float) info.loads[2] / shiftfloat;
		// meminfo
		result->mem_total = info.totalram  * info.mem_unit;
		result->mem_free = info.freeram * info.mem_unit;
		result->mem_used = result->mem_total - result->mem_free;
		result->mem_buff = info.bufferram * info.mem_unit;
		result->mem_cached = meminfo_cached * 1024;
		result->mem_freem = result->mem_free + result->mem_buff + result->mem_cached;
		result->mem_share = info.sharedram * info.mem_unit;
		result->mem_total_swap = info.totalswap * info.mem_unit;
		result->mem_free_swap = info.freeswap * info.mem_unit;
		result->mem_used_swap = result->mem_total_swap - result->mem_free_swap;
	}

	// set timestamp for function call
	cs_ftime(&result->time_started);

	return 0;
}

/*
* calculates the elapsed CPU usage between 2 measuring points. in percent and stores to cur_usage
*/
void calc_cpu_usage_pct(struct pstat* cur_usage, struct pstat* last_usage)
{
	const double total_time_diff = cur_usage->cpu_total_time - last_usage->cpu_total_time;

	//time difference between cur_usage/last_usage when created / in sec
	cur_usage->gone_refresh = comp_timeb(&cur_usage->time_started, &last_usage->time_started)/1000;

	if(cur_usage->gone_refresh < 1){
		//set to N/A since result may provide wrong results (/proc not updated)
		cur_usage->check_available |= (1 << 9);
		cur_usage->check_available |= (1 << 10);
		cur_usage->check_available |= (1 << 11);
	}
	else{
		int64_t cur_ticks = cur_usage->utime_ticks + cur_usage->cutime_ticks;
		int64_t last_ticks = last_usage->utime_ticks + last_usage->cutime_ticks;
		//reset flags if set bevore
		cur_usage->check_available &= ~(1 << 9);
		cur_usage->check_available &= ~(1 << 10);
		cur_usage->check_available &= ~(1 << 11);

		cur_usage->cpu_usage_user = 100.0 * llabs(cur_ticks - last_ticks) / total_time_diff;

		cur_ticks = cur_usage->stime_ticks + cur_usage->cstime_ticks;
		last_ticks = last_usage->stime_ticks + last_usage->cstime_ticks;

		cur_usage->cpu_usage_sys = 100.0 * llabs(cur_ticks - last_ticks) / total_time_diff;
	}
}
#endif

#ifdef WITH_SSL
SSL *cur_ssl(void)
{
	return (SSL *) pthread_getspecific(getssl);
}

/* Locking functions for SSL multithreading */
struct CRYPTO_dynlock_value
{
	pthread_mutex_t mutex;
};

/* function really needs unsigned long to prevent compiler warnings... */
static unsigned long SSL_id_function(void)
{
	return ((unsigned long) pthread_self());
}

static void SSL_locking_function(int32_t mode, int32_t type, const char *file, int32_t line)
{
	if(mode & CRYPTO_LOCK)
	{
		cs_writelock(&lock_cs[type]);
	}
	else
	{
		cs_writeunlock(&lock_cs[type]);
	}
	// just to remove compiler warnings...
	if(file || line) { return; }
}

static struct CRYPTO_dynlock_value *SSL_dyn_create_function(const char *file, int32_t line)
{
	struct CRYPTO_dynlock_value *l;
	if(!cs_malloc(&l, sizeof(struct CRYPTO_dynlock_value)))
		{ return NULL; }

	if(pthread_mutex_init(&l->mutex, NULL))
	{
		// Initialization of mutex failed.
		NULLFREE(l);
		return (NULL);
	}
	pthread_mutex_init(&l->mutex, NULL);
	// just to remove compiler warnings...
	if(file || line) { return l; }
	return l;
}

static void SSL_dyn_lock_function(int32_t mode, struct CRYPTO_dynlock_value *l, const char *file, int32_t line)
{
	if(mode & CRYPTO_LOCK)
	{
		pthread_mutex_lock(&l->mutex);
	}
	else
	{
		pthread_mutex_unlock(&l->mutex);
	}
	// just to remove compiler warnings...
	if(file || line) { return; }
}

static void SSL_dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int32_t line)
{
	pthread_mutex_destroy(&l->mutex);
	NULLFREE(l);
	// just to remove compiler warnings...
	if(file || line) { return; }
}

/* Init necessary structures for SSL in WebIf*/
SSL_CTX *SSL_Webif_Init(void)
{
	SSL_CTX *ctx;

	static const char *cs_cert = "oscam.pem";

	if(pthread_key_create(&getssl, NULL))
	{
		cs_log("Could not create getssl");
	}

	// set locking callbacks for SSL
	int32_t i, num = CRYPTO_num_locks();
	lock_cs = (CS_MUTEX_LOCK *) OPENSSL_malloc(num * sizeof(CS_MUTEX_LOCK));

	for(i = 0; i < num; ++i)
	{
		cs_lock_create(&lock_cs[i], "ssl_lock_cs", 10000);
	}
	/* static lock callbacks */
	CRYPTO_set_id_callback(SSL_id_function);
	CRYPTO_set_locking_callback(SSL_locking_function);
	/* dynamic lock callbacks */
	CRYPTO_set_dynlock_create_callback(SSL_dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(SSL_dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(SSL_dyn_destroy_function);

	if(cfg.http_force_sslv3)
	{
		ctx = SSL_CTX_new(SSLv3_server_method());
#ifdef SSL_CTX_clear_options
		SSL_CTX_clear_options(ctx, SSL_OP_ALL); //we CLEAR all bug workarounds! This is for security reason
#else
		cs_log("WARNING: You enabled to force sslv3 but your system does not support to clear the ssl workarounds! SSL security will be reduced!");
#endif
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2); // we force SSL v3 !
		SSL_CTX_set_cipher_list(ctx, SSL_TXT_RC4);
	}
	else
		{ ctx = SSL_CTX_new(SSLv23_server_method()); }

	char path[128];

	if(!cfg.http_cert)
		{ get_config_filename(path, sizeof(path), cs_cert); }
	else
		{ cs_strncpy(path, cfg.http_cert, sizeof(path)); }

	if(!ctx)
		goto out_err;

	if(SSL_CTX_use_certificate_file(ctx, path, SSL_FILETYPE_PEM) <= 0)
		goto out_err;

	if(SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM) <= 0)
		goto out_err;

	if(!SSL_CTX_check_private_key(ctx))
	{
		cs_log("SSL: Private key does not match the certificate public key");
		goto out_err;
	}

	cs_log("load ssl certificate file %s", path);
	return ctx;

out_err:
	ERR_print_errors_fp(stderr);
	ERR_remove_state(0);
	SSL_CTX_free(ctx);
	return NULL;
}
#endif

#endif
