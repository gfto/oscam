//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#ifdef WEBIF

#include "module-webif-lib.h"
#include "module-webif-pages.h"
#include "oscam-config-funcs.h"
#include "oscam-files.h"

extern const char *tpl[][3];
extern char *JSCRIPT;
extern char *CSS;

#ifdef TOUCH
#define TOUCH_SUBDIR "touch/"
extern char *TOUCH_JSCRIPT;
extern char *TOUCH_CSS;
extern char *TOUCH_TPLSTATUS;
#endif

extern int32_t ssl_active;
extern pthread_key_t getkeepalive;
extern pthread_key_t getssl;
extern CS_MUTEX_LOCK *lock_cs;
extern char noncekey[33];

static int8_t b64decoder[256];
static int8_t *tplchksum;

/* Adds a name->value-mapping or appends to it. You will get a reference back which you may freely
   use (but you should not call free/realloc on this!)*/
char *tpl_addVar(struct templatevars *vars, uint8_t addmode, char *name, char *value){
	if(name == NULL || value == NULL) return "";
	int32_t i;
	char *tmp,*result = NULL;
	for(i = (*vars).varscnt-1; i >= 0; --i){
		if(strcmp((*vars).names[i], name) == 0){
			result = (*vars).values[i];
			break;
		}
	}
	if(result == NULL){
		if((*vars).varsalloc <= (*vars).varscnt){
			if(!cs_realloc(&(*vars).names, (*vars).varsalloc * 2 * sizeof(char**), -1)) return "";
			if(!cs_realloc(&(*vars).values, (*vars).varsalloc * 2 * sizeof(char**), -1)) return "";
			if(!cs_realloc(&(*vars).vartypes, (*vars).varsalloc * 2 * sizeof(uint8_t*), -1)) return "";
			(*vars).varsalloc = (*vars).varscnt * 2;
		}
		int32_t len = strlen(name) + 1;
		if(!cs_malloc(&tmp, len * sizeof(char), -1)) return "";
		memcpy(tmp, name, len);
		(*vars).names[(*vars).varscnt] = tmp;

		len = strlen(value) + 1;
		if(!cs_malloc(&tmp, len * sizeof(char), -1)){
			free((*vars).names[(*vars).varscnt]);
			return "";
		}
		memcpy(tmp, value, len);
		(*vars).values[(*vars).varscnt] = tmp;
		(*vars).vartypes[(*vars).varscnt] = addmode;
		(*vars).varscnt++;
	} else {
		int32_t oldlen = 0, newlen = strlen(value);
		if(addmode == TPLAPPEND || addmode == TPLAPPENDONCE) oldlen = strlen((*vars).values[i]);
		if(!cs_realloc(&((*vars).values[i]), (oldlen + newlen + 1) * sizeof(char), -1)) return value;
		memcpy((*vars).values[i] + oldlen, value, newlen + 1);
		(*vars).vartypes[i] = addmode;
	}
	return tmp;
}

/* Adds a message to be output on the page using the TPLMESSAGE template. */
char *tpl_addMsg(struct templatevars *vars, char *value){
	tpl_addVar(vars, TPLADDONCE, "MESSAGE", value);
	(*vars).messages++;
	return tpl_addVar(vars, TPLAPPEND, "MESSAGES", tpl_getTpl(vars, "MESSAGEBIT"));
}

/* Allows to add a char array which has been allocated by malloc. It will automatically get
  freed when calling tpl_clear(). Please do NOT free the memory yourself or realloc
  it after having added the array here! */
char *tpl_addTmp(struct templatevars *vars, char *value){
	if(value == NULL) return "";
	if((*vars).tmpalloc <= (*vars).tmpcnt){
		if(!cs_realloc (&(*vars).tmp, (*vars).tmpalloc * 2 * sizeof(char**), -1)) return value;
		(*vars).tmpalloc = (*vars).tmpcnt * 2;
	}
	(*vars).tmp[(*vars).tmpcnt] = value;
	(*vars).tmpcnt++;
	return value;
}

/* Allows to do a dynamic printf without knowing and defining the needed memory size. If you specify
   varname, the printf-result will be added/appended to the varlist, if varname=NULL it will only be returned.
   In either case you will always get a reference back which you may freely use (but you should not call
   free/realloc on this as it will be automatically cleaned!)*/
char *tpl_printf(struct templatevars *vars, uint8_t addmode, char *varname, char *fmtstring, ...){
	uint32_t needed;
	char test[1];
	va_list argptr;

	va_start(argptr,fmtstring);
	needed = vsnprintf(test, 1, fmtstring, argptr);
	va_end(argptr);

	char *result;
	if(!cs_malloc(&result, (needed + 1) * sizeof(char), -1)) return "";
	va_start(argptr,fmtstring);
	vsnprintf(result, needed + 1, fmtstring, argptr);
	va_end(argptr);

	if(varname == NULL) tpl_addTmp(vars, result);
	else {
		char *tmp = tpl_addVar(vars, addmode, varname, result);
		free(result);
		result = tmp;
	}
	return result;
}

/* Returns the value for a name or an empty string if nothing was found. */
char *tpl_getVar(struct templatevars *vars, char *name){
	int32_t i;
	char *result = NULL;
	for(i = (*vars).varscnt-1; i >= 0; --i){
		if(strcmp((*vars).names[i], name) == 0){
			result = (*vars).values[i];
			break;
		}
	}
	if(result == NULL) return "";
	else {
		if((*vars).vartypes[i] == TPLADDONCE || (*vars).vartypes[i] == TPLAPPENDONCE){
			// This is a one-time-use variable which gets cleaned up automatically after retrieving it
			if(!cs_malloc(&(*vars).values[i], 1 * sizeof(char), -1)){
				(*vars).values[i] = result;
				result[0] = '\0';
				return result;
			} else {
				(*vars).values[i][0] = '\0';
				return tpl_addTmp(vars, result);
			}
		} else return result;
	}
}

/* Initializes all variables for a templatevar-structure and returns a pointer to it. Make
   sure to call tpl_clear() when you are finished or you'll run into a memory leak! */
struct templatevars *tpl_create(void) {
	struct templatevars *vars;
	if(!cs_malloc(&vars, sizeof(struct templatevars), -1)) return NULL;
	(*vars).varsalloc = 64;
	(*vars).varscnt = 0;
	(*vars).tmpalloc = 64;
	(*vars).tmpcnt = 0;
	if(!cs_malloc(&(*vars).names, (*vars).varsalloc * sizeof(char**), -1)){
		free(vars);
		return NULL;
	}
	if(!cs_malloc(&(*vars).values, (*vars).varsalloc * sizeof(char**), -1)){
		free((*vars).names);
		free(vars);
		return NULL;
	};
	if(!cs_malloc(&(*vars).vartypes, (*vars).varsalloc * sizeof(uint8_t*), -1)){
		free((*vars).names);
		free((*vars).values);
		free(vars);
		return NULL;
	};
	if(!cs_malloc(&(*vars).tmp, (*vars).tmpalloc * sizeof(char**), -1)){
		free((*vars).names);
		free((*vars).values);
		free((*vars).vartypes);
		free(vars);
		return NULL;
	};
	return vars;
}

/* Clears all allocated memory for the specified templatevar-structure. */
void tpl_clear(struct templatevars *vars){
	int32_t i;
	for(i = (*vars).varscnt-1; i >= 0; --i){
		free((*vars).names[i]);
		free((*vars).values[i]);
	}
	free((*vars).names);
	free((*vars).values);
	free((*vars).vartypes);
	for(i = (*vars).tmpcnt-1; i >= 0; --i){
		free((*vars).tmp[i]);
	}
	free((*vars).tmp);
	free(vars);
}

/* Creates a path to a template file. You need to set the resultsize to the correct size of result. */
char *tpl_getFilePathInSubdir(const char *path, const char* subdir, const char *name, const char* ext, char *result, uint32_t resultsize){
	int path_len = strlen(path);
	const char *path_fixup = "";
	if (path_len && path[path_len - 1] != '/')
		path_fixup = "/";
	if (path_len + strlen(path_fixup) + strlen(name) + strlen(subdir) + strlen(ext) < resultsize) {
		snprintf(result, resultsize, "%s%s%s%s%s", path, path_fixup, subdir, name, ext);
	} else result[0] = '\0';

	return result;
}

char *tpl_getTplPath(const char *name, const char *path, char *result, uint32_t resultsize){
	return tpl_getFilePathInSubdir(path, "", name, ".tpl", result,  resultsize);
}

#define check_conf(CONFIG_VAR, text) \
	if(config_##CONFIG_VAR() && strncmp(#CONFIG_VAR, text, len) == 0) {ok = 1; break;}

/* Returns an unparsed template either from disk or from internal templates.
   Note: You must free() the result after using it and you may get NULL if an error occured!*/
static char *tpl_getUnparsedTpl(const char* name, int8_t removeHeader, const char* subdir){
  int32_t i;  
  int32_t tplcnt = tpl_count();
  char *result;

  if (cfg.http_tpl) {
  	char path[255];
  	if ( (strlen(tpl_getFilePathInSubdir(cfg.http_tpl, subdir, name, ".tpl", path, 255)) > 0 && file_exists(path))
      || (strlen(subdir) > 0
       && strlen(tpl_getFilePathInSubdir(cfg.http_tpl, ""    , name, ".tpl", path, 255)) > 0 && file_exists(path))) {
			FILE *fp;
			char buffer[1024];
			memset(buffer, 0, sizeof(buffer));
			int32_t read, allocated = 1025, offset, size = 0;
			if(!cs_malloc(&result, allocated * sizeof(char), -1)) return NULL;
			if((fp = fopen(path,"r"))!=NULL){
			while((read = fread(&buffer,sizeof(char),1024,fp)) > 0){
				offset = 0;
				if(size == 0 && removeHeader){
					/* Remove version string from output and check if it is valid for output */
					char *pch1 = strstr(buffer,"<!--OSCam");
					if(pch1 != NULL){
						char *pch2 = strstr(pch1,"-->");
						if(pch2 != NULL){
							offset = pch2 - buffer + 4;
							read -= offset;
							pch2[0] = '\0';
							char *ptr1, *ptr2, *saveptr1 = NULL, *saveptr2 = NULL;
							for (i = 0, ptr1 = strtok_r(pch1 + 10, ";", &saveptr1); (ptr1) && i < 4 ; ptr1 = strtok_r(NULL, ";", &saveptr1), i++){
								if(i == 3 && strlen(ptr1) > 2){
									int8_t ok = 0;
									for (ptr2 = strtok_r(ptr1, ",", &saveptr2); (ptr2) && ok == 0 ; ptr2 = strtok_r(NULL, ",", &saveptr2)){
										size_t len = strlen(ptr2);
										check_conf(CS_ANTICASC, ptr2);
										check_conf(CS_CACHEEX, ptr2);
										check_conf(HAVE_DVBAPI, ptr2);
										check_conf(IPV6SUPPORT, ptr2);
										check_conf(IRDETO_GUESSING, ptr2);
										check_conf(LCDSUPPORT, ptr2);
										check_conf(LEDSUPPORT, ptr2);
										check_conf(MODULE_CAMD33, ptr2);
										check_conf(MODULE_CAMD35, ptr2);
										check_conf(MODULE_CAMD35_TCP, ptr2);
										check_conf(MODULE_CCCAM, ptr2);
										check_conf(MODULE_CCCSHARE, ptr2);
										check_conf(MODULE_CONSTCW, ptr2);
										check_conf(MODULE_GBOX, ptr2);
										check_conf(MODULE_MONITOR, ptr2);
										check_conf(MODULE_NEWCAMD, ptr2);
										check_conf(MODULE_PANDORA, ptr2);
										check_conf(MODULE_RADEGAST, ptr2);
										check_conf(MODULE_SERIAL, ptr2);
										check_conf(READER_BULCRYPT, ptr2);
										check_conf(READER_CONAX, ptr2);
										check_conf(READER_CRYPTOWORKS, ptr2);
										check_conf(READER_DRE, ptr2);
										check_conf(READER_IRDETO, ptr2);
										check_conf(READER_NAGRA, ptr2);
										check_conf(READER_SECA, ptr2);
										check_conf(READER_TONGFANG, ptr2);
										check_conf(READER_VIACCESS, ptr2);
										check_conf(READER_VIDEOGUARD, ptr2);
										check_conf(WITH_CARDREADER, ptr2);
										check_conf(WITH_DEBUG, ptr2);
										check_conf(WITH_LB, ptr2);
										check_conf(WITH_LIBCRYPTO, ptr2);
										check_conf(WITH_LIBUSB, ptr2);
										check_conf(WITH_PCSC, ptr2);
										check_conf(WITH_SSL, ptr2);
										check_conf(WITH_STAPI, ptr2);
									}
									if(ok == 0) return result;
									break;
								}
							}
						}
					}
				}
				if(allocated < size + read + 1) {
					allocated += size + 1024;
					if(!cs_realloc(&result, allocated * sizeof(char), -1)) return NULL;
				}
				memcpy(result + size, buffer + offset, read);
				size += read;
			}
			result[size] = '\0';
			fclose (fp);
			return result;
			}
	  }
  }
  
  int8_t chksum = 0;
  for(i = strlen(name); i > 0; --i){
		chksum += name[i];
	}

  for(i = 0; i < tplcnt; ++i){
  	if(chksum == tplchksum[i] && name[0] == tpl[i][0][0]){	// basic check to save strcmp calls as we are doing this hundreds of times per page in some cases
  		if(strcmp(name, tpl[i][0]) == 0) break;
  	}
  }
  
 	if(i >= 0 && i < tplcnt){
#ifdef TOUCH
		const char* tpl_res = (!strcmp(subdir, TOUCH_SUBDIR) && i == 12) ? TOUCH_TPLSTATUS : tpl[i][1];
#else
		const char* tpl_res = tpl[i][1];
#endif
		int32_t len = strlen(tpl_res) + 1;
 		if(!cs_malloc(&result, len * sizeof(char), -1)) return NULL;
 		memcpy(result, tpl_res, len);
 	} else {
 		if(!cs_malloc(&result, 1 * sizeof(char), -1)) return NULL;
 		result[0] = '\0';
  }
 	return result;
}

/* Returns the specified template with all variables/other templates replaced or an
   empty string if the template doesn't exist. Do not free the result yourself, it
   will get automatically cleaned up! */
char *tpl_getTpl(struct templatevars *vars, const char* name){

	char *tplorg = tpl_getUnparsedTpl(name, 1, tpl_getVar(vars, "SUBDIR"));
	if(!tplorg) return "";
	char *tplend = tplorg + strlen(tplorg);
	char *pch, *pch2, *tpl=tplorg;
	char varname[33];

	int32_t tmp,respos = 0;
	int32_t allocated = 2 * strlen(tpl) + 1;
	char *result;
	if(!cs_malloc(&result, allocated * sizeof(char), -1)) return "";

	while(tpl < tplend){
		if(tpl[0] == '#' && tpl[1] == '#' && tpl[2] != '#'){
			pch2 = tpl;
			pch = tpl + 2;
			while(pch[0] != '\0' && (pch[0] != '#' || pch[1] != '#')) ++pch;
			if(pch - pch2 < 32 && pch[0] == '#' && pch[1] == '#'){
				memcpy(varname, pch2 + 2, pch - pch2 - 2);
				varname[pch - pch2 - 2] = '\0';
				if(strncmp(varname, "TPL", 3) == 0){
					if((*vars).messages > 0 || strncmp(varname, "TPLMESSAGE", 10) != 0)
						pch2 = tpl_getTpl(vars, varname + 3);
					else pch2 = "";
				} else {
					pch2 = tpl_getVar(vars, varname);
				}
				tmp = strlen(pch2);
				if(tmp + respos + 2 >= allocated){
					allocated = tmp + respos + 256;
					if(!cs_realloc(&result, allocated * sizeof(char), -1)) return "";
				}
				memcpy(result + respos, pch2, tmp);
				respos += tmp;
				tpl = pch + 2;
			}
		} else {
			if(respos + 2 >= allocated){
				allocated = respos + 256;
				if(!cs_realloc(&result, allocated * sizeof(char), -1)) return "";
			}
			result[respos] = tpl[0];
			++respos;
			++tpl;
		}
	}
	free(tplorg);
	result[respos] = '\0';
	tpl_addTmp(vars, result);
	return result;
}

/* Saves all templates to the specified paths. Existing files will be overwritten! */
int32_t tpl_saveIncludedTpls(const char *path){
  int32_t tplcnt = tpl_count();
  int32_t i, cnt = 0;
  char tmp[256];
  FILE *fp;
  for(i = 0; i < tplcnt; ++i){
  	if(strlen(tpl_getTplPath(tpl[i][0], path, tmp, 256)) > 0 && (fp = fopen(tmp,"w")) != NULL){
  		int32_t len = strlen(tpl[i][1]);
  		if(strncmp(tpl[i][0], "IC", 2) != 0){
  			fprintf(fp, "<!--OSCam;%lu;%s;%s;%s-->\n", crc32(0L, (unsigned char*)tpl[i][1], len), CS_VERSION, CS_SVN_VERSION, tpl[i][2]);
  		}
			fwrite(tpl[i][1], sizeof(char), len, fp);
			fclose (fp);
			++cnt;
		}
	}
	return cnt;
}

/* Checks all disk templates in a directory if they are still current or may need upgrade! */
void tpl_checkOneDirDiskRevisions(const char* subdir) {
	char dirpath[255] = "\0";
	snprintf(dirpath, 255, "%s%s", cfg.http_tpl ? cfg.http_tpl : "", subdir);

	int32_t i, tplcnt = tpl_count();
		char path[255];
		for(i = 0; i < tplcnt; ++i){
			if(strncmp(tpl[i][0], "IC", 2) != 0 && strlen(tpl_getTplPath(tpl[i][0], dirpath, path, 255)) > 0 && file_exists(path)){
				int8_t error = 1;
				char *tplorg = tpl_getUnparsedTpl(tpl[i][0], 0, subdir);
				unsigned long checksum = 0, curchecksum = crc32(0L, (unsigned char*)tpl[i][1], strlen(tpl[i][1]));
				char *ifdefs = "", *pch1 = strstr(tplorg,"<!--OSCam");
				if(pch1 != NULL){
					char *version = "?", *revision = "?";
					char *pch2 = strstr(pch1,"-->");
					if(pch2 != NULL){
						pch2[0] = '\0';
						int32_t j;
						char *ptr1, *saveptr1 = NULL;
						for (j = 0, ptr1 = strtok_r(pch1 + 10, ";", &saveptr1); (ptr1) && j < 4 ; ptr1 = strtok_r(NULL, ";", &saveptr1), j++){
							if(j == 0) checksum = strtoul(ptr1, NULL, 10);
							else if(j == 1) version = ptr1;
							else if(j == 2) revision = ptr1;
							else if(j == 3) ifdefs = ptr1;
						}
					}
					if(checksum != curchecksum){			
						cs_log("WARNING: Your http disk template %s was created for an older revision of OSCam and was changed in original OSCam (%s,r%s). Please consider upgrading it!", path, version, revision);
					} else error = 0;
				} else cs_log("WARNING: Your http disk template %s is in the old template format without revision info. Please consider upgrading it!", path);
				if(error) cs_log("If you are sure that it is current, add the following line at the beginning of the template to suppress this warning: <!--OSCam;%lu;%s;%s;%s-->", curchecksum, CS_VERSION, CS_SVN_VERSION, ifdefs);
				free(tplorg);
			}
		}
}

/* Checks whether disk templates need upgrade - including sub-directories */
void tpl_checkDiskRevisions(void) {
	char subdir[255];
	char dirpath[255];
	if (cfg.http_tpl) {
		tpl_checkOneDirDiskRevisions("");

		DIR *hdir;
		struct dirent entry;
		struct dirent *result;
		struct stat s;
		if((hdir = opendir(cfg.http_tpl)) != NULL) {
			while(cs_readdir_r(hdir, &entry, &result) == 0 && result != NULL) {
				if (strcmp(".", entry.d_name) == 0 || strcmp("..", entry.d_name) == 0) {
					continue;
				}
				snprintf(dirpath, 255, "%s%s", cfg.http_tpl, entry.d_name);
				if (stat(dirpath, &s) == 0) {
					if (s.st_mode & S_IFDIR) {
						snprintf(subdir, 255,
						#ifdef WIN32
									"%s\\"
						#else
									"%s/"
						#endif
								, entry.d_name);
						tpl_checkOneDirDiskRevisions(subdir);
					}
				}
			}
			closedir(hdir);
		}
	}
}

/* Create some easy checksums (but they should be sufficient for our needs) in order to speedup lookup of templates. */
void prepareTplChecksums(void) {
	int32_t i, j;
  int32_t tplcnt = tpl_count();
  cs_malloc(&tplchksum,sizeof(int8_t) * tplcnt, SIGINT);

  for(i = 0; i < tplcnt; ++i){
  	tplchksum[i] = 0;
  	for(j = strlen(tpl[i][0]); j > 0; --j){
  		tplchksum[i] += tpl[i][0][j];
  	}
  }
}

/* Parses a value in an authentication string by removing all quotes/whitespace. Note that the original array is modified. */
static char *parse_auth_value(char *value){
	char *pch = value;
	char *pch2;
	value = strstr(value, "=");
	if(value != NULL){
		do{
			++value;
		} while (value[0] == ' ' || value[0] == '"');
		pch = value;
		for(pch2 = value + strlen(value) - 1; pch2 >= value && (pch2[0] == ' ' || pch2[0] == '"' || pch2[0] == '\r' || pch2[0] == '\n'); --pch2) pch2[0] = '\0';
	}
	return pch;
}

/* Parses the date out of a "If-Modified-Since"-header. Note that the original string is modified. */
time_t parse_modifiedsince(char * value){
	int32_t day = -1, month = -1, year = -1, hour = -1, minutes = -1, seconds = -1;
	char months[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	char *str, *saveptr1 = NULL;
	time_t modifiedheader = 0;
	value += 18;
	// Parse over weekday at beginning...
	while(value[0] == ' ' && value[0] != '\0') ++value;
	while(value[0] != ' ' && value[0] != '\0') ++value;
	// According to http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3.1 three different timeformats are allowed so we need a bit logic to parse all of them...
	if(value[0] != '\0'){
		++value;
		for(month = 0; month < 12; ++month){
			if(strstr(value, months[month])) break;
		}
		if(month > 11) month = -1;
		for (str=strtok_r(value, " ", &saveptr1); str; str=strtok_r(NULL, " ", &saveptr1)){
			switch(strlen(str)){
				case 1:
				case 2:
					day = atoi(str);
					break;

				case 4:
					if(str[0] != 'G')
						year = atoi(str);
					break;

				case 8:
					if(str[2] == ':' && str[5] == ':'){
						hour = atoi(str);
						minutes = atoi(str + 3);
						seconds = atoi(str + 6);
					}
					break;

				case 9:
					if(str[2] == '-' && str[6] == '-'){
						day = atoi(str);
						year = atoi(str + 7) + 2000;
					}
					break;
			}
		}
		if(day > 0 && day < 32 && month > 0 && year > 0 && year < 9999 && hour > -1 && hour < 24 && minutes > -1 && minutes < 60 && seconds > -1 && seconds < 60){
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

/* Converts a char to it's hex representation. See urlencode and char_to_hex on how to use it.*/
static char to_hex(char code) {
	static const char hex[] = "0123456789abcdef";
	return hex[(int)code & 15];
}

/* Converts a char array to a char array with hex values (needed for example for md5).
	Note that result needs to be at least (p_array_len * 2) + 1 large. */
static void char_to_hex(const unsigned char* p_array, uint32_t p_array_len, unsigned char *result) {
	result[p_array_len * 2] = '\0';
	const unsigned char *p_end = p_array + p_array_len;
	uint32_t pos = 0;
	const unsigned char* p;
	for (p = p_array; p != p_end; p++, pos+=2 ) {
		result[pos    ] = to_hex(*p >> 4);
		result[pos + 1] = to_hex(*p & 15);
	}
}

/* Calculates the currently valid nonce value and copies it to result. Please note that result needs to be at least (MD5_DIGEST_LENGTH * 2) + 1 large. */
void calculate_nonce(char *result){
  char noncetmp[128];
  unsigned char md5tmp[MD5_DIGEST_LENGTH];
  snprintf(noncetmp, sizeof(noncetmp), "%d:%s", (int)time(NULL)/AUTHNONCEVALIDSECS, noncekey);
  char_to_hex(MD5((unsigned char*)noncetmp, strlen(noncetmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char*)result);
}

/* Checks if authentication is correct. Returns -1 if not correct, 1 if correct and 2 if nonce isn't valid anymore.
   Note that authstring will be modified. */
int32_t check_auth(char *authstring, char *method, char *path, char *expectednonce){
	int32_t authok = 0, uriok = 0;
	char *authnonce = "";
	char *authnc = "";
	char *authcnonce = "";
	char *authresponse = "";
	char *uri = "";
	char *username = "";
	char *expectedPassword = cfg.http_pwd;
	char *pch = authstring + 22;
	char *pch2;
	char *saveptr1=NULL;

	for(pch = strtok_r (pch, ",", &saveptr1); pch; pch = strtok_r (NULL, ",", &saveptr1)){
		pch2 = pch;
	  while(pch2[0] == ' ' && pch2[0] != '\0') ++pch2;
	  if(strncmp(pch2, "nonce", 5) == 0){
	  	authnonce=parse_auth_value(pch2);
	  } else if (strncmp(pch2, "nc", 2) == 0){
	  	authnc=parse_auth_value(pch2);
	  } else if (strncmp(pch2, "cnonce", 6) == 0){
	  	authcnonce=parse_auth_value(pch2);
	  } else if (strncmp(pch2, "response", 8) == 0){
	  	authresponse=parse_auth_value(pch2);
	  } else if (strncmp(pch2, "uri", 3) == 0){
	  	uri=parse_auth_value(pch2);
	  } else if (strncmp(pch2, "username", 8) == 0){
	  	username=parse_auth_value(pch2);
	  }
	}

	if(strncmp(uri, path, strlen(path)) == 0) uriok = 1;
	else {
		pch2 = uri;
		for(pch = uri; pch[0] != '\0'; ++pch) {
			if(pch[0] == '/') pch2 = pch;
			if(strncmp(pch2, path, strlen(path)) == 0) uriok = 1;
		}
	}
	if (uriok == 1 && streq(username, cfg.http_user)) {
		char A1tmp[3 + strlen(username) + strlen(AUTHREALM) + strlen(expectedPassword)];
		char A1[(MD5_DIGEST_LENGTH * 2) + 1], A2[(MD5_DIGEST_LENGTH * 2) + 1], A3[(MD5_DIGEST_LENGTH * 2) + 1];
		unsigned char md5tmp[MD5_DIGEST_LENGTH];
		snprintf(A1tmp, sizeof(A1tmp), "%s:%s:%s", username, AUTHREALM, expectedPassword);
		char_to_hex(MD5((unsigned char*)A1tmp, strlen(A1tmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char*)A1);

		char A2tmp[2 + strlen(method) + strlen(uri)];
		snprintf(A2tmp, sizeof(A2tmp), "%s:%s", method, uri);
		char_to_hex(MD5((unsigned char*)A2tmp, strlen(A2tmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char*)A2);

		char A3tmp[10 + strlen(A1) + strlen(A2) + strlen(authnonce) + strlen(authnc) + strlen(authcnonce)];
		snprintf(A3tmp, sizeof(A3tmp), "%s:%s:%s:%s:auth:%s", A1, authnonce, authnc, authcnonce, A2);
		char_to_hex(MD5((unsigned char*)A3tmp, strlen(A3tmp), md5tmp), MD5_DIGEST_LENGTH, (unsigned char*)A3);

		if(strcmp(A3, authresponse) == 0) {
			if(strcmp(expectednonce, authnonce) == 0) authok = 1;
			else authok = 2;
		}
	}
	return authok;
}

int32_t webif_write_raw(char *buf, FILE* f, int32_t len) {
	errno=0;
#ifdef WITH_SSL
	if (ssl_active) {
		return SSL_write((SSL*)f, buf, len);
	} else
#endif
		return fwrite(buf, 1, len, f);
}

int32_t webif_write(char *buf, FILE* f) {
	return webif_write_raw(buf, f, strlen(buf));
}

int32_t webif_read(char *buf, int32_t num, FILE *f) {
	errno=0;
#ifdef WITH_SSL
	if (ssl_active) {
		return SSL_read((SSL*)f, buf, num);
	} else
#endif
		return read(fileno(f), buf, num);
}

void send_headers(FILE *f, int32_t status, char *title, char *extra, char *mime, int32_t cache, int32_t length, char *content, int8_t forcePlain){
  time_t now;
  char timebuf[32];
  char buf[sizeof(PROTOCOL) + sizeof(SERVER) + strlen(title) + (extra == NULL?0:strlen(extra)+2) + (mime == NULL?0:strlen(mime)+2) + 350];
  char *pos = buf;
  struct tm timeinfo;

  pos += snprintf(pos, sizeof(buf)-(pos-buf), "%s %d %s\r\n", PROTOCOL, status, title);
  pos += snprintf(pos, sizeof(buf)-(pos-buf), "Server: %s\r\n", SERVER);

  now = time(NULL);
  cs_gmtime_r(&now, &timeinfo);
  strftime(timebuf, sizeof(timebuf), RFC1123FMT, &timeinfo);
  pos += snprintf(pos, sizeof(buf)-(pos-buf), "Date: %s\r\n", timebuf);

	if (extra)
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"%s\r\n", extra);

	if (mime)
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"Content-Type: %s\r\n", mime);

	if(status != 304){
		if(!cache){
			pos += snprintf(pos, sizeof(buf)-(pos-buf),"Cache-Control: no-store, no-cache, must-revalidate\r\n");
			pos += snprintf(pos, sizeof(buf)-(pos-buf),"Expires: Sat, 10 Jan 2000 05:00:00 GMT\r\n");
		} else {
			pos += snprintf(pos, sizeof(buf)-(pos-buf),"Cache-Control: public, max-age=7200\r\n");
		}
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"Content-Length: %d\r\n", length);
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"Last-Modified: %s\r\n", timebuf);
		if(content){
			uint32_t checksum = (uint32_t)crc32(0L, (uchar *)content, length);
			pos += snprintf(pos, sizeof(buf)-(pos-buf),"ETag: \"%u\"\r\n", checksum==0?1:checksum);
		}
	}
	if(*(int8_t *)pthread_getspecific(getkeepalive))
		pos += snprintf(pos, sizeof(buf)-(pos-buf), "Connection: Keep-Alive\r\n");
	else
		pos += snprintf(pos, sizeof(buf)-(pos-buf), "Connection: close\r\n");
	pos += snprintf(pos, sizeof(buf)-(pos-buf),"\r\n");
	if(forcePlain == 1) fwrite(buf, 1, strlen(buf), f);
	else webif_write(buf, f);
}

void send_error(FILE *f, int32_t status, char *title, char *extra, char *text, int8_t forcePlain){
	char buf[(2* strlen(title)) + strlen(text) + 128];
	char *pos = buf;
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\r\n", status, title);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "<BODY><H4>%d %s</H4>\r\n", status, title);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "%s\r\n", text);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "</BODY></HTML>\r\n");
	send_headers(f, status, title, extra, "text/html", 0, strlen(buf), NULL, forcePlain);
	if(forcePlain == 1) fwrite(buf, 1, strlen(buf), f);
	else webif_write(buf, f);
}

void send_error500(FILE *f){
	send_error(f, 500, "Internal Server Error", NULL, "The server encountered an internal error that prevented it from fulfilling this request.", 0);
}

void send_header304(FILE *f){
	send_headers(f, 304, "Not Modified", NULL, NULL, 1, 0, NULL, 0);
}

/*
 * function for sending files.
 */
void send_file(FILE *f, char *filename, char* subdir, time_t modifiedheader, uint32_t etagheader){
	int8_t fileno = 0;
	int32_t size = 0;
	char* mimetype = "", *result = " ", *allocated = NULL;
	time_t moddate;
  	char path[255];

	if (!strcmp(filename, "CSS")){
		filename = cfg.http_css ? cfg.http_css : "";
		if (subdir && strlen(subdir) > 0) {
			filename = tpl_getFilePathInSubdir(cfg.http_tpl ? cfg.http_tpl : "", subdir, "site", ".css", path, 255);
		}
		mimetype = "text/css";
		fileno = 1;
	} else if (!strcmp(filename, "JS")){
		filename = cfg.http_jscript ? cfg.http_jscript : "";
		if (subdir && strlen(subdir) > 0) {
			filename = tpl_getFilePathInSubdir(cfg.http_tpl ? cfg.http_tpl : "", subdir, "oscam", ".js", path, 255);
		}
		mimetype = "text/javascript";
		fileno = 2;
	}

	if(strlen(filename) > 0 && file_exists(filename) == 1){
		struct stat st;
		stat(filename, &st);
		moddate = st.st_mtime;
		// We need at least size 1 or keepalive gets problems on some browsers...
		if(st.st_size > 0){
			FILE *fp;
			int32_t read;
			if((fp = fopen(filename, "r"))==NULL) return;
			if(!cs_malloc(&allocated, st.st_size + 1, -1)){
				send_error500(f);
				fclose(fp);
				return;
			}
			if((read = fread(allocated, 1, st.st_size, fp)) == st.st_size){
			  allocated[read] = '\0';
			}
			fclose(fp);
		}

		if (fileno == 1 && cfg.http_prepend_embedded_css) { // Prepend Embedded CSS
			char* separator = "/* External CSS */";
			char* oldallocated = allocated;
			int32_t newsize = strlen(CSS) + strlen(separator) + 2;
			if (oldallocated) newsize += strlen(oldallocated) + 1;
			if(!cs_malloc(&allocated, newsize, -1)){
				if (oldallocated) free(oldallocated);
				send_error500(f);
				return;
			}
			snprintf(allocated, newsize, "%s\n%s\n%s",
					 CSS, separator, (oldallocated != NULL ? oldallocated : ""));
			if (oldallocated) free(oldallocated);
		}

		if (allocated) result = allocated;

	} else {
#ifdef TOUCH
		char* res_tpl = strcmp(subdir, TOUCH_SUBDIR)
			? (fileno == 1 ? CSS : JSCRIPT)
			: (fileno == 1 ? TOUCH_CSS : TOUCH_JSCRIPT);
		if (strlen(res_tpl) > 0) result = res_tpl;
#else
		if (fileno == 1 && strlen(CSS) > 0){
			result = CSS;
		} else if (fileno == 2 && strlen(JSCRIPT) > 0){
			result = JSCRIPT;
		}
#endif
		moddate = first_client->login;
	}

	size = strlen(result);

	if((etagheader == 0 && moddate < modifiedheader) || (etagheader > 0 && (uint32_t)crc32(0L, (uchar *)result, size) == etagheader)){
		send_header304(f);
	} else {
		send_headers(f, 200, "OK", NULL, mimetype, 1, size, result, 0);
		webif_write(result, f);
	}
	if (allocated) free(allocated);
}

/* Helper function for urldecode.*/
static int32_t x2i(int32_t i){
	i=toupper(i);
	i = i - '0';
	if(i > 9) i = i - 'A' + '9' + 1;
	return i;
}

/* Decodes values in a http url. Note: The original value is modified! */
void urldecode(char *s){
	int32_t c, c1, n;
	char *t;
	t = s;
	n = strlen(s);
	while(n >0){
		c = *s++;
		if(c == '+') c = ' ';
		else if(c == '%' && n > 2){
			c = *s++;
			c1 = c;
			c = *s++;
			c = 16*x2i(c1) + x2i(c);
			n -= 2;
		}
		*t++ = c;
		n--;
	}
	*t = 0;
}

/* Encode values in a http url. Do not call free() or realloc on the returned reference or you will get memory corruption! */
char *urlencode(struct templatevars *vars, char *str){
	char buf[strlen(str) * 3 + 1];
	char *pstr = str, *pbuf = buf;
	while (*pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') *pbuf++ = *pstr;
		else if (*pstr == ' ') *pbuf++ = '+';
		else {
			*pbuf++ = '%';
			*pbuf++ = to_hex(*pstr >> 4);
			*pbuf++ = to_hex(*pstr & 15);
		}
		++pstr;
	}
	*pbuf = '\0';
	/* Allocate the needed memory size and store it in the templatevars */
	if(!cs_malloc(&pbuf, strlen(buf) + 1, -1)) return "";
	memcpy(pbuf, buf, strlen(buf) + 1);
	return tpl_addTmp(vars, pbuf);
}

/* XML-Escapes a char array. The returned reference will be automatically cleaned through the templatevars-mechanism tpl_clear().
   Do not call free() or realloc on the returned reference or you will get memory corruption! */
char *xml_encode(struct templatevars *vars, char *chartoencode) {
	int32_t i, pos = 0, len = strlen(chartoencode);
	char *result;
	/* In worst case, every character could get converted to 6 chars (we only support ASCII, for Unicode it would be 7)*/
	char encoded[len * 6 + 1], buffer[7];
	for (i = 0; i < len; ++i){
		switch(chartoencode[i]) {
			case '&': memcpy(encoded + pos, "&amp;", 5); pos+=5; break;
			case '<': memcpy(encoded + pos, "&lt;", 4); pos+=4; break;
			case '>': memcpy(encoded + pos, "&gt;", 4); pos+=4; break;
			case '"': memcpy(encoded + pos, "&quot;", 6); pos+=6; break;
			case '\'': memcpy(encoded + pos, "&apos;", 6); pos+=6; break;

			default:
				if ( (unsigned int)chartoencode[i] < 32 || (cs_http_use_utf8 != 1 && (unsigned int)chartoencode[i] > 127)) {
					snprintf(buffer, 7, "&#%d;", chartoencode[i] + 256);
					memcpy(encoded + pos, buffer, strlen(buffer));
					pos+=strlen(buffer);

				} else {
					encoded[pos] = chartoencode[i];
					++pos;
				}

		}
	}
	/* Allocate the needed memory size and store it in the templatevars */
	if(!cs_malloc(&result, pos + 1, -1)) return "";
	memcpy(result, encoded, pos);
	result[pos] = '\0';
	return tpl_addTmp(vars, result);
}

/* Prepares the base64 decoding array */
void b64prepare(void) {
	const unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int32_t i;
	for (i = sizeof(b64decoder) - 1; i >= 0; --i) {
		b64decoder[i] = -1;
	}

	for (i = sizeof(alphabet) - 1; i >= 0; --i) {
		b64decoder[alphabet[i]] = i;
	}
}

/* Decodes a base64-encoded string. The given array will be used directly for output and is thus modified! */
int32_t b64decode(unsigned char *result){
	int32_t i, len = strlen((char *)result), j = 0, bits = 0, char_count = 0;

	for(i = 0; i < len; ++i){
		if (result[i] == '=') break;
		int8_t tmp = b64decoder[result[i]];
		if(tmp == -1) continue;
		bits += tmp;
		++char_count;
		if (char_count == 4) {
			result[j++] = bits >> 16;
			result[j++] = (bits >> 8) & 0xff;
			result[j++] = bits & 0xff;
			bits = 0;
			char_count = 0;
		} else {
			bits <<= 6;
		}
	}
	if (i == len) {
		if (char_count) {
			result[j] = '\0';
			return 0;
		}
	} else {
		switch (char_count) {
			case 1:
				result[j] = '\0';
				return 0;
			case 2:
				result[j++] = bits >> 10;
				result[j] = '\0';
				break;
			case 3:
				result[j++] = bits >> 16;
				result[j++] = (bits >> 8) & 0xff;
				result[j] = '\0';
			break;
		}
	}
	return j;
}

/* Format a seconds integer to hh:mm:ss or dd hh:mm:ss depending hrs >24 */
char *sec2timeformat(struct templatevars *vars, int32_t seconds) {

	char *value;
	if(seconds <= 0)
		return "00:00:00";

	if(!cs_malloc(&value, 16 * sizeof(char), -1))
		return "00:00:00";

	int32_t secs = 0, fullmins = 0, mins = 0, fullhours = 0, hours = 0,	days = 0;

	secs = seconds % 60;
	if (seconds >= 60) {
		fullmins = seconds / 60;
		mins = fullmins % 60;
		if(fullmins >= 60) {
			fullhours = fullmins / 60;
			hours = fullhours % 24;
			days = fullhours / 24;
		}
	}

	if(days == 0)
		snprintf(value, 16, "%02d:%02d:%02d", hours, mins, secs);
	else
		snprintf(value, 16, "%02dd %02d:%02d:%02d", days, hours, mins, secs);

	return tpl_addTmp(vars, value);
}

/* Parse url parameters and save them to params array. The pch pointer is increased to the position where parsing stopped. */
void parseParams(struct uriparams *params, char *pch) {
	char *pch2;
	// parsemode = 1 means parsing next param, parsemode = -1 parsing next
  //value; pch2 points to the beginning of the currently parsed string, pch is the current position
	int32_t parsemode = 1;

	pch2=pch;
	while(pch[0] != '\0') {
		if((parsemode == 1 && pch[0] == '=') || (parsemode == -1 && pch[0] == '&')) {
			pch[0] = '\0';
			urldecode(pch2);
			if(parsemode == 1) {
				if(params->paramcount >= MAXGETPARAMS) break;
				++params->paramcount;
				params->params[params->paramcount-1] = pch2;
			} else {
				params->values[params->paramcount-1] = pch2;
			}
			parsemode = -parsemode;
			pch2 = pch + 1;
		}
		++pch;
	}
	/* last value wasn't processed in the loop yet... */
	if(parsemode == -1 && params->paramcount <= MAXGETPARAMS) {
		urldecode(pch2);
		params->values[params->paramcount-1] = pch2;
	}
}

/* Returns the value of the parameter called name or an empty string if it doesn't exist. */
char *getParam(struct uriparams *params, char *name){
	int32_t i;
	for(i=(*params).paramcount-1; i>=0; --i){
		if(strcmp((*params).params[i], name) == 0) return (*params).values[i];
	}
	return "";
}


#ifdef WITH_SSL
SSL * cur_ssl(void){
	return (SSL *) pthread_getspecific(getssl);
}

/* Locking functions for SSL multithreading */
struct CRYPTO_dynlock_value{
    pthread_mutex_t mutex;
};

/* function really needs unsigned long to prevent compiler warnings... */
static unsigned long SSL_id_function(void){
	return ((unsigned long) pthread_self());
}

static void SSL_locking_function(int32_t mode, int32_t type, const char *file, int32_t line) {
	if (mode & CRYPTO_LOCK) {
		cs_writelock(&lock_cs[type]);
	} else {
		cs_writeunlock(&lock_cs[type]);
	}
	// just to remove compiler warnings...
	if(file || line) return;
}

static struct CRYPTO_dynlock_value *SSL_dyn_create_function(const char *file, int32_t line) {
    struct CRYPTO_dynlock_value *l;
    if(!cs_malloc(&l, sizeof(struct CRYPTO_dynlock_value), -1)) return (NULL);
		if(pthread_mutex_init(&l->mutex, NULL)) {
			// Initialization of mutex failed.
			free(l);
			return (NULL);
		}
    pthread_mutex_init(&l->mutex, NULL);
    // just to remove compiler warnings...
		if(file || line) return l;
    return l;
}

static void SSL_dyn_lock_function(int32_t mode, struct CRYPTO_dynlock_value *l, const char *file, int32_t line) {
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&l->mutex);
	} else {
		pthread_mutex_unlock(&l->mutex);
	}
	// just to remove compiler warnings...
	if(file || line) return;
}

static void SSL_dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int32_t line) {
	pthread_mutex_destroy(&l->mutex);
	free(l);
	// just to remove compiler warnings...
	if(file || line) return;
}

/* Init necessary structures for SSL in WebIf*/
SSL_CTX *SSL_Webif_Init(void) {
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();

	SSL_CTX *ctx;

	static const char *cs_cert="oscam.pem";

	if (pthread_key_create(&getssl, NULL)) {
		cs_log("Could not create getssl");
	}

	// set locking callbacks for SSL
	int32_t i, num = CRYPTO_num_locks();
	lock_cs = (CS_MUTEX_LOCK*) OPENSSL_malloc(num * sizeof(CS_MUTEX_LOCK));

	for (i = 0; i < num; ++i) {
		cs_lock_create(&lock_cs[i], 10, "ssl_lock_cs");
	}
	/* static lock callbacks */
	CRYPTO_set_id_callback(SSL_id_function);
	CRYPTO_set_locking_callback(SSL_locking_function);
	/* dynamic lock callbacks */
	CRYPTO_set_dynlock_create_callback(SSL_dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(SSL_dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(SSL_dyn_destroy_function);

	if(cfg.http_force_sslv3){
		ctx = SSL_CTX_new(SSLv3_server_method());
		#ifdef SSL_CTX_clear_options
		SSL_CTX_clear_options(ctx, SSL_OP_ALL); //we CLEAR all bug workarounds! This is for security reason
		#else
		cs_log("WARNING: You enabled to force sslv3 but your system does not support to clear the ssl workarounds! SSL security will be reduced!");
		#endif
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2); // we force SSL v3 !
		SSL_CTX_set_cipher_list(ctx, SSL_TXT_RC4);
	} else
		ctx = SSL_CTX_new(SSLv23_server_method());

	char path[128];

	if (!cfg.http_cert)
		snprintf(path, sizeof(path), "%s%s", cs_confdir, cs_cert);
	else
		cs_strncpy(path, cfg.http_cert, sizeof(path));

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return NULL;
       }

	if (SSL_CTX_use_certificate_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		cs_log("SSL: Private key does not match the certificate public key");
		return NULL;
	}
	cs_log("load ssl certificate file %s", path);
	return ctx;
}
#endif

#endif
