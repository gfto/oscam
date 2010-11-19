//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#ifdef WEBIF
#include "oscam-http.h"

/* Adds a name->value-mapping or appends to it. You will get a reference back which you may freely
   use (but you should not call free/realloc on this!)*/
char *tpl_addVar(struct templatevars *vars, int append, char *name, char *value){
	int i;
	char *tmp,*result = NULL;
	for(i = (*vars).varscnt-1; i >= 0; --i){
		if(strcmp((*vars).names[i], name) == 0){
			result = (*vars).values[i];
			break;
		}
	}
	if(result == NULL){
		if((*vars).varsalloc <= (*vars).varscnt){
			(*vars).varsalloc = (*vars).varscnt * 2;
			(*vars).names = (char**) realloc ((*vars).names, (*vars).varsalloc * sizeof(char**));
			(*vars).values = (char**) realloc ((*vars).values, (*vars).varsalloc * sizeof(char**));
		}
		tmp = (char *) malloc((strlen(name) + 1) * sizeof(char));
		strcpy(tmp, name);
		(*vars).names[(*vars).varscnt] = tmp;
		tmp = (char *) malloc((strlen(value) + 1) * sizeof(char));
		strcpy(tmp, value);
		(*vars).values[(*vars).varscnt] = tmp;
		(*vars).varscnt = (*vars).varscnt + 1;
	} else {
		int newlen = strlen(value);
		if(append == 1){
			int oldlen = strlen((*vars).values[i]);
			tmp = (char*) malloc ((oldlen + newlen + 1) * sizeof(char));
			memcpy(tmp, (*vars).values[i], oldlen);
			strcpy(tmp + oldlen, value);
		} else {
			tmp = (char*) malloc ((newlen + 1) * sizeof(char));
			strcpy(tmp, value);
		}
		free((*vars).values[i]);
		(*vars).values[i] = tmp;
	}
	return tmp;
}

/* Allows to add a char array which has been allocated by malloc. It will automatically get
  freed when calling tpl_clear(). Please do NOT free the memory yourself or realloc
  it after having added the array here! */
char *tpl_addTmp(struct templatevars *vars, char *value){
	if((*vars).tmpalloc <= (*vars).tmpcnt){
		(*vars).tmpalloc = (*vars).tmpcnt * 2;
		(*vars).tmp = (char**) realloc ((*vars).tmp, (*vars).tmpalloc * sizeof(char**));
	}
	(*vars).tmp[(*vars).tmpcnt] = value;
	(*vars).tmpcnt = (*vars).tmpcnt + 1;
	return value;
}

/* Allows to do a dynamic printf without knowing and defining the needed memory size. If you specify
   varname, the printf-result will be added/appended to the varlist. You will always get a reference
   back which you may freely use (but you should not call free/realloc on this!)*/
char *tpl_printf(struct templatevars *vars, int append, char *varname, char *fmtstring, ...){
	unsigned int allocated = strlen(fmtstring) - (strlen(fmtstring)%16) + 16;
	char *result, *tmp = (char *) malloc(allocated * sizeof(char));
	va_list argptr;

	va_start(argptr,fmtstring);
	vsnprintf(tmp ,allocated, fmtstring, argptr);
	va_end(argptr);
	while (strlen(tmp) + 1 == allocated){
		allocated += 16;
		tmp = (char *) realloc(tmp, allocated * sizeof(char));
		va_start(argptr,fmtstring);
		vsnprintf(tmp, allocated, fmtstring, argptr);
		va_end(argptr);
	}
	result = (char *) malloc(strlen(tmp) + 1 * sizeof(char));
	strcpy(result, tmp);
	free(tmp);
	if(varname == NULL) tpl_addTmp(vars, result);
	else {
		char *tmp = tpl_addVar(vars, append, varname, result);
		free(result);
		result = tmp;
	}
	return result;
}

/* Returns the value for a name or an empty string if nothing was found. */
char *tpl_getVar(struct templatevars *vars, char *name){
	int i;
	char *result = NULL;
	for(i = (*vars).varscnt-1; i >= 0; --i){
		if(strcmp((*vars).names[i], name) == 0){
			result = (*vars).values[i];
			break;
		}
	}
	if(result == NULL) return "";
	else return result;
}

/* Initializes all variables vor a templatevar-structure and returns a pointer to it. Make
   sure to call tpl_clear() when you are finished or you'll run into a memory leak! */
struct templatevars *tpl_create(){
	struct templatevars *vars = (struct templatevars *) malloc(sizeof(struct templatevars));
	(*vars).varsalloc = 16;
	(*vars).varscnt = 0;
	(*vars).tmpalloc = 16;
	(*vars).tmpcnt = 0;
	(*vars).names = (char**) malloc ((*vars).varsalloc * sizeof(char**));
	(*vars).values = (char**) malloc ((*vars).varsalloc * sizeof(char**));
	(*vars).tmp = (char**) malloc ((*vars).tmpalloc * sizeof(char**));
	return vars;
}

/* Clears all allocated memory for the specified templatevar-structure. */
void tpl_clear(struct templatevars *vars){
	int i;
	for(i = (*vars).varscnt-1; i >= 0; --i){
		free((*vars).names[i]);
		free((*vars).values[i]);
	}
	free((*vars).names);
	free((*vars).values);
	for(i = (*vars).tmpcnt-1; i >= 0; --i){
		free((*vars).tmp[i]);
	}
	free((*vars).tmp);
	free(vars);
}

/* Creates a path to a template file. You need to set the resultsize to the correct size of result. */
char *tpl_getTplPath(const char *name, const char *path, char *result, unsigned int resultsize){
	char *pch;
	if((strlen(path) + strlen(name) + 6) <= resultsize){
		strcpy(result, path);
		strcat(result, name);
		strcat(result, ".tpl");
		result[resultsize - 1] = '\0';
		for(pch = result + strlen(path); pch[0] != '\0'; ++pch){
			if(pch[0] == '/' || pch[0] == '\\') pch[0] = ' ';
		}
	} else result[0] = '\0';
	return result;
}

/* Returns an unparsed template either from disk or from internal templates.
   Note: You must free() the result after using it!*/
char *tpl_getUnparsedTpl(const char* name){
  int i;
  int tplcnt = sizeof(tpl)/sizeof(char *);
  int tplmapcnt = sizeof(tplmap)/sizeof(char *);
  char *result;

  for(i = 0; i < tplcnt; ++i){
  	if(strcmp(name, tpl[i]) == 0) break;
  }

  if(strlen(cfg->http_tpl) > 0){
  	char path[200];
  	if(strlen(tpl_getTplPath(name, cfg->http_tpl, path, 200)) > 0 && file_exists(path)){
			FILE *fp;
			char buffer[1024];
			int read, allocated = 1025, size = 0;
			result = (char *) malloc(allocated * sizeof(char));
			if((fp = fopen(path,"r"))!=NULL){
			while((read = fread(&buffer,sizeof(char),1024,fp)) > 0){
				if(allocated < size + read + 1) {
					allocated += size + 1024;
					result = (char *) realloc(result, allocated * sizeof(char));
				}
				memcpy(result + size, buffer, read);
				size += read;
			}
			result[size] = '\0';
			fclose (fp);
			return result;
			}
	  }
  }
 	if(i >= 0 && i < tplmapcnt){
 		int len = (strlen(tplmap[i])) + 1;
 		result = (char *) malloc(len * sizeof(char));
 		memcpy(result, tplmap[i], len);
 	} else {
 		result = (char *) malloc(1 * sizeof(char));
 		result[0] = '\0';
  }
 	return result;
}

/* Returns the specified template with all variables/other templates replaced or an
   empty string if the template doesn't exist*/
char *tpl_getTpl(struct templatevars *vars, const char* name){
	char *tplorg = tpl_getUnparsedTpl(name);
	char *tplend = tplorg + strlen(tplorg);
	char *pch, *pch2, *tpl=tplorg;
	char varname[33];

	int tmp,respos = 0;
	int allocated = 2 * strlen(tpl) + 1;
	char *result = (char *) malloc(allocated * sizeof(char));

	while(tpl < tplend){
		if(tpl[0] == '#' && tpl[1] == '#' && tpl[2] != '#'){
			pch2 = tpl;
			pch = tpl + 2;
			while(pch[0] != '\0' && (pch[0] != '#' || pch[1] != '#')) ++pch;
			if(pch - pch2 < 32 && pch[0] == '#' && pch[1] == '#'){
				memcpy(varname, pch2 + 2, pch - pch2 - 2);
				varname[pch - pch2 - 2] = '\0';
				if(strncmp(varname, "TPL", 3) == 0){
					pch2 = tpl_getTpl(vars, varname + 3);
				} else {
					pch2 = tpl_getVar(vars, varname);
				}
				tmp = strlen(pch2);
				if(tmp + respos + 2 >= allocated){
					allocated = tmp + respos + 256;
					result = (char *) realloc(result, allocated * sizeof(char));
				}
				memcpy(result + respos, pch2, tmp);
				respos += tmp;
				tpl = pch + 2;
			}
		} else {
			if(respos + 2 >= allocated){
				allocated = respos + 256;
				result = (char *) realloc(result, allocated * sizeof(char));
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
int tpl_saveIncludedTpls(const char *path){
	int tplcnt = sizeof(tpl)/sizeof(char *);
  int tplmapcnt = sizeof(tplmap)/sizeof(char *);
  int i, cnt = 0;
  char tmp[200];
  FILE *fp;
  for(i = 0; i < tplcnt && i < tplmapcnt; ++i){
  	if(strlen(tpl_getTplPath(tpl[i], path, tmp, 200)) > 0 && (fp = fopen(tmp,"w")) != NULL){
			fwrite(tplmap[i], sizeof(char), strlen(tplmap[i]), fp);
			fclose (fp);
			++cnt;
		}
	}
	return cnt;
}

/* Parses a value in an authentication string by removing all quotes/whitespace. Note that the original array is modified*/
char *parse_auth_value(char *value){
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

/* Calculates the currently valid nonce value and copies it to result*/
void calculate_nonce(char *result, int resultlen){
	char *expectednonce, *noncetmp;
  noncetmp = (char*) malloc (128*sizeof(char));
  sprintf(noncetmp, "%d", (int)time(NULL)/AUTHNONCEVALIDSECS);
  strcat(noncetmp, ":");
  strcat(noncetmp, noncekey);
  fflush(stdout);
  expectednonce =char_to_hex(MD5((unsigned char*)noncetmp, strlen(noncetmp), NULL), MD5_DIGEST_LENGTH, hex2ascii);
  cs_strncpy(result, expectednonce, resultlen);
  free(noncetmp);
	free(expectednonce);
}

/* Checks if authentication is correct. Returns -1 if not correct, 1 if correct and 2 if nonce isn't valid anymore */
int check_auth(char *authstring, char *method, char *path, char *expectednonce){
	int authok = 0, uriok = 0;
	char *authnonce;
	char *authnc;
	char *authcnonce;
	char *uri;
	char *authresponse;
	char *A1tmp, *A2tmp, *A3tmp;
	char *A1, *A2, *A3;
  char *pch, *pch2;

	authnonce = "";
	authnc = "";
	authcnonce = "";
	authresponse = "";
	uri = "";
	pch = authstring + 22;
	pch = strtok (pch,",");
	while (pch != NULL){
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
	  }
	  pch = strtok (NULL, ",");
	}
	if(strncmp(uri, path, strlen(path)) == 0) uriok = 1;
	else {
		pch2 = uri;
		for(pch = uri; pch[0] != '\0'; ++pch) {
			if(pch[0] == '/') pch2 = pch;
		}
		if(strncmp(pch2, path, strlen(path)) == 0) uriok = 1;
	}
	if(uriok == 1){
		A1tmp = (char*) malloc ((3 + strlen(cfg->http_user) + strlen(AUTHREALM) + strlen(cfg->http_pwd))*sizeof(char));
		strcpy(A1tmp, cfg->http_user);
		strcat(A1tmp, ":");
		strcat(A1tmp, AUTHREALM);
		strcat(A1tmp, ":");
		strcat(A1tmp, cfg->http_pwd);
		A2tmp = (char*) malloc ((2 + strlen(method) + strlen(uri))*sizeof(char));
		strcpy(A2tmp, method);
		strcat(A2tmp, ":");
		strcat(A2tmp, uri);
		A1=char_to_hex(MD5((unsigned char*)A1tmp, strlen(A1tmp), NULL), MD5_DIGEST_LENGTH, hex2ascii);
		A2=char_to_hex(MD5((unsigned char*)A2tmp, strlen(A2tmp), NULL), MD5_DIGEST_LENGTH, hex2ascii);
		A3tmp = (char*) malloc ((10 + strlen(A1) + strlen(A2) + strlen(authnonce) + strlen(authnc) + strlen(authcnonce))*sizeof(char));
		strcpy(A3tmp, A1);
		strcat(A3tmp, ":");
		strcat(A3tmp, authnonce);
		strcat(A3tmp, ":");
		strcat(A3tmp, authnc);
		strcat(A3tmp, ":");
		strcat(A3tmp, authcnonce);
		strcat(A3tmp, ":auth:");
		strcat(A3tmp, A2);
		A3=char_to_hex(MD5((unsigned char*)A3tmp, strlen(A3tmp), NULL), MD5_DIGEST_LENGTH, hex2ascii);
		if(strcmp(A3, authresponse) == 0) {
			if(strcmp(expectednonce, authnonce) == 0) authok = 1;
			else authok = 2;
		}
		free(A1tmp);
		free(A2tmp);
		free(A3tmp);
		free(A1);
		free(A2);
		free(A3);
	}
	return authok;
}

#ifdef WITH_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

int webif_write(char *buf, FILE* f) {
#ifdef WITH_SSL
	if (cfg->http_use_ssl) {
		return SSL_write((SSL*)f, buf, strlen(buf));
	} else
#endif
		return fwrite(buf, 1, strlen(buf), f);
}

int webif_read(char *buf, int num, FILE *f) {
#ifdef WITH_SSL
	if (cfg->http_use_ssl) {
		return SSL_read((SSL*)f, buf, num);
	} else
#endif
	{
		buf[0]='\0';
		int len=0;
		while (fgets(buf+len, num-len-1, f)) {
			if (buf[0+len] == '\r' && buf[1+len] == '\n') break;
			len=strlen(buf);
		}
		return len;
	}
}

void send_headers(FILE *f, int status, char *title, char *extra, char *mime){

  time_t now;
  char timebuf[128];
  char buf[1024];

  sprintf(buf, "%s %d %s\r\n", PROTOCOL, status, title);
  sprintf(buf, "Server: %s\r\n", SERVER);

  now = time(NULL);
  strftime(timebuf, sizeof(timebuf), RFC1123FMT, gmtime(&now));
  sprintf(buf, "Date: %s\r\n", timebuf);

	if (extra)
		sprintf(buf, "%s\r\n", extra);

	if (mime)
		sprintf(buf, "Content-Type: %s\r\n", mime);

	strftime(timebuf, sizeof(timebuf), RFC1123FMT, gmtime(&now));
	sprintf(buf, "Cache-Control: no-store, no-cache, must-revalidate\r\n");
	sprintf(buf, "Expires: Sat, 26 Jul 1997 05:00:00 GMT\r\n");
	sprintf(buf, "Last-Modified: %s\r\n", timebuf);
	sprintf(buf, "Connection: close\r\n");
	sprintf(buf, "\r\n");
	webif_write(buf, f);
}

void send_css(FILE *f){
	if(strlen(cfg->http_css) > 0 && file_exists(cfg->http_css) == 1){
		FILE *fp;
		char buffer[1024];
		int read;

		if((fp = fopen(cfg->http_css,"r"))==NULL) return;
		while((read = fread(buffer,sizeof(char),1024,fp)) > 0) webif_write(buffer, f);
		fclose (fp);
	} else {
		webif_write(CSS, f);
	}
}

void send_js(FILE *f){
	if(strlen(cfg->http_jscript) > 0 && file_exists(cfg->http_jscript) == 1){
		FILE *fp;
		char buffer[1024];
		int read;

		if((fp = fopen(cfg->http_jscript,"r"))==NULL) return;
		while((read = fread(buffer,sizeof(char),1024,fp)) > 0) webif_write(buffer, f);
		fclose (fp);
	} else {
		webif_write(JSCRIPT, f);
	}
}

void send_error(FILE *f, int status, char *title, char *extra, char *text){
	char buf[1024];
	send_headers(f, status, title, extra, "text/html");
	sprintf(buf, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\r\n", status, title);
	sprintf(buf, "<BODY><H4>%d %s</H4>\r\n", status, title);
	sprintf(buf, "%s\r\n", text);
	sprintf(buf, "</BODY></HTML>\r\n");
	webif_write(buf, f);
}

char *getParam(struct uriparams *params, char *name){
	int i;
	for(i=(*params).paramcount-1; i>=0; --i){
		if(strcmp((*params).params[i], name) == 0) return (*params).values[i];
	}
	return "";
}

char *getParamDef(struct uriparams *params, char *name, char* def){
	int i;
	for(i=(*params).paramcount-1; i>=0; --i){
		if(strcmp((*params).params[i], name) == 0) return (*params).values[i];
	}
	return def;
}

#endif
