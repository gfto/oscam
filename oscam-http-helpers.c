//FIXME Not checked on threadsafety yet; after checking please remove this line
#include "globals.h"
#ifdef WEBIF
#ifdef WITH_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#include "oscam-http.h"

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
struct templatevars *tpl_create(){
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
char *tpl_getTplPath(const char *name, const char *path, char *result, uint32_t resultsize){
	char *pch;
	if((strlen(path) + strlen(name) + 6) <= resultsize){
		snprintf(result, resultsize, "%s%s.tpl", path, name);
		for(pch = result + strlen(path); pch[0] != '\0'; ++pch){
			if(pch[0] == '/' || pch[0] == '\\') pch[0] = ' ';
		}
	} else result[0] = '\0';
	return result;
}

/* Returns an unparsed template either from disk or from internal templates.
   Note: You must free() the result after using it and you may get NULL if an error occured!*/
char *tpl_getUnparsedTpl(const char* name){
  int32_t i;
  int32_t tplcnt = sizeof(tpl)/sizeof(char *);
  int32_t tplmapcnt = sizeof(tplmap)/sizeof(char *);
  char *result;

  for(i = 0; i < tplcnt; ++i){
  	if(strcmp(name, tpl[i]) == 0) break;
  }

  if(strlen(cfg.http_tpl) > 0){
  	char path[255];
  	if(strlen(tpl_getTplPath(name, cfg.http_tpl, path, 255)) > 0 && file_exists(path)){
			FILE *fp;
			char buffer[1024];
			int32_t read, allocated = 1025, size = 0;
			if(!cs_malloc(&result, allocated * sizeof(char), -1)) return NULL;
			if((fp = fopen(path,"r"))!=NULL){
			while((read = fread(&buffer,sizeof(char),1024,fp)) > 0){
				if(allocated < size + read + 1) {
					allocated += size + 1024;
					if(!cs_realloc(&result, allocated * sizeof(char), -1)) return NULL;
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
 		int32_t len = (strlen(tplmap[i])) + 1;
 		if(!cs_malloc(&result, len * sizeof(char), -1)) return NULL;
 		memcpy(result, tplmap[i], len);
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
	char *tplorg = tpl_getUnparsedTpl(name);
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
					pch2 = tpl_getTpl(vars, varname + 3);
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
	int32_t tplcnt = sizeof(tpl)/sizeof(char *);
  int32_t tplmapcnt = sizeof(tplmap)/sizeof(char *);
  int32_t i, cnt = 0;
  char tmp[256];
  FILE *fp;
  for(i = 0; i < tplcnt && i < tplmapcnt; ++i){
  	if(strlen(tpl_getTplPath(tpl[i], path, tmp, 256)) > 0 && (fp = fopen(tmp,"w")) != NULL){
			fwrite(tplmap[i], sizeof(char), strlen(tplmap[i]), fp);
			fclose (fp);
			++cnt;
		}
	}
	return cnt;
}

/* Parses a value in an authentication string by removing all quotes/whitespace. Note that the original array is modified. */
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
	  } else if (strncmp(pch2, "username", 8) == 0){
	  	username=parse_auth_value(pch2);
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
	if(uriok == 1 && strcmp(username, cfg.http_user) == 0){
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

void send_headers(FILE *f, int32_t status, char *title, char *extra, char *mime, int32_t cache, int32_t length, int8_t forcePlain){
  time_t now;
  char timebuf[32];
  char buf[sizeof(PROTOCOL) + sizeof(SERVER) + strlen(title) + (extra == NULL?0:strlen(extra)+2) + (mime == NULL?0:strlen(mime)+2) + 300];
  char *pos = buf;
	
  pos += snprintf(pos, sizeof(buf)-(pos-buf), "%s %d %s\r\n", PROTOCOL, status, title);
  pos += snprintf(pos, sizeof(buf)-(pos-buf), "Server: %s\r\n", SERVER);

  now = time(NULL);
  strftime(timebuf, sizeof(timebuf), RFC1123FMT, gmtime(&now));
  pos += snprintf(pos, sizeof(buf)-(pos-buf), "Date: %s\r\n", timebuf);

	if (extra)
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"%s\r\n", extra);

	if (mime)
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"Content-Type: %s\r\n", mime);

	if(!cache){
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"Cache-Control: no-store, no-cache, must-revalidate\r\n");
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"Expires: Sat, 26 Jul 1997 05:00:00 GMT\r\n");
	} else {
		pos += snprintf(pos, sizeof(buf)-(pos-buf),"Cache-Control: public, max-age=7200\r\n");
	}
	pos += snprintf(pos, sizeof(buf)-(pos-buf),"Content-Length: %d\r\n", length);
	pos += snprintf(pos, sizeof(buf)-(pos-buf),"Last-Modified: %s\r\n", timebuf);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "Connection: close\r\n");
	pos += snprintf(pos, sizeof(buf)-(pos-buf),"\r\n");
	if(forcePlain == 1) fwrite(buf, 1, strlen(buf), f);
	else webif_write(buf, f);
}

/*
 * function for sending files.
 */
void send_file(FILE *f, char *filename){
	int32_t fileno = 0;
	char* mimetype = "";

	if (!strcmp(filename, "CSS")){
		filename = cfg.http_css;
		mimetype = "text/css";
		fileno = 1;
	} else if (!strcmp(filename, "JS")){
		filename = cfg.http_jscript;
		mimetype = "text/javascript";
		fileno = 2;
	}

	if(strlen(filename) > 0 && file_exists(filename) == 1){
		FILE *fp;
		char buffer[1024];
		int32_t read;
		struct stat st;
		
		stat(filename, &st);		
		if((fp = fopen(filename, "r"))==NULL) return;
		send_headers(f, 200, "OK", NULL, mimetype, 1, st.st_size, 0);
		while((read = fread(buffer,sizeof(char), 1023, fp)) > 0) {
			buffer[read] = '\0';			
			webif_write(buffer, f);
		}

		fclose (fp);
	} else {
		if (fileno == 1){
			send_headers(f, 200, "OK", NULL, mimetype, 1, strlen(CSS), 0);
			webif_write(CSS, f);
		} else if (fileno == 2){
			send_headers(f, 200, "OK", NULL, mimetype, 1, strlen(JSCRIPT), 0);
			webif_write(JSCRIPT, f);
		}
	}
}

void send_error(FILE *f, int32_t status, char *title, char *extra, char *text, int8_t forcePlain){
	char buf[(2* strlen(title)) + strlen(text) + 128];
	char *pos = buf;
	send_headers(f, status, title, extra, "text/html", 0, strlen(buf), forcePlain);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\r\n", status, title);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "<BODY><H4>%d %s</H4>\r\n", status, title);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "%s\r\n", text);
	pos += snprintf(pos, sizeof(buf)-(pos-buf), "</BODY></HTML>\r\n");
	if(forcePlain == 1) fwrite(buf, 1, strlen(buf), f);
	else webif_write(buf, f);
}

void send_error500(FILE *f){
	send_error(f, 500, "Internal Server Error", NULL, "The server encountered an internal error that prevented it from fulfilling this request.", 0);
}

/* Helper function for urldecode.*/
int32_t x2i(int32_t i){
	i=toupper(i);
	i = i - '0';
	if(i > 9) i = i - 'A' + '9' + 1;
	return i;
}

/* Decodes values in a http url. Note: The original value is modified! */
void urldecode(char *s){
	int32_t c, c1, n;
	char *s0,*t;
	t = s0 = s;
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
				if ( (unsigned int)chartoencode[i] < 32 || (unsigned int)chartoencode[i] > 127 ) {
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

int32_t b64decode(unsigned char *result){
	char inalphabet[256], decoder[256];
	unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int32_t i, len = strlen((char *)result), j = 0, bits = 0, char_count = 0;
	
	for (i = sizeof(alphabet) - 1; i >= 0; --i) {
		inalphabet[alphabet[i]] = 1;
		decoder[alphabet[i]] = i;
	}
	for(i = 0; i < len; ++i){
		if (result[i] == '=') break;
		if (!inalphabet[result[i]]) continue;
		bits += decoder[result[i]];
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
	if (seconds > 60) {
		fullmins = seconds / 60;
		mins = fullmins % 60;
		if(fullmins > 60) {
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

struct s_reader *get_reader_by_label(char *lbl){
	struct s_reader *rdr;
	LL_ITER *itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(itr)))
	  if (strcmp(lbl, rdr->label) == 0) break;
	ll_iter_release(itr);
	return rdr;
}

struct s_client *get_client_by_name(char *name) {
	struct s_client *cl;
	for (cl = first_client; cl ; cl = cl->next) {
		if (strcmp(name, cl->account->usr) == 0)
			return cl;
	}
	return NULL;
}

struct s_auth *get_account_by_name(char *name) {
	struct s_auth *account;
	for (account=cfg.account; (account); account=account->next) {
		if(strcmp(name, account->usr) == 0)
			return account;
	}
	return NULL;
}

#ifdef WITH_SSL
pthread_key_t getssl;
SSL * cur_ssl(void){
	return (SSL *) pthread_getspecific(getssl);
}

/* Locking functions for SSL multithreading */
static pthread_mutex_t *lock_cs;
struct CRYPTO_dynlock_value{
    pthread_mutex_t mutex;
};

/* function really needs unsigned long to prevent compiler warnings... */
unsigned long SSL_id_function(void){
	return ((unsigned long) pthread_self());
}

void SSL_locking_function(int32_t mode, int32_t type, const char *file, int32_t line){
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&lock_cs[type]);
	} else {
		pthread_mutex_unlock(&lock_cs[type]);
	}
	// just to remove compiler warnings...
	if(file || line) return;
}

struct CRYPTO_dynlock_value *SSL_dyn_create_function(const char *file, int32_t line){
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

void SSL_dyn_lock_function(int32_t mode, struct CRYPTO_dynlock_value *l, const char *file, int32_t line){
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&l->mutex);
	} else {
		pthread_mutex_unlock(&l->mutex);
	}
	// just to remove compiler warnings...
	if(file || line) return;
}

void SSL_dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int32_t line){
	pthread_mutex_destroy(&l->mutex);
	free(l);
	// just to remove compiler warnings...
	if(file || line) return;
}

/* Init necessary structures for SSL in WebIf*/
SSL_CTX *SSL_Webif_Init() {
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();

	SSL_METHOD *meth;
	SSL_CTX *ctx;

	static const char *cs_cert="oscam.pem";
	
	// set locking callbacks for SSL
	int32_t i, num = CRYPTO_num_locks();
	lock_cs = (pthread_mutex_t*) OPENSSL_malloc(num * sizeof(pthread_mutex_t));
	
	for (i = 0; i < num; ++i) {
		if(pthread_mutex_init(&lock_cs[i], NULL)){
			while(--i > 0){
				pthread_mutex_destroy(&lock_cs[i]);
				--i;
			}
			free(lock_cs);
			return NULL;
		};
	}
	/* static lock callbacks */ 
	CRYPTO_set_id_callback(SSL_id_function);
	CRYPTO_set_locking_callback(SSL_locking_function);
	/* dynamic lock callbacks */
	CRYPTO_set_dynlock_create_callback(SSL_dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(SSL_dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(SSL_dyn_destroy_function); 

	meth = SSLv23_server_method();

	ctx = SSL_CTX_new(meth);

	char path[128];

	if (cfg.http_cert[0]==0)
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
