#ifndef MODULE_WEBIF_LIB_H_
#define MODULE_WEBIF_LIB_H_

#ifdef WITH_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* The server string in the http header */
#define SERVER "webserver/1.0"
/* The protocol that gets output. Currently only 1.0 is possible as 1.1 requires many features we don't have. */
#define PROTOCOL "HTTP/1.0"
/* The RFC1123 time format which is used in http headers. */
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"
/* The realm for http digest authentication. Gets displayed to browser. */
#define AUTHREALM "Forbidden"
/* How long a nonce is valid in seconds. If it isn't valid anymore, the browser gets a "stale=true" message and must resubmit with the current nonce. */
#define AUTHNONCEVALIDSECS 15
/* The maximum amount of GET parameters the webserver will parse. */
#define MAXGETPARAMS 100
/* The refresh delay (in seconds) when stopping OSCam via http. */
#define SHUTDOWNREFRESH 30
/* Templates: Adds a variable. The variable can be used as often as wanted. */
#define TPLADD 0
/* Templates: Appends a variable or adds it if doesn't exist yet. The variable can be used as often as wanted. */
#define TPLAPPEND 1
/* Templates: Adds a variable which will be reset to "" after being used once, either through tpl_getVar or when used in a template.
   tpl_addVar/tpl_printf don't do a reset and will overwrite the appendmode with a new value. */
#define TPLADDONCE 2
/* Templates: Appends a variable or adds it if doesn't exist yet. The variable will be reset to "" after being used once. See TPLADDONCE for details. */
#define TPLAPPENDONCE 3

struct s_connection {
	int32_t socket;
	struct s_client *cl;
	IN_ADDR_T remote;
#ifdef WITH_SSL
	SSL *ssl;
#endif
};

enum refreshtypes { REFR_ACCOUNTS, REFR_CLIENTS, REFR_SERVER, REFR_ANTICASC, REFR_SERVICES };

struct templatevars {
	uint32_t varscnt;
	uint32_t varsalloc;
	uint32_t tmpcnt;
	uint32_t tmpalloc;
	char **names;
	char **values;
	uint8_t *vartypes;
	char **tmp;
	uint8_t messages;
};

struct uriparams {
	int32_t paramcount;
	char *params[MAXGETPARAMS];
	char *values[MAXGETPARAMS];
};

extern char *tpl_addVar(struct templatevars *vars, uint8_t addmode, char *name, char *value);
extern char *tpl_addMsg(struct templatevars *vars, char *value);
extern char *tpl_addTmp(struct templatevars *vars, char *value);
extern char *tpl_printf(struct templatevars *vars, uint8_t addmode, char *varname, char *fmtstring, ...) __attribute__ ((format (printf, 4, 5)));
extern char *tpl_getVar(struct templatevars *vars, char *name);
extern struct templatevars *tpl_create(void);
extern void tpl_clear(struct templatevars *vars);
extern char *tpl_getFilePathInSubdir(const char *path, const char* subdir, const char *name, const char* ext, char *result, uint32_t resultsize);
extern char *tpl_getTplPath(const char *name, const char *path, char *result, uint32_t resultsize);
extern char *tpl_getTpl(struct templatevars *vars, const char* name);
extern int32_t tpl_saveIncludedTpls(const char *path);
extern void tpl_checkOneDirDiskRevisions(const char* subdir);
extern void tpl_checkDiskRevisions(void);
extern void prepareTplChecksums(void);
extern char *parse_auth_value(char *value);
extern time_t parse_modifiedsince(char * value);
extern void calculate_nonce(char *result);
extern int32_t check_auth(char *authstring, char *method, char *path, char *expectednonce);
extern int32_t webif_write_raw(char *buf, FILE* f, int32_t len);
extern int32_t webif_write(char *buf, FILE* f);
extern int32_t webif_read(char *buf, int32_t num, FILE *f);
extern void send_headers(FILE *f, int32_t status, char *title, char *extra, char *mime, int32_t cache, int32_t length, char *content, int8_t forcePlain);
extern void send_error(FILE *f, int32_t status, char *title, char *extra, char *text, int8_t forcePlain);
extern void send_error500(FILE *f);
extern void send_header304(FILE *f);
extern void send_file(FILE *f, char *filename, char* subdir, time_t modifiedheader, uint32_t etagheader);
extern void urldecode(char *s);
extern char *urlencode(struct templatevars *vars, char *str);
extern char *xml_encode(struct templatevars *vars, char *chartoencode);
extern void b64prepare(void);
extern int32_t b64decode(unsigned char *result);
extern char *sec2timeformat(struct templatevars *vars, int32_t seconds);
extern void parseParams(struct uriparams *params, char *pch);
extern char *getParam(struct uriparams *params, char *name);

#ifdef WITH_SSL
extern SSL * cur_ssl(void);
extern unsigned long SSL_id_function(void);
extern void SSL_locking_function(int32_t mode, int32_t type, const char *file, int32_t line);
extern struct CRYPTO_dynlock_value *SSL_dyn_create_function(const char *file, int32_t line);
extern void SSL_dyn_lock_function(int32_t mode, struct CRYPTO_dynlock_value *l, const char *file, int32_t line);
extern void SSL_dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int32_t line);
extern SSL_CTX *SSL_Webif_Init(void);
#endif

#endif
