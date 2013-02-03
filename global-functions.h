#ifndef GLOBAL_FUNCTIONS_H_
#define GLOBAL_FUNCTIONS_H_

/* ===========================
 *           oscam
 * =========================== */
extern void cs_exit_oscam(void);
extern void cs_restart_oscam(void);
extern int32_t cs_get_restartmode(void);

extern int32_t accept_connection(int32_t i, int32_t j);
extern void start_thread(void * startroutine, char * nameroutine);
extern void add_check(struct s_client *client, int8_t action, void *ptr, int32_t size, int32_t ms_delay);
extern void cs_reload_config(void);
extern void cs_exit(int32_t sig);
extern int32_t write_to_pipe(struct s_client *, int32_t, uchar *, int32_t);
extern int32_t read_from_pipe(struct s_client *, uchar **);
extern void set_signal_handler(int32_t , int32_t , void (*));
extern void cs_waitforcardinit(void);
extern int32_t process_client_pipe(struct s_client *cl, uchar *buf, int32_t l);
extern void *clientthread_init(void * init);
extern void kill_thread(struct s_client *cl);
extern void cs_debug_level(void);

#include "oscam-log.h"
#include "oscam-log-reader.h"

/* ===========================
 *        oscam-reader
 * =========================== */
extern void * start_cardreader(void *);

/* ===========================
 *        oscam-simples
 * =========================== */
extern char *get_servicename(struct s_client *cl, uint16_t srvid, uint16_t caid, char *buf);
extern char *get_tiername(uint16_t tierid, uint16_t caid, char *buf);
extern char *get_provider(uint16_t caid, uint32_t provid, char *buf, uint32_t buflen);
void add_provider(uint16_t caid, uint32_t provid, const char *name, const char *sat, const char *lang);

#endif
