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
extern int32_t recv_from_udpipe(uchar *);
extern void cs_exit(int32_t sig);
extern int32_t write_to_pipe(struct s_client *, int32_t, uchar *, int32_t);
extern int32_t read_from_pipe(struct s_client *, uchar **);
extern int32_t process_input(uchar *, int32_t, int32_t);
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
extern int32_t hostResolve(struct s_reader * reader);
extern int32_t network_tcp_connection_open(struct s_reader *);
extern void network_tcp_connection_close(struct s_reader *, char *);
extern void block_connect(struct s_reader *rdr);
extern int32_t is_connect_blocked(struct s_reader *rdr);
void cs_add_entitlement(struct s_reader *rdr, uint16_t caid, uint32_t provid, uint64_t id, uint32_t class, time_t start, time_t end, uint8_t type);
extern void cs_clear_entitlement(struct s_reader *rdr);

extern void reader_do_idle(struct s_reader * reader);
extern void casc_check_dcw(struct s_reader * reader, int32_t idx, int32_t rc, uchar *cw);
extern void casc_do_sock_log(struct s_reader * reader);
extern void reader_do_card_info(struct s_reader * reader);

/* ===========================
 *        oscam-simples
 * =========================== */
extern char *get_servicename(struct s_client *cl, uint16_t srvid, uint16_t caid, char *buf);
extern char *get_tiername(uint16_t tierid, uint16_t caid, char *buf);
extern char *get_provider(uint16_t caid, uint32_t provid, char *buf, uint32_t buflen);
void add_provider(uint16_t caid, uint32_t provid, const char *name, const char *sat, const char *lang);

#endif
