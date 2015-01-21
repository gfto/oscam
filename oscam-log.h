#ifndef OSCAM_LOG_H_
#define OSCAM_LOG_H_

int32_t cs_init_log(void);
void cs_reopen_log(void);
int32_t cs_open_logfiles(void);
void cs_disable_log(int8_t disabled);
void cs_reinit_loghist(uint32_t size);

void cs_log_txt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void cs_log_dump(const uint8_t *buf, int32_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

#define cs_log(fmt, params...)          cs_log_txt(fmt, ##params)
#define cs_dump(buf, n, fmt, params...) cs_log_dump(buf,  n, fmt, ##params)

#define cs_debug_mask(mask, fmt, params...)         do { if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) cs_log_txt(fmt, ##params); } while(0)
#define cs_ddump_mask(mask, buf, n, fmt, params...) do { if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) cs_log_dump(buf , n, fmt, ##params); } while(0)

void logCWtoFile(ECM_REQUEST *er, uchar *cw);

int32_t cs_init_statistics(void);
void cs_statistics(struct s_client *client);

void log_free(void);

#endif
