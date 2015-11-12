#ifndef OSCAM_LOG_H_
#define OSCAM_LOG_H_

#ifndef MODULE_LOG_PREFIX
#define MODULE_LOG_PREFIX NULL
#endif

int32_t cs_init_log(void);
void cs_reopen_log(void);
int32_t cs_open_logfiles(void);
void cs_disable_log(int8_t disabled);
void cs_reinit_loghist(uint32_t size);

void cs_log_txt(const char *log_prefix, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void cs_log_hex(const char *log_prefix, const uint8_t *buf, int32_t n, const char *fmt, ...) __attribute__((format(printf, 4, 5)));

#define cs_log(fmt, params...)              cs_log_txt(MODULE_LOG_PREFIX, fmt, ##params)
#define cs_log_dump(buf, n, fmt, params...) cs_log_hex(MODULE_LOG_PREFIX, buf,  n, fmt, ##params)

#define cs_log_dbg(mask, fmt, params...)         do { if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) cs_log_txt(MODULE_LOG_PREFIX, fmt, ##params); } while(0)
#define cs_log_dump_dbg(mask, buf, n, fmt, params...) do { if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) cs_log_hex(MODULE_LOG_PREFIX, buf , n, fmt, ##params); } while(0)

int32_t cs_init_statistics(void);
void cs_statistics(struct s_client *client);

void log_free(void);

// Compatability with older function names. If your code uses these
// it must migrate to the new names using find + replace
// *** DO NOT USE OLD NAMES NEW CODE! ***
#define cs_debug_mask             cs_log_dbg
#define rdr_debug_mask            rdr_log_dbg
#define rdr_debug_mask_sensitive  rdr_log_dbg_sensitive
#define cs_ddump_mask             cs_log_dump_dbg
#define rdr_ddump_mask            rdr_log_dump_dbg

#if defined(WEBIF) || defined(MODULE_MONITOR)

extern LLIST *log_history;

struct s_log_history
{
	char *txt;
	uint64_t counter;
};

#endif

#endif
