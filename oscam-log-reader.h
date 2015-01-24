#ifndef OSCAM_LOG_READER_H_
#define OSCAM_LOG_READER_H_

void rdr_log(struct s_reader *reader, char *, ...) __attribute__((format(printf, 2, 3)));
void rdr_log_sensitive(struct s_reader *reader, char *, ...) __attribute__((format(printf, 2, 3)));

void rdr_log_dbg(struct s_reader *reader, uint16_t mask, char *fmt, ...) __attribute__((format(printf, 3, 4)));
void rdr_log_dbg_sensitive(struct s_reader *reader, uint16_t mask, char *fmt, ...) __attribute__((format(printf, 3, 4)));

void rdr_log_dump(struct s_reader *reader, const uint8_t *buf, int n, char *fmt, ...) __attribute__((format(printf, 4, 5)));
void rdr_log_dump_dbg(struct s_reader *reader, uint16_t mask, const uint8_t *buf, int n, char *fmt, ...) __attribute__((format(printf, 5, 6)));

#endif
