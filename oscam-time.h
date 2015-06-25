#ifndef OSCAM_TIME_H_
#define OSCAM_TIME_H_

enum clock_type {
	CLOCK_TYPE_UNKNOWN,
	CLOCK_TYPE_REALTIME,
	CLOCK_TYPE_MONOTONIC,
};

int64_t comp_timeb(struct timeb *tpa, struct timeb *tpb);
int64_t comp_timebus(struct timeb *tpa, struct timeb *tpb);
time_t cs_timegm(struct tm *tm);
struct tm *cs_gmtime_r(const time_t *timep, struct tm *r);
char *cs_ctime_r(const time_t *timep, char *buf);
void cs_ftime(struct timeb *tp);
void cs_ftimeus(struct timeb *tp);
void cs_sleepms(uint32_t msec);
void cs_sleepus(uint32_t usec);

void add_ms_to_timespec(struct timespec *timeout, int32_t msec);
void add_ms_to_timeb(struct timeb *tb, int32_t ms);
int64_t add_ms_to_timeb_diff(struct timeb *tb, int32_t ms);

time_t cs_walltime(struct timeb *tp);
time_t cs_time(void);

static inline bool cs_valid_time(struct timeb *tp) { return tp->time != 0; }

void cs_gettime(struct timespec *ts);

enum clock_type cs_getclocktype(void);


void __cs_pthread_cond_init(const char *n, pthread_cond_t *cond);
void cs_pthread_cond_init(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond);

void __cs_pthread_cond_init_nolog(const char *n, pthread_cond_t *cond);
void cs_pthread_cond_init_nolog(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond);

void sleepms_on_cond(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t msec);

#endif
