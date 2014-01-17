#ifndef OSCAM_TIME_H_
#define OSCAM_TIME_H_

enum clock_type {
	CLOCK_TYPE_UNKNOWN,
	CLOCK_TYPE_REALTIME,
	CLOCK_TYPE_MONOTONIC,
};

int32_t comp_timeb(struct timeb *tpa, struct timeb *tpb);
time_t cs_timegm(struct tm *tm);
struct tm *cs_gmtime_r(const time_t *timep, struct tm *r);
char *cs_ctime_r(const time_t *timep, char *buf);
void cs_ftime(struct timeb *tp);
void cs_sleepms(uint32_t msec);
void cs_sleepus(uint32_t usec);

void add_ms_to_timespec(struct timespec *timeout, int32_t msec);
void add_ms_to_timeb(struct timeb *tb, int32_t ms);
int32_t add_ms_to_timeb_diff(struct timeb *tb, int32_t ms);

void sleepms_on_cond(pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t msec);

time_t cs_walltime(struct timeb *tp);
void cs_gettime(struct timespec *ts);
enum clock_type cs_getclocktype(struct timeb *now);
void __cs_pthread_cond_init(pthread_cond_t *cond);
void cs_pthread_cond_init(pthread_mutex_t *mutex, pthread_cond_t *cond);

#endif
