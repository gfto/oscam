#include "globals.h"
#include "oscam-time.h"

static enum clock_type clock_type = CLOCK_TYPE_UNKNOWN;

#if defined(CLOCKFIX)
struct timeval lasttime; // holds previous time to detect systemtime adjustments due to eg transponder change on dvb receivers
#endif

int64_t comp_timeb(struct timeb *tpa, struct timeb *tpb)
{
	return (int64_t)(((int64_t)(tpa->time - tpb->time) * 1000ull) + ((int64_t) tpa->millitm - (int64_t) tpb->millitm));
}

int64_t comp_timebus(struct timeb *tpa, struct timeb *tpb)
{
	return (int64_t)(((int64_t)(tpa->time - tpb->time) * 1000000ull) + ((int64_t) tpa->millitm - (int64_t) tpb->millitm));
}

/* Checks if year is a leap year. If so, 1 is returned, else 0. */
static int8_t is_leap(unsigned int y)
{
	return (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

/* Drop-in replacement for timegm function as some plattforms strip the function from their libc.. */
time_t cs_timegm(struct tm *tm)
{
	time_t result = 0;
	int32_t i;
	if(tm->tm_mon > 12 || tm->tm_mon < 0 || tm->tm_mday > 31 || tm->tm_min > 60 || tm->tm_sec > 60 || tm->tm_hour > 24)
		{ return 0; }
	for(i = 70; i < tm->tm_year; ++i)
	{
		result += is_leap(i + 1900) ? 366 : 365;
	}
	for(i = 0; i < tm->tm_mon; ++i)
	{
		if(i == 0 || i == 2 || i == 4 || i == 6 || i == 7 || i == 9 || i == 11) { result += 31; }
		else if(i == 3 || i == 5 || i == 8 || i == 10) { result += 30; }
		else if(is_leap(tm->tm_year + 1900)) { result += 29; }
		else { result += 28; }
	}
	result += tm->tm_mday - 1;
	result *= 24;
	result += tm->tm_hour;
	result *= 60;
	result += tm->tm_min;
	result *= 60;
	result += tm->tm_sec;
	return result;
}

/* Drop-in replacement for gmtime_r as some plattforms strip the function from their libc. */
struct tm *cs_gmtime_r(const time_t *timep, struct tm *r)
{
	static const int16_t daysPerMonth[13] = { 0,
											31,
											31 + 28,
											31 + 28 + 31,
											31 + 28 + 31 + 30,
											31 + 28 + 31 + 30 + 31,
											31 + 28 + 31 + 30 + 31 + 30,
											31 + 28 + 31 + 30 + 31 + 30 + 31,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31
											};
	time_t i;
	time_t work = * timep % 86400;
	r->tm_sec = work % 60;
	work /= 60;
	r->tm_min = work % 60;
	r->tm_hour = work / 60;
	work = * timep / 86400;
	r->tm_wday = (4 + work) % 7;
	for(i = 1970; ; ++i)
	{
		time_t k = is_leap(i) ? 366 : 365;
		if(work >= k)
			{ work -= k; }
		else
			{ break; }
	}
	r->tm_year = i - 1900;
	r->tm_yday = work;
	r->tm_mday = 1;
	if(is_leap(i) && work > 58)
	{
		if(work == 59)
			{ r->tm_mday = 2; } /* 29.2. */
		work -= 1;
	}
	for(i = 11; i && daysPerMonth[i] > work; --i)
		{ ; }
	r->tm_mon   = i;
	r->tm_mday += work - daysPerMonth[i];
	return r;
}

/* Drop-in replacement for ctime_r as some plattforms strip the function from their libc. */
char *cs_ctime_r(const time_t *timep, char *buf)
{
	struct tm t;
	localtime_r(timep, &t);
	strftime(buf, 26, "%c\n", &t);
	return buf;
}

void cs_ftime(struct timeb *tp)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
#if defined(CLOCKFIX)
	if (tv.tv_sec > lasttime.tv_sec || (tv.tv_sec == lasttime.tv_sec && tv.tv_usec >= lasttime.tv_usec)){ // check for time issues!
		lasttime = tv; // register this valid time 
	}
	else
	{
		tv = lasttime;
		settimeofday(&tv, NULL); // set time back to last known valid time
		//fprintf(stderr, "*** WARNING: BAD TIME AFFECTING WHOLE OSCAM ECM HANDLING, SYSTEMTIME SET TO LAST KNOWN VALID TIME **** \n");
	}
#endif	
	tp->time    = tv.tv_sec;
	tp->millitm = tv.tv_usec / 1000;
}

void cs_ftimeus(struct timeb *tp)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
#if defined(CLOCKFIX)
	if (tv.tv_sec > lasttime.tv_sec || (tv.tv_sec == lasttime.tv_sec && tv.tv_usec >= lasttime.tv_usec)){ // check for time issues!
		lasttime = tv; // register this valid time 
	}
	else
	{
		tv = lasttime;
		settimeofday(&tv, NULL); // set time back to last known valid time
		//fprintf(stderr, "*** WARNING: BAD TIME AFFECTING WHOLE OSCAM ECM HANDLING, SYSTEMTIME SET TO LAST KNOWN VALID TIME **** \n");
	}
#endif	
	tp->time    = tv.tv_sec;
	tp->millitm = tv.tv_usec;
}

void cs_sleepms(uint32_t msec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = msec / 1000;
	req_ts.tv_nsec = (msec % 1000) * 1000000L;
	int32_t olderrno = errno; // Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping
	while (1)
	{
		/* Sleep for the time specified in req_ts. If interrupted by a
		signal, place the remaining time left to sleep back into req_ts. */
		int rval = nanosleep (&req_ts, &req_ts);
		if (rval == 0)
			break; // Completed the entire sleep time; all done.
		else if (errno == EINTR)
			continue; // Interrupted by a signal. Try again.
		else 
			break; // Some other error; bail out.
	}
	errno = olderrno;
}

void cs_sleepus(uint32_t usec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = usec / 1000000;
	req_ts.tv_nsec = (usec % 1000000) * 1000L;
	int32_t olderrno = errno;       // Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping
	while (1)
	{
		/* Sleep for the time specified in req_ts. If interrupted by a
		signal, place the remaining time left to sleep back into req_ts. */
		int rval = nanosleep (&req_ts, &req_ts);
		if (rval == 0)
			break; // Completed the entire sleep time; all done.
		else if (errno == EINTR)
			continue; // Interrupted by a signal. Try again.
		else 
			break; // Some other error; bail out.
	}
	errno = olderrno;
}

void add_ms_to_timespec(struct timespec *timeout, int32_t msec)
{
	struct timespec now;
	int64_t nanosecs, secs;
	const int64_t NANOSEC_PER_MS = 1000000;
	const int64_t NANOSEC_PER_SEC = 1000000000;
	cs_gettime(&now);
	nanosecs = (int64_t) (msec * NANOSEC_PER_MS + now.tv_nsec);
	if (nanosecs >= NANOSEC_PER_SEC){
		secs = now.tv_sec + (nanosecs / NANOSEC_PER_SEC);
		nanosecs %= NANOSEC_PER_SEC;
	}
	else{
		secs = now.tv_sec;
	}
	timeout->tv_sec = (long)secs;
	timeout->tv_nsec = (long)nanosecs;
}

void add_ms_to_timeb(struct timeb *tb, int32_t ms)
{
	if (ms >= 1000){
		tb->time += ms / 1000;
		tb->millitm += (ms % 1000);
	}
	else{
		tb->millitm += ms;
	}
	if(tb->millitm >= 1000)
	{
		tb->millitm %= 1000;
		tb->time++;
	}
}

int64_t add_ms_to_timeb_diff(struct timeb *tb, int32_t ms)
{
	struct timeb tb_now;
	add_ms_to_timeb(tb, ms);
	cs_ftime(&tb_now);
	return comp_timeb(tb, &tb_now);
}

#if defined(__UCLIBC__)
#  define __UCLIBC_VER (__UCLIBC_MAJOR__ * 10000 + __UCLIBC_MINOR__ * 100 + __UCLIBC_SUBLEVEL__)
#else
#  define __UCLIBC_VER 999999
#endif

#if defined(__GLIBC__)
#  define __GLIBCVER (__GLIBC__ * 100 + __GLIBC_MINOR__)
#else
#  define __GLIBCVER 9999
#endif

// Assume we have HAVE_pthread_condattr_setclock if CLOCK_MONOTONIC is defined
#if defined(CLOCKFIX) && defined(CLOCK_MONOTONIC)
#define HAVE_pthread_condattr_setclock 1
#endif

#if defined(HAVE_pthread_condattr_setclock)
// UCLIBC 0.9.31 does not have pthread_condattr_setclock
#  if __UCLIBC_VER < 932
#     undef HAVE_pthread_condattr_setclock
#  endif
// glibc 2.3.6 in ppc old toolchain do not have pthread_condattr_setclock
#  if __GLIBCVER < 204
#     undef HAVE_pthread_condattr_setclock
#  endif
// android's libc not have pthread_condattr_setclock
#  if __BIONIC__
#     undef HAVE_pthread_condattr_setclock
#  endif
#endif

void __cs_pthread_cond_init(const char *n, pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	SAFE_CONDATTR_INIT_R(&attr, n); // init condattr with defaults
#if 0
#if defined(HAVE_pthread_condattr_setclock)
	enum clock_type ctype = cs_getclocktype();
	pthread_condattr_setclock(&attr, (ctype == CLOCK_TYPE_MONOTONIC) ? CLOCK_MONOTONIC : CLOCK_REALTIME);
#endif
#endif
	SAFE_COND_INIT_R(cond, &attr, n); // init thread with right clock assigned
	pthread_condattr_destroy(&attr);
}

void __cs_pthread_cond_init_nolog(const char *n, pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	SAFE_CONDATTR_INIT_NOLOG_R(&attr, n); // init condattr with defaults
#if 0
#if defined(HAVE_pthread_condattr_setclock)
	enum clock_type ctype = cs_getclocktype();
	pthread_condattr_setclock(&attr, (ctype == CLOCK_TYPE_MONOTONIC) ? CLOCK_MONOTONIC : CLOCK_REALTIME);
#endif
#endif
	SAFE_COND_INIT_NOLOG_R(cond, &attr, n); // init thread with right clock assigned
	pthread_condattr_destroy(&attr);
}


void sleepms_on_cond(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond, uint32_t msec)
{
	struct timespec ts;
	add_ms_to_timespec(&ts, msec);
	SAFE_MUTEX_LOCK_R(mutex, n);
	pthread_cond_timedwait(cond, mutex, &ts); // sleep on sleep_cond
	SAFE_MUTEX_UNLOCK_R(mutex, n);
}

void cs_pthread_cond_init(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond)
{
	SAFE_MUTEX_INIT_R(mutex, NULL, n);
	__cs_pthread_cond_init(n, cond);
}

void cs_pthread_cond_init_nolog(const char *n, pthread_mutex_t *mutex, pthread_cond_t *cond)
{
	SAFE_MUTEX_INIT_NOLOG_R(mutex, NULL, n);
	__cs_pthread_cond_init(n, cond);
}

enum clock_type cs_getclocktype(void) {
	if (clock_type == CLOCK_TYPE_UNKNOWN) {
		struct timespec ts;
		cs_gettime(&ts); // init clock type
	}
	return clock_type;
}

time_t cs_walltime(struct timeb *tp)
{
	// we dont need to fetch time again and calculate if oscam is already using realtimeclock!
	if (clock_type != CLOCK_TYPE_MONOTONIC)
		return tp->time;

	struct timespec ts;
	struct timeval tv;

	cs_gettime(&ts);
	gettimeofday(&tv, NULL);
	int64_t skew = tv.tv_sec - ts.tv_sec;
	return(tp->time + skew);
}

/* Return real time clock value calculated based on cs_gettime(). Use this instead of time() */
time_t cs_time(void)
{
	struct timeb tb;
	cs_ftime(&tb);
	return cs_walltime(&tb);
}

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

void cs_gettime(struct timespec *ts)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
#if defined(CLOCKFIX)
	if (tv.tv_sec > lasttime.tv_sec || (tv.tv_sec == lasttime.tv_sec && tv.tv_usec >= lasttime.tv_usec)){ // check for time issues!
		lasttime = tv; // register this valid time 
	}
	else
	{
		tv = lasttime;
		settimeofday(&tv, NULL); // set time back to last known valid time
		//fprintf(stderr, "*** WARNING: BAD TIME AFFECTING WHOLE OSCAM ECM HANDLING, SYSTEMTIME SET TO LAST KNOWN VALID TIME **** \n");
	}
#endif
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
	clock_type = CLOCK_TYPE_REALTIME;
	return;
#if 0
#if !defined(CLOCKFIX) || (!defined(CLOCK_MONOTONIC) && !defined(__MACH__))
	struct timeval tv;
    gettimeofday(&tv, NULL);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
	clock_type = CLOCK_TYPE_REALTIME;
	return;
#elif defined (__MACH__)
// OS X does not have clock_gettime, use clock_get_time
	clock_serv_t cclock;
	mach_timespec_t mts;
	host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);
	ts->tv_sec = mts.tv_sec;
	ts->tv_nsec = mts.tv_nsec;
	clock_type = CLOCK_TYPE_REALTIME;
#else
	if (clock_type == CLOCK_TYPE_REALTIME) { // monotonic returned error
		clock_gettime(CLOCK_REALTIME, ts);
		return;
	}
	int32_t	ret = clock_gettime(CLOCK_MONOTONIC, ts);
	clock_type = CLOCK_TYPE_MONOTONIC;
	if ((ret < 0 && errno == EINVAL)){ // Error fetching time from this source (Shouldn't happen on modern Linux)
		clock_gettime(CLOCK_REALTIME, ts);
		clock_type = CLOCK_TYPE_REALTIME;
	}
#endif
#endif
}
