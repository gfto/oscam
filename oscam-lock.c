#define MODULE_LOG_PREFIX "lock"

#include "globals.h"
#include "oscam-lock.h"
#include "oscam-time.h"

extern char *LOG_LIST;

/**
 * creates a lock
 **/
void cs_lock_create(const char *n, CS_MUTEX_LOCK *l, const char *name, uint32_t timeout_ms)
{
	memset(l, 0, sizeof(CS_MUTEX_LOCK));
	l->timeout = timeout_ms / 1000;
	l->name = name;
	SAFE_MUTEX_INIT_R(&l->lock, NULL, n);
	__cs_pthread_cond_init(n, &l->writecond);
	__cs_pthread_cond_init(n, &l->readcond);
#ifdef WITH_MUTEXDEBUG
	cs_log_dbg(D_TRACE, "lock %s created", name);
#endif
}

/**
 * creates a lock
 **/
void cs_lock_create_nolog(const char *n, CS_MUTEX_LOCK *l, const char *name, uint32_t timeout_ms)
{
	memset(l, 0, sizeof(CS_MUTEX_LOCK));
	l->timeout = timeout_ms / 1000;
	l->name = name;
	SAFE_MUTEX_INIT_NOLOG_R(&l->lock, NULL, n);
	__cs_pthread_cond_init(n, &l->writecond);
	__cs_pthread_cond_init(n, &l->readcond);
#ifdef WITH_MUTEXDEBUG
	cs_log_dbg(D_TRACE, "lock %s created", name);
#endif
}

void cs_lock_destroy(const char *pn, CS_MUTEX_LOCK *l)
{
	if(!l || !l->name || l->flag) { return; }

	cs_rwlock_int(pn, l, WRITELOCK);
#ifdef WITH_DEBUG
	const char *old_name = l->name;
#endif
	l->name = NULL; //No new locks!
	cs_rwunlock_int(pn, l, WRITELOCK);

	//Do not destroy when having pending locks!
	int32_t n = (l->timeout / 10) + 2;
	while((--n > 0) && (l->writelock || l->readlock)) { cs_sleepms(10); }

	cs_rwlock_int(pn, l, WRITELOCK);
	l->flag++; //No new unlocks!
	cs_rwunlock_int(pn, l, WRITELOCK);

#ifdef WITH_DEBUG
	if(!n && old_name != LOG_LIST)
		{ cs_log("WARNING lock %s destroy timed out.", old_name); }
#endif

	pthread_mutex_destroy(&l->lock);
	pthread_cond_destroy(&l->writecond);
	pthread_cond_destroy(&l->readcond);
#ifdef WITH_MUTEXDEBUG
	cs_log_dbg(D_TRACE, "lock %s destroyed", l->name);
#endif
}

void cs_rwlock_int(const char *n, CS_MUTEX_LOCK *l, int8_t type)
{
	struct timespec ts;
	int8_t ret = 0;

	if(!l || !l->name || l->flag)
		{ return; }

	SAFE_MUTEX_LOCK_R(&l->lock, n);

	add_ms_to_timespec(&ts, l->timeout * 1000);
	ts.tv_nsec = 0; // 100% resemble previous code, I consider it wrong 
	if(type == WRITELOCK)
	{
		l->writelock++;
		// if read- or writelock is busy, wait for unlock
		if(l->writelock > 1 || l->readlock > 0)
			{ ret = pthread_cond_timedwait(&l->writecond, &l->lock, &ts); }
	}
	else
	{
		l->readlock++;
		// if writelock is busy, wait for unlock
		if(l->writelock > 0)
			{ ret = pthread_cond_timedwait(&l->readcond, &l->lock, &ts); }
	}

	if(ret > 0)
	{
		// lock wasn't returned within time, assume locking thread to
		// be stuck or finished, so enforce lock.
		l->writelock = (type == WRITELOCK) ? 1 : 0;
		l->readlock = (type == WRITELOCK) ? 0 : 1;
#ifdef WITH_DEBUG
		if(l->name != LOG_LIST)
			{ cs_log("WARNING lock %s (%s) timed out.", l->name, (type == WRITELOCK) ? "WRITELOCK" : "READLOCK"); }
#endif
	}

	SAFE_MUTEX_UNLOCK_R(&l->lock, n);
#ifdef WITH_MUTEXDEBUG
	//cs_log_dbg(D_TRACE, "lock %s locked", l->name);
#endif
	return;
}

void cs_rwlock_int_nolog(const char *n, CS_MUTEX_LOCK *l, int8_t type)
{
	struct timespec ts;
	int8_t ret = 0;

	if(!l || !l->name || l->flag)
		{ return; }

	SAFE_MUTEX_LOCK_NOLOG_R(&l->lock, n);

	add_ms_to_timespec(&ts, l->timeout * 1000);
	ts.tv_nsec = 0; // 100% resemble previous code, I consider it wrong 
	if(type == WRITELOCK)
	{
		l->writelock++;
		// if read- or writelock is busy, wait for unlock
		if(l->writelock > 1 || l->readlock > 0)
			{ ret = pthread_cond_timedwait(&l->writecond, &l->lock, &ts); }
	}
	else
	{
		l->readlock++;
		// if writelock is busy, wait for unlock
		if(l->writelock > 0)
			{ ret = pthread_cond_timedwait(&l->readcond, &l->lock, &ts); }
	}

	if(ret > 0)
	{
		// lock wasn't returned within time, assume locking thread to
		// be stuck or finished, so enforce lock.
		l->writelock = (type == WRITELOCK) ? 1 : 0;
		l->readlock = (type == WRITELOCK) ? 0 : 1;
#ifdef WITH_DEBUG
		if(l->name != LOG_LIST)
			{ cs_log("WARNING lock %s (%s) timed out.", l->name, (type == WRITELOCK) ? "WRITELOCK" : "READLOCK"); }
#endif
	}

	SAFE_MUTEX_UNLOCK_NOLOG_R(&l->lock, n);
#ifdef WITH_MUTEXDEBUG
	//cs_log_dbg(D_TRACE, "lock %s locked", l->name);
#endif
	return;
}

void cs_rwunlock_int(const char *n, CS_MUTEX_LOCK *l, int8_t type)
{

	if(!l || l->flag) { return; }

	SAFE_MUTEX_LOCK_R(&l->lock, n);

	if(type == WRITELOCK)
		{ l->writelock--; }
	else
		{ l->readlock--; }

	if(l->writelock < 0) { l->writelock = 0; }
	if(l->readlock < 0) { l->readlock = 0; }

	// waiting writelocks always have priority. If one is waiting, signal it
	if(l->writelock)
		{ SAFE_COND_SIGNAL_R(&l->writecond, n); }
	// Otherwise signal a waiting readlock (if any)
	else if(l->readlock && type != READLOCK)
		{ SAFE_COND_BROADCAST_R(&l->readcond, n); }

	SAFE_MUTEX_UNLOCK_R(&l->lock, n);

#ifdef WITH_MUTEXDEBUG
#ifdef WITH_DEBUG
	if(l->name != LOG_LIST)
	{
		const char *typetxt[] = { "", "write", "read" };
		cs_log_dbg(D_TRACE, "%slock %s: released", typetxt[type], l->name);
	}
#endif
#endif
}

void cs_rwunlock_int_nolog(const char *n, CS_MUTEX_LOCK *l, int8_t type)
{

	if(!l || l->flag) { return; }

	SAFE_MUTEX_LOCK_NOLOG_R(&l->lock, n);

	if(type == WRITELOCK)
		{ l->writelock--; }
	else
		{ l->readlock--; }

	if(l->writelock < 0) { l->writelock = 0; }
	if(l->readlock < 0) { l->readlock = 0; }

	// waiting writelocks always have priority. If one is waiting, signal it
	if(l->writelock)
		{ SAFE_COND_SIGNAL_R(&l->writecond, n); }
	// Otherwise signal a waiting readlock (if any)
	else if(l->readlock && type != READLOCK)
		{ SAFE_COND_BROADCAST_R(&l->readcond, n); }

	SAFE_MUTEX_UNLOCK_NOLOG_R(&l->lock, n);

#ifdef WITH_MUTEXDEBUG
#ifdef WITH_DEBUG
	if(l->name != LOG_LIST)
	{
		const char *typetxt[] = { "", "write", "read" };
		cs_log_dbg(D_TRACE, "%slock %s: released", typetxt[type], l->name);
	}
#endif
#endif
}

int8_t cs_try_rwlock_int(const char *n, CS_MUTEX_LOCK *l, int8_t type)
{
	if(!l || !l->name || l->flag)
		{ return 0; }

	int8_t status = 0;

	SAFE_MUTEX_LOCK_R(&l->lock, n);

	if(type == WRITELOCK)
	{
		if(l->writelock || l->readlock)
			{ status = 1; }
		else
			{ l->writelock++; }
	}
	else
	{
		if(l->writelock)
			{ status = 1; }
		else
			{ l->readlock++; }
	}

	SAFE_MUTEX_UNLOCK_R(&l->lock, n);

#ifdef WITH_MUTEXDEBUG
#ifdef WITH_DEBUG
	if(l->name != LOG_LIST)
	{
		const char *typetxt[] = { "", "write", "read" };
		cs_log_dbg(D_TRACE, "try_%slock %s: status=%d", typetxt[type], l->name, status);
	}
#endif
#endif
	return status;
}
