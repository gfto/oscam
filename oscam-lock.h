#ifndef OSCAM_LOCK_H_
#define OSCAM_LOCK_H_

// Lock types
#define WRITELOCK 1
#define READLOCK 2

void cs_lock_create(const char *n, CS_MUTEX_LOCK *l, const char *name, uint32_t timeout_ms);
void cs_lock_destroy(const char *n, CS_MUTEX_LOCK *l);
void cs_rwlock_int(const char *n, CS_MUTEX_LOCK *l, int8_t type);
void cs_rwunlock_int(const char *n, CS_MUTEX_LOCK *l, int8_t type);
int8_t cs_try_rwlock_int(const char *n, CS_MUTEX_LOCK *l, int8_t type);

void cs_lock_create_nolog(const char *n, CS_MUTEX_LOCK *l, const char *name, uint32_t timeout_ms);
void cs_rwlock_int_nolog(const char *n, CS_MUTEX_LOCK *l, int8_t type);
void cs_rwunlock_int_nolog(const char *n, CS_MUTEX_LOCK *l, int8_t type);

#define cs_writelock(n, l) cs_rwlock_int(n, l, WRITELOCK)
#define cs_readlock(n, l)  cs_rwlock_int(n, l, READLOCK)
#define cs_writeunlock(n, l)   cs_rwunlock_int(n, l, WRITELOCK)
#define cs_readunlock(n, l)    cs_rwunlock_int(n, l, READLOCK)
#define cs_try_writelock(n, l) cs_try_rwlock_int(n, l, WRITELOCK)
#define cs_try_readlock(n, l)  cs_try_rwlock_int(n, l, READLOCK)

#define cs_writelock_nolog(n, l) 	cs_rwlock_int_nolog(n, l, WRITELOCK)
#define cs_writeunlock_nolog(n, l)	cs_rwunlock_int_nolog(n, l, WRITELOCK)

#endif
