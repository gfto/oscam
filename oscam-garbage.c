#define MODULE_LOG_PREFIX "gc"

#include "globals.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-time.h"

#define HASH_BUCKETS 250

struct cs_garbage
{
	time_t time;
	void *data;
#ifdef WITH_DEBUG
	char *file;
	uint32_t line;
#endif
	struct cs_garbage *next;
};

static int32_t counter = 0;
static pthread_mutex_t add_lock;
static struct cs_garbage *garbage_first[HASH_BUCKETS];
static CS_MUTEX_LOCK garbage_lock[HASH_BUCKETS];
static pthread_t garbage_thread;
static int32_t garbage_collector_active;
static int32_t garbage_debug;

#ifdef WITH_DEBUG
void add_garbage_debug(void *data, char *file, uint32_t line)
{
#else
void add_garbage(void *data)
{
#endif
	if(!data)
		{ return; }

	if(!garbage_collector_active || garbage_debug == 1)
	{
		NULLFREE(data);
		return;
	}

	SAFE_MUTEX_LOCK(&add_lock);
	
	int32_t bucket = counter++;
	
	if(counter >= HASH_BUCKETS)
	{
		counter = 0;
	}
	
	SAFE_MUTEX_UNLOCK(&add_lock);
	
	struct cs_garbage *garbage = (struct cs_garbage*)malloc(sizeof(struct cs_garbage));
	if(garbage == NULL)
	{
		cs_log("*** MEMORY FULL -> FREEING DIRECT MAY LEAD TO INSTABILITY!!!! ***");
		NULLFREE(data);
		return;
	}
	garbage->time = time(NULL);
	garbage->data = data;
	garbage->next = NULL;
#ifdef WITH_DEBUG
	garbage->file = file;
	garbage->line = line;
#endif

	cs_writelock(__func__, &garbage_lock[bucket]);

#ifdef WITH_DEBUG
	if(garbage_debug == 2)
	{
		struct cs_garbage *garbagecheck = garbage_first[bucket];
		while(garbagecheck)
		{
			if(garbagecheck->data == data)
			{
				cs_log("Found a try to add garbage twice. Not adding the element to garbage list...");
				cs_log("Current garbage addition: %s, line %d.", file, line);
				cs_log("Original garbage addition: %s, line %d.", garbagecheck->file, garbagecheck->line);
				cs_writeunlock(__func__, &garbage_lock[bucket]);
				NULLFREE(garbage);
				return;
			}
			garbagecheck = garbagecheck->next;
		}
	}
#endif

	garbage->next = garbage_first[bucket];  
	garbage_first[bucket] = garbage;
	
	cs_writeunlock(__func__, &garbage_lock[bucket]);
}

static pthread_cond_t sleep_cond;
static pthread_mutex_t sleep_cond_mutex;

static void garbage_collector(void)
{
	int32_t i,j;
	struct cs_garbage *garbage, *next, *prev, *first;
	set_thread_name(__func__);
	int32_t timeout_time = 2*cfg.ctimeout/1000+6;
		
	while(garbage_collector_active)
	{
		time_t deltime = time(NULL) - timeout_time;
		
		for(i = 0; i < HASH_BUCKETS; ++i)
		{
			j = 0;
			cs_writelock(__func__, &garbage_lock[i]);
			first = garbage_first[i];
			
			for(garbage = first, prev = NULL; garbage; prev = garbage, garbage = garbage->next,j++)
			{
				if(j==2)
 				{
					j++;
					cs_writeunlock(__func__, &garbage_lock[i]);
				}

				if(garbage->time < deltime)     // all following elements are too new
				{
					if(prev)
					{
						prev->next = NULL;
					}
					else
					{
						garbage_first[i] = NULL;
					}
					break;
				}
			}

			if(j<3)
			{
				cs_writeunlock(__func__, &garbage_lock[i]);
			}

			// list has been taken out before so we don't need a lock here anymore!
			while(garbage)
			{
				next = garbage->next;
				free(garbage->data);
				free(garbage);
				garbage = next;
			}
		}
		sleepms_on_cond(__func__, &sleep_cond_mutex, &sleep_cond, 500);
	}
	pthread_exit(NULL);
}

void start_garbage_collector(int32_t debug)
{
	garbage_debug = debug;
	int32_t i;
	
	SAFE_MUTEX_INIT(&add_lock, NULL);
	
	for(i = 0; i < HASH_BUCKETS; ++i)
	{
		cs_lock_create(__func__, &garbage_lock[i], "garbage_lock", 9000);

		garbage_first[i] = NULL;
	}
	cs_pthread_cond_init(__func__, &sleep_cond_mutex, &sleep_cond);

	garbage_collector_active = 1;

	int32_t ret = start_thread("garbage", (void *)&garbage_collector, NULL, &garbage_thread, 0, 1);
	if(ret)
	{
		cs_exit(1);
	}
}

void stop_garbage_collector(void)
{
	if(garbage_collector_active)
	{
		int32_t i;

		garbage_collector_active = 0;
		SAFE_COND_SIGNAL(&sleep_cond);
		cs_sleepms(500);
		SAFE_COND_SIGNAL(&sleep_cond);
		SAFE_THREAD_JOIN(garbage_thread, NULL);
		for(i = 0; i < HASH_BUCKETS; ++i)
			{ cs_writelock(__func__, &garbage_lock[i]); }

		for(i = 0; i < HASH_BUCKETS; ++i)
		{
			while(garbage_first[i])
			{
				struct cs_garbage *next = garbage_first[i]->next;
				NULLFREE(garbage_first[i]->data);
				NULLFREE(garbage_first[i]);
				garbage_first[i] = next;
			}
		}
		
		for(i = 0; i < HASH_BUCKETS; ++i)
		{ 
			cs_writeunlock(__func__, &garbage_lock[i]);
			cs_lock_destroy(__func__, &garbage_lock[i]);
		}

 		pthread_mutex_destroy(&add_lock);
 		pthread_cond_destroy(&sleep_cond);
		pthread_mutex_destroy(&sleep_cond_mutex);
	}
}
