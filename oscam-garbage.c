#include "globals.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-string.h"

#define HASH_BUCKETS 16

struct cs_garbage {
        time_t time;
        void * data;
        #ifdef WITH_DEBUG
        char *file;
        uint16_t line;
        #endif
        struct cs_garbage *next;
};

struct cs_garbage *garbage_first[HASH_BUCKETS];
CS_MUTEX_LOCK garbage_lock[HASH_BUCKETS];
pthread_t garbage_thread;
int32_t garbage_collector_active = 0;
int32_t garbage_debug = 0;

#ifdef WITH_DEBUG
void add_garbage_debug(void *data, char *file, uint16_t line) {
#else
void add_garbage(void *data) {
#endif
	if (!data)
		return;

	if (!garbage_collector_active || garbage_debug == 1) {
		free(data);
		return;
	}

	int32_t bucket = (uintptr_t)data/16 % HASH_BUCKETS;
	cs_writelock(&garbage_lock[bucket]);

#ifdef WITH_DEBUG
	if(garbage_debug == 2){
		struct cs_garbage *garbagecheck = garbage_first[bucket];
		while(garbagecheck) {
			if(garbagecheck->data == data) {
				cs_log("Found a try to add garbage twice. Not adding the element to garbage list...");
				cs_log("Current garbage addition: %s, line %d.", file, line);
				cs_log("Original garbage addition: %s, line %d.", garbagecheck->file, garbagecheck->line);
				cs_writeunlock(&garbage_lock[bucket]);
				return;
			}
			garbagecheck = garbagecheck->next;
		}
	}
#endif

	struct cs_garbage *garbage;
	if (!cs_malloc(&garbage, sizeof(struct cs_garbage)))
	{
     free(data);
     cs_writeunlock(&garbage_lock[bucket]);
     return;
    }
	garbage->time = time(NULL);
	garbage->data = data;
	garbage->next = garbage_first[bucket];
	#ifdef WITH_DEBUG
	garbage->file = file;
	garbage->line = line;
	#endif
	garbage_first[bucket] = garbage;

	cs_writeunlock(&garbage_lock[bucket]);
}

void garbage_collector(void) {
        time_t now;
        int8_t i;
        struct cs_garbage *garbage, *next, *prev;

        while (garbage_collector_active) {

                for(i = 0; i < HASH_BUCKETS; ++i){
	                cs_writelock(&garbage_lock[i]);
	                now = time(NULL);

	                prev = NULL;
	                garbage = garbage_first[i];
	                while (garbage) {
	                        next = garbage->next;
	                        if (now > (time_t)(garbage->time+2*cfg.ctimeout/1000+1)) { //clienttimeout +1 second
	                                free(garbage->data);

	                                if (prev)
	                                        prev->next = next;
	                                else
	                                        garbage_first[i] = next;
	                                free(garbage);
	                        }
	                        else
	                                prev = garbage;
	                        garbage = next;
	                }
	                cs_writeunlock(&garbage_lock[i]);
	              }
                cs_sleepms(1000);
        }
        pthread_exit(NULL);
}

void start_garbage_collector(int32_t debug) {

	garbage_debug = debug;
	int8_t i;
	for(i = 0; i < HASH_BUCKETS; ++i){
		cs_lock_create(&garbage_lock[i], 5, "garbage_lock");

		garbage_first[i] = NULL;
	}
	pthread_attr_t attr;
	pthread_attr_init(&attr);

	garbage_collector_active = 1;

	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	int32_t ret = pthread_create(&garbage_thread, &attr, (void*)&garbage_collector, NULL);
	if(ret){
		cs_log("ERROR: can't create garbagecollector thread (errno=%d %s)", ret, strerror(ret));
		pthread_attr_destroy(&attr);
		cs_exit(1);
	} else
		pthread_detach(garbage_thread);
	pthread_attr_destroy(&attr);
}

void stop_garbage_collector(void)
{
	if (garbage_collector_active) {
		int8_t i;

		garbage_collector_active = 0;
		for(i = 0; i < HASH_BUCKETS; ++i)
			cs_writelock(&garbage_lock[i]);

		pthread_cancel(garbage_thread);
		cs_sleepms(100);

		for(i = 0; i < HASH_BUCKETS; ++i){
			while (garbage_first[i]) {
				struct cs_garbage *next = garbage_first[i]->next;
				free(garbage_first[i]->data);
				free(garbage_first[i]);
				garbage_first[i] = next;
			}
		}
	}
}
