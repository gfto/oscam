#include <pthread.h>

#include "globals.h"
#include "module-datastruct-llist.h"
#define HASH_BUCKETS 16

struct cs_garbage {
        time_t time;
        void * data;
        #ifdef WITH_DEBUG
        char *file;
        int32_t line;
        #endif
        struct cs_garbage *next;
};

struct cs_garbage *garbage_first[HASH_BUCKETS];
pthread_mutex_t garbage_lock[HASH_BUCKETS];
pthread_t garbage_thread;
int32_t garbage_collector_active = 0;
int32_t garbage_debug = 0;

#ifdef WITH_DEBUG
void add_garbage_debug(void *data, char *file, int32_t line) {
#else
void add_garbage(void *data) {
#endif
        if (!data)
                return;
                
        if (!garbage_collector_active || garbage_debug) {
          free(data);
          return;
        }
		
		int32_t bucket = (uintptr_t)data/16 % HASH_BUCKETS;
        while (cs_trylock(&garbage_lock[bucket])) {
        	cs_debug_mask(D_TRACE, "trylock add_garbage wait");	
        	cs_sleepms(50);
        }
        
        struct cs_garbage *garbagecheck = garbage_first[bucket];
        while(garbagecheck) {
        	if(garbagecheck->data == data) {
      			cs_log("Found a try to add garbage twice. Not adding the element to garbage list...");
      			#ifdef WITH_DEBUG
      			cs_log("Current garbage addition: %s, line %d.", file, line);
      			cs_log("Original garbage addition: %s, line %d.", garbagecheck->file, garbagecheck->line);
      			#else
      			cs_log("Please compile with debug for exact info.");
      			#endif
        		break;
        	}
        	garbagecheck = garbagecheck->next;
        }
		
		if (garbagecheck == NULL) {
	        struct cs_garbage *garbage = malloc(sizeof(struct cs_garbage));
	        garbage->time = time(NULL);
	        garbage->data = data;
	        garbage->next = garbage_first[bucket];
	        #ifdef WITH_DEBUG
	        garbage->file = file;
	        garbage->line = line;
	        #endif
	        garbage_first[bucket] = garbage;
	    }

        cs_unlock(&garbage_lock[bucket]);
}

void garbage_collector() {
        time_t now;
        int32_t i;
        struct cs_garbage *garbage, *next, *prev;
        
        while (garbage_collector_active) {
                
                for(i = 0; i < HASH_BUCKETS; ++i){
	                while (cs_trylock(&garbage_lock[i])) {
	                	cs_debug_mask(D_TRACE, "trylock garbage_collector wait");
	                	cs_sleepms(50);
	                }
	                now = time(NULL);
	
	                prev = NULL;
	                garbage = garbage_first[i];  
	                while (garbage) {
	                        next = garbage->next;
	                        if (now > garbage->time+5) { //5 seconds!
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
	                cs_unlock(&garbage_lock[i]);
	              }
                cs_sleepms(1000);
        }
        pthread_exit(NULL);
}

void start_garbage_collector(int32_t debug) {

	garbage_debug = debug;
	int32_t i;
	for(i = 0; i < HASH_BUCKETS; ++i){
		pthread_mutex_init(&garbage_lock[i], NULL);

		garbage_first[i] = NULL;
	}
	pthread_attr_t attr;
	pthread_attr_init(&attr);

	garbage_collector_active = 1;

#ifndef TUXBOX
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	pthread_create(&garbage_thread, &attr, (void*)&garbage_collector, NULL);
	pthread_detach(garbage_thread);
	pthread_attr_destroy(&attr);
}

void stop_garbage_collector()
{
        if (garbage_collector_active) {
                int32_t i;
                
                garbage_collector_active = 0;
                for(i = 0; i < HASH_BUCKETS; ++i)
                	cs_lock(&garbage_lock[i]);
                
                pthread_cancel(garbage_thread);
                cs_sleepms(100);
                
                for(i = 0; i < HASH_BUCKETS; ++i){
	                while (garbage_first[i]) {
	                  struct cs_garbage *next = garbage_first[i]->next;
	                  free(garbage_first[i]->data);
	                  free(garbage_first[i]);
	                  garbage_first[i] = next;
	                }
                	cs_unlock(&garbage_lock[i]);
                	pthread_mutex_destroy(&garbage_lock[i]);
                }
        }
}
