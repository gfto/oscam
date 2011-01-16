#include <pthread.h>

#include "globals.h"
#include "module-datastruct-llist.h"

struct cs_garbage {
        time_t time;
        void * data;
        struct cs_garbage *next;
};

struct cs_garbage *garbage_first = NULL;
pthread_mutex_t garbage_lock;
pthread_t garbage_thread;
int garbage_collector_active = 0;

void add_garbage(void *data) {
        if (!data)
                return;
                
        if (!garbage_collector_active) {
          free(data);
          return;
        }
                
        pthread_mutex_lock(&garbage_lock);

        struct cs_garbage *garbage = malloc(sizeof(struct cs_garbage));
        garbage->time = time(NULL);
        garbage->data = data;
        garbage->next = garbage_first;
        garbage_first = garbage;

        pthread_mutex_unlock(&garbage_lock);
}

void garbage_collector() {
        time_t now;
        struct cs_garbage *garbage, *next, *prev;
        
        while (garbage_collector_active) {
                
                pthread_mutex_lock(&garbage_lock);
              
                now = time(NULL);

                prev = NULL;
                garbage = garbage_first;  
                while (garbage) {
                        next = garbage->next;
                        if (now > garbage->time+5) { //5 seconds!
                                free(garbage->data);
                                
                                if (prev)
                                        prev->next = next;
                                else
                                        garbage_first = next;
                                free(garbage);
                        }
                        else
                                prev = garbage;
                        garbage = next;
                }
                pthread_mutex_unlock(&garbage_lock);

                cs_sleepms(1000);
        }
}

void start_garbage_collector() {

        pthread_mutex_init(&garbage_lock, NULL);

        garbage_first = NULL;
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
                garbage_collector_active = 0;
                pthread_mutex_lock(&garbage_lock);
                
                pthread_cancel(garbage_thread);
                
                while (garbage_first) {
                  struct cs_garbage *next = garbage_first->next;
                  free(garbage_first->data);
                  free(garbage_first);
                  garbage_first = next;
                }
                pthread_mutex_unlock(&garbage_lock);
                pthread_mutex_destroy(&garbage_lock);
        }
}
