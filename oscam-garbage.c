#include <pthread.h>

#include "globals.h"
#include "module-datastruct-llist.h"

struct cs_garbage {
        time_t time;
        void * data;
        struct cs_garbage *next;
};

struct cs_garbage *garbage_first;
pthread_mutex_t garbage_lock;

void add_garbage(void *data) {
        if (!data)
                return;
                
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
        
        while (1) {
                cs_sleepms(1000);
                
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
        }
}

void start_garbage_collector() {

        pthread_mutex_init(&garbage_lock, NULL);

        garbage_first = NULL;
        pthread_t temp;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
#ifndef TUXBOX
				pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
        pthread_create(&temp, &attr, (void*)&garbage_collector, NULL);
        pthread_detach(temp);
        pthread_attr_destroy(&attr);                                                  
}

