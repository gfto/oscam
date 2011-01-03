#include "globals.h"
#include "module-datastruct-llist.h"

LLIST *garbage_list;

struct cs_garbage {
        time_t time;
        void * data;
};

void add_garbage(void *data) {
        if (!data)
                return;
                
        pthread_mutex_lock(&garbage_list->lock);
        
        struct cs_garbage *garbage = malloc(sizeof(struct cs_garbage));
        garbage->time = time(NULL);
        garbage->data = data;
        ll_append(garbage_list, garbage);
        
        pthread_mutex_unlock(&garbage_list->lock);
}

void garbage_collector() {
        LL_ITER *it;
        time_t now;
        struct cs_garbage *garbage;
        while (1) {
                cs_sleepms(1000);
                
                now = time(NULL);
                it = ll_iter_create(garbage_list);
                while ((garbage = ll_iter_next(it))) {
                        if (now > garbage->time+5) { //5 seconds!
                                free(garbage->data);
                                ll_iter_remove_data(it);
                        }
                }
                ll_iter_release(it);       
        }
}

void start_garbage_collector() {

        garbage_list = ll_create();
        pthread_t temp;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
        pthread_create(&temp, &attr, (void*)&garbage_collector, NULL);
        pthread_detach(temp);
        pthread_attr_destroy(&attr);                                                  
}

