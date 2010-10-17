/*
 * module-obj-llist.h
 *
 *  Created on: 23.04.2010
 *      Author: alno
 */

#ifndef OSCAMLLIST_D__H_
#define OSCAMLLIST_D__H_

/******************************** */
/* LINKED LIST CODE - IF IT'S USEFUL ELSEWHERE, IT SHOULD BE SPLIT OFF INTO linkedlist.h/.c */
/******************************** */

// Simple, doubly linked
// This is thread-safe, so requires pthread. Also expect locking if iterators are not destroyed.

#include <pthread.h>

struct llist_node {
	void *obj;
	struct llist_node *prv;
	struct llist_node *nxt;
};

typedef struct llist {
	struct llist_node *first;
	struct llist_node *last;
	int items;
	pthread_mutex_t lock;
} LLIST_D_;

typedef struct llist_itr {
	LLIST_D_ *l;
	struct llist_node *cur;
} LLIST_D__ITR;

LLIST_D_ *llist_create(void);                  // init linked list
void llist_destroy(LLIST_D_ *l);               // de-init linked list - frees all objects on the list
void llist_clear(LLIST_D_ *l);                 // frees all objects on the list

void *llist_append(LLIST_D_ *l, void *o);       // append object onto bottom of list, returns ptr to obj
void *llist_insert_first(LLIST_D_ *l, void *o);       // append object onto bottom of list, returns ptr to obj

void *llist_itr_init(LLIST_D_ *l, LLIST_D__ITR *itr);       // linked list iterator, returns ptr to first obj
//void llist_itr_release(LLIST_D__ITR *itr);               // release iterator
void *llist_itr_next(LLIST_D__ITR *itr);                 // iterates, returns ptr to next obj

void *llist_itr_insert(LLIST_D__ITR *itr, void *o);  // insert object at itr point, iterates to and returns ptr to new obj
void *llist_itr_remove(LLIST_D__ITR *itr);           // remove obj at itr, iterates to and returns ptr to next obj

int llist_count(LLIST_D_ *l);    // returns number of obj in list

#endif /* OSCAMLLIST_D__H_ */
