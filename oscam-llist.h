/*
 * oscam-llist.h
 *
 *  Created on: 23.04.2010
 *      Author: alno
 */

#ifndef OSCAMLLIST_H_
#define OSCAMLLIST_H_

/******************************** */
/* LINKED LIST CODE - IF IT'S USEFUL ELSEWHERE, IT SHOULD BE SPLIT OFF INTO linkedlist.h/.c */
/******************************** */

// Simple, doubly linked
// This is thread-safe, so requires pthread. Also expect locking if iterators are not destroyed.

#include <pthread.h>

#define NULLFREE(X) do { if (X) { free(X); X = NULL; } } while(0)

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
} LLIST;

typedef struct llist_itr {
	LLIST *l;
	struct llist_node *cur;
} LLIST_ITR;

LLIST *llist_create(void);                  // init linked list
void llist_destroy(LLIST *l);               // de-init linked list - frees all objects on the list

void *llist_append(LLIST *l, void *o);       // append object onto bottom of list, returns ptr to obj

void *llist_itr_init(LLIST *l, LLIST_ITR *itr);       // linked list iterator, returns ptr to first obj
//void llist_itr_release(LLIST_ITR *itr);               // release iterator
void *llist_itr_next(LLIST_ITR *itr);                 // iterates, returns ptr to next obj

void *llist_itr_insert(LLIST_ITR *itr, void *o);  // insert object at itr point, iterates to and returns ptr to new obj
void *llist_itr_remove(LLIST_ITR *itr);           // remove obj at itr, iterates to and returns ptr to next obj

int llist_count(LLIST *l);    // returns number of obj in list

#endif /* OSCAMLLIST_H_ */
