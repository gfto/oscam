/*
 * module-obj-llist.c
 *
 *  Created on: 23.04.2010
 *      Author: alno
 */

#include <string.h>
#include <stdlib.h>
#include "module-obj-llist.h"

LLIST *llist_create(void)
{
	LLIST *l = malloc(sizeof(LLIST));
	if (!l)
		return NULL;
	memset(l, 0, sizeof(LLIST));

	pthread_mutex_init(&l->lock, NULL);

	l->items = 0;

	return l;
}

void llist_destroy(LLIST *l)
{
	LLIST_ITR itr;
	if (!l)
		return;
	void *o = llist_itr_init(l, &itr);
	while (o) {
		free(o);
		o = llist_itr_remove(&itr);
	}
	free(l);
	//  llist_itr_release(&itr);
}

void *llist_append(LLIST *l, void *o)
{
	if (!l)
		return NULL;
	pthread_mutex_lock(&l->lock);
	if (o) {
		struct llist_node *ln = malloc(sizeof(struct llist_node));
		if (!ln) {
			pthread_mutex_unlock(&l->lock);
			return NULL;
		}

		memset(ln, 0, sizeof(struct llist_node));
		ln->obj = o;

		if (l->last) {
			ln->prv = l->last;
			ln->prv->nxt = ln;
		} else {
			l->first = ln;
		}
		l->last = ln;

		l->items++;
	}
	pthread_mutex_unlock(&l->lock);

	return o;
}

void *llist_itr_init(LLIST *l, LLIST_ITR *itr)
{
	if (!l || !itr)
		return NULL;
	// pthread_mutex_lock(&l->lock);
	if (l->first) {

		memset(itr, 0, sizeof(LLIST_ITR));
		itr->cur = l->first;
		itr->l = l;

		return itr->cur->obj;
	}

	return NULL;
}
/*
void llist_itr_release(LLIST_ITR *itr)
{
 // pthread_mutex_unlock(&itr->l->lock);
}
 */
void *llist_itr_next(LLIST_ITR *itr)
{
	if (itr->cur->nxt) {
		itr->cur = itr->cur->nxt;
		return itr->cur->obj;
	}

	return NULL;
}

void *llist_itr_remove(LLIST_ITR *itr)  // this needs cleaning - I was lazy
{
	if (!itr || !itr->l || itr->l->items == 0)
		return NULL;
	itr->l->items--;
	if ((itr->cur == itr->l->first) && (itr->cur == itr->l->last)) {
		NULLFREE(itr->cur);
		itr->l->first = NULL;
		itr->l->last = NULL;
		return NULL;
	} else if (itr->cur == itr->l->first) {
		struct llist_node *nxt = itr->cur->nxt;
		NULLFREE(itr->cur);
		nxt->prv = NULL;
		itr->l->first = nxt;
		itr->cur = nxt;
	} else if (itr->cur == itr->l->last) {
		itr->l->last = itr->cur->prv;
		itr->l->last->nxt = NULL;
		NULLFREE(itr->cur);
		return NULL;
	} else {
		struct llist_node *nxt = itr->cur->nxt;
		itr->cur->prv->nxt = itr->cur->nxt;
		itr->cur->nxt->prv = itr->cur->prv;
		NULLFREE(itr->cur);
		itr->cur = nxt;
	}

	return itr->cur->obj;
}

int llist_count(LLIST *l)
{
	return l->items;
}

