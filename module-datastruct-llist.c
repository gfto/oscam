
/* singularly linked-list */

#include <stdlib.h>

#include "globals.h"
#include "module-datastruct-llist.h"

/*
  Locking rules:
  
  mutex lock is needed when...
  1. l->initial is modified/accessed
  2. LL_NODE nxt modified/accessed


*/
static void _destroy(LLIST *l)
{
    if (!l) return;
    pthread_mutex_destroy(&l->lock);
    add_garbage(l);
}

LLIST *ll_create()
{
    LLIST *l = calloc(1, sizeof(LLIST));
    pthread_mutex_init(&l->lock, NULL);
    return l;
}

void ll_destroy(LLIST *l)
{
    if (!l) return;
    ll_clear(l);

    _destroy(l);
}

void ll_destroy_data(LLIST *l)
{
    if (!l) return;
    ll_clear_data(l);

    _destroy(l);
}

void ll_clear(LLIST *l)
{
    if (!l) return;

    LL_ITER *it = ll_iter_create(l);
    while (ll_iter_next(it))
        ll_iter_remove(it);
    ll_iter_release(it);
    l->count = 0;
}

void ll_clear_data(LLIST *l)
{
    if (!l) return;

    LL_ITER *it = ll_iter_create(l);
    while (ll_iter_next(it))
        ll_iter_remove_data(it);
    ll_iter_release(it);
    l->count = 0;
}

LL_NODE* ll_append_nolock(LLIST *l, void *obj)
{
    if (l && obj) {
        LL_NODE *new = calloc(1, sizeof(LL_NODE));
        LL_NODE *n = l->initial;

        new->obj = obj;
        
        if (n) {
            while (n->nxt) n = n->nxt;
            n->nxt = new;
        } else
            l->initial = new;
    
        l->count++;
        return new;
    }

    return NULL;
}

LL_NODE* ll_append(LLIST *l, void *obj)
{
    if (l && obj) {
        pthread_mutex_lock(&l->lock);
        LL_NODE *n = ll_append_nolock(l, obj);
        pthread_mutex_unlock(&l->lock);
        return n;
    }
    return NULL;
}

LL_NODE *ll_prepend(LLIST *l, void *obj)
{
    if (l && obj) {
        LL_NODE *new = calloc(1, sizeof(LL_NODE));

        pthread_mutex_lock(&l->lock);
        new->obj = obj;
        new->nxt = l->initial;

        l->initial = new;
        l->count++;
        pthread_mutex_unlock(&l->lock);

        return new;
    }

    return NULL;
}

LL_ITER *ll_iter_create(LLIST *l)
{
    if (!l) return NULL;
    LL_ITER *it;
		struct s_client *cl = cur_client();
    if(cl && !cl->itused){
    	it = &(cl->it);
    	it->prv = NULL;
      it->cur = NULL;
    	cl->itused = 1;
    } else
    	if(!cs_malloc(&it, sizeof(LL_ITER), -1)) return NULL;
    it->l = l;
    return it;
}

LL_ITER *ll_iter_create_s(LLIST *l, LL_ITER *it)
{
    if (!l) return NULL;
    it->l = l;
    return it;
}

void ll_iter_release(LL_ITER *it)
{	
	struct s_client *cl = cur_client();
  if(cl && cl->itused && it == &(cl->it)){
  	cl->itused = 0;
  // We don't need add_garbage here as iterators aren't shared across threads
  } else free(it);
}

void *ll_iter_next_nolock(LL_ITER *it)
{
    if (it && it->l) {
        if (it->cur) {
            it->prv = it->cur;
            it->cur = it->cur->nxt;
        } else if (it->l->initial && !it->prv)
            it->cur = it->l->initial;
        
        if (it->cur)
            return it->cur->obj;
    }

    return NULL;
}

void *ll_iter_next(LL_ITER *it)
{
    if (it && it->l) {
    	pthread_mutex_lock(&it->l->lock);
    	void *res = ll_iter_next_nolock(it);
		pthread_mutex_unlock(&it->l->lock);
		return res;
    }
    return NULL;
}

void *ll_iter_move(LL_ITER *it, int offset)
{
    if (it && it->l) {
    	pthread_mutex_lock(&it->l->lock);
    	int i;
    	void *res = NULL;
    	for (i=0; i<offset; i++) {
    		res = ll_iter_next_nolock(it);
    		if (!res) break;
		}
		pthread_mutex_unlock(&it->l->lock);
		return res;
    }
    return NULL;
}

void *ll_iter_peek(LL_ITER *it, int offset)
{
	if (it && it->l) {
		pthread_mutex_lock(&it->l->lock);
	    LL_NODE *n = it->cur;
	    int i;

	    for (i = 0; i < offset; i++) {
	    	if (n)
            	n = n->nxt;
			else 
				break;
		}
		pthread_mutex_unlock(&it->l->lock);
	    
		if (!n)
			return NULL;
		return n->obj;
	}
	return NULL;
}

void ll_iter_reset(LL_ITER *it)
{
    if (it) {
        it->prv = NULL;
        it->cur = NULL;
    }
}

void ll_iter_insert(LL_ITER *it, void *obj)
{
    if (it && obj) {
	   	pthread_mutex_lock(&it->l->lock);
        if (!it->cur || !it->cur->nxt)
            ll_append_nolock(it->l, obj);
        else {
            LL_NODE *n = calloc(1, sizeof(LL_NODE));

            n->obj = obj;
            n->nxt = it->cur->nxt;
            it->cur->nxt = n;

            it->l->count++;
        }
        pthread_mutex_unlock(&it->l->lock);
    }
}

void *ll_iter_remove(LL_ITER *it)
{
   	void *obj = NULL;
    if (it) {
    	pthread_mutex_lock(&it->l->lock);
        LL_NODE *del = it->cur;
        if (del && !del->flag++) { //preventing duplicate free because of multiple threads
            obj = del->obj;
            LL_NODE *prv = it->prv;
            
            if (prv)
                prv->nxt = del->nxt;
            else
                it->l->initial = del->nxt;
            it->l->count--;

            ll_iter_reset(it);
            while (prv && ll_iter_next_nolock(it))
                if (it->cur == prv)
                    break;

            add_garbage(del);
        }
        pthread_mutex_unlock(&it->l->lock);
    }

    return obj;
}

void ll_iter_remove_data(LL_ITER *it)
{
    void *obj = ll_iter_remove(it);
    add_garbage(obj);
}

int ll_count(LLIST *l)
{
    if (!l)
      return 0;
      
    return l->count;
}

void *ll_has_elements(LLIST *l) {
  if (!l || !l->initial)
    return NULL;
  return l->initial->obj;
}

int ll_contains(LLIST *l, void *obj)
{
    if (!l || !obj)
      return 0;
    LL_ITER *it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(it))) {
      if (data==obj)
        break;
    }
    ll_iter_release(it);
    return (data==obj);
}

void ll_remove(LLIST *l, void *obj)
{
    LL_ITER *it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(it))) {
      if (data==obj)
        ll_iter_remove(it);
    }
    ll_iter_release(it);
}

void ll_remove_data(LLIST *l, void *obj)
{
    LL_ITER *it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(it))) {
      if (data==obj)
        ll_iter_remove_data(it);
    }
    ll_iter_release(it);
}

// removes all elements from l where elements are in elements_to_remove 
int ll_remove_all(LLIST *l, LLIST *elements_to_remove)
{
		int count = 0;
		LL_ITER *it1 = ll_iter_create(l);
		LL_ITER *it2 = ll_iter_create(elements_to_remove);
		
		void *data1, *data2;
		while ((data1=ll_iter_next(it1))) {
				ll_iter_reset(it2);
				while ((data2=ll_iter_next(it2))) {
						if (data1 == data2) {
								ll_iter_remove(it1);
								count++;
								break;
						}
				}
		}

		ll_iter_release(it2);
		ll_iter_release(it1);
		
		return count;
}
