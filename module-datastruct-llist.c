
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
    if (!l->flag++) {
	    pthread_mutex_destroy(&l->lock);
	    add_garbage(l);
	}
}

LLIST *ll_create()
{
    LLIST *l = calloc(1, sizeof(LLIST));
    pthread_mutex_init(&l->lock, NULL);
    return l;
}

void ll_lock(LLIST *l)
{
	while (l && !l->flag && pthread_mutex_trylock(&l->lock)) {
		cs_debug_mask(D_TRACE, "trylock ll_lock wait");
		cs_sleepms(50);
	}
}

void ll_unlock(LLIST *l)
{
	if (l && !l->flag)
		pthread_mutex_unlock(&l->lock);
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

static void ll_clear_int(LLIST *l, int clear_data)
{
    if (!l) return;

    ll_lock(l);
    LL_ITER *it = ll_iter_create(l);
    while (ll_iter_next_nolock(it)) {
    	if (it->cur && !it->cur->flag++) {
    		if (clear_data)
    			add_garbage(it->cur->obj);
    		add_garbage(it->cur);
		}
    }
    ll_iter_release(it);
    l->count = 0;
    l->initial = 0;
    ll_unlock(l);
}

void ll_clear(LLIST *l)
{
	ll_clear_int(l, 0);
}


void ll_clear_data(LLIST *l)
{
	ll_clear_int(l, 1);
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
        ll_lock(l);
        LL_NODE *n = ll_append_nolock(l, obj);
        ll_unlock(l);
        return n;
    }
    return NULL;
}

LL_NODE *ll_prepend(LLIST *l, void *obj)
{
    if (l && obj) {
        LL_NODE *new = calloc(1, sizeof(LL_NODE));

        ll_lock(l);
        new->obj = obj;
        new->nxt = l->initial;

        l->initial = new;
        l->count++;
        ll_unlock(l);

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

void *ll_iter_next(LL_ITER *it)
{
    if (it && it->l) {
		ll_lock(it->l);
    	void *res = ll_iter_next_nolock(it);
		ll_unlock(it->l);
		return res;
    }
    return NULL;
}

void *ll_iter_move(LL_ITER *it, int32_t offset)
{
    if (it && it->l) {
    	ll_lock(it->l);
    	int32_t i;
    	void *res = NULL;
    	for (i=0; i<offset; i++) {
    		res = ll_iter_next_nolock(it);
    		if (!res) break;
		}
		ll_unlock(it->l);
		return res;
    }
    return NULL;
}

void *ll_iter_peek(LL_ITER *it, int32_t offset)
{
	if (it && it->l) {
		ll_lock(it->l);
	    LL_NODE *n = it->cur;
	    int32_t i;

	    for (i = 0; i < offset; i++) {
	    	if (n)
            	n = n->nxt;
			else 
				break;
		}
		ll_unlock(it->l);
	    
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
	   	ll_lock(it->l);
        if (!it->cur || !it->cur->nxt)
            ll_append_nolock(it->l, obj);
        else {
            LL_NODE *n = calloc(1, sizeof(LL_NODE));

            n->obj = obj;
            n->nxt = it->cur->nxt;
            it->cur->nxt = n;

            it->l->count++;
        }
        ll_unlock(it->l);
    }
}

void *ll_iter_remove(LL_ITER *it)
{
   	void *obj = NULL;
    if (it) {
    	ll_lock(it->l);
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
        ll_unlock(it->l);
    }

    return obj;
}

int ll_iter_move_first(LL_ITER *it) 
{
	int moved = 0;
    if (it) {
    	ll_lock(it->l);
        LL_NODE *move = it->cur;
        if (move && !move->flag++) { //preventing duplicate free because of multiple threads
            LL_NODE *prv = it->prv;
            
            if (prv)
                prv->nxt = move->nxt;
            else
                it->l->initial = move->nxt;
					        	
			move->nxt = it->l->initial;
			it->l->initial = move;
			moved = 1;
			
			ll_iter_reset(it);
        }
        ll_unlock(it->l);
    }
    return moved;
}

void ll_iter_remove_data(LL_ITER *it)
{
    void *obj = ll_iter_remove(it);
    add_garbage(obj);
}

int32_t ll_count(LLIST *l)
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

int32_t ll_contains(LLIST *l, void *obj)
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

int32_t ll_remove(LLIST *l, void *obj)
{
	int n = 0;
    LL_ITER *it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(it))) {
      	if (data==obj) {
        	ll_iter_remove(it);
        	n++;
        }
    }
    ll_iter_release(it);
    return n;
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
int32_t ll_remove_all(LLIST *l, LLIST *elements_to_remove)
{
		int32_t count = 0;
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
