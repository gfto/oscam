
/* singularly linked-list */

#include "globals.h"
#include "module-datastruct-llist.h"

/*
  Locking rules:
  
  mutex lock is needed when...
  1. l->initial + l->last is modified/accessed
  2. LL_NODE nxt modified/accessed


*/
static void _destroy(LLIST *l)
{
	if (!l) return;  	
	if (!l->flag++) {
		cs_lock_destroy(&l->lock);
		add_garbage(l);
	}
}

LLIST *ll_create()
{
    LLIST *l = cs_malloc(&l, sizeof(LLIST), 0);
    cs_lock_create(&l->lock, 5, "ll_lock");
    return l;
}

int32_t ll_lock(LLIST *l)
{
	if (l)
		cs_writelock(&l->lock);
	return 1;
}

void ll_unlock(LLIST *l)
{
	if (l) {
		l->version++;
		cs_writeunlock(&l->lock);
	}
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

static void *ll_iter_next_nolock(LL_ITER *it)
{
	if (it && it->l) {
		if (it->l->version > it->ll_version) {
			cs_debug_mask_nolock(D_TRACE, "list changed, searching new position");

			LL_NODE *ptr;
			for (ptr = it->l->initial; ptr; ptr = ptr->nxt) {
				if (!it->cur && !it->prv) {
					it->cur = ptr;
					break;
				}

				if (ptr == it->prv && ptr->nxt != it->cur) {
					it->cur = ptr->nxt;
					break;
				}
				if (ptr == it->cur) {
					it->prv = ptr;
					it->cur = ptr->nxt;
					break;
				}
			}

			if (it->cur)
				return it->cur->obj;

		} else {
			if (it->cur) {
				it->prv = it->cur;
				it->cur = it->cur->nxt;
			} else if (it->l->initial && !it->prv)
				it->cur = it->l->initial;
        
			if (it->cur)
				return it->cur->obj;
		}
	}
	return NULL;
}

static void ll_clear_int(LLIST *l, int32_t clear_data)
{
    if (!l) return;

    if (!ll_lock(l)) return;
    
    LL_NODE *n=l->initial, *nxt;
    while (n) {
    	nxt = n->nxt;
    	if (n && !n->flag++) {
    		if (clear_data)
    			add_garbage(n->obj);
    		add_garbage(n);
		}
		n = nxt;
    }
    l->count = 0;
    l->initial = 0;
    l->last = 0;
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
        LL_NODE *new;
        if(!cs_malloc(&new,sizeof(LL_NODE), -1)) return NULL;
        new->obj = obj;
        
        if (l->last)
            l->last->nxt = new;
        else
            l->initial = new;
		l->last = new;    
		
        l->count++;
        return new;
    }

    return NULL;
}

LL_NODE* ll_append(LLIST *l, void *obj)
{
    if (l && obj) {
        if (!ll_lock(l)) return NULL;
        
        LL_NODE *n = ll_append_nolock(l, obj);
        ll_unlock(l);
        return n;
    }
    return NULL;
}

LL_NODE *ll_prepend(LLIST *l, void *obj)
{
    if (l && obj) {
        LL_NODE *new;
        if(!cs_malloc(&new,sizeof(LL_NODE), -1)) return NULL;

        if (!ll_lock(l)) { add_garbage(new); return NULL; }

        new->obj = obj;
        new->nxt = l->initial;

        l->initial = new;
        if (!l->last)
        	l->last = l->initial;
        l->count++;
        ll_unlock(l);

        return new;
    }

    return NULL;
}

LL_ITER ll_iter_create(LLIST *l)
{
	LL_ITER it;
	memset(&it, 0, sizeof(it));
	it.l = l;
	if (it.l)
		it.ll_version = it.l->version;
	return it;
}


void *ll_iter_next(LL_ITER *it)
{
    if (it && it->l) {
		if (!ll_lock(it->l)) return NULL;
		void *res = ll_iter_next_nolock(it);
		ll_unlock(it->l);
		it->ll_version = it->l->version;
		return res;
    }
    return NULL;
}

void *ll_iter_move(LL_ITER *it, int32_t offset)
{
    if (it && it->l) {
    	if (!ll_lock(it->l)) return NULL;
    	int32_t i;
    	void *res = NULL;
    	for (i=0; i<offset; i++) {
    		res = ll_iter_next_nolock(it);
    		if (!res) break;
	}
	ll_unlock(it->l);
	it->ll_version = it->l->version;
	return res;
    }
    return NULL;
}

void *ll_iter_peek(LL_ITER *it, int32_t offset)
{
	if (it && it->l) {
		if (!ll_lock(it->l)) return NULL;
		
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
	   	if (!ll_lock(it->l)) return;
	   	
        if (!it->cur || !it->cur->nxt)
            ll_append_nolock(it->l, obj);
        else {
            LL_NODE *n;
            if(!cs_malloc(&n,sizeof(LL_NODE), -1)) { ll_unlock(it->l); return; }

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
    	if (!ll_lock(it->l)) return NULL;
        LL_NODE *del = it->cur;
        if (del && !del->flag++) { //preventing duplicate free because of multiple threads
            obj = del->obj;
            LL_NODE *prv = it->prv;
            
            if (prv)
                prv->nxt = del->nxt;
            else
                it->l->initial = del->nxt;
            if (!it->l->initial)
            	it->l->last = NULL;
			else if (del == it->l->last)
				it->l->last = prv;
				
            it->l->count--;
            ll_iter_reset(it);
            while (prv && ll_iter_next_nolock(it))
                if (it->cur == prv)
                    break;

            add_garbage(del);
        }
        ll_unlock(it->l);
        it->ll_version = it->l->version;
    }

    return obj;
}

int32_t ll_iter_move_first(LL_ITER *it) 
{
	int32_t moved = 0;
    if (it) {
    	if (!ll_lock(it->l)) return moved;
    	
        LL_NODE *move = it->cur;
        if (move && !move->flag++) { //preventing duplicate free because of multiple threads
            LL_NODE *prv = it->prv;
            
            if (prv)
                prv->nxt = move->nxt;
            else
                it->l->initial = move->nxt;
					        	
			if (prv && it->l->last == move)
				it->l->last = prv;
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
    LL_ITER it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(&it))) {
      if (data==obj)
        break;
    }
    return (data==obj);
}

void *ll_contains_data(LLIST *l, void *obj, uint32_t size) {
    if (!l || !obj)
      return NULL; 
    LL_ITER it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(&it))) {
      if (!memcmp(data,obj,size))
        break;
    }
    return data; 
}

int32_t ll_remove(LLIST *l, void *obj)
{
	int32_t n = 0;
    LL_ITER it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(&it))) {
      	if (data==obj) {
        	ll_iter_remove(&it);
        	n++;
        }
    }
    return n;
}

void ll_remove_data(LLIST *l, void *obj)
{
    LL_ITER it = ll_iter_create(l);
    void *data;
    while ((data=ll_iter_next(&it))) {
      if (data==obj)
        ll_iter_remove_data(&it);
    }
}

// removes all elements from l where elements are in elements_to_remove 
int32_t ll_remove_all(LLIST *l, LLIST *elements_to_remove)
{
		int32_t count = 0;
		LL_ITER it1 = ll_iter_create(l);
		LL_ITER it2 = ll_iter_create(elements_to_remove);
		
		void *data1, *data2;
		while ((data1=ll_iter_next(&it1))) {
				ll_iter_reset(&it2);
				while ((data2=ll_iter_next(&it2))) {
						if (data1 == data2) {
								ll_iter_remove(&it1);
								count++;
								break;
						}
				}
		}

		return count;
}

void ll_sort(LLIST *l, void *compare)
{
	if (!l || !l->initial || !compare) return;
	
	if (!ll_lock(l)) return;

	//Because this list has no prv pointer, we can not do qsort, so 
	//copy to a flat array, sort them, and then copy back
	void **p = cs_malloc(&p, l->count*sizeof(p[0]), 0);
	LL_NODE *n = l->initial;
	int32_t i=0;
	while (n) {
		p[i++] = n->obj;
		n=n->nxt;
	}
	
	cs_debug_mask(D_TRACE, "sort: count %d size %d", l->count, sizeof(p[0]));
	
	qsort(p, l->count, sizeof(p[0]), compare);
	
	n = l->initial;
	i = 0;
	while (n) {
		n->obj = p[i++];
		n=n->nxt;
	}
	
	free(p);
	
	ll_unlock(l);
}
