
/* singularly linked-list */

#include <stdlib.h>

#include "globals.h"
#include "module-datastruct-llist.h"

static void _destroy(LLIST *l)
{
    if (!l) return;
    
    if (l->lock) {
      pthread_mutex_unlock(l->lock);
      pthread_mutex_destroy(l->lock);
      add_garbage(l->lock);
    }

    add_garbage(l);
}

LLIST *ll_create()
{
    LLIST *l = calloc(1, sizeof(LLIST));
    
    l->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(l->lock, NULL);

    return l;
}

LLIST *ll_create_nolock()
{
    LLIST *l = calloc(1, sizeof(LLIST));
    
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
    void *obj;

    LL_ITER *it = ll_iter_create(l);
    while ((obj = ll_iter_next(it)))
        ll_iter_remove(it);
    l->count = 0;
    ll_iter_release(it);
}

void ll_clear_data(LLIST *l)
{
		if (!l) return;
    void *obj;

    LL_ITER *it = ll_iter_create(l);
    while ((obj = ll_iter_next(it)))
        ll_iter_remove_data(it);
    l->count = 0;
    ll_iter_release(it);
}

void ll_append_nolock(LLIST *l, void *obj)
{
    if (l && obj) {
        LL_NODE *new = calloc(1, sizeof(LL_NODE));
        LL_NODE *n = l->initial;

        new->obj = obj;
        
        if (n) {
            while (n->nxt) n = n->nxt;
            n->nxt = new;
            new->prv = n;
        } else
            l->initial = new;
        l->count++;
    }
}

void ll_append(LLIST *l, void *obj)
{
    if (l && obj) {
        if (l->lock)
            pthread_mutex_lock(l->lock);
        ll_append_nolock(l, obj);
        if (l->lock)
            pthread_mutex_unlock(l->lock);
    }
}

LL_ITER *ll_iter_create(LLIST *l)
{
    LL_ITER *it = malloc(sizeof(LL_ITER));

    it->l = l;
    if (l) {
        if (l->lock)
          pthread_mutex_lock(l->lock);
        it->cur = l->initial;
    }
    else
      it->cur = NULL;

    return it;
}

void ll_iter_release(LL_ITER *it)
{
    if(it->l && it->l->lock)
      pthread_mutex_unlock(it->l->lock);

    add_garbage(it);
}

void *ll_iter_next(LL_ITER *it)
{
    if (it) {
        if (it->cur) {
            void *obj = it->cur->obj;
           
            it->cur = it->cur->nxt;

            return obj;
        }
    }

    return NULL;
}

void *ll_iter_peek(LL_ITER *it, int offset)
{
    LL_NODE *n = it->cur;
    int i;

    for (i = 0; i < offset; i++)
        if (n)
            n = n->nxt;
        else
            return NULL;

    if (!n)
      return NULL;
      
    return n->obj;
}

void ll_iter_reset(LL_ITER *it)
{
    if (it && it->l)
      it->cur = it->l->initial;
}

void ll_iter_insert(LL_ITER *it, void *obj)
{
    if(it && obj) {
        if (!it->cur)
          ll_append_nolock(it->l, obj);
        else {
          LL_NODE *n = calloc(1, sizeof(LL_NODE));
          n->obj = obj;
          n->nxt = it->cur;
          n->prv = it->cur->prv;

          it->cur->prv->nxt = n;
          it->cur->prv = n;
          it->l->count++;
        }
    }
}

void *ll_iter_remove(LL_ITER *it)
{
    if (it && it->l) {
        LL_NODE *n;

        // if is last node, handle differently
        if (!it->cur && it->l->initial) {
            n = it->l->initial;
            while (n->nxt) n = n->nxt; 
        } else
            n = it->cur->prv;

        if (n) {
            void *obj = n->obj;
            if (n->nxt) n->nxt->prv = n->prv;
            if (n->prv) n->prv->nxt = n->nxt;
            else it->l->initial = n->nxt;

            it->l->count--;
            add_garbage(n);
            return obj;
        }
    }

    return NULL;
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

void ll_insert_at_nolock(LLIST *l, void *obj, int pos)
{
    if (!l || !obj)
      return;
      
    LL_NODE *new = calloc(1, sizeof(LL_NODE));
    LL_NODE *n = l->initial;
    int i;
    
    for (i = 0; i < pos; i++)
        if (n)
            n = n->nxt;
        else
            break;

    new->obj = obj;
    new->nxt = n;

    if (n && n->prv) n->prv->nxt = new;
    else l->initial = new;
    l->count++;
    
    if (n) n->prv = new;
}

void ll_insert_at(LLIST *l, void *obj, int pos)
{
    if (!l || !obj)
      return;
      
    if (l->lock)
      pthread_mutex_lock(l->lock);
    ll_insert_at_nolock(l, obj, pos);
    if (l->lock)
      pthread_mutex_unlock(l->lock);
}

//Returns first object if there is one
void *ll_has_elements(LLIST *l) {
  if (!l || !l->initial)
    return NULL;
  return l->initial->obj;
}

