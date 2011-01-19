
/* singularly linked-list */

#include <stdlib.h>

#include "globals.h"
#include "module-datastruct-llist.h"

static void _destroy(LLIST *l)
{
    if (!l) return;
    
    add_garbage(l);
}

LLIST *ll_create()
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

LL_NODE* ll_append(LLIST *l, void *obj)
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

LL_NODE *ll_prepend(LLIST *l, void *obj)
{
    if (l && obj) {
        LL_NODE *new = calloc(1, sizeof(LL_NODE));

        new->obj = obj;
        new->nxt = l->initial;

        l->initial = new;
        l->count++;

        return new;
    }

    return NULL;
}

LL_ITER *ll_iter_create(LLIST *l)
{
    if (!l) return NULL;

    LL_ITER *it = calloc(1, sizeof(LL_ITER));

    it->l = l;

    return it;
}

void ll_iter_release(LL_ITER *it)
{
    add_garbage(it);
}

void *ll_iter_next(LL_ITER *it)
{
    if (it) {
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
    if (it) {
        it->prv = NULL;
        it->cur = NULL;
    }
}

void ll_iter_insert(LL_ITER *it, void *obj)
{
    if (it && obj) {
        if (!it->cur || !it->cur->nxt)
            ll_append(it->l, obj);
        else {
            LL_NODE *n = calloc(1, sizeof(LL_NODE));

            n->obj = obj;
            n->nxt = it->cur->nxt;
            it->cur->nxt = n;

            it->l->count++;
        }
    }
}

void *ll_iter_remove(LL_ITER *it)
{
    if (it) {
        LL_NODE *del = it->cur;

        if (del) {
            void *obj = del->obj;
            LL_NODE *prv = it->prv;
            
            if (prv)
                prv->nxt = del->nxt;
            else
                it->l->initial = del->nxt;

            it->l->count--;

            ll_iter_reset(it);
            while (prv && ll_iter_next(it))
                if (it->cur == prv)
                    break;

            add_garbage(del);
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

void *ll_has_elements(LLIST *l) {
  if (!l || !l->initial)
    return NULL;
  return l->initial->obj;
}

int ll_contains(LLIST *l, void *obj)
{
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
