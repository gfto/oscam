
/* singularly linked-list */

#include <stdlib.h>

#include "globals.h"
#include "module-datastruct-llist.h"

static void _destroy(LLIST *l)
{
    pthread_mutex_unlock(&l->lock);
    pthread_mutex_destroy(&l->lock);

    NULLFREE(l);
}

LLIST *ll_create()
{
    LLIST *l = calloc(1, sizeof(LLIST));

    pthread_mutex_init(&l->lock, NULL);

    return l;
}

void ll_destroy(LLIST *l)
{
    ll_clear(l);

    _destroy(l);
}

void ll_destroy_data(LLIST *l)
{
    ll_clear_data(l);

    _destroy(l);
}

void ll_clear(LLIST *l)
{
    void *obj;

    LL_ITER *it = ll_iter_create(l);
    while ((obj = ll_iter_next(it)))
        ll_iter_remove(it);
    ll_iter_release(it);
}

void ll_clear_data(LLIST *l)
{
    void *obj;

    LL_ITER *it = ll_iter_create(l);
    while ((obj = ll_iter_next(it)))
        ll_iter_remove_data(it);
    ll_iter_release(it);
}

void ll_append(LLIST *l, void *obj)
{
    if (obj) {
        LL_NODE *new = calloc(1, sizeof(LL_NODE));
        LL_NODE *n = l->initial;

        new->obj = obj;
        
        if (n) {
            while (n->nxt) n = n->nxt;
            n->nxt = new;
            new->prv = n;
        } else
            l->initial = new;
    }
}

LL_ITER *ll_iter_create(LLIST *l)
{
    LL_ITER *it = malloc(sizeof(LL_ITER));

    it->l = l;
    it->cur = l->initial;

    pthread_mutex_lock(&l->lock);

    return it;
}

void ll_iter_release(LL_ITER *it)
{
    pthread_mutex_unlock(&it->l->lock);

    NULLFREE(it);
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
    it->cur = it->l->initial;
}

void ll_iter_insert(LL_ITER *it, void *obj)
{
    if(obj) {
        LL_NODE *n = calloc(1, sizeof(LL_NODE));
        n->obj = obj;
        n->nxt = it->cur;
        n->prv = it->cur->prv;

        it->cur->prv->nxt = n;
        it->cur->prv = n;
    }
}

void *ll_iter_remove(LL_ITER *it)
{
    if (it) {
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

            NULLFREE(n);
            return obj;
        }
    }

    return NULL;
}

void ll_iter_remove_data(LL_ITER *it)
{
    void *obj = ll_iter_remove(it);
    NULLFREE(obj);
}

int ll_count(LLIST *l)
{
    void *obj;
    int c = 0;

    LL_ITER *it = ll_iter_create(l);;
    while ((obj = ll_iter_next(it))) c++;
    ll_iter_release(it);

    return c;
}

void ll_insert_at(LLIST *l, void *obj, int pos)
{
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
    
    if (n) n->prv = new;
}

