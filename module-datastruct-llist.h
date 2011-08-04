
/* singularly linked-list */

#ifndef DATASTRUCT_LLIST_H_
#define DATASTRUCT_LLIST_H_

typedef struct llnode LL_NODE;
struct llnode {
    void *obj;
    LL_NODE *nxt;
    unsigned char flag;
};

typedef struct llist LLIST;
struct llist {
//    void *obj;
    LL_NODE *initial;
    LL_NODE *last;
    int32_t count;
    CS_MUTEX_LOCK lock;
    int32_t flag;
};

typedef struct lliter LL_ITER;
struct lliter {
    LLIST *l;
    LL_NODE *cur, *prv;
};

LLIST *ll_create();             // create llist, return ptr to llist
void ll_destroy(LLIST *l);      // same as ll_clear_abstract() but frees up LLIST mem as well
void ll_destroy_data(LLIST *l); // same as ll_clear_data() but frees up obj allocations as well
void ll_clear(LLIST *l);        // frees up all llnodes nodes but not data held in obj ptrs
void ll_clear_data(LLIST *l);   // same as ll_clear_data() but frees up obj allocations as well

void ll_sort(LLIST *l, void *compare); // sorts the list, compare = int func(const T *a, const T *b)
LL_NODE *ll_append(LLIST *l, void *obj);                // append obj to llist
LL_NODE *ll_prepend(LLIST *l, void *obj);               // prepend obj to llist

LL_ITER ll_iter_create(LLIST *l);              // return ptr to iterator obj
void *ll_iter_next(LL_ITER *it);                // iterate to and return next llnode obj, returns NULL at end
void *ll_iter_peek(LL_ITER *it, int32_t offset);    // return obj at offset from iterator but do not iterate
void ll_iter_reset(LL_ITER *it);                // reset itrerator to first llnode
void ll_iter_insert(LL_ITER *it, void *obj);    // insert obj at iterator node
void *ll_iter_remove(LL_ITER *it);              // remove llnode at iterator, returns ptr to the llnode obj removed
void ll_iter_remove_data(LL_ITER *it);          // remove llnode and free llnode obj
void *ll_iter_move(LL_ITER *it, int32_t offset);    // moves the iterator position
int32_t ll_iter_move_first(LL_ITER *it);            // moves an entry to top
int32_t ll_count(LLIST *l);                 // return number of items in list
void *ll_has_elements(LLIST *l);        // returns first obj if has one

int32_t ll_contains(LLIST *l, void *obj);
void *ll_contains_data(LLIST *l, void *obj, uint32_t size); 
int32_t ll_remove(LLIST *l, void *obj);
void ll_remove_data(LLIST *l, void *obj);
int32_t ll_remove_all(LLIST *l, LLIST *elements_to_remove); // removes all elements from l where elements are in elements_to_remove
#endif
