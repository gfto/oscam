
/* singularly linked-list */

typedef struct llnode LLNODE;
struct llnode {
    void *obj;
    LLNODE *nxt;
};

typedef struct llist LLIST;
struct llist {
    void *obj;
    LLNODE *initial;
    pthread_mutex_t lock;
};

typedef struct lliter LLITER;
struct lliter {
    LLIST *l;
    LLNODE *current;
};

LLIST *ll_create();			// create llist, return ptr to llist
void ll_destroy_abstract(LLIST *l);	// same as ll_clear_abstract() but frees up LLIST mem as well
void ll_destroy_data(LLIST *l);		// same as ll_clear_data() but frees up obj allocations as well
void ll_clear_abstract(LLIST *l);	// frees up all llnodes nodes but not data held in obj ptrs
void ll_clear_data(LLIST *l);		// same as ll_clear_data() but frees up obj allocations as well

void ll_append(LLIST *l, void *obj);    // append obj to llist

LLITER *ll_iter_create(LLIST *l);	// return ptr to iterator obj
void ll_iter_release(LLITER *it);       // free up the iterator obj
void *ll_iter_next(LLITER *it);         // iterate to and return next llnode obj, returns NULL at end
void ll_iter_reset(LLITER *it);         // reset itrerator to first llnode
void ll_iter_insert(LLITER *it, void *obj);    // insert obj at iterator node
void *ll_iter_remove(LLITER *it);       // remove llnode at iterator, returns ptr to obj removed
void ll_iter_remove_data(LLITER *it);   // remove llnode and free llnode obj

int ll_count(LLIST *l);                 // return number of items in list
