#include "tommyDS_hashlin/tommytypes.h"
#include "tommyDS_hashlin/tommyhashlin.h"
#include "tommyDS_hashlin/tommylist.h"

typedef tommy_node node;
typedef tommy_hashlin hash_table;
typedef tommy_list list;

void init_hash_table(void *ht, void *ll);
void add_hash_table(void *ht, void *ht_node, void *ll, void *ll_node, void *obj, void *key, int key_len);
void *find_hash_table(void *ht, void *key, int key_len, void *compare);
void *search_remove_elem_hash_table(void *ht, void *key, int key_len, void *compare);
void *remove_elem_hash_table(void *ht, void *ht_node);
int count_hash_table(void *ht);
void deinitialize_hash_table(void *ht);
void sort_list(void *ll, void *cmp);
void *remove_elem_list(void *ll, void *ll_node);
void *get_first_node_list(void *ll);
void *get_first_elem_list(void *ll);
void *get_data_from_node(void *node);
