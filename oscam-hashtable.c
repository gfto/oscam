#include "tommyDS_hashlin/tommychain.h"
#include "tommyDS_hashlin/tommyhash.h"
#include "tommyDS_hashlin/tommyhashlin.h"
#include "tommyDS_hashlin/tommylist.h"
#include "tommyDS_hashlin/tommytypes.h"
#include "tommyDS_hashlin/tommyhash.c"
#include "tommyDS_hashlin/tommyhashlin.c"
#include "tommyDS_hashlin/tommylist.c"

void init_hash_table(void *ht, void *ll){
	tommy_hashlin_init(ht);
	tommy_list_init(ll);
}

void add_hash_table(void *ht, void *ht_node, void *ll, void *ll_node, void *obj, void *key, int key_len){
	tommy_hashlin_insert(ht, ht_node, obj, tommy_hash_u32(0,key,key_len));
	tommy_list_insert_tail(ll, ll_node, obj);
}

void *find_hash_table(void *ht, void *key, int key_len, void *compare){
	return tommy_hashlin_search(ht, compare, key, tommy_hash_u32(0,key,key_len));
}

void *search_remove_elem_hash_table(void *ht, void *key, int key_len, void *compare){
	return tommy_hashlin_remove	(ht,compare,key,tommy_hash_u32(0,key,key_len));
}

void *remove_elem_hash_table(void *ht, void *ht_node){
	return tommy_hashlin_remove_existing(ht,ht_node);
}

int count_hash_table(void *ht){
	return tommy_hashlin_count(ht);
}

void deinitialize_hash_table(void *ht){
	tommy_hashlin_done(ht);
}

void sort_list(void *ll, void *cmp){
	tommy_list_sort (ll, cmp);
}

void *remove_elem_list(void *ll, void *ll_node){
	return tommy_list_remove_existing(ll,ll_node);
}

void *get_first_node_list(void *ll){
	return tommy_list_head(ll);
}

void *get_first_elem_list(void *ll){
	if (tommy_list_head(ll))
		return tommy_list_head(ll)->data;
	else return NULL;
}

void *get_data_from_node(void *node){
	if (node)
		return ((tommy_node *)node)->data;
	else return NULL;
}

