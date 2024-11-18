#ifndef _HASHMAP_CACHE_H
#define _HASHMAP_CACHE_H

typedef struct cache_node cache_node;

typedef struct hashmap_cache {
    char **keys; 
    cache_node **values; 
    int size; 
} hashmap_cache;

hashmap_cache* create_hashmap_cache(int size);

void insert_into_hashmap_cache(hashmap_cache *hashmap, char *filename, cache_node *node);

cache_node* get_from_hashmap_cache(hashmap_cache *hashmap, char *filename);

void remove_from_hashmap_cache(hashmap_cache *hashmap, char *filename);

void free_hashmap_cache(hashmap_cache *hashmap);

#endif