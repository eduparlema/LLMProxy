#ifndef _HASHMAP_H
#define _HASHMAP_H

typedef struct cache_node cache_node;

typedef struct Hashmap {
    char **keys; 
    cache_node **values; 
    int size; 
} Hashmap;

Hashmap* create_hashmap(int size);

void insert_into_hashmap(Hashmap *hashmap, char *filename, cache_node *node);

cache_node* get_from_hashmap(Hashmap *hashmap, char *filename);

void remove_from_hashmap(Hashmap *hashmap, char *filename);

void free_hashmap(Hashmap *hashmap);

#endif