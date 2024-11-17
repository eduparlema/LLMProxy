#ifndef _HASHMAP_H
#define _HASHMAP_H

typedef struct Hashmap {
    char **keys; 
    void **values; // generic pointers, might be a cache node or a client node
    int size; 
} Hashmap;

Hashmap* create_hashmap(int size);

void insert_into_hashmap(Hashmap *hashmap, char *key, void *value);

void* get_from_hashmap(Hashmap *hashmap, char *key);

void remove_from_hashmap(Hashmap *hashmap, char *key);

void free_hashmap(Hashmap *hashmap);

#endif