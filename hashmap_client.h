#ifndef _HASHMAP_H
#define _HASHMAP_H

#include "client_list.h"

typedef struct hashmap_node {
    int key; 
    client_node *value; 
    struct hashmap_node *next;
} hashmap_node;

typedef struct hashmap_client {
    hashmap_node **buckets;
    int size; 
} hashmap_client;

hashmap_client* create_hashmap_client(int size);

int insert_into_hashmap_client(hashmap_client *hashmap, int fd, client_node *node);

client_node* get_from_hashmap_client(hashmap_client *hashmap, int fd);

void remove_from_hashmap_client(hashmap_client *hashmap, int fd);

void free_hashmap_client(hashmap_client *hashmap);

#endif