#ifndef _CACHE_H
#define _CACHE_H

#include <stdbool.h>
#include <time.h>

#define MAX_URL_LENGTH 100

// Definition of the cache_node used as the double linked list 
typedef struct cache_node {
    char url[MAX_URL_LENGTH]; 
    int max_age;
    struct timespec expiration_time; // max_age + t, where t is the time since the Epoch
    char *response_content;
    ssize_t response_size;
    struct cache_node *next;
    struct cache_node *prev;
} cache_node;

typedef struct hashmap_cache hashmap_cache;

// definition of the cache itself (double linked list + hashmap)
typedef struct cache {
    cache_node *head; 
    cache_node *tail; 
    hashmap_cache *hashmap; 
    int count; //number of items in the cache 
    cache_node *oldest_node; // keeps track of the node with earliest expiration
    // no need for max_size variable since that information is in the hashmap
} cache;

// helper functions for the double linked list 
void add_node(cache *cache, cache_node *node);

void remove_node(cache *cache, cache_node *node);


// cache functions 
cache* create_cache(int size);

void put(cache *cache, char *url, int max_age, char *content, ssize_t content_size);

ssize_t get(cache* cache, char *url, char *content_buffer);

void free_cache(cache *cache);

void print_cache_nodes(cache *cache);

void print_node_stats(cache *cache);

bool in_cache(cache *cache, char *url);

bool is_stale(cache *cache, char *url);

cache_node *get_node(cache *cache, char *url);


#endif // _CHACHE_H