#ifndef _HASHMAP_PROXY_H
#define _HASHMAP_PROXY_H

#include <stddef.h> // For size_t

typedef struct hashmap_node {
    int key;                // Key for the hashmap (e.g., file descriptor)
    void *value;            // Pointer to the value (generic type)
    struct hashmap_node *next; // Pointer to the next node for collision handling
} hashmap_node;

typedef struct hashmap_proxy {
    hashmap_node **buckets; // Array of bucket pointers
    int size;               // Number of buckets in the hashmap
} hashmap_proxy;

/**
 * Create a hashmap with the given size.
 * @param size Number of buckets
 * @return Pointer to the created hashmap
 */
hashmap_proxy* create_hashmap_proxy(int size);

/**
 * Insert a key-value pair into the hashmap.
 * @param hashmap Pointer to the hashmap
 * @param key Key associated with the value
 * @param value Pointer to the value
 * @return 0 if successful, -1 on failure
 */
int insert_into_hashmap_proxy(hashmap_proxy *hashmap, int key, void *value);

/**
 * Retrieve a value from the hashmap by its key.
 * @param hashmap Pointer to the hashmap
 * @param key Key to look up
 * @return Pointer to the value, or NULL if not found
 */
void* get_from_hashmap_proxy(hashmap_proxy *hashmap, int key);

/**
 * Check if a key exists in the hashmap.
 * @param hashmap Pointer to the hashmap.
 * @param key The key to check for existence.
 * @return 1 if the key exists, 0 otherwise.
 */
int in_hashmap_proxy(hashmap_proxy *hashmap, int key);

/**
 * Remove a key-value pair from the hashmap by its key.
 * @param hashmap Pointer to the hashmap
 * @param key Key to remove
 */
void remove_from_hashmap_proxy(hashmap_proxy *hashmap, int key);

/**
 * Free the hashmap and all its nodes.
 * @param hashmap Pointer to the hashmap
 */
void free_hashmap_proxy(hashmap_proxy *hashmap);

#endif
