#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include "hashmap.h"
#define DELETED_NODE ((void*)-1)  // Used for linear probing


// hashfunction (djb2 algorithm: http://www.cse.yorku.ca/~oz/hash.html)
unsigned long hash_function(const char *str, int size) {
    unsigned long hash = 5381; 
    int c; 
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % size;
}

Hashmap* create_hashmap(int size) {
    Hashmap *hashmap = (Hashmap *)malloc(sizeof(hashmap));
    hashmap->keys = (char **)calloc(size, sizeof(char *));  
    hashmap->values = (void **)calloc(size, sizeof(void *));
    hashmap->size = size;
    return hashmap;
}

void insert_into_hashmap(Hashmap *hashmap, char *key, void *value) {
    unsigned long index = hash_function(key, hashmap->size);

    // Linear probing to handle collisions 
    while (hashmap->keys[index] != NULL && hashmap->values[index] != DELETED_NODE){
        if (strcmp(hashmap->keys[index], key) == 0) {
            // If key already exists, replace value 
            hashmap->values[index] = value;
            return;
        }
        index = (index + 1) % hashmap->size;
    }

    // Insert the new (key, value) pair
    hashmap->keys[index] = strdup(key); 
    hashmap->values[index] = value;
}

void* get_from_hashmap(Hashmap *hashmap, char *key) {
    unsigned long index = hash_function(key, hashmap->size);
    unsigned long original_index = index;  
    unsigned long probed_count = 0;        
    
    // Linear probing to handle collisions
    while (hashmap->keys[index] != NULL) {
        // Check if the current index matches the desired key and is not a deleted node
        if (hashmap->values[index] != DELETED_NODE && strcmp(hashmap->keys[index], key) == 0) {
            return hashmap->values[index];
        }
        
        // Increment the index for probing
        index = (index + 1) % hashmap->size;
        probed_count++;

        // Probed all slots
        if (index == original_index || probed_count >= hashmap->size) {
            break;
        }
    }

    return NULL;  // Not found
}


void remove_from_hashmap(Hashmap *hashmap, char *filename) {
    unsigned long index = hash_function(filename, hashmap->size);

    // linear probing 
    while (hashmap->keys[index] != NULL) {
        if (hashmap->values[index] != DELETED_NODE && strcmp(hashmap->keys[index], filename) == 0) {
            // Mark slot as deleted 
            free(hashmap->keys[index]);
            hashmap->keys[index] = (char *)DELETED_NODE;
            hashmap->values[index] = DELETED_NODE;
            return;
        }
        index = (index + 1) % hashmap->size;
    }
}

void free_hashmap(Hashmap *hashmap) {
    free(hashmap->keys);
    free(hashmap->values);
    free(hashmap);
}
