#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashmap_proxy.h"
#include "client_list.h"

unsigned int hash_func(int fd, int size) {
    return (unsigned int) (fd % size);
}

hashmap_proxy* create_hashmap_proxy(int size) {
    hashmap_proxy *hashmap = (hashmap_proxy *)malloc(sizeof(hashmap_proxy));
    if (!hashmap) {
        perror("Failed to create hashmap");
        return NULL;
    }
    hashmap->buckets = calloc(size, sizeof(hashmap_node)); // initialize buckets
    if (!hashmap->buckets) {
        perror("Failed to allocate memory for buckets");
        return NULL;
    }
    hashmap->size = size;
    return hashmap;
}

int insert_into_hashmap_proxy(hashmap_proxy *hashmap, int key, void *value) {
    unsigned int index = hash_func(key, hashmap->size);
    hashmap_node *new_node = malloc(sizeof(hashmap_node));
    if (!new_node) {
        perror("Failed to allocate memory for hashmap!");
        return -1;
    }

    new_node->key = key;
    new_node->value = value;
    new_node->next = NULL;

    // Insert at the beginning of the linked list for this bucket 
    new_node->next = hashmap->buckets[index];
    hashmap->buckets[index] = new_node;
    return 0;
}

void* get_from_hashmap_proxy(hashmap_proxy *hashmap, int key) {
    unsigned int index = hash_func(key, hashmap->size);
    hashmap_node *current = hashmap->buckets[index];

    // Traverse the linked list to find the key
    while (current != NULL) {
        if (current->key == key) {
            return current->value;
        }
        current = current->next;
    }
    return NULL;
}

int in_hashmap_proxy(hashmap_proxy *hashmap, int key) {
    unsigned int index = hash_func(key, hashmap->size);
    hashmap_node *current = hashmap->buckets[index];

    // Traverse the linked list to find the key
    while (current != NULL) {
        if (current->key == key) {
            return -1; // Key exists
        }
        current = current->next;
    }
    return 0; // Key does not exist
}


void remove_from_hashmap_proxy(hashmap_proxy *hashmap, int key) {
    unsigned int index = hash_func(key, hashmap->size);
    hashmap_node *current = hashmap->buckets[index];
    hashmap_node *prev = NULL;

    // Traverse the linked list to find key
    while (current != NULL) {
        if (current->key == key) {
            if (prev == NULL) {
                hashmap->buckets[index] = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

void free_hashmap_proxy(hashmap_proxy *hashmap) {
    for (int i = 0; i < hashmap->size; i++) {
        hashmap_node *current = hashmap->buckets[i];
        while (current != NULL) {
            hashmap_node *temp = current;
            current = current->next; 
            free(temp->value);
            free(temp);
        }
    }
    free(hashmap->buckets);
    free(hashmap);
}