#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashmap_client.h"
#include "client_list.h"

unsigned int hash(int fd, int size) {
    return (unsigned int) (fd % size);
}

// Create a new hashmap
hashmap_client *create_hashmap_client(int size) {
    hashmap_client *hashmap = (hashmap_client *)malloc(sizeof(hashmap_client));
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

int insert_into_hashmap_client(hashmap_client *hashmap, int fd, client_node *node) {
    unsigned int index = hash(fd, hashmap->size);
    hashmap_node *new_node = malloc(sizeof(hashmap_node));
    if (!new_node) {
        perror("Failed to allocate memory for hashmap!");
        return -1;
    }

    new_node->key = fd;
    new_node->value = node;
    new_node->next = NULL;

    // Insert at the beginning of the linked list for this bucket 
    new_node->next = hashmap->buckets[index];
    hashmap->buckets[index] = new_node;
}

client_node *get_from_hashmap_client(hashmap_client *hashmap, int fd) {
    unsigned int index = hash(fd, hashmap->size);
    hashmap_node *current = hashmap->buckets[index];

    // Traverse the linked list to find the key
    while (current != NULL) {
        if (current->key == fd) {
            return current->value;
        }
        current = current->next;
    }
    return NULL;
}

void remove_from_hashmap_client(hashmap_client *hashmap, int fd) {
    unsigned int index = hash(fd, hashmap->size);
    hashmap_node *current = hashmap->buckets[index];
    hashmap_node *prev = NULL;

    // Traverse the linked list to find key
    while (current != NULL) {
        if (current->key == fd) {
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

void free_hashmap_client(hashmap_client *hashmap) {
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
