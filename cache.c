#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "hashmap_cache.h"
#include "cache.h"

// Helper functions for the double linked list 
void add_node(cache *cache, cache_node *node) {
    cache_node *prev_node = cache->tail->prev; 
    cache->tail->prev = node;
    node->next = cache->tail;
    node->prev = prev_node;
    prev_node->next = node;

    cache->count++;
}

void remove_node(cache *cache, cache_node *node) {
    cache_node *prev_node = node->prev;
    cache_node *next_node = node->next;
    prev_node->next = next_node;
    next_node->prev = prev_node;

    cache->count--;
}

bool is_stale(cache *cache, char *url) {
    // get the node from the hashmap
    cache_node *node = get_from_hashmap_cache(cache->hashmap, url);

    struct timespec current_time;
    // Get the current time 
    clock_gettime(CLOCK_REALTIME, &current_time);

    // Compare current time with node's expiration time
    if (current_time.tv_sec > node->expiration_time.tv_sec ||
        (current_time.tv_sec == node->expiration_time.tv_sec &&
         current_time.tv_nsec > node->expiration_time.tv_nsec)) {
        return true; 
    }
    
    return false;
}

bool in_cache(cache *cache, char *url) {
    return (get_from_hashmap_cache(cache->hashmap, url) != NULL);
}

// Called only if we know that url is in cache
cache_node *get_node(cache *cache, char *url) {
    return get_from_hashmap_cache(cache->hashmap, url);
}

void update_oldest_node(cache *cache) {
    cache->oldest_node = NULL;
    cache_node *current = cache->head->next; // Start from the first real node
    while (current != cache->tail) {
        if (cache->oldest_node == NULL || 
            current->expiration_time.tv_sec < cache->oldest_node->expiration_time.tv_sec ||
            (current->expiration_time.tv_sec == cache->oldest_node->expiration_time.tv_sec && 
            current->expiration_time.tv_nsec < cache->oldest_node->expiration_time.tv_nsec)) {
            cache->oldest_node = current;
        }
        current = current->next;
    }
}

void add_content_to_cache(cache_node *node, char *content, ssize_t content_size) {
    // check if there was already content before
    if (node->response_content != NULL) {
        free(node->response_content);
        node->response_content = NULL;
    }
    
    node->response_content = (char *)malloc(content_size);
    if (node->response_content == NULL) {
        perror("Failed to allocate memory for response content.");
        return;
    } 

    // copy the content to the node
    memcpy(node->response_content, content, content_size);
    node->response_size = content_size;
}


// cache functions implementation 
cache* create_cache(int size) {
    cache *new_cache = (cache*)malloc(sizeof(cache));

    // initialize the hashmap 
    new_cache->hashmap = create_hashmap_cache(size);

    // allocate and initialize sentinel nodes 
    new_cache->head = (cache_node*)malloc(sizeof(cache_node));
    new_cache->tail = (cache_node*)malloc(sizeof(cache_node));

    new_cache->head->next = new_cache->tail;
    new_cache->head->prev = NULL;
    new_cache->tail->prev = new_cache->head;
    new_cache->tail->next = NULL;

    new_cache->count = 0; 

    new_cache->oldest_node = NULL;

    return new_cache;
}

void print_node_stats(cache *cache) {
    cache_node *current = cache->head->next; // Start after the head sentinel

    if (current == cache->tail) {
        printf("Cache is empty.\n");
        return;
    }
    int nodeno = 0; 
    printf("Cache contents (from most recent to least recent):\n");
    while (current != cache->tail) { // Traverse until the tail sentinel
        printf("url: %s, Max Age: %d, Expiration Time: %ld.%09ld\n", 
            current->url, 
            current->max_age, 
            (long)current->expiration_time.tv_sec, 
            current->expiration_time.tv_nsec);

        // printf("Content is: \n %s \n", current->response_content);
        
        current = current->next; // Move to the next node
    }
}

void print_cache_nodes(cache *cache) {
    cache_node *current = cache->head->next; // Start after the head sentinel

    if (current == cache->tail) {
        printf("Cache is empty.\n");
    }

    // Initial buffer size and increment size
    size_t buffer_size = 256; 
    char *result = malloc(buffer_size); // Dynamic buffer
    if (result == NULL) {
        printf("Memory allocation failed.\n");
    }
    
    result[0] = '\0'; // Initialize with empty string

    while (current != cache->tail) { // Traverse until the tail sentinel
        // Check if we need to expand the buffer
        size_t required_size = strlen(result) + strlen(current->url) + 4; // +3 for ' - ' or '_' and +1 for '\0'
        if (required_size > buffer_size) {
            buffer_size *= 2;
            result = realloc(result, buffer_size);
            if (result == NULL) {
                printf("Memory reallocation failed.\n");
            }
        }

        // Append the url name to the result
        strcat(result, current->url);

        // Add the separator based on if this is the last node or not
        if (current->next != cache->tail) {
            strcat(result, " - ");
        }

        current = current->next; // Move to the next node
    }

    printf("Cache contents: %s\n", result); // For logging purposes

    // return result; // Return the resulting string
}

void put(cache *cache, char *url, int max_age, char *content, ssize_t content_size) {
    cache_node *existing_node = get_from_hashmap_cache(cache->hashmap, url);
    // If it reaches here then node must be stale so refresh
    if (existing_node != NULL) {
        // If node already exists, just update stuff if is not a retrieval!
        printf("File %s alread in cache, updating and refreshing!\n", url);
        existing_node->max_age = max_age;
        clock_gettime(CLOCK_REALTIME, &existing_node->expiration_time);
        existing_node->expiration_time.tv_sec += max_age;

        // refresh content
        add_content_to_cache(existing_node, content, content_size);

        // update oldest node
        update_oldest_node(cache);
        return;
    }

    // Check if we have enough space in hashmap before inserting
    if (cache->count >= cache->hashmap->size) { 
        printf("Not enough space in cache, about to evict!\n");
        // First check if the oldest node is defined and is stale
        cache_node *evicted_node = NULL;

        if (cache->oldest_node && is_stale(cache, cache->oldest_node->url)) {
            // Evict the stale oldest_node 
            evicted_node = cache->oldest_node;
            remove_from_hashmap_cache(cache->hashmap, evicted_node->url);  // Remove from hashmap
            remove_node(cache, evicted_node);  // Remove from linked list
        
            printf("Evicted oldest stale url %s\n!", evicted_node->url);
            
        } else {
            // Evict LRU node since no stale nodes present
            evicted_node = cache->head->next; 
            remove_from_hashmap_cache(cache->hashmap, evicted_node->url);
            remove_node(cache, evicted_node);
            printf("Evicted LRU url %s\n!", evicted_node->url);
        }
        // update oldest_stale_node 
        update_oldest_node(cache);
        free(evicted_node);
    }

    // create a new cache_node 
    cache_node *new_node = (cache_node*)malloc(sizeof(cache_node));
    new_node->response_content = NULL;
    strncpy(new_node->url, url, MAX_URL_LENGTH);
    new_node->max_age = max_age;
    clock_gettime(CLOCK_REALTIME, &new_node->expiration_time); // Used to find expiration_time
    new_node->expiration_time.tv_sec += max_age;

    // add the content from the response to the cache
    add_content_to_cache(new_node, content, content_size);


    printf("INSERTED <%s> to hashmap_cache\n", url);
    // Add the new node to the hashmap 
    insert_into_hashmap_cache(cache->hashmap, url, new_node);

    // Add node to double linked list 
    add_node(cache, new_node);

    // update oldest_node if necessary
    if (cache->oldest_node == NULL || 
        new_node->expiration_time.tv_sec < cache->oldest_node->expiration_time.tv_sec ||
        (new_node->expiration_time.tv_sec == cache->oldest_node->expiration_time.tv_sec &&
         new_node->expiration_time.tv_nsec < cache->oldest_node->expiration_time.tv_nsec)) {
        cache->oldest_node = new_node;  // Update if this is the new oldest node
    }
    printf("Successfully added!\n");
}

ssize_t get(cache* cache, char *url, char *content_buffer) {
    // only calling get() if node is in cache and not stale
    printf("Getting url %s\n", url);
    cache_node *node = get_from_hashmap_cache(cache->hashmap, url);

    // remove and add node so it is to the left of the tail 
    remove_node(cache, node);

    // add it back so it is not LRU
    add_node(cache, node);

    // copy the content from the node into the buffer
    memcpy(content_buffer, node->response_content, node->response_size);

    printf("Successfully retrieved url!\n");

    return node->response_size;
}


void free_cache(cache* cache) { 
    // Free all the cache nodes between head and tail
    cache_node *current = cache->head->next;
    while (current != cache->tail) {
        cache_node *next_node = current->next;
        free(current);
        current = next_node;
    }

    // Free the sentinel nodes (head and tail)
    free(cache->head);
    free(cache->tail);
    // Free the hashmap
    free_hashmap_cache(cache->hashmap);

    // Free the cache structure itself
    free(cache);
}


// Handle the Cache-Control header line (Get the max-age)
// If Cache-Control is not present max age is 3600 s 
// Modify response to the client adding Age
// Create cache with size 10 