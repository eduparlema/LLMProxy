#ifndef _CLIENT_LIST_H
#define _CLIENT_LIST_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cache.h"

#define DEFAULT_TIMEOUT 600
#define MAX_URL_LENGTH 2000
#define KB (1024)
#define MAX_REQUEST_SIZE (16 * KB) // 8 kilobytes

// Note: Since TCP ensures that we receive the data in order, a client can
// have at most one incomplete message at a time.

typedef struct client_node {
    int socketfd;                     // File descriptor for the client connection
    char IP_addr[INET_ADDRSTRLEN];    // Client IP address
    time_t last_activity;             // Timestamp of the last activity for timeout handling
    SSL *ssl;                         // SSL context for secure communication, NULL for non-SSL
    char request_url[MAX_URL_LENGTH]; // URL requested by the client
    char *request_buffer;             // Buffer to store the request header
    size_t bytes_received;            // How much of the header has been received
    int header_received;              // Flag to indicate if the header is fully received
    struct client_node *next;         // Pointer to the next client in the list
    struct client_node *prev;         // Pointer to the previous client in the list
} client_node;

// Create and initialize a new client node
client_node *create_client_node(int socketfd);

// Free the memory associated with a client node
void free_client_node(client_node *node);

typedef struct client_list {
    client_node *head;
    client_node *tail;
} client_list;

typedef struct hashmap_client hashmap_client;

// Create and initialize a client list
client_list *create_client_list();

// Free the memory associated with a client list
void free_client_list(client_list *cli_list);

// Add a client to the client list
void add_client(client_list *client_list, client_node *client);

// Remove a client from the client list
void remove_client(client_list *client_list, client_node *client);

// Get the minimum timeout value for all clients in the list
time_t get_min_time(client_list *client_list);

// Check and handle clients that have timed out
void check_timeout(fd_set *master_set, hashmap_client *hashmap, client_list *client_list);

#endif
