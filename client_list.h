#ifndef _CLIENT_LIST_H
#define _CLIENT_LIST_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>

#include "cache.h"

#define MAX_PACKET_SIZE 400
#define MAX_CLIENTID_LENGTH 20

// Note: Since TCP ensures that we receive the data in order, a client can 
// have at most one incomplete message at a time.
typedef struct client_node {
    int socketfd;
    time_t last_activity; // helpful to handle timeouts
    char request_url[MAX_URL_LENGTH];
    char *request_buffer;
    size_t bytes_received; // how much of the header has been received
    int header_received;
    struct client_node *next;
    struct client_node *prev; 
} client_node;

client_node *create_client_node(int socketfd);

void free_client_node(client_node *node);

typedef struct client_list {
    client_node *head;
    client_node *tail;
} client_list;

typedef struct Hashmap Hashmap;

client_list *create_client_list();

void free_client_list(client_list *cli_list);

void add_client(client_list *client_list, client_node *client);

void remove_client(client_list *client_list, client_node *client);

time_t get_min_time(client_list *client_list);

void check_timeout(fd_set *master_set, Hashmap *hashmap, client_list *client_list);

#endif 