#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "client_list.h"

#define KB (1024)
#define MB (KB * KB)
#define MAX_REQUEST_SIZE (8 * KB) // 8 kilobytes

client_list *create_client_list() {
    client_list *cli_list = (client_list *) malloc(sizeof(client_list));

    // Allocate and initialize the sentinel nodes
    cli_list->head = (client_node *) malloc(sizeof(client_node));
    cli_list->tail = (client_node *) malloc(sizeof(client_node));

    cli_list->head->next = cli_list->tail;
    cli_list->head->prev = NULL;
    cli_list->tail->prev = cli_list->head;
    cli_list->tail->next = NULL;

    return cli_list;
}

void free_client_list(client_list *cli_list) {
    // Free all client nodes
    client_node *current = cli_list->head->next; // Start from the first actual node

    while (current != cli_list->tail) { 
        client_node *temp = current;  
        current = current->next;    
        free(temp);                      
    }

    // Free the sentinel nodes
    // free(cli_list->head);
    // free(cli_list->tail);

    // Finally, free the client list itself
    free(cli_list);
}

client_node *create_client_node(int socketfd) {
    client_node *node = (client_node *) malloc(sizeof(client_node));
    if (!node) {
        perror("ERROR allocating space for client_node");
        exit(EXIT_FAILURE);
    }
    node->socketfd = socketfd;
    memset(&node->IP_addr, 0, INET_ADDRSTRLEN);
    node->last_activity = time(NULL);
    memset(&node->request_url, 0, MAX_URL_LENGTH);
    node->request_buffer = (char *) malloc(MAX_REQUEST_SIZE);
    node->bytes_received = 0;
    node->header_received = 0;
    node->next = NULL;
    node->prev = NULL;
    return node;
}

void free_client_node(client_node *node) {
    if (!node) {
        return;
    }
    if (node->request_buffer) {
        free(node->request_buffer);
        node->request_buffer = NULL;
    }
    free(node);
}

void add_client(client_list *client_list, client_node *client) {
    client_node *prev_node = client_list->tail->prev;
    client_list->tail->prev = client;
    client->next = client_list->tail;
    client->prev = prev_node;
    prev_node->next = client;
}

void remove_client(client_list *client_list, client_node *client) {
    client_node *prev_node = client->prev;
    client_node *next_node = client->next; 
    prev_node->next = next_node;
    next_node->prev = prev_node;
}

time_t get_min_time(client_list *client_list) {
    client_node *current = client_list->head->next;
    time_t result = 0;
    while (current != NULL && current != client_list->tail) {
        time_t elapsed_time = time(NULL) - current->last_activity;
        result = (result > elapsed_time) ? result : elapsed_time;
        current = current->next;
    }
    return DEFAULT_TIMEOUT - result;
}