#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "client_list.h"

#define KB (1024)
#define MB (KB * KB)

client_list *create_client_list() {
    client_list *cli_list = (client_list *) malloc(sizeof(client_list));
    if (!cli_list) {
        perror("[create_client_list] ERROR allocating space for client_list");
        exit(EXIT_FAILURE);
    }

    cli_list->head = (client_node *) malloc(sizeof(client_node));
    if (!cli_list->head) {
        perror("[create_client_list] ERROR allocating space for head node");
        free(cli_list);
        exit(EXIT_FAILURE);
    }

    cli_list->tail = (client_node *) malloc(sizeof(client_node));
    if (!cli_list->tail) {
        perror("[create_client_list] ERROR allocating space for tail node");
        free(cli_list->head);
        free(cli_list);
        exit(EXIT_FAILURE);
    }

    cli_list->head->next = cli_list->tail;
    cli_list->head->prev = NULL;
    cli_list->tail->prev = cli_list->head;
    cli_list->tail->next = NULL;

    return cli_list;
}

void free_client_list(client_list *cli_list) {
    if (!cli_list) {
        return;
    }

    // free all client nodes
    client_node *current = cli_list->head->next;
    while (current != cli_list->tail) {
        client_node *temp = current;
        current = current->next;

        if (temp) {
            free_client_node(temp);
        }
    }

    // free the sentinel nodes
    if (cli_list->head) free(cli_list->head);
    if (cli_list->tail) free(cli_list->tail);

    // free the client list itself
    free(cli_list);
}



client_node *create_client_node(int socketfd) {
    client_node *node = (client_node *) malloc(sizeof(client_node));
    if (!node) {
        perror("[create_client_node] ERROR allocating space for client_node");
        exit(EXIT_FAILURE);
    }

    // Initialize fields
    node->socketfd = socketfd;
    memset(&node->IP_addr, 0, INET_ADDRSTRLEN);
    node->last_activity = time(NULL);
    memset(&node->request_url, 0, 8 * KB);
    node->request_buffer = (char *) malloc(1 * MB);
    if (!node->request_buffer) {
        perror("[create_client_node] ERROR allocating space for request_buffer");
        free(node);
        exit(EXIT_FAILURE);
    }
    node->bytes_received = 0;
    node->header_received = 0;
    node->header_length = 0;
    node->content_length = 0;
    node->next = NULL;
    node->prev = NULL;
    node->ssl = NULL;

    return node;
}


void free_client_node(client_node *node) {
    if (!node) {
        return;
    }

    // Free the SSL context if it exists
    if (node->ssl) {
        // Shut down the SSL connection
        SSL_shutdown(node->ssl);
        // Free the SSL object
        SSL_free(node->ssl);
        // Set to NULL for safety
        node->ssl = NULL;
    }

    // Free the request buffer
    if (node->request_buffer) {
        free(node->request_buffer);
        node->request_buffer = NULL;
    }

    // Free the client node itself
    free(node);
}


void add_client(client_list *client_list, client_node *client) {
    if (!client_list || !client) {
        fprintf(stderr, "[add_client] Error: NULL client_list or client passed to add_client\n");
        return;
    }

    client_node *prev_node = client_list->tail->prev;
    client_list->tail->prev = client;
    client->next = client_list->tail;
    client->prev = prev_node;
    prev_node->next = client;
}


void remove_client(client_list *client_list, client_node *client) {
    if (!client_list || !client || client == client_list->head || client == client_list->tail) {
        fprintf(stderr, "[add_client] Error: Invalid client or attempt to remove sentinel nodes\n");
        return;
    }

    client_node *prev_node = client->prev;
    client_node *next_node = client->next;

    if (prev_node) {
        prev_node->next = next_node;
    }
    if (next_node) {
        next_node->prev = prev_node;
    }

    free_client_node(client);
}


time_t get_min_time(client_list *client_list) {
    client_node *current = client_list->head->next;
    time_t result = DEFAULT_TIMEOUT;

    while (current != NULL && current != client_list->tail) {
        time_t elapsed_time = time(NULL) - current->last_activity;
        time_t remaining_time = DEFAULT_TIMEOUT - elapsed_time;

        if (remaining_time < result) {
            result = remaining_time;
        }

        current = current->next;
    }

    return result > 0 ? result : 0;
}
