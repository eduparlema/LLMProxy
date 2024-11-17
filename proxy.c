#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <signal.h>

#include "proxy.h"
#include "cache.h"
#include "client_list.h"
#include "hashmap.h"

#define KB (1024)
#define MB (KB * KB)
#define MAX_REQUEST_SIZE (8 * KB) // 8 kilobytes
#define MAX_RESPONSE_SIZE (10 * MB) + 50 // 10 MB + 50 bytes for the Age:
#define MAX_HOSTNAME_SIZE 101
#define PORT_SIZE 6 
#define DEFAULT_PORT 80
#define DEFAULT_MAX_AGE 3600
#define DEFAULT_CACHE_SIZE 10
#define MAX_CLIENTS 541 // Max number of clients

#define ERR_HOST_NOT_RESOLVED -2

int master_socketfd; // master socket
int server_socketfd; // socket established to communicate with server

// Global variable to control the infinite loop
volatile sig_atomic_t ctrl_c_ended = 0;

void handle_sigint(int sig) {
    close(master_socketfd);
    ctrl_c_ended = 1;
}

int find_max_fd(fd_set *set, int max_possible_fd) {
    int max_fd = -1; 
    for (int fd = 0; fd < max_possible_fd; fd ++) {
        if (FD_ISSET(fd, set)) {
            max_fd = fd;
        }
    }
    return max_fd;
}

int create_server_socket(int portno) {
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketfd < 0) {
        perror("socket");
    }
    struct sockaddr_in proxy_addr;
    memset((char *) &proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY; //IP address of local machine
    proxy_addr.sin_port = htons(portno);

    // bind 
    if (bind(socketfd, (struct sockaddr *) &proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("binding");
        close(socketfd);
        return -1;
    }
    printf("Socket bound correctly to port %d\n", portno);
    return socketfd;
}

int create_client_socket(struct sockaddr_in server_addr, int portno, char *hostname) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 1) {
        perror("ERROR opening socket!");
        return -1;
    }
    server = gethostbyname(hostname);
    if (server == NULL) {
        return ERR_HOST_NOT_RESOLVED;
    }
    memset((char *) &server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
            (char *)&server_addr.sin_addr.s_addr,
            server->h_length);
    server_addr.sin_port = htons(portno);

    // connect with the server 
    if ((connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr))) < 0) {
        perror("ERROR connecting with the server");
        return -1;
    }
    printf("Connected to host with IP: %s\n", inet_ntoa(server_addr.sin_addr));

    return sockfd;
}

size_t read_message(int socketfd, char *buffer, int buffer_size) {
    int nbytes = read(socketfd, buffer, buffer_size);
    if (nbytes < 0) {
        perror("ERROR reading");
        return -1;
    } else if (nbytes == 0) {
        printf("Connection closed by the client %d\n", socketfd);
        return -1;
    }
    return nbytes;
}

char *get_ip(int socketfd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    // get the address (IP + port)
    if (getpeername(socketfd, (struct sockaddr *)&addr, &len) == -1) {
        perror("getpeername failed");
        // TODO: Invoke a error handling to remove that fd from the set 
        // and continue the loop
        exit(EXIT_FAILURE); // exiting for now
    }
    // convert IP to a string
    char IP_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), IP_addr, INET_ADDRSTRLEN);
    return IP_addr;
}

int handle_request_buffer(char *request_buffer, int buffer_size, client_node *client) {
    size_t remaining_space = MAX_REQUEST_SIZE - client->bytes_received - 1;
    if (buffer_size > remaining_space) {
        perror("Request buffer overflow client!\n");
        return -1;
    }
    // Append new data to request buffer
    memcpy(client->request_buffer + client->bytes_received, request_buffer, buffer_size);
    client->bytes_received += buffer_size;
    client->request_buffer[client->bytes_received] = '\0';

    // Check if the header is complete
    char *header_end = strstr(client->request_buffer, "\r\n\r\n");
    if (header_end) {
        client->header_received = 1;
        return header_end - client->request_buffer + 4; // return header length
    }
    return 0; //incomplete header
}

void close_client_connection(int socketfd, fd_set *master_set, client_list *cli_list, 
                                Hashmap *clilist_hashmap, const char *IP_addr, client_node *client) {
    close(socketfd); // close socket
    if (FD_ISSET(socketfd, master_set)) {
        FD_CLR(socketfd, master_set); // remove from set
    }
    remove_client(cli_list, client);
    remove_from_hashmap(clilist_hashmap, IP_addr);
    free_client_node(client);
}

int handle_request();

int start_proxy(int portno) {
    /***************  Proxy acts as a SERVER ***************/
    printf("Proxy started!\n");
    master_socketfd = create_server_socket(portno);
    if (listen(master_socketfd, 5) == -1) {
        perror("listen");
        return -1;
    }

    // Initialize variables useful variables for select()
    struct sockaddr_in client_addr;
    socklen_t client_len;

    fd_set master_set, temp_set;
    FD_ZERO(&master_set);
    FD_ZERO(&temp_set);
    FD_SET(master_socketfd, &master_set);
    int fd_max = master_socketfd;

    // Initialize cache
    cache *cache = create_cache(DEFAULT_CACHE_SIZE);
    // Initialize client_list
    client_list *cli_list = create_client_list();
    // Initialize client list hashmap for faste lookups
    // (key, value) -> (IP address, client_node)
    Hashmap *clilist_hashmap = create_hashmap(MAX_CLIENTS);

    char *request_buffer; // buffer to store the request from clients

    signal(SIGINT, handle_sigint); // to stop server with ctrl+C
    while (1) {
        int is_get_request = 1; // Check if it is a GET request to see if we cache it
        int n; // bytes read or wrote for error checking

        temp_set = master_set; 

        int activity = select(fd_max + 1, &temp_set, NULL, NULL, NULL);
        if (activity < 0) {
            if (ctrl_c_ended) {
                printf("\nThe server was ended!\n");
            } else {
                perror("select");
                exit(EXIT_FAILURE); // TODO: Keep here?
            }
            break;
        }
        // Service all the sockets with pending input
        for (int i = 0; i <= fd_max; i++) {
            if (FD_ISSET(i, &temp_set)) {
                if (i == master_socketfd) {
                    printf("Connection request to proxy!\n");
                    /* Connection request to proxy */
                    client_len = sizeof(client_addr);
                    int client_socketfd = accept(master_socketfd,
                                                 (struct sockaddr *) &client_addr,
                                                 &client_len);
                    if (client_socketfd < 0) {
                        perror("accept");
                        exit(EXIT_FAILURE);
                    }
                    // Get the IP address (key of hashmap)
                    char IP_addr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(client_addr.sin_addr), IP_addr, INET_ADDRSTRLEN);

                    printf("Accepted request from client with IP %s and fd %hd.\n",
                            IP_addr, client_socketfd);
                    FD_SET(client_socketfd, &master_set); // Add to set
                    // update fd_max
                    fd_max = (client_socketfd > fd_max) ? client_socketfd : fd_max;

                    // add to hashmap and list
                    if (get_from_hashmap(clilist_hashmap, IP_addr) == NULL) {
                        // add if the IP address is not in the map
                        printf("Added client with IP address %s to hashmap\n!", IP_addr);
                        client_node *node = create_client_node(client_socketfd);
                        // TODO: Update url info of client node once you get the url
                        insert_into_hashmap(clilist_hashmap, IP_addr, node);
                        add_client(cli_list, node);
                    }
                } else {
                    printf("Request arriving from a client!\n");
                    char *IP_addr = get_ip(i);
                    client_node *client = get_from_hashmap(clilist_hashmap, IP_addr);
                    if (client == NULL) {
                        // sanity check
                        printf("ERROR: client with IP %s, not in hashmap!\n", IP_addr);
                    }
                    printf("A client with IP address %s is sending a request!\n", IP_addr);
                    // First read everything into a buffer
                    request_buffer = (char *) malloc(MAX_REQUEST_SIZE);
                    int nbytes = read_message(client->socketfd, request_buffer, MAX_REQUEST_SIZE);
                    if (nbytes < 0) {
                        close_client_connection(i, &master_set, cli_list, clilist_hashmap, IP_addr, client);
                        printf("ERROR reading, removing client\n");
                        continue; 
                    }
                    // handle request buffer
                    if (handle_request_buffer(request_buffer, nbytes, client) == -1) {
                        close_client_connection(i, &master_set, cli_list, clilist_hashmap, IP_addr, client);
                    }
                    if (client->header_received) {
                        printf("Complete header received!\n");
                        // TODO: Do what the proxy did in A1
                        handle_request();
                    } else {
                        printf("Partial header received!\n");
                        continue;
                    }
                }
            }
        }
    }
    // TODO: FREE stuff
    free(request_buffer);  
}