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
#include "cache.h"
#include "helpers.h"

#define MAX_REQUEST_SIZE 512
#define MAX_HEADER_SIZE 512
#define KB (1024)
#define MB (KB * KB)
#define MAX_RESPONSE_SIZE (10 * MB) + 50 // 10 MB + 50 bytes for the Age:
#define MAX_HOSTNAME_SIZE 101
#define PORT_SIZE 6 
#define DEFAULT_PORT 80
#define DEFAULT_MAX_AGE 3600
#define DEFAULT_CACHE_SIZE 10

#define ERR_HOST_NOT_RESOLVED -2


int proxy_socketfd;
int client_socketfd;
int server_socketfd;

// Global variable to control the loop
volatile sig_atomic_t ctrl_c_ended = 0;

void handle_sigint(int sig) {
    close(proxy_socketfd);
    ctrl_c_ended = 1;
}

int create_server_socket(int portno) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd < 0) {
        perror("ERROR opening the socket"); 
    }
    struct sockaddr_in proxy_addr;
    memset((char *) &proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY; //IP address of local machine
    proxy_addr.sin_port = htons(portno);

    // Bind
    if (bind(sockfd, (struct sockaddr *) &proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("ERROR on binding");
        close(sockfd);
        return -1;
    }
    printf("Socket bound correctly to port %d\n", portno);
    return sockfd;
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

ssize_t read_from_socket(int socketfd, char *buffer, ssize_t buffer_size, int request) {
    ssize_t bytes_read = 0;
    ssize_t total_bytes = 0;
    ssize_t content_length = -1; 
    char *end_header; 

    // Read the data from the socket in chunks
    int header_received = 0; 
    while ((bytes_read = read(socketfd, buffer + total_bytes, buffer_size - total_bytes - 1)) > 0) {
        total_bytes += bytes_read;

        // printf("Bytes read so far: %d\n", total_bytes);

        if (!header_received) {
            buffer[total_bytes] = '\0'; // Null terminate the header
            end_header = strstr(buffer, "\r\n\r\n");
            if (end_header) {
                header_received = 1;
                
                if (request) {
                    break;
                }               
                // Extract Content-Length
                char *content_length_str = strstr(buffer, "Content-Length: ");
                if (content_length_str) {
                    content_length_str += strlen("Content-Length: "); // Move past the header name
                    content_length = atoi(content_length_str); // Convert to long
                }
                // printf("Response body length is %d\n", content_length);
            }
        }
        // Break if buffer is full
        if (total_bytes >= buffer_size - 1) {
            break;
        }
        // Break if header is received and we've read enough bytes
        if (header_received && content_length != -1 && total_bytes >= (content_length + (end_header - buffer + 4))) {
            break;
        }
    }
    if (bytes_read == -1) {
        // Error handling
        perror("Error reading from socket");
        return -1;
    }
    return total_bytes; // Return the total number of bytes read
}


/* Function that starts proxy. This is the main function of this file */
int start_proxy(int portno) {
    /***************  Proxy acts as a SERVER ***************/
    printf("Proxy started!\n");
    proxy_socketfd = create_server_socket(portno);

    if (listen(proxy_socketfd, 5) == -1) {
        perror("listen");
        return -1;
    }

    // initialize cache 
    cache *cache = create_cache(DEFAULT_CACHE_SIZE);
    signal(SIGINT, handle_sigint);
    while (1) {
        int is_get_request = 1; // Checks if is a GET request to see if we cache it
        int n; // bytes read or wrote for error checking
        struct sockaddr_in client_addr; 
        socklen_t client_len = sizeof(client_addr);
        client_socketfd = accept(proxy_socketfd, (struct sockaddr *) &client_addr, &client_len); 
        if (client_socketfd < 0) {
            if (ctrl_c_ended) {
                printf("\nUser ended the proxy\n");
                break;
            } else {
                perror("ERROR on accept");
                break;
            }
            
        }
        printf("Accepted the request from the client with IP: %s\n", inet_ntoa(client_addr.sin_addr));

        // read from client_socket
        char request_buffer[MAX_REQUEST_SIZE];
        ssize_t request_size = read_from_socket(client_socketfd, request_buffer, MAX_REQUEST_SIZE, 1);
        if (request_size < 0) {
            perror("ERROR reading from socket");
            break;
        }

        char hostname[MAX_HOSTNAME_SIZE];
        char port[PORT_SIZE];
        get_hostname_and_port(request_buffer, hostname, port);

        // if no port specified set it to 80 
        int request_portno = (strlen(port) != 0) ? atoi(port) : DEFAULT_PORT;

        char url[MAX_HOSTNAME_SIZE + 100];
        get_url(request_buffer, url, request_portno);

        if (strstr(request_buffer, "GET ") == NULL) {
            is_get_request = 0; // not a get request so do not cache
        }

        // Allocate space for the response content
        char *response_buffer = (char *) malloc(MAX_RESPONSE_SIZE); // allocate 10MB
        ssize_t response_size; 

        // check if URL is in cache and it is not stale and it is a get_request
        if (in_cache(cache, url) && !is_stale(cache, url) && is_get_request) {
            printf("Url %s in cache!\n", url);
            // get the content from the cache, no need to go to the server
            response_size =  get(cache, url, response_buffer);

            // /* edit response header  */ 
            cache_node *node = get_node(cache, url);

            // get current time
            struct timespec current_time;
            clock_gettime(CLOCK_REALTIME, &current_time);

            // get time when node was inserted into cache
            long time_inserted = node->expiration_time.tv_sec - node->max_age;

            // get age 
            long age = current_time.tv_sec - time_inserted;

            // make it into a string
            char age_value[20]; 
            snprintf(age_value, sizeof(age_value), "%ld", age);


            char *copy_response_buffer = (char *) malloc(MAX_RESPONSE_SIZE); // Allocate memory for the copy
            if (copy_response_buffer == NULL) {
                perror("Failed to allocate memory for copy of response_buffer");
            }

            memcpy(copy_response_buffer, response_buffer, MAX_RESPONSE_SIZE);

            ssize_t age_line_length = add_age_to_header(copy_response_buffer, response_size, age_value);

            // simple forward response to the client
            n = write(client_socketfd, copy_response_buffer, response_size + age_line_length);
            if (n < 0) {
                perror("ERROR writing to socket");
                break;
            }

            free(copy_response_buffer);
        } 
        else {
            if (!in_cache(cache, url)) {
                printf("Url %s is not in cache, going to server!\n", url);
            } else if (!is_get_request) {
                printf("Not a get request, going to the server!");
            }
            /***************  Proxy acts as a CLIENT ***************/
            struct sockaddr_in server_addr; 
            server_socketfd = create_client_socket(server_addr, request_portno, hostname);

            if (server_socketfd == -1) {
                perror("ERROR openening the socket!");
                break;
            }

            if (server_socketfd == ERR_HOST_NOT_RESOLVED) {
                dprintf(client_socketfd, "Could not resolve host %s\n", hostname);
                printf("Could not resolve host!\n");
                close(client_socketfd);
                continue;
            }
            
            // forward request to the server 
            n = write(server_socketfd, request_buffer, strlen(request_buffer));
            if (n < 0) {
                perror("ERROR writing to the server");
                break;
            }
            printf("Request forwarded to the server!\n");

            // read response from the server
            response_size = read_from_socket(server_socketfd, response_buffer, MAX_RESPONSE_SIZE, 0);

            // Either put or update the cache (put function takes care of both)
            int max_age = get_max_age(response_buffer);
            printf("This is the max age: %d\n", max_age);
            // Only cache GET_REQUESTS
            if (is_get_request) {
                put(cache, url, max_age, response_buffer, response_size);
            }
            printf("Added URL <%s> to cache!\n", url);

            // close connection with the server
            close(server_socketfd);

            // forward response to the client
            n = write(client_socketfd, response_buffer, response_size);
            if (n < 0) {
                perror("ERROR writing to socket");
                break;
            }
        }

        printf("\nThe cache size is: %d\n", cache->count);

        print_cache_nodes(cache);

        // free response buffer
        free(response_buffer);      
        // Close connection with client
        close(client_socketfd);
    }
    close(proxy_socketfd);
    free_cache(cache);
    
    return 0;
}