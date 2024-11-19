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
#include "hashmap_client.h"

#define KB (1024)
#define MB (KB * KB)
#define MAX_REQUEST_SIZE (8 * KB) // 8 kilobytes
#define MAX_RESPONSE_SIZE (10 * MB) + 50 // 10 MB + 50 bytes for the Age:
#define MAX_HOSTNAME_SIZE 256
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
    for (int fd = 0; fd <= max_possible_fd; fd ++) {
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

    free(request_buffer);

    return 0; //incomplete header
}

void close_client_connection(client_node *client, fd_set *master_set, client_list *cli_list,
                                hashmap_client *clilist_hashmap) {
    close(client->socketfd);
    if (FD_ISSET(client->socketfd, master_set)) {
        FD_CLR(client->socketfd, master_set);
    }
    remove_client(cli_list, client);
    remove_from_hashmap_client(clilist_hashmap, client->socketfd);
    free_client_node(client);
}

void check_timeout(fd_set *master_set, hashmap_client *hashmap, client_list *cli_list) {
    client_node *current = cli_list->head->next;
    while (current != NULL && current != cli_list->tail) {
        if ((time(NULL) - current->last_activity) >= DEFAULT_TIMEOUT) {
            char IP_addr[INET_ADDRSTRLEN];
            printf("No request from client with IP %s\n", current->IP_addr);
            close_client_connection(current, master_set, cli_list, hashmap);
        }
        current = current->next;
    }
}

int get_hostname_and_port(const char *request, char *hostname, size_t hostname_size, char *port, size_t port_size) {
    // Extract the "Host:" header
    const char *host_line = strstr(request, "Host:");
    if (host_line == NULL) {
        perror("INVALID HTTP: Host header not found!\n");
        return -1; // Invalid HTTP
    }

    // Skip "Host:" and any leading spaces
    host_line += strlen("Host:");
    while (*host_line == ' ') {
        host_line++;
    }

    // Find the end of the header line
    const char *end_of_line = strpbrk(host_line, "\r\n");
    if (end_of_line == NULL) {
        perror("INVALID HTTP: Host header format!\n");
        return -1; // Invalid HTTP
    }

    // Check for a port delimiter
    const char *colon_pos = strchr(host_line, ':');
    if (colon_pos != NULL && colon_pos < end_of_line) {
        // Copy port
        size_t port_length = (size_t)(end_of_line - colon_pos - 1);
        if (port_length >= port_size) {
            perror("INVALID HTTP: Port buffer too small!\n");
            return -1; // Invalid HTTP
        }
        strncpy(port, colon_pos + 1, port_length);
        port[port_length] = '\0';

        // Adjust hostname length
        end_of_line = colon_pos;
    } else {
        // No port found, return default empty string for port
        strncpy(port, "", port_size);
    }

    // Copy hostname
    size_t hostname_length = (size_t)(end_of_line - host_line);
    if (hostname_length >= hostname_size) {
        perror("INVALID HTTP: Hostname buffer too small!\n");
        return -1; // Invalid HTTP
    }
    strncpy(hostname, host_line, hostname_length);
    hostname[hostname_length] = '\0';

    return 0; // Success
}

void modify_url(char *original_url, char *modified_url, int port) {
    // Find and remove " HTTP/1.1" first
    char *http_version = strstr(original_url, " HTTP/");
    if (http_version) {
        *http_version = '\0';  // Terminate the string before " HTTP/1.1"
    }

    // Find the start of the hostname by locating "://"
    char *path_start = strstr(original_url, "://");
    if (path_start == NULL) {
        perror("Invalid URL format.");
        return;
    }

    // Move past the '://'
    path_start += 3;

    // Find the first '/' after the hostname (start of the path)
    char *slash_pos = strchr(path_start, '/');

    // Construct the port string
    char port_str[10];
    snprintf(port_str, sizeof(port_str), ":%d", port);

    if (slash_pos) {
        // Copy up to the slash position (hostname) and append the port
        size_t host_length = slash_pos - original_url;
        strncpy(modified_url, original_url, host_length);  // Copy until the slash
        strcat(modified_url, port_str);              // Append the port
        strcat(modified_url, slash_pos);             // Append the path (slash included)
    } else {
        // No path, just append the port to the hostname
        strcpy(modified_url, original_url);   // Copy the entire URL
        strcat(modified_url, port_str); // Append the port
    }
}

/**
 * Extracts the full URL from an HTTP GET request.
 *
 * @param httpRequest The HTTP request string to parse for the URL.
 * @return A dynamically allocated string containing the URL from the GET request,
 *         or NULL on error.
 *
 * This function searches for the "GET" method in the HTTP request and extracts
 * the URL that follows.
 * If the "GET " or " HTTP" markers are not found, the function logs an error
 * and returns NULL.
 */
char* getURLFromRequest(const char httpRequest[]) {
    // Create a local copy of the httpRequest
    char requestCopy[MAX_REQUEST_SIZE];
    strncpy(requestCopy, httpRequest, MAX_REQUEST_SIZE - 1);
    requestCopy[MAX_REQUEST_SIZE - 1] = '\0';

    // Find the first occurrence of "GET "
    char *GetLine = strstr(requestCopy, "GET ");
    if (GetLine == NULL) {
        fprintf(stderr, "getURLFromRequest - ERROR: GET line not found in the request.\n");
        return NULL;
    }

    // Move past "GET " to the actual URL
    GetLine += strlen("GET ");

    // Find the end of the URL (' HTTP')
    char *endOfGetLine = strstr(GetLine, " HTTP");
    if (endOfGetLine != NULL) {
        *endOfGetLine = '\0';
    } else {
        fprintf(stderr, "getURLFromRequest - ERROR: End of GET line not found.\n");
        return NULL;
    }

    // Return a copy of the URL
    return strdup(GetLine);
}

int get_url(char *header_buffer, char *url, int port) {
    char *get_line;
    get_line = strstr(header_buffer, "HEAD ");
    if (get_line) {
        get_line += strlen("HEAD ");
    } else {
        get_line = strstr(header_buffer, "GET ");
        if (get_line){
            get_line += strlen("GET ");
        } else {
            perror("INVALID HTTP: expected GET or HEAD");
            return -1; // Invalid HTTP
        }
    }

    // Find the end of the header line
    char *end_of_line = strchr(get_line, '\r');
    if (end_of_line == NULL) {
        end_of_line = strchr(end_of_line, '\n');
    }

    ssize_t url_length = end_of_line ? (ssize_t) (end_of_line - get_line) : strlen(get_line);

    strncpy(url, get_line, url_length);
    url[url_length] = '\0'; // Null-terminate the URL

    // // Modify the URL to append the port
    // char modified_url[url_length + PORT_SIZE];
    // modify_url(url, modified_url, port);

    // // copy back to url
    // strncpy(url, modified_url, url_length + PORT_SIZE);
}

ssize_t add_age_to_header(char *response_buffer, ssize_t response_length, char *age_value) {
    // Create the Age header line
    char age_header[50]; // Ensure this is large enough for "Age: <value>\r\n"
    snprintf(age_header, sizeof(age_header), "\r\nAge: %s\r\n\r\n", age_value);

    // Find the end of the headers
    char *end_of_header = strstr(response_buffer, "\r\n\r\n");
    if (end_of_header == NULL) {
        printf("Invalid HTTP response: No header ending found.\n");
        return -1;
    }

    // response_length = strlen(response_buffer);

    // Move the rest of the response body down to make room for the new header
    ssize_t header_length = end_of_header - response_buffer + 4; // +4 for "\r\n\r\n"
    ssize_t body_length = response_length - header_length;

    // Shift the body down to make room for the new header
    memmove(end_of_header + strlen(age_header), end_of_header + 4, body_length + 1); // +1 for the null terminator

    // Insert the new Age header
    memcpy(end_of_header, age_header, strlen(age_header));

    return strlen(age_header);
}

ssize_t read_from_server(int socketfd, char *buffer, ssize_t buffer_size) {
    ssize_t bytes_read = 0;
    ssize_t total_bytes = 0;
    ssize_t content_length = -1;
    char *end_header;

    // Read the data from the socket in chunks
    int header_received = 0;
    while ((bytes_read = read(socketfd, buffer + total_bytes, buffer_size - total_bytes - 1)) > 0) {
        total_bytes += bytes_read;

        printf("Bytes read so far: %d\n", total_bytes);
        // printf("Buffer size: %d, bytes read: %d\n", buffer_size, bytes_read);
        // printf("buffer_size - total_bytes - 1: %d\n", buffer_size - total_bytes - 1);

        if (!header_received) {
            buffer[total_bytes] = '\0'; // Null terminate the header
            end_header = strstr(buffer, "\r\n\r\n");
            if (end_header) {
                header_received = 1;
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

int get_max_age(char *header_buffer) {
    // Extract the Cache-Control: line
    char *cache_line = strstr(header_buffer, "Cache-Control:");
    if (cache_line == NULL) {
        printf("Cache control not present in response\n");
        return DEFAULT_MAX_AGE;
    }

    // Extract max-age from here
    char *max_age_str = strstr(cache_line, "max-age=");
    if (max_age_str == NULL) {
        return DEFAULT_MAX_AGE;
    }
    max_age_str += strlen("max-age=");

    int max_age = atoi(max_age_str);

    return max_age;
}

int handle_request(client_node *client, int client_socketfd, cache *cache) {
    int is_get_request = 1;

    char hostname[MAX_HOSTNAME_SIZE];
    char port[PORT_SIZE];
    if (get_hostname_and_port(client->request_buffer, hostname, MAX_HOSTNAME_SIZE, port, PORT_SIZE) == -1) {
        printf("INVALID HTTP, removing client\n");
        return -1;
    }

    // if no port specified set it to 80
    int request_portno = (strlen(port) != 0) ? atoi(port) : DEFAULT_PORT;


    printf("<><> REQUEST BUFFER IN CLIENT: \n%s\nEND", client->request_buffer);

    char *url = getURLFromRequest(client->request_buffer);
    if (url == NULL) {
        fprintf(stderr, "handle_request : ERROR - Could not extract URL from request.\n");
        return -1;
    }

    printf("My url is %s\n", url);

    if (strstr(client->request_buffer, "GET ") == NULL) {
        is_get_request = 0; // not a get request so do not cache
    }

    strncpy(client->request_url, url, strlen(url));
    printf("This is the url: %s\n", url);

    char *response_buffer = (char *) malloc(MAX_RESPONSE_SIZE); // Allocate 10MB
    size_t response_size;

    // check if url is in cache and it is not stale and it is a get_request
    if (in_cache(cache, url) && !is_stale(cache, url) && is_get_request) {
        printf("Url %s in cache!\n", url);
        // get the content from the cache, no need to go to the server
        response_size = get(cache, url, response_buffer);

        /* edit response header */ //TODO: IMPROVE THIS!
        cache_node *node = get_node(cache, url);
        // get current time
        struct timespec current_time;
        clock_gettime(CLOCK_REALTIME, &current_time);
        // get time when node was inserted into cache
        long time_insrted = node->expiration_time.tv_sec - node->max_age;
        // get age
        long age = current_time.tv_sec - time_insrted;
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
        if (write(client_socketfd, copy_response_buffer, response_size + age_line_length) < 0){
            perror("ERROR writing to socket");
            return -1;
        }

        free(copy_response_buffer);
    } else {
        if (!in_cache(cache, url)) {
            printf("Url %s is not in cache, going to the server!\n", url);
        } else if (!is_get_request) {
            printf("Not a GET request, going to the server!\n");
        }
        /***************  Proxy acts as a CLIENT ***************/
        struct sockaddr_in server_addr;
        server_socketfd = create_client_socket(server_addr, request_portno, hostname);

        if (server_socketfd == -1) {
            dprintf(client_socketfd, "Could not request from server\n");
            perror("ERROR opening socket");
            return -1;
        }

        if (server_socketfd == ERR_HOST_NOT_RESOLVED) {
            dprintf(client_socketfd, "Could not resolve host %s\n", hostname);
            printf("Could not resolve host!\n");
            return -1;
        }

        // forward request to server
        if (write(server_socketfd, client->request_buffer, strlen(client->request_buffer)) < 0) {
            perror("ERROR writing to the server");
            return -1;
        }
        printf("Request forwarded to the server!\n");

        // Read response from the server
        response_size = read_from_server(server_socketfd, response_buffer, MAX_RESPONSE_SIZE);

        // Either put or update the cache (put function takes care of both)
        int max_age = get_max_age(response_buffer);
        printf("This is the max age: %d\n", max_age);
        // Only cache GET requests
        if (is_get_request) {
            put(cache, url, max_age, response_buffer, response_size);
        }
        printf("Added URL <%s> to cache!\n", url);

        // Close connection with server
        close(server_socketfd);

        // Forward response to client
        if (write(client_socketfd, response_buffer, response_size) < 0) {
            perror("ERROR writing to client\n");
            return -1;
        }
        free(response_buffer);
    }
    // reset the partial request buffer from client
    memset(client->request_buffer, 0, sizeof(client->request_buffer));
}

int start_proxy(int portno) {
    /***************  Proxy acts as a SERVER ***************/
    printf("Proxy started!\n");
    master_socketfd = create_server_socket(portno);
    if (listen(master_socketfd, 5) == -1) {
        perror("listen");
        return -1;
    }

    // Initialize variables for select()
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
    // (key, value) -> (socketfd, client_node)
    hashmap_client *clilist_hashmap = create_hashmap_client(MAX_CLIENTS);

    char *request_buffer; // buffer to store the request from clients

    signal(SIGINT, handle_sigint); // to stop server with ctrl+C

    time_t min_time_until_expiration;
    struct timeval timeout;

    while (1) {
        min_time_until_expiration = get_min_time(cli_list);
        timeout.tv_sec = min_time_until_expiration;
        timeout.tv_usec = 0;
        printf("WILL TIMEOUT IN %d seconds\n", min_time_until_expiration);

        temp_set = master_set;

        int activity = select(fd_max + 1, &temp_set, NULL, NULL, &timeout);
        if (activity < 0) {
            if (ctrl_c_ended) {
                printf("\nThe server was ended!\n");
            } else {
                perror("select");
                exit(EXIT_FAILURE); // TODO: Keep here?
            }
            break;
        } else if (activity == 0) {
            // Check if any timed-out
            printf("Timed out, checking if we need to remove some clients\n");
            check_timeout(&master_set, clilist_hashmap, cli_list);
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

                    printf("Accepted the request from the client with IP %s and fd %hd.\n",
                                inet_ntoa(client_addr.sin_addr), client_socketfd);
                    FD_SET(client_socketfd, &master_set); // Add to set
                    // update fd_max
                    fd_max = (client_socketfd > fd_max) ? client_socketfd : fd_max;
                    // add to hashmap and list
                    if (get_from_hashmap_client(clilist_hashmap, client_socketfd) == NULL) {
                        // add if the socketfd is not in the map
                        printf("Added client with fd %d to hashmap!\n", client_socketfd);
                        client_node *node = create_client_node(client_socketfd);
                        strncpy(node->IP_addr, inet_ntoa(client_addr.sin_addr), INET_ADDRSTRLEN);
                        insert_into_hashmap_client(clilist_hashmap, client_socketfd, node);
                        add_client(cli_list, node);
                    }
                } else {
                    printf("Request arriving from client with fd: %d!\n", i);
                    client_node *client = get_from_hashmap_client(clilist_hashmap, i);
                    if (client == NULL) {
                        // sanity check
                        printf("ERROR: client with IP %s, not in hashmap!\n", client->IP_addr);
                        exit(EXIT_FAILURE);
                    }
                    printf("A client with IP address %s and fd %d is sending a request!\n", client->IP_addr, i);
                    // Refresh its timeout time
                    client->last_activity = time(NULL);
                    // First read everything into a buffer
                    request_buffer = (char *) malloc(MAX_REQUEST_SIZE);
                    int nbytes = read(client->socketfd, request_buffer, MAX_REQUEST_SIZE);
                    if (nbytes <= 0) {
                        if (nbytes <= 0) {
                            printf("Connection closed by client %d!\n", client->socketfd);
                            close_client_connection(client, &master_set, cli_list, clilist_hashmap);

                        }
                        continue;
                    }
                    // handle request buffer
                    if (handle_request_buffer(request_buffer, nbytes, client) < 0) {
                        close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                    }
                    if (client->header_received) {
                        printf("Complete header received!\n");
                        printf("<>This is the header: \n%s\n", client->request_buffer);
                        if (handle_request(client, i, cache) < 0) {
                            close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                        }
                    } else {
                        printf("Partial header received!\n");
                        continue;
                    }
                }
            }
        };

        fd_max = find_max_fd(&master_set, fd_max);
        printf("\nThe size of the cache is: %d\n", cache->count);
        print_cache_nodes(cache);
    }
    close(master_socketfd);
    free_cache(cache);
    free_hashmap_client(clilist_hashmap);
    free_client_list(cli_list);
}
