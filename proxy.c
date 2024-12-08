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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "proxy.h"
#include "client_list.h"
#include "hashmap_proxy.h"

#define KB (1024)
#define MB (KB * KB)
#define MAX_RESPONSE_SIZE 1 * MB // 10 MB + 50 bytes for the Age:
#define MAX_HOSTNAME_SIZE 256
#define PORT_SIZE 6
#define DEFAULT_PORT 443
#define DEFAULT_MAX_AGE 300
#define MAX_CLIENTS 541 // Max number of clients

int master_socketfd; // master socket

// Global variable to control the infinite loop
volatile sig_atomic_t ctrl_c_ended = 0;

void handle_sigint(int sig) {
    close(master_socketfd);
    ctrl_c_ended = 1;
}

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_client_context() {
    const SSL_METHOD *method = TLS_client_method(); // Use the client method
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL client context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set minimum and maximum supported TLS protocol versions
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        perror("Failed to set minimum TLS version for client context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        perror("Failed to set maximum TLS version for client context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method(); // Use the server method
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL server context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the root certificate (used for signing dynamically generated certificates)
    if (SSL_CTX_use_certificate_file(ctx, "ca.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "ca.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

    // Set minimum and maximum supported TLS protocol versions
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        perror("Failed to set minimum TLS version for server context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        perror("Failed to set maximum TLS version for server context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to generate a domain-specific certificate
X509 *generate_certificate(char *hostname, EVP_PKEY *pkey, EVP_PKEY *ca_pkey, X509 *ca_cert) {
    if (!hostname || !pkey || !ca_pkey || !ca_cert) {
        fprintf(stderr, "[generate_certificate] Invalid parameters passed to generate_certificate.\n");
        return NULL;
    }

    // Create a new X509 certificate structure
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "[generate_certificate] Failed to create X509 certificate.\n");
        return NULL;
    }

    // Set the certificate version to v3
    X509_set_version(cert, 2);

    // Assign a unique serial number
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (!serial || !ASN1_INTEGER_set(serial, rand())) {
        fprintf(stderr, "[generate_certificate] Failed to set serial number.\n");
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        return NULL;
    }
    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);

    // Set the certificate's validity period
    long valid_days = 365;
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * valid_days);

    // Set the public key for the certificate
    X509_set_pubkey(cert, pkey);

    // Set the subject name of the certificate (using the provided hostname)
    X509_NAME *name = X509_get_subject_name(cert);
    if (!name || !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0)) {
        fprintf(stderr, "[generate_certificate] Failed to set subject name.\n");
        X509_free(cert);
        return NULL;
    }
    X509_set_subject_name(cert, name);

    // Set the issuer name (from the CA certificate)
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add Subject Alternative Name (SAN) extension
    char san_entry[256];
    snprintf(san_entry, sizeof(san_entry), "DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_entry);
    if (!ext || !X509_add_ext(cert, ext, -1)) {
        fprintf(stderr, "[generate_certificate] Failed to add SAN extension.\n");
        X509_EXTENSION_free(ext);
        X509_free(cert);
        return NULL;
    }
    X509_EXTENSION_free(ext);

    // Sign the certificate using the CA's private key
    if (!X509_sign(cert, ca_pkey, EVP_sha256())) {
        fprintf(stderr, "[generate_certificate] Failed to sign the certificate.\n");
        X509_free(cert);
        return NULL;
    }

    return cert;
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

server_node *create_server_node(int sockfd, int clientfd, SSL *client_ssl, SSL *ssl, char *hostname){
    server_node *node = (server_node *) malloc(sizeof(server_node));
    node->sockfd = sockfd;
    node->clientfd = clientfd;
    node->client_ssl = client_ssl;
    node->ssl = ssl;
    node->header_parsed = 0;
    node->content_length = 0;
    node->bytes_received = 0;
    node->chunked = 0;
    node->keep_alive = 1;
    strncpy(node->hostname, hostname, MAX_HOSTNAME_SIZE);

    return node;
}

int create_server_socket(int portno) {
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketfd < 0) {
        perror("socket");
    }

    // setsockopt: Handy debugging trick to avoid "Address alrd in use error"
    int optval = 1;
    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
        perror("ERROR in setsockopt with flag SO_REUSEADDR");
        close(socketfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in proxy_addr;
    memset((char *) &proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
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

// Debug SSL Info Callback fn
void SSL_info_callback(const SSL *ssl, int where, int ret) {
    const char *state = SSL_state_string_long(ssl);
    const char *where_str = (where & SSL_CB_LOOP) ? "LOOP" :
                            (where & SSL_CB_HANDSHAKE_START) ? "HANDSHAKE START" :
                            (where & SSL_CB_HANDSHAKE_DONE) ? "HANDSHAKE DONE" :
                            (where & SSL_CB_ALERT) ? "ALERT" :
                            (where & SSL_CB_EXIT) ? "EXIT" : "UNKNOWN";
    printf("[SSL INFO] State: %s, Event: %s, Ret: %d\n", state, where_str, ret);
}

int create_simple_client_socket(struct sockaddr_in server_addr, int portno, char *hostname) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 1) {
        perror("ERROR opening socket!");
        return -1;
    }
    server = gethostbyname(hostname);
    if (server == NULL) {
        return -1;
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

SSLConnection create_client_socket(struct sockaddr_in server_addr, int portno, char *hostname, SSL_CTX *client_ctx) {
    printf("[create_client_socket] Connecting to hostname: %s, port: %d\n", hostname, portno);

    SSLConnection connection = { .sockfd = -1, .ssl = NULL };
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[create_client_socket] ERROR opening socket!");
        return connection;
    }

    struct hostent *server = gethostbyname(hostname);
    if (!server) {
        fprintf(stderr, "[create_client_socket] ERROR: Hostname resolution failed for %s\n", hostname);
        perror("gethostbyname");
        close(sockfd);
        return connection;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(portno);

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("[create_client_socket] ERROR connecting to the server");
        close(sockfd);
        return connection;
    }
    printf("[create_client_socket] Connected to host with IP: %s\n", inet_ntoa(server_addr.sin_addr));

    // Wrap the socket with SSL
    SSL *ssl = SSL_new(client_ctx);
    if (!ssl) {
        fprintf(stderr, "[create_client_socket] ERROR creating SSL object.\n");
        perror("ssl_new");
        close(sockfd);
        return connection;
    }

    SSL_set_fd(ssl, sockfd);
    SSL_set_info_callback(ssl, SSL_info_callback);

    if (SSL_set_tlsext_host_name(ssl, hostname) != 1) {
        fprintf(stderr, "[create_client_socket] ERROR: Failed to set SNI.\n");
        perror("failed to set SNI");
        close(sockfd);
        SSL_free(ssl);
        return connection;
    }

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[create_client_socket] SSL connection failed.\n");
        perror("SSL connection failed");
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        return connection;
    }

    printf("[create_client_socket] SSL connection established.\n");

    // Extract and log server certificate details
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        if (line) {
            printf("[create_client_socket] Server certificate subject: %s\n", line);
            OPENSSL_free(line);
        } else {
            printf("[create_client_socket] Failed to retrieve subject name.\n");
        }
        X509_free(cert);
    } else {
        printf("[create_client_socket] No server certificate presented.\n");
    }

    connection.sockfd = sockfd;
    connection.ssl = ssl;
    return connection;
}

int handle_request_buffer(char *request_buffer, int buffer_size, client_node *client) {
    if (!request_buffer || !client) {
        fprintf(stderr, "[handle_request_buffer]: NULL request_buffer or client provided.\n");
        return -1;
    }

    size_t remaining_space = MAX_REQUEST_SIZE - client->bytes_received - 1;

    // Refresh client's timeout time
    client->last_activity = time(NULL);

    if (buffer_size > remaining_space) {
        fprintf(stderr, "[handle_request_buffer]: Request buffer overflow detected.\n");
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

    return 0; // Incomplete header
}

void close_client_connection(client_node *client, fd_set *master_set, client_list *cli_list,
                             hashmap_proxy *clilist_hashmap) {
    if (!client) {
        fprintf(stderr, "[close_client_connection] Attempted to close a NULL client connection.\n");
        return;
    }

    int socketToClean = client->socketfd;
    printf("[close_client_connection] Closing connection for client FD %d.\n", socketToClean);

    // Clean up SSL resources if they exist
    if (client->ssl) {
        printf("[close_client_connection] Shutting down SSL for client FD %d.\n", socketToClean);
        // int shutdown_status = SSL_shutdown(client->ssl); // Attempt to close SSL connection gracefully
        // if (shutdown_status == 0) {
        //     printf("[close_client_connection] SSL shutdown incomplete for client FD %d. Retrying.\n", socketToClean);
        //     SSL_shutdown(client->ssl); // Retry shutdown if needed
        // }
        SSL_free(client->ssl); // Free the SSL object
        client->ssl = NULL; // Ensure no dangling pointer
        printf("[close_client_connection] Cleaned up SSL resources for client FD %d.\n", socketToClean);
    }

    // Close the socket if it's valid
    if (client->socketfd >= 0) {
        printf("[close_client_connection] Closing socket FD %d.\n", socketToClean);
        if (close(client->socketfd) < 0) {
            perror("[close_client_connection] Error closing socket");
        }
        FD_CLR(client->socketfd, master_set); // Remove from the master set
        printf("[close_client_connection] Closed socket FD %d.\n", socketToClean);
    }

    // Remove the client from the hashmap
    if (clilist_hashmap) {
        printf("[close_client_connection] Removing client FD %d from hashmap.\n", socketToClean);
        remove_from_hashmap_proxy(clilist_hashmap, client->socketfd);
        printf("[close_client_connection] Client FD %d removed from hashmap.\n", socketToClean);
    }

    // Remove the client from the list
    if (cli_list && client) {
        printf("[close_client_connection] Removing client FD %d from the list.\n", socketToClean);
        remove_client(cli_list, client);
        printf("[close_client_connection] Client FD %d removed from the list.\n", socketToClean);
    }

    printf("[close_client_connection] Successfully closed and cleaned up client FD %d.\n", socketToClean);
}

void check_timeout(fd_set *master_set, hashmap_proxy *hashmap, client_list *cli_list) {
    if (!cli_list || !cli_list->head || !cli_list->tail) {
        fprintf(stderr, "check_timeout: Invalid client list.\n");
        return;
    }

    client_node *current = cli_list->head->next;
    while (current != NULL && current != cli_list->tail) {
        time_t elapsed_time = time(NULL) - current->last_activity;

        printf("Checking client with IP %s and fd %d. Last activity: %ld seconds ago.\n",
               current->IP_addr, current->socketfd, elapsed_time);

        // If client has timed out
        if (elapsed_time >= DEFAULT_TIMEOUT) {
            printf("Client with IP %s and fd %d has timed out. Closing connection.\n",
                   current->IP_addr, current->socketfd);

            close_client_connection(current, master_set, cli_list, hashmap);

            // we remove the client from the list, so reset current
            current = cli_list->head->next;
        } else {
            current = current->next;
        }
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

int handle_connect_request(client_node *client, SSL_CTX *server_ctx, X509 *ca_cert, EVP_PKEY *ca_pkey, const char *request_buffer) {
    if (!client) {
        fprintf(stderr, "[handle_connect_request] Null client node provided.\n");
        return -1;
    }

    if (client->ssl) {
        fprintf(stderr, "[handle_connect_request] Cleaning up existing SSL connection for FD %d.\n", client->socketfd);
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }

    char hostname[MAX_HOSTNAME_SIZE], port[PORT_SIZE];
    if (get_hostname_and_port(request_buffer, hostname, sizeof(hostname), port, sizeof(port)) < 0) {
        fprintf(stderr, "[handle_connect_request] Failed to parse CONNECT request.\n");
        return -1;
    }

    printf("[handle_connect_request] CONNECT request received for hostname: %s, port: %s\n", hostname, port);

    // Send back "200 Connection established" response
    const char *response = "HTTP/1.1 200 Connection established\r\n\r\n";
    if (write(client->socketfd, response, strlen(response)) <= 0) {
        perror("[handle_connect_request] Failed to send connection established response.");
        return -1;
    }
    printf("[handle_connect_request] Sent '200 Connection established' to client.\n");

    if (!ca_cert) {
        fprintf(stderr, "[handle_connect_request] CA certificate is NULL. Cannot generate domain-specific certificate.\n");
        return -1;
    }

    printf("Generating domain CA.\n");
    // Dynamically generate domain-specific certificate and key using EVP_PKEY_CTX
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "[handle_connect_request] Failed to generate RSA key using EVP_PKEY.\n");
        if (ctx) EVP_PKEY_CTX_free(ctx);
        if (pkey) EVP_PKEY_free(pkey);
        return -1;
    }

    // Free the context after key generation
    printf("Freeing SSL Context.\n");
    EVP_PKEY_CTX_free(ctx);

    printf("Generating CA Certificate.\n");
    X509 *cert = generate_certificate(hostname, pkey, ca_pkey, ca_cert);
    if (!cert || !pkey) {
        fprintf(stderr, "[handle_connect_request] Failed to generate domain-specific certificate for %s.\n", hostname);
        return -1;
    }

    // Create new SSL session for the client
    printf("Doing an SSL NEW with server context.\n");
    client->ssl = SSL_new(server_ctx);
    if (!client->ssl) {
        perror("[handle_connect_request] Failed to create SSL session for client.");
        return -1;
    }

    // Set dynamically generated certificate and key for this SSL session
    if (SSL_use_certificate(client->ssl, cert) <= 0 || SSL_use_PrivateKey(client->ssl, pkey) <= 0) {
        fprintf(stderr, "[handle_connect_request] Failed to set certificate/key for SSL session.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_set_fd(client->ssl, client->socketfd);


    // Debug logs for SSL handshake
    SSL_set_info_callback(client->ssl, SSL_info_callback);

    // Perform SSL handshake with the client
    printf("Doing an SSL Handshake with the client.\n");
    int ret = SSL_accept(client->ssl);
    if (ret <= 0) {
        int err = SSL_get_error(client->ssl, ret);
        fprintf(stderr, "[handle_connect_request] SSL_accept() failed with error: %d\n", err);
        ERR_print_errors_fp(stderr);
        SSL_free(client->ssl);
        client->ssl = NULL;
        return -1;
    }

    printf("[handle_connect_request] SSL handshake completed with client.\n");

    return 0;
}

ssize_t read_from_socket_simple(int socketfd, char *buffer, ssize_t buffer_size, int request) {
    ssize_t bytes_read = 0;
    ssize_t total_bytes = 0;
    ssize_t content_length = -1;
    char *end_header;
    // Read the data from the socket in chunks
    int header_received = 0;
    while ((bytes_read = read(socketfd, buffer + total_bytes, buffer_size - total_bytes - 1)) > 0 && (!ctrl_c_ended)) {
        total_bytes += bytes_read;
        printf("Bytes read so far: %zd\n", total_bytes);
        printf("Buffer size: %zd, bytes read: %zd\n", buffer_size, bytes_read);
        printf("buffer_size - total_bytes - 1: %zd\n", buffer_size - total_bytes - 1);
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

int handle_non_ssl_request(char *request_buffer, int client_socketfd, hashmap_proxy *server_hashmap, fd_set *master_set, int fd_max) {
    char hostname[MAX_HOSTNAME_SIZE];
    char port[PORT_SIZE];
    get_hostname_and_port(request_buffer, hostname, MAX_HOSTNAME_SIZE, port, PORT_SIZE);

    // if no port specified set it to 80
    int request_portno = (strlen(port) != 0) ? atoi(port) : DEFAULT_PORT;

    struct sockaddr_in server_addr;
    int server_socketfd = create_simple_client_socket(server_addr, request_portno, hostname);

    printf("CREATED SOCKET WITH FD: %d\n", server_socketfd);

    if (server_socketfd == -1) {
        perror("ERROR openening the socket!");
        return -1;
    }

    printf("This is the request buffer: %s\n", request_buffer);

    // forward request to the server
    int n = write(server_socketfd, request_buffer, strlen(request_buffer));
    if (n < 0) {
        perror("ERROR writing to the server");
        return -1;
    }
    printf("Request forwarded to the server!\n");

    char *response_buffer = (char *) malloc(MAX_RESPONSE_SIZE); // Allocate 10MB
    // read response from the server
    int response_size = read_from_socket_simple(server_socketfd, response_buffer, MAX_RESPONSE_SIZE, 0);
    if (response_size < 0) {
        close(server_socketfd);
        return -1;
    }

    printf("THIS IS THE HTTP RESPONSE: %s\n", response_buffer);

    // close connection with the server
    close(server_socketfd);
    // forward response to the client
    n = write(client_socketfd, response_buffer, response_size);
    if (n < 0) {
        perror("ERROR writing to socket");
        return -1;
    }
    printf("WROTE HTTP RESPONSE TO CLIENT!\n");
    return 0;

    // server_node *server = create_server_node(server_socketfd, client_socketfd, NULL, NULL);

    // if (insert_into_hashmap_proxy(server_hashmap, server_socketfd, server) < 0) {
    //     fprintf(stderr, "ERROR inserting server node into hashmap.\n");
    //     printf("[handle_non_ssl] CLOSING SERVERSOCKFD!\n");
    //     close(server_socketfd);
    //     return -1;
    // }
    // printf("Created server node (HTTP) successfully!\n");
    // FD_SET(server_socketfd, master_set);
    // printf("Added server sockfd %d to master set.\n", server_socketfd);
    // return (server_socketfd > fd_max) ? server_socketfd : fd_max;
}

int parse_http_headers(const char *response, size_t response_size, server_node *server) {
    char *headers_end = strstr(response, "\r\n\r\n");
    if (!headers_end) {
        return -1;
    }

    // Extract headers
    size_t headers_length = headers_end - response + 4;
    char *headers = strndup(response, headers_length);

    // Look for Content-Length
    char *content_length_str = strstr(headers, "\nContent-Length:");
    if (!content_length_str) {
        printf("Did not find Cotent-Lenght!!!!\n");
        content_length_str = strstr(headers, "\ncontent-length");
    }
    if (content_length_str) {
        printf("Content length available\n");
        content_length_str += strlen("Content-Length: "); // Move past the header name
        server->content_length = atoi(content_length_str);
    } else {
        printf("Did not find content-length: \n");
    }

    // Check for transfer encoding
    char *transfer_encoding = strstr(headers, "Transfer-Encoding: chunked");
    if (!transfer_encoding) {
        transfer_encoding = strstr(headers, "transfer-encoding: chunked");
    }
    if (transfer_encoding) {
        server->chunked = 1;
        printf("[read_from_server] Transfer-Encoding: chunked detected.\n");
    }

    // Check for Connection header
    if (strstr(headers, "Connection: keep-alive")) {
        server->keep_alive = 1;
    } else if (strstr(headers, "Connection: close") || strstr(headers, "connection: close")) {
        server->keep_alive = 0;
    }

    free(headers);
    return 0;
}

int start_proxy(int portno) {
    printf("[start_proxy] Proxy started!\n");

    // Initialize OpenSSL
    initialize_openssl();

    // Create SSL contexts
    SSL_CTX *ssl_ctx = create_server_context(); // Server-side context
    SSL_CTX *client_ctx = create_client_context(); // Client-side context
    if (!ssl_ctx || !client_ctx) {
        fprintf(stderr, "Failed to create SSL contexts.\n");
        cleanup_openssl();
        return -1;
    }

    printf("[start_proxy] SSL contexts created successfully.\n");

    // Create and bind the master socket
    master_socketfd = create_server_socket(portno);
    if (listen(master_socketfd, 5) == -1) {
        perror("listen");
        SSL_CTX_free(ssl_ctx);
        SSL_CTX_free(client_ctx);
        cleanup_openssl();
        return -1;
    }
    printf("[start_proxy] Server socket created and listening on port %d.\n", portno);

    // Initialize data structures
    struct sockaddr_in client_addr;
    socklen_t client_len;
    fd_set master_set, temp_set;
    FD_ZERO(&master_set);
    FD_ZERO(&temp_set);
    FD_SET(master_socketfd, &master_set);
    int fd_max = master_socketfd;

    client_list *cli_list = create_client_list();
    hashmap_proxy *clilist_hashmap = create_hashmap_proxy(MAX_CLIENTS);
    hashmap_proxy *server_hashmap = create_hashmap_proxy(MAX_CLIENTS); // Hahsmap to keep track of servers

    signal(SIGINT, handle_sigint); // Handle Ctrl+C

    FILE *ca_cert_file = fopen("ca.crt", "r");
    if (!ca_cert_file) {
        fprintf(stderr, "[start_proxy] Failed to open ca.crt.\n");
        SSL_CTX_free(ssl_ctx);
        SSL_CTX_free(client_ctx);
        cleanup_openssl();
        return -1;
    }
    X509 *ca_cert = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if (!ca_cert) {
        fprintf(stderr, "[start_proxy] Failed to load CA certificate.\n");
        SSL_CTX_free(ssl_ctx);
        SSL_CTX_free(client_ctx);
        cleanup_openssl();
        return -1;
    }

    FILE *ca_key_file = fopen("ca.key", "r");
    if (!ca_key_file) {
        fprintf(stderr, "[start_proxy] Failed to open CA private key file.\n");
        SSL_CTX_free(ssl_ctx);
        SSL_CTX_free(client_ctx);
        cleanup_openssl();
        return -1;
    }

    EVP_PKEY *ca_pkey = PEM_read_PrivateKey(ca_key_file, NULL, NULL, NULL);
    fclose(ca_key_file);
    if (!ca_pkey) {
        fprintf(stderr, "[start_proxy] Failed to read CA private key.\n");
        SSL_CTX_free(ssl_ctx);
        SSL_CTX_free(client_ctx);
        cleanup_openssl();
        return -1;
    }

    while (1) {
        // Timeout calculations for select
        time_t min_time_until_expiration = get_min_time(cli_list);
        struct timeval timeout = { .tv_sec = min_time_until_expiration, .tv_usec = 0 };

        temp_set = master_set;
        printf("These are present in master_set: \n");
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &master_set)) {
                printf("%d\n", i);
            }
        }
        int activity = select(fd_max + 1, &temp_set, NULL, NULL, &timeout);
        if (activity < 0) {
            if (ctrl_c_ended) {
                printf("[start_proxy] \nProxy server shut down.\n");
                break;
            }
            perror("select");
            printf("Error with select, exiting!\n");
            exit(EXIT_FAILURE);
        } else if (activity == 0) {
            printf("[start_proxy] Timeout reached, checking for expired clients.\n");
            check_timeout(&master_set, clilist_hashmap, cli_list);
            continue;
        }

        // Handle incoming activity
        for (int i = 0; i <= fd_max; i++) {
            if (!FD_ISSET(i, &temp_set)) continue;
            if (i == master_socketfd) {
                // Acept new connections
                client_len = sizeof(client_addr);
                int client_socketfd = accept(master_socketfd, (struct sockaddr *)&client_addr, &client_len);
                if (client_socketfd < 0) {
                    perror("accept");
                    continue;
                }

                printf("[start_proxy] Accepted connection from %s, fd: %d.\n", inet_ntoa(client_addr.sin_addr), client_socketfd);

                // Add to client tracking structures
                FD_SET(client_socketfd, &master_set);
                fd_max = (client_socketfd > fd_max) ? client_socketfd : fd_max;

                if (get_from_hashmap_proxy(clilist_hashmap, client_socketfd) == NULL) {
                    printf("[start_proxy] New client detected: Socket FD %d, IP: %s\n",
                        client_socketfd, inet_ntoa(client_addr.sin_addr));

                    // Create and initialize a new client node
                    client_node *node = create_client_node(client_socketfd);
                    strncpy(node->IP_addr, inet_ntoa(client_addr.sin_addr), INET_ADDRSTRLEN);

                    // Add the new client node to the hashmap and client list
                    insert_into_hashmap_proxy(clilist_hashmap, client_socketfd, node);
                    add_client(cli_list, node);
                    printf("[start_proxy] New client added to hashmap and list: Socket FD %d\n", client_socketfd);
                } else {
                    printf("[start_proxy] Existing client found: Socket FD %d\n", client_socketfd);
                }
            } else {
                /**** Handle client connection ****/
                if (in_hashmap_proxy(clilist_hashmap, i)) {
                    printf("HANDLING A CLIENT CONNECTION FD: %d!\n", i);
                    client_node *client = get_from_hashmap_proxy(clilist_hashmap, i);
                    if (client == NULL) {
                        fprintf(stderr, "Client with fd %d not found in hashmap.\n", i);
                        printf("Client not found in hashmap, EXITING!\n");
                        exit(EXIT_FAILURE);
                    }

                    printf("[start_proxy] Processing request from client %s, fd: %d.\n", client->IP_addr, i);

                    char *request_buffer = (char *)malloc(MAX_REQUEST_SIZE);
                    if (!request_buffer) {
                        perror("Error allocating request buffer.");
                        close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                        continue;
                    }

                    if (!client->ssl) {
                        int read_bytes = read(client->socketfd, request_buffer, MAX_REQUEST_SIZE - 1);
                        if (read_bytes <= 0) {
                            if (read_bytes < 0) {
                                perror("[start_proxy] read");
                            }
                            
                            close(client->socketfd);
                            FD_CLR(client->socketfd, &master_set);

                            // Remove the client from the hashmap
                            if (clilist_hashmap) {
                                printf("[close_client_connection] Removing client FD %d from hashmap.\n", i);
                                remove_from_hashmap_proxy(clilist_hashmap, client->socketfd);
                                printf("[close_client_connection] Client FD %d removed from hashmap.\n", i);
                            }

                            // Remove the client from the list
                            if (cli_list && client) {
                                printf("[close_client_connection] Removing client FD %d from the list.\n", i);
                                remove_client(cli_list, client);
                                printf("[close_client_connection] Client FD %d removed from the list.\n", i);
                            }
                        } else if (read_bytes > 0) {
                            printf("[start_proxy] Non-SSL Request Buffer: %.*s\n", read_bytes, request_buffer);
                            // Ensure null-termination of the buffer
                            request_buffer[read_bytes] = '\0';

                            // Find the end of the HTTP header (\r\n\r\n)
                            char *header_end = strstr(request_buffer, "\r\n\r\n");
                            if (header_end) {
                                size_t header_length = header_end - request_buffer + 4; // Include \r\n\r\n
                                if (header_length > MAX_REQUEST_SIZE) {
                                    fprintf(stderr, "[start_proxy] Header exceeds maximum size.\n");
                                    close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                                    free(request_buffer);
                                    continue;
                                }

                                // Temporarily null-terminate the header for safe processing
                                char saved_char = request_buffer[header_length];
                                request_buffer[header_length] = '\0';

                                // Check if "CONNECT" is within the header
                                if (strstr(request_buffer, "CONNECT") != NULL) {
                                    // Handle CONNECT request and perform SSL handshake
                                    printf("[start_proxy] Client establishing an SSL connection...\n");
                                    if (handle_connect_request(client, ssl_ctx, ca_cert, ca_pkey, request_buffer) < 0) {
                                        perror("[start_proxy] Failed to handle CONNECT request from client.\n");
                                        close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                                    }
                                } else {
                                    // Handle other types of HTTP requests (e.g., non-SSL)
                                    // printf("HANDLING NON SSL REQUEST!\n");
                                    // int res = handle_non_ssl_request(request_buffer, i, server_hashmap, &master_set, fd_max);
                                    // if (res < 0) {
                                    //     printf("ERROR with handle_non_ssl_request");
                                    //     exit(EXIT_FAILURE);
                                    // } else {
                                    //     fd_max = res;
                                    // }
                                    FD_CLR(i, &master_set);
                                    continue; // Ignore non-SSL requests for now
                                }

                                // Restore the buffer
                                request_buffer[header_length] = saved_char;
                            } else {
                                fprintf(stderr, "[start_proxy] Malformed request: Missing header delimiter.\n");
                                close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                            }
                        }
                        free(request_buffer);
                        continue;
                    }

                    printf("[start_proxy] Client already established a secure connection.\n");
                    // Read request
                    int nbytes = SSL_read(client->ssl, request_buffer, MAX_REQUEST_SIZE-1);
                    if (nbytes <= 0) {
                        int ssl_error = SSL_get_error(client->ssl, nbytes);
                        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                            printf("[start_proxy] Client %d closed SSL connection.\n", client->socketfd);
                        } else {
                            perror("ERROR SSL read");
                            fprintf(stderr, "[start_proxy] SSL read error for client %d: %d.\n", client->socketfd, ssl_error);
                            ERR_print_errors_fp(stderr);
                        }
                        free(request_buffer);
                        close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                        continue;
                    }

                    // Process the request buffer
                    if (handle_request_buffer(request_buffer, nbytes, client) < 0) {
                        free(request_buffer);
                        close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                        continue;
                    }

                    if (client->header_received) {
                        printf("[start_proxy] Complete header received from client %s.\n", client->IP_addr);
                        printf("<><><> This is the header <><><> \n%s\n", client->request_buffer);
                        int is_get_request = 1;

                        char hostname[MAX_HOSTNAME_SIZE];
                        char port[PORT_SIZE];
                        if (get_hostname_and_port(client->request_buffer, hostname, MAX_HOSTNAME_SIZE, port, PORT_SIZE) == -1) {
                            printf("[handle_request] INVALID HTTP, removing client\n");
                            close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                            continue;
                        }

                        // if no port specified set it to 80
                        int request_portno = (strlen(port) != 0) ? atoi(port) : DEFAULT_PORT;

                        /***************  Proxy acts as a CLIENT ***************/
                        struct sockaddr_in server_addr;
                        SSLConnection server_connection = create_client_socket(server_addr, request_portno, hostname, client_ctx);

                        if (server_connection.sockfd == -1 || !server_connection.ssl) {
                            printf("[handle_request] Could not request from server on socket %d\n", i);
                            perror("ERROR connecting to the server");
                            close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                            continue;
                        }

                        // Forward request to server
                        if (SSL_write(server_connection.ssl, client->request_buffer, strlen(client->request_buffer)) <= 0) {
                            fprintf(stderr, "ERROR writing to the server.\n");
                            printf("<> CLOSIGN SERVERSOCKFD!\n");
                            ERR_print_errors_fp(stderr);
                            close(server_connection.sockfd);
                            SSL_free(server_connection.ssl);
                            close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                            continue;
                        }

                        printf("Request forwarded to the server!\n");

                        // create server node
                        server_node *server = create_server_node(server_connection.sockfd, i, client->ssl, server_connection.ssl, hostname);
                        // add server to hashmap
                        if (insert_into_hashmap_proxy(server_hashmap, server_connection.sockfd, server) < 0) {
                            fprintf(stderr, "ERROR inserting server node into hashmap.\n");
                            printf(">< CLOSIGN SERVERSOCKFD!\n");
                            close(server_connection.sockfd);
                            SSL_free(server_connection.ssl);
                            close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                            continue;
                        }
                        printf("Created server node successfully!\n");
                        FD_SET(server->sockfd, &master_set);
                        fd_max = (server->sockfd > fd_max) ? server->sockfd : fd_max;
                        printf("Added server sockfd %d to master set.\n", server->sockfd);

                        // reset the partial request buffer from client
                        memset(client->request_buffer, 0, MAX_REQUEST_SIZE);
                        client->bytes_received = 0;
                        client->header_received = 0;
                        memset(client->request_url, 0, MAX_URL_LENGTH);
                    }

                } else if (in_hashmap_proxy(server_hashmap, i)) {
                    /**** Handle server connection ****/
                    printf("HANDLING A SERVER CONNECTION FD %d!\n", i);
                    server_node *server = get_from_hashmap_proxy(server_hashmap, i);
                    printf("Got server with hostname %s and fd %d from hashmap!\n", server->hostname, i);
                    char *response_buffer = (char *) malloc(MAX_RESPONSE_SIZE); // Allocate 1MB
                    printf("Allocated response buffer!\n");
                    size_t response_size = 0;

                    printf("INFO ABOUT SERVER WITH FD %d\n", i);
                    printf("SOCKFD: %d\n", server->sockfd);
                    printf("CLIENT_SOCKFD: %d\n", server->clientfd);
                    if (server->ssl) {
                        printf("SERVER->SSL IS NOT NULL!\n");
                    }

                    if (server->ssl) {
                        printf("[start_proxy] Reading an HTTPS request from server!\n");
                        response_size = SSL_read(server->ssl, response_buffer, MAX_RESPONSE_SIZE);
                        printf("Read %zd bytes from server!\n", response_size);

                        printf("[start_proxy] Response size: %zd\n", response_size);
                        if (response_size <= 0 || response_size == -1) {
                            printf("SSL FREEING SOCKET FD %d!\n", server->sockfd);
                            SSL_free(server->ssl);
                            printf("CLOSING SERVERSOCKET FD %d!\n", server->sockfd);
                            close(server->sockfd);
                            remove_from_hashmap_proxy(server_hashmap, server->sockfd);
                            free(response_buffer);
                            FD_CLR(i, &master_set);
                            continue;
                        }

                        // Forward response to client
                        printf("[start_proxy] Forwarding response to client...\n");
                        int res = SSL_write(server->client_ssl, response_buffer, response_size);
                        if (res <= 0) {
                            if (res < 0) {
                                printf("[start_proxy] Issue doing SSL_write to client_ssl...\n");
                                fprintf(stderr, "ERROR writing response to client.\n");
                                perror("ERROR writing  to client");
                                client_node *client = get_from_hashmap_proxy(clilist_hashmap, server->clientfd);
                                close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                            }
                            
                            ERR_print_errors_fp(stderr);
                            SSL_free(server->ssl);
                            printf("CLOSING SERVERSOCKET FD %d!\n", server->sockfd);
                            close(server->sockfd);
                            remove_from_hashmap_proxy(server_hashmap, server->sockfd);
                            free(response_buffer);
                            FD_CLR(i, &master_set);
                            
                            continue;
                        }

                        if (!server->header_parsed) {
                            if (parse_http_headers(response_buffer, response_size, server) == 0) {
                                server->header_parsed = 1;
                                printf("Header parsed! Content-Length: %zu, Chunked: %d, Alive: %d\n",
                                    server->content_length, server->chunked, server->keep_alive);
                            } else {
                                free(response_buffer);
                                continue;
                            }
                        }

                        if (server->chunked) {
                            // TODO: CLOSE WHEN LAST CHUNKED RECEIVED!
                        } else if (!server->keep_alive && server->content_length > 0) {
                            server->bytes_received += response_size;
                            if (server->bytes_received >= server->content_length) {
                                printf("Full response received (Content-Length matched).\n");
                                close(server->sockfd);
                                if (server->ssl) {
                                    printf("ABOUT TO FREE SSL!\n");
                                    SSL_free(server->ssl);
                                    printf("FREED SSL server!\n");
                                }
                                remove_from_hashmap_proxy(server_hashmap, server->sockfd);
                                printf("REMOVED SERVER FROM HASHMAP\n");
                                FD_CLR(server->sockfd, &master_set);
                            }
                        }
                        else {
                            printf("Neither content length nor transfer-encoding found!\n");
                            printf("----------------------------------");
                            printf("Header: \n%s\n", response_buffer);
                            printf("----------------------------------");
                            // printf("Closing server socket!\n");
                            // close(server->sockfd);
                            // if (server->ssl) {
                            //     SSL_free(server->ssl);
                            // }
                            // remove_from_hashmap_proxy(server_hashmap, server->sockfd);
                            // FD_CLR(server->sockfd, &master_set);
                        }

                    }

                    free(response_buffer);  // Free the allocated buffer after use

                } else {
                    printf("SANITY CHECK: Should never reach here!\n");
                    return -1;
                }
            }
        }
        fd_max = find_max_fd(&master_set, fd_max);
    }

    // Cleanup resources
    close(master_socketfd);
    SSL_CTX_free(ssl_ctx);
    SSL_CTX_free(client_ctx);
    cleanup_openssl();
    free_hashmap_proxy(clilist_hashmap);
    free_hashmap_proxy(server_hashmap);
    free_client_list(cli_list);

    return 0;
}
