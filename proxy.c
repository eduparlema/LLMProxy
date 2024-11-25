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
#include "cache.h"
#include "client_list.h"
#include "hashmap_client.h"

#define KB (1024)
#define MB (KB * KB)
#define MAX_RESPONSE_SIZE (20 * MB) + 50 // 10 MB + 50 bytes for the Age:
#define MAX_HOSTNAME_SIZE 256
#define PORT_SIZE 6
#define DEFAULT_PORT 443
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
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL)); // Use current timestamp for serial number

    // Set the certificate's validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year validity

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
    X509_EXTENSION *ext = NULL;
    STACK_OF(GENERAL_NAME) *san_names = sk_GENERAL_NAME_new_null();
    if (!san_names) {
        fprintf(stderr, "[generate_certificate] Failed to allocate SAN names.\n");
        X509_free(cert);
        return NULL;
    }

    GENERAL_NAME *san_name = GENERAL_NAME_new();
    if (san_name) {
        // Set the SAN type to DNS name
        ASN1_IA5STRING *ia5_hostname = ASN1_IA5STRING_new();
        if (ia5_hostname) {
            ASN1_STRING_set(ia5_hostname, hostname, strlen(hostname));
            GENERAL_NAME_set0_value(san_name, GEN_DNS, ia5_hostname);
            sk_GENERAL_NAME_push(san_names, san_name);
        } else {
            fprintf(stderr, "[generate_certificate] Failed to allocate ASN1_IA5STRING for hostname.\n");
            GENERAL_NAME_free(san_name);
            sk_GENERAL_NAME_free(san_names);
            X509_free(cert);
            return NULL;
        }
    } else {
        fprintf(stderr, "[generate_certificate] Failed to allocate GENERAL_NAME.\n");
        sk_GENERAL_NAME_free(san_names);
        X509_free(cert);
        return NULL;
    }

    // Create the SAN extension
    ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, san_names);
    if (!ext || !X509_add_ext(cert, ext, -1)) {
        fprintf(stderr, "[generate_certificate] Failed to add SAN extension.\n");
        X509_EXTENSION_free(ext);
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
        X509_free(cert);
        return NULL;
    }

    // Cleanup
    X509_EXTENSION_free(ext);
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    // Sign the certificate using the CA's private key
    if (!X509_sign(cert, ca_pkey, EVP_sha256())) {
        fprintf(stderr, "[generate_certificate] Failed to sign the certificate.\n");
        X509_free(cert);
        return NULL;
    }

    return cert;
}

void close_ssl_connection(SSL *ssl, int socketfd) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(socketfd);
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
        close(sockfd);
        return connection;
    }

    SSL_set_fd(ssl, sockfd);
    SSL_set_info_callback(ssl, SSL_info_callback);

    if (SSL_set_tlsext_host_name(ssl, hostname) != 1) {
        fprintf(stderr, "[create_client_socket] ERROR: Failed to set SNI.\n");
        close(sockfd);
        SSL_free(ssl);
        return connection;
    }

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[create_client_socket] SSL connection failed.\n");
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
                             hashmap_client *clilist_hashmap) {
    if (!client) {
        fprintf(stderr, "[close_client_connection] Attempted to close a NULL client connection.\n");
        return;
    }

    int socketToClean = client->socketfd;
    printf("[close_client_connection] Closing connection for client FD %d.\n", socketToClean);

    // Clean up SSL resources if they exist
    if (client->ssl) {
        printf("[close_client_connection] Shutting down SSL for client FD %d.\n", socketToClean);
        int shutdown_status = SSL_shutdown(client->ssl); // Attempt to close SSL connection gracefully
        if (shutdown_status == 0) {
            printf("[close_client_connection] SSL shutdown incomplete for client FD %d. Retrying.\n", socketToClean);
            SSL_shutdown(client->ssl); // Retry shutdown if needed
        }
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
        if (FD_ISSET(client->socketfd, master_set)) {
            FD_CLR(client->socketfd, master_set); // Remove from the master set
        }
        printf("[close_client_connection] Closed socket FD %d.\n", socketToClean);
    }

    // Remove the client from the hashmap
    if (clilist_hashmap) {
        printf("[close_client_connection] Removing client FD %d from hashmap.\n", socketToClean);
        remove_from_hashmap_client(clilist_hashmap, client->socketfd);
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


void check_timeout(fd_set *master_set, hashmap_client *hashmap, client_list *cli_list) {
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

ssize_t read_from_server(SSL *ssl, char *buffer, ssize_t buffer_size) {
    ssize_t bytes_read = 0;
    ssize_t total_bytes = 0;
    ssize_t content_length = -1;
    char *end_header = NULL;
    int header_received = 0; // Flag to track if HTTP headers have been fully received
    int is_chunked = 0;      // Flag to indicate chunked transfer encoding

    while ((bytes_read = SSL_read(ssl, buffer + total_bytes, buffer_size - total_bytes - 1)) > 0) {
        if (bytes_read > 0) {
            total_bytes += bytes_read;
            buffer[total_bytes] = '\0'; // Null terminate the buffer for header parsing

            printf("[read_from_server] Bytes read so far: %zd\n", total_bytes);

            if (!header_received) {
                end_header = strstr(buffer, "\r\n\r\n"); // Check for end of HTTP headers
                if (end_header) {
                    header_received = 1;

                    // Log the complete header
                    printf("\n--- Response Header ---\n");
                    fwrite(buffer, sizeof(char), end_header - buffer, stdout);
                    printf("\n-----------------------\n");

                    // Extract `Content-Length` header (case-insensitive)
                    char *content_length_str = strstr(buffer, "\ncontent-length: ");
                    if (!content_length_str) {
                        content_length_str = strstr(buffer, "\nContent-Length: ");
                    }

                    if (content_length_str) {
                        content_length_str += strlen("Content-Length: "); // Move past the header name
                        content_length = atoi(content_length_str); // Parse content length
                        printf("[read_from_server] Content-Length: %zd\n", content_length);
                    } else {
                        printf("[read_from_server] Content-Length header not found.\n");
                    }


                    // Check for `Transfer-Encoding: chunked`
                    char *transfer_encoding = strstr(buffer, "Transfer-Encoding: chunked");
                    if (!transfer_encoding) {
                        transfer_encoding = strstr(buffer, "transfer-encoding: chunked");
                    }
                    if (transfer_encoding) {
                        is_chunked = 1;
                        printf("[read_from_server] Transfer-Encoding: chunked detected.\n");
                    }
                }
            }

            if (header_received) {
                if (is_chunked) {
                    // Handle chunked transfer encoding
                    ssize_t body_offset = end_header - buffer + 4;
                    char *chunk_start = buffer + body_offset;
                    while (1) {
                        char *chunk_size_str = strstr(chunk_start, "\r\n");
                        if (!chunk_size_str) break;

                        // Parse the chunk size
                        ssize_t chunk_size = strtol(chunk_start, NULL, 16);
                        if (chunk_size == 0) {
                            printf("[read_from_server] Final chunk received.\n");
                            break; // Last chunk
                        }

                        chunk_start = chunk_size_str + 2 + chunk_size + 2; // Move past chunk data and CRLF
                        total_bytes += chunk_size;

                        if (chunk_start >= buffer + total_bytes) {
                            break; // Exit if buffer is exhausted
                        }
                    }
                    break;
                } else if (content_length != -1 &&
                           total_bytes >= (content_length + (end_header - buffer + 4))) {
                    printf("[read_from_server] Full response received.\n");
                    break;
                } else if (content_length == -1 && !is_chunked) {
                    // TODO: Make more robust in the future
                    break;
                }
            }
        } else if (bytes_read == 0) {
            // Connection closed by the server
            printf("[read_from_server] Server closed the connection.\n");
            break;
        } else {
            // SSL error handling
            int ssl_error = SSL_get_error(ssl, bytes_read);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue; // Retry reading or writing
            } else {
                fprintf(stderr, "[read_from_server] SSL read error: %d\n", ssl_error);
                ERR_print_errors_fp(stderr);
                return -1; // Return error
            }
        }
    }

    // Print the body of the response if available
    if (header_received && content_length != -1) {
        printf("\n--- Response Body ---\n");

        if (total_bytes > content_length) {
            printf("[read_from_server] Response body:\n");
            fwrite(buffer + (end_header - buffer + 4), sizeof(char), content_length, stdout);
            printf("\n...\n");
        }
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

int handle_request(client_node *client, int client_socketfd, cache *cache, SSL_CTX *client_ctx) {
    int is_get_request = 1;

    char hostname[MAX_HOSTNAME_SIZE];
    char port[PORT_SIZE];
    if (get_hostname_and_port(client->request_buffer, hostname, MAX_HOSTNAME_SIZE, port, PORT_SIZE) == -1) {
        printf("[handle_request] INVALID HTTP, removing client\n");
        return -1;
    }

    // if no port specified set it to 80
    int request_portno = (strlen(port) != 0) ? atoi(port) : DEFAULT_PORT;


    printf("[handle_request] <><> REQUEST BUFFER IN CLIENT: \n%s\nEND\n", client->request_buffer);

    char *url = getURLFromRequest(client->request_buffer);
    if (url == NULL) {
        fprintf(stderr, "handle_request : ERROR - Could not extract URL from request.\n");
        return -1;
    }

    printf("[handle_request] My url is %s\n", url);

    if (strstr(client->request_buffer, "GET ") == NULL) {
        is_get_request = 0; // not a get request so do not cache
    }

    strncpy(client->request_url, url, strlen(url));
    printf("[handle_request] This is the url: %s\n", url);

    char *response_buffer = (char *) malloc(MAX_RESPONSE_SIZE); // Allocate 10MB
    size_t response_size;

    // check if url is in cache and it is not stale and it is a get_request
    if (in_cache(cache, url) && !is_stale(cache, url) && is_get_request) {
        printf("[handle_request] Url %s in cache!\n", url);
        // get the content from the cache, no need to go to the server
        response_size = get(cache, url, response_buffer);

        /* edit response header */ //TODO: IMPROVE THIS!
        cache_node *node = get_node(cache, url);

        if (!node) {
            printf("ERROR, node is empty!\n");
        }
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
        if (!copy_response_buffer) {
            perror("[handle_request] Failed to allocate memory for response buffer copy");
            free(response_buffer);
            return -1;
        }
        memcpy(copy_response_buffer, response_buffer, MAX_RESPONSE_SIZE);
        ssize_t age_line_length = add_age_to_header(copy_response_buffer, response_size, age_value);
        if (age_line_length < 0) {
            fprintf(stderr, "[handle_request] Failed to add Age header to response.\n");
            free(copy_response_buffer);
            free(response_buffer);
            return -1;
        }

        // simple forward response to the client
        if (SSL_write(client->ssl, copy_response_buffer, response_size + age_line_length) <= 0) {
            perror("ERROR writing to socket");
            return -1;
        }

        free(copy_response_buffer);
    } else {
        if (!in_cache(cache, url)) {
            printf("[handle_request] Url %s is not in cache, going to the server!\n", url);
        } else if (!is_get_request) {
            printf("[handle_request] Not a GET request, going to the server!\n");
        }

        /***************  Proxy acts as a CLIENT ***************/
        struct sockaddr_in server_addr;
        SSLConnection server_connection = create_client_socket(server_addr, request_portno, hostname, client_ctx);

        if (server_connection.sockfd == -1 || !server_connection.ssl) {
            printf("[handle_request] Could not request from server on socket %d\n", client_socketfd);
            perror("ERROR connecting to the server");
            return -1;
        }

        // Forward request to server
        if (SSL_write(server_connection.ssl, client->request_buffer, strlen(client->request_buffer)) <= 0) {
            fprintf(stderr, "ERROR writing to the server.\n");
            ERR_print_errors_fp(stderr);
            close(server_connection.sockfd);
            SSL_free(server_connection.ssl);
            return -1;
        }
        printf("[handle_request] Request forwarded to the server!\n");

        // Read response from the server
        response_size = read_from_server(server_connection.ssl, response_buffer, MAX_RESPONSE_SIZE);

        if (response_size <= 0) {
            fprintf(stderr, "ERROR reading response from the server.\n");
            close(server_connection.sockfd);
            SSL_free(server_connection.ssl);
            return -1;
        }

        // Either put or update the cache (put function takes care of both)
        int max_age = get_max_age(response_buffer);
        printf("[handle_request] This is the max age: %d\n", max_age);
        if (is_get_request) {
            put(cache, url, max_age, response_buffer, response_size);
        }
        printf("[handle_request] Added URL <%s> to cache!\n", url);

        // Close the server connection
        SSL_shutdown(server_connection.ssl);
        SSL_free(server_connection.ssl);
        close(server_connection.sockfd);

        // Forward response to client
        if (SSL_write(client->ssl, response_buffer, response_size) <= 0) {
            fprintf(stderr, "ERROR writing response to client.\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
        free(response_buffer);

    }
    // reset the partial request buffer from client
    memset(client->request_buffer, 0, MAX_REQUEST_SIZE);
    return 0;
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
    EVP_PKEY_CTX_free(ctx);

    X509 *cert = generate_certificate(hostname, pkey, ca_pkey, ca_cert);
    if (!cert || !pkey) {
        fprintf(stderr, "[handle_connect_request] Failed to generate domain-specific certificate for %s.\n", hostname);
        return -1;
    }

    // Create new SSL session for the client
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

    cache *cache = create_cache(DEFAULT_CACHE_SIZE);
    client_list *cli_list = create_client_list();
    hashmap_client *clilist_hashmap = create_hashmap_client(MAX_CLIENTS);

    printf("[start_proxy] Created cache, client list, and hashmap.\n");

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
        int activity = select(fd_max + 1, &temp_set, NULL, NULL, &timeout);
        if (activity < 0) {
            if (ctrl_c_ended) {
                printf("[start_proxy] \nProxy server shut down.\n");
                break;
            }
            perror("select");
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
                // Accept new connections
                printf("[start_proxy] Connection request to proxy!\n");
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

                if (get_from_hashmap_client(clilist_hashmap, client_socketfd) == NULL) {
                    printf("[start_proxy] New client detected: Socket FD %d, IP: %s\n",
                        client_socketfd, inet_ntoa(client_addr.sin_addr));

                    // Create and initialize a new client node
                    client_node *node = create_client_node(client_socketfd);
                    strncpy(node->IP_addr, inet_ntoa(client_addr.sin_addr), INET_ADDRSTRLEN);

                    // Add the new client node to the hashmap and client list
                    insert_into_hashmap_client(clilist_hashmap, client_socketfd, node);
                    add_client(cli_list, node);
                    printf("[start_proxy] New client added to hashmap and list: Socket FD %d\n", client_socketfd);
                } else {
                    printf("[start_proxy] Existing client found: Socket FD %d\n", client_socketfd);
                }
            } else {
                // Handle existing client connections
                client_node *client = get_from_hashmap_client(clilist_hashmap, i);
                if (client == NULL) {
                    fprintf(stderr, "Client with fd %d not found in hashmap.\n", i);
                    exit(EXIT_FAILURE);
                }

                printf("[start_proxy] Processing request from client %s, fd: %d.\n", client->IP_addr, i);

                char *request_buffer = (char *)malloc(MAX_REQUEST_SIZE);
                if (!request_buffer) {
                    perror("Error allocating request buffer.");
                    close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                    continue;
                }

                if (client->ssl) {
                    printf("[start_proxy] Client already established a secure connection.\n");
                } else {
                    printf("[start_proxy] Client establishing an SSL connection...\n");
                    int read_bytes = read(client->socketfd, request_buffer, MAX_REQUEST_SIZE - 1);
                    if (read_bytes < 0) {
                        perror("[start_proxy] read");
                        close(client->socketfd);
                        FD_CLR(client->socketfd, &master_set);
                    } else if (read_bytes > 0) {
                        printf("[start_proxy] Non-SSL Request Buffer: %.*s\n", read_bytes, request_buffer);
                        if (strstr(request_buffer, "CONNECT") != NULL) {
                            // Handle CONNECT request and perform SSL handshake
                            if (handle_connect_request(client, ssl_ctx, ca_cert, ca_pkey, request_buffer) < 0) {
                                fprintf(stderr, "[start_proxy] Failed to handle CONNECT request from client.\n");
                                close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                                continue;
                            }


                            // Connection is now wrapped in SSL, wait for further requests
                            continue;
                        }
                    }
                }

                int nbytes = SSL_read(client->ssl, request_buffer, MAX_REQUEST_SIZE);
                if (nbytes <= 0) {
                    int ssl_error = SSL_get_error(client->ssl, nbytes);
                    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                        printf("[start_proxy] Client %d closed SSL connection.\n", client->socketfd);
                    } else {
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
                    if (handle_request(client, i, cache, client_ctx) < 0) {
                        close_client_connection(client, &master_set, cli_list, clilist_hashmap);
                    }
                }

                free(request_buffer);
            }
        }

        // Update fd_max
        fd_max = find_max_fd(&master_set, fd_max);
    }

    // Cleanup resources
    close(master_socketfd);
    SSL_CTX_free(ssl_ctx);
    SSL_CTX_free(client_ctx);
    cleanup_openssl();
    free_cache(cache);
    free_hashmap_client(clilist_hashmap);
    free_client_list(cli_list);

    return 0;
}
