#ifndef _PROXY_H
#define _PROXY_H

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "client_list.h"

#define MAX_HOSTNAME_SIZE 256

// Represents an SSL connection
typedef struct {
   int sockfd;  // Socket file descriptor
   SSL *ssl;    // SSL context for secure communication
} SSLConnection;

typedef struct {
   int sockfd; // Socket file descriptor
   int clientfd;
   SSL *client_ssl; // Its corresponding client's socket
   SSL *ssl;  // SSL context for secure communication
   char hostname[MAX_HOSTNAME_SIZE];
   int header_parsed;
   size_t content_length;
   size_t bytes_received;
   int chunked;
   int keep_alive;
} server_node;

server_node *create_server_node(int sockfd, int clientfd, SSL *client_ssl, SSL *ssl, char *hostname);

/* start_proxy
   Starts the proxy so that it is actively listening at portno.
   portno - port number.
*/
int start_proxy(int portno);

/* create_server_socket
   Creates a socket to communicate with the client. It is useful
   when the proxy behaves as a SERVER. It initializes the
   proxy_addr and binds it to the socket.
   portno - port number.
*/
int create_server_socket(int portno);

/* create_client_socket
   Creates an SSL-wrapped socket to communicate with the server. It is useful
   when the proxy behaves as a CLIENT. It initializes the server_addr, wraps
   the connection with SSL, and performs the handshake.
   server_addr - address of the server.
   portno - port number.
   hostname - name of the host we are trying to fetch data from.
   ctx - SSL context for creating the SSL connection.
   Returns an SSLConnection struct with socket and SSL context.
*/
SSLConnection create_client_socket(struct sockaddr_in server_addr, int portno, char *hostname, SSL_CTX *ctx);

/* handle_request_buffer
   Reads data from a buffer into a client's request buffer. Handles
   possibly incomplete reads from a client (TCP may or may not send
   the complete header in one go, so partial headers are stored).
   request_buffer - buffer containing data read from the socket.
   buffer_len - length of data read into the buffer.
   client - client node making the request.
   Returns 0 on success, -1 on failure.
*/
int handle_request_buffer(char *request_buffer, int buffer_size, client_node *client,
                            fd_set *master_set, client_list *cli_list, hashmap_proxy *clilist_hashmap,
                             SSL_CTX *client_ctx, hashmap_proxy *server_hashmap);

/* read_from_server
   Reads data from the server over an SSL connection into a buffer.
   ssl - SSL context for the secure connection.
   buffer - buffer to store the response data.
   buffer_size - size of the buffer.
   Returns the number of bytes read, or -1 on error.
*/
ssize_t read_from_server(server_node *server, char *buffer, ssize_t buffer_size,
                            hashmap_proxy *server_hashmap, fd_set *master_set);

#endif
