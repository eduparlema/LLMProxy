#ifndef _PROXY_H
#define _PROXY_H

#include <netinet/in.h>

#include "client_list.h"

/* start_proxy 
    Starts the proxy so that it is actively listening at portno 
   portno - port number
*/
int start_proxy(int portno);

/* create_server_socket
    Creates a socket to communicate with the client. It is useful 
    for when the proxy behaves as a SERVER. It initializes the 
    proxy_add and binds it to the socket. 
   proxy_add - address of the proxy 
   portno - port number 
*/
int create_server_socket(int portno);

/* create_client_socket
    Creates a socket to communicate with the server. It is useful 
    for when the proxy behaves as a CLIENT. It initializes the 
    server_add
   server_add - address of the server
   portno - port number 
   hostname - name of the host we are trying to fetch data from
*/
int create_client_socket(struct sockaddr_in server_add, int portno, char *hostname);

/* read_from_socket
    Reads data from socketfd and stores them into buffer.
   socketfd - socket where we want to read from
   buffer - buffer where the data will be stored 
   buffer_size - maximum size of the buffer
   request - 1 if reading from a client (it is getting a request),
    0 if reading from the server (it is getting a response)
*/
// ssize_t read_from_socket(int socketfd, char *buffer, ssize_t buffer_size, int request);

/* read_message
    Reads at most buffer_size bytes from socketfd and stores them into buffer.
   socketfd - socket where we want to read from
   buffer - buffer where the data will be stored 
   buffer_size - maximum size of the buffer
*/
size_t read_message(int socketfd, char *buffer, int buffer_size);

/* habndle_request_buffer
    Reads data from a buffer into a client's request buffer. Handles
    possibly incomplete reads from a client (TCP may or may not send
    the complete header in one go so we must store partial headers)
   request_buffer - buffer were we store all data available with a read
   buffer_len data we read fom the read() call to the socket
   client - client node of the calling making the request
*/
int handle_request_buffer(char *request_buffer, int buffer_len, client_node *client);

/* handle_request
    Gets the data asked from the client's request, it either gets it from
    the cache or from request it from the server itself
   request_buffer - buffer were we store all data available with a read
   buffer_len data we read fom the read() call to the socket
   client - client node of the calling making the request
*/
int handle_request();

/* get_ip
    Gets IP address from a connected socketfd
   socketfd - socket connected to proxy
*/
int get_ip(client_list *cli_list, int socketfd, char *IP_addr, size_t buffer_size);

#endif 