#ifndef _PROXY_H
#define _PROXY_H

#include <netinet/in.h>

/* start_proxy 
    Starts the proxy so that it is actively listening at portno 
   portno - port number
*/
void start_proxy(int portno);

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

#endif 