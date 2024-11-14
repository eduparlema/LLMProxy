#ifndef _HELPERS_H
#define _HELPERS_H

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>


void get_hostname_and_port(char *request, char *hostname, char *port);

int get_max_age(char *header_buffer);

void modify_url(char *original_url, char *modified_url, int port);

void get_url(char *header_buffer, char *url, int port);

ssize_t add_age_to_header(char *response_buffer, ssize_t response_length, char *age_value);


#endif