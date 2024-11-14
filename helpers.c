#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "cache.h"

#define PORT_SIZE 6 
#define DEFAULT_MAX_AGE 3600

void get_hostname_and_port(char *request, char *hostname, char *port) {
    // Extract the Host: line 
    char *host_line = strstr(request, "Host:");
    if (host_line == NULL) {
        perror("Host header not found!");
        return;
    }

    host_line += strlen("Host: ");

    const char *end_of_line = strchr(host_line, '\r');
    if (end_of_line == NULL) {
        end_of_line = strchr(host_line, '\n');
    }
    
    size_t hostname_length = end_of_line ? (size_t)(end_of_line - host_line) : strlen(host_line);

    char *colon_pos = strchr(host_line, ':');
    if (colon_pos != NULL && colon_pos < host_line + hostname_length) {
        strncpy(port, colon_pos + 1, 6);  
        port[5] = '\0';
        
        // Adjust hostname length to exclude the port part
        hostname_length = (size_t)(colon_pos - host_line);
    } else {
        // No port was found, set port buffer to an empty string
        port[0] = '\0';
    }

    // copy hostname
    strncpy(hostname, host_line, hostname_length);
    hostname[hostname_length] = '\0';
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

void get_url(char *header_buffer, char *url, int port) {
    char *get_line;
    
    get_line = strstr(header_buffer, "HEAD ");
    if (get_line) {
        get_line += strlen("HEAD ");
    } else {
        get_line = strstr(header_buffer, "GET ");
        get_line += strlen("GET ");
    }

    char *end_of_line = strchr(get_line, '\r');
    if (end_of_line == NULL) {
        end_of_line = strchr(end_of_line, '\n');
    }

    ssize_t url_length = end_of_line ? (ssize_t) (end_of_line - get_line) : strlen(get_line);

    
    strncpy(url, get_line, url_length);
    url[url_length] = '\0'; // Null-terminate the URL

    // Modify the URL to append the port
    char modified_url[url_length + PORT_SIZE];
    modify_url(url, modified_url, port);

    // copy back to url 
    strncpy(url, modified_url, url_length + PORT_SIZE);
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