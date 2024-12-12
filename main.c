#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "proxy.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port_number>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    int portno = atoi(argv[1]);
    int ret = start_proxy(portno);
    printf("PROXY returned %d\n", ret);
}