#ifndef _WIKIPEDIA_H
#define _WIKIPEDIA_H

#include <zlib.h>
#include <stdio.h>

#define KB (1024)
#define MB (KB * KB)

char *decompress_gzip_dynamic(const char *compressed_data, size_t compressed_size);

char *escape_json_string(const char *input) ;

#endif