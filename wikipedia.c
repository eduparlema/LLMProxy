#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>
#include <gumbo.h>

#include "wikipedia.h"

// Helper function to escape special JSON characters
char *escape_json_string(const char *input) {
    size_t len = strlen(input);
    char *escaped = malloc(len * 2 + 1); // Allocate enough space
    if (!escaped) {
        perror("Failed to allocate memory");
        return NULL;
    }

    char *out = escaped;
    for (const char *p = input; *p; p++) {
        switch (*p) {
            case '\"': *out++ = '\\'; *out++ = '\"'; break; // Escape double quotes
            case '\\': *out++ = '\\'; *out++ = '\\'; break; // Escape backslashes
            case '\b': *out++ = '\\'; *out++ = 'b'; break;  // Escape backspace
            case '\f': *out++ = '\\'; *out++ = 'f'; break;  // Escape form feed
            case '\n': *out++ = '\\'; *out++ = 'n'; break;  // Escape newline
            case '\r': *out++ = '\\'; *out++ = 'r'; break;  // Escape carriage return
            case '\t': *out++ = '\\'; *out++ = 't'; break;  // Escape tab
            default: *out++ = *p; break;                   // Copy other characters
        }
    }
    *out = '\0';
    return escaped;
}

// Function to recursively extract text from a GumboNode
// void extract_text(const GumboNode *node, const *buffer) {
//     if (node == NULL) {
//         return; // Exit if node is NULL
//     }

//     if (node->type == GUMBO_NODE_TEXT) {
//         size_t length = strlen(node->v.text.text);
//         printf("GUMBO: %s (Length: %zu)\n", node->v.text.text, length);
//     } else if (node->type == GUMBO_NODE_ELEMENT) {
//         printf("GUMBO IS A NODE ELEMENT\n");
//         const GumboVector *children = &node->v.element.children;
//         for (unsigned int i = 0; i < children->length; ++i) {
//             extract_text((GumboNode *)children->data[i]);
//         }
//     } else {
//         printf("Node Type: %u\n", node->type);
//     }
// }

void extract_text(const GumboNode *node, char *buffer) {
    if (node == NULL) {
        return; // Exit if node is NULL
    }

    if (node->type == GUMBO_NODE_TEXT) {
        size_t length = strlen(node->v.text.text);
        // Check if there is enough space in the buffer
        if (strlen(buffer) + length + 1 >= 10 * MB) { // +1 for the newline
            perror("Buffer overflow");
            return;
        }
        strncat(buffer, node->v.text.text, length);
        strcat(buffer, "\n"); // Add newline to separate text nodes in the buffer
    } else if (node->type == GUMBO_NODE_ELEMENT) {
        const GumboVector *children = &node->v.element.children;
        for (unsigned int i = 0; i < children->length; ++i) {
            extract_text((GumboNode *)children->data[i], buffer);
        }
    }
}



char *decompress_gzip_dynamic(const char *compressed_data, size_t compressed_size) {
    size_t buffer_size = 8192; // Initial buffer size
    char *decompressed = malloc(buffer_size);
    if (!decompressed) {
        perror("Failed to allocate memory");
        return NULL;
    }

    z_stream stream = {0};
    inflateInit2(&stream, 16 + MAX_WBITS);

    stream.next_in = (Bytef *)compressed_data;
    stream.avail_in = compressed_size;

    int ret;
    do {
        stream.next_out = (Bytef *)decompressed + stream.total_out;
        stream.avail_out = buffer_size - stream.total_out;

        if (stream.avail_out == 0) {
            // Double the buffer size
            buffer_size *= 2;
            char *new_buffer = realloc(decompressed, buffer_size);
            if (!new_buffer) {
                perror("Failed to reallocate memory");
                inflateEnd(&stream);
                free(decompressed);
                return NULL;
            }
            decompressed = new_buffer;
            stream.next_out = (Bytef *)decompressed + stream.total_out;
            stream.avail_out = buffer_size - stream.total_out;
        }

        ret = inflate(&stream, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR) {
            fprintf(stderr, "Decompression failed\n");
            inflateEnd(&stream);
            free(decompressed);
            return NULL;
        }
    } while (ret != Z_STREAM_END);

    inflateEnd(&stream);

    // Null-terminate and print the decompressed data
    decompressed[stream.total_out] = '\0';

    char *content = strstr(decompressed, "mw-content-ltr");
    // then find second occurence of <p
    // stop at first occurence </p>
    if (content) {
        GumboOutput *output = gumbo_parse(content);
        if (output == NULL) {
            fprintf(stderr, "Gumbo parse failed\n");
            free(decompressed); // Free decompressed buffer if parsing fails
            return NULL;
        }

        char *buffer = (char *)malloc(10 * MB); // Allocate a buffer with 10 MB size
        if (buffer == NULL) {
            perror("Failed to allocate memory");
            gumbo_destroy_output(&kGumboDefaultOptions, output);
            return NULL;
        }

        buffer[0] = '\0'; // Null-terminate the buffer

        // Extract text from the GumboNode tree into the buffer
        extract_text(output->root, buffer);

        // Clean up Gumbo resources
        gumbo_destroy_output(&kGumboDefaultOptions, output);

        // Free the buffer when done
        // free(buffer);
        free(decompressed);

        return buffer;
    } else {
        fprintf(stderr, "Substring 'mw-content-lr' not found in decompressed data.\n");
    }

    return decompressed;
}