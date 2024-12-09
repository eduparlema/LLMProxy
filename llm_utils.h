#ifndef LLM_UTILS_H
#define LLM_UTILS_H

#include <stddef.h>

// Function declarations
void llmproxy_request(char *model, char *system, char *query, char *response_body);
int extract_reddit_post_content(const char *response, char *post_content, size_t post_content_size);

#endif // LLM_UTILS_H
