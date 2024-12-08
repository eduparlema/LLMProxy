#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>


// dont change
const char *url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";

// add your API key
const char *x_api_key = "x-api-key: comp112LTuxIOiW2QlPI2EU86dIzdsqw9FefbBjso3ayqf4"; // Your API key


// This function is called by libcurl to write data into a string buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb; // Total size of received data
    strncat(data, ptr, total_size); // Append the received data to the buffer
    return total_size;
}

void llmproxy_request(char *model, char *system, char *query, char *response_body){
    CURL *curl;
    CURLcode res;


    char *request_fmt = "{\n"
                        "  \"model\": \"%s\",\n"
                        "  \"system\": \"%s\",\n"
                        "  \"query\": \"%s\",\n"
                        "  \"temperature\": %.2f,\n"
                        "  \"lastk\": %d,\n"
                        "  \"session_id\": \"%s\"\n"
                        "}";

    // JSON data to send in the POST request
    char request[4096];
    memset(request, 0, 4096);
    snprintf(request,
             sizeof(request),
             request_fmt,
             model,
             system,
             query,
             0.0,
             1,
             "GenericSession");


    printf("Initiating request: %s\n", request);

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
        // Set the URL of the Proxy Agent server server
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Set the Content-Type to application/json
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        // Add x-api-key to header
        headers = curl_slist_append(headers, x_api_key);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // add request
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);


        // Set the write callback function to capture response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        // Set the buffer to write the response into
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_body);

        // Perform the POST request
        res = curl_easy_perform(curl);

        // Check if the request was successful
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize CURL.\n");
    }
}

int main() {

    // Buffer to store response data
    char response_body[4096] = "";
    llmproxy_request("4o-mini", "Answer my question in a funny manner", "Who are the Jumbos", response_body);
    printf("Response: %s\n", response_body);
    return 0;
}
