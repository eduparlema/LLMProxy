import json
import requests
import sys


def main():
    # dont change
    url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";

    # set your API key
    x_api_key = "your-api-key-goes-here"





    headers = {
        'x-api-key': x_api_key
    }


    request = {
        'model': '4o-mini',
        'system': "Answer my question in a funny manner",
        'query': "Who are the Jumbos",
        'temperature': 0.0,
        'lastk': 1,
        'session_id': "GenericSession",
    }


    print(f"Initiating request: {request}")

    try:
        response = requests.post(url, headers=headers, json=request)

        if response.status_code == 200:
            print(f"Response: {response.text}")
        else:
            print(f"Error: Received response code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
