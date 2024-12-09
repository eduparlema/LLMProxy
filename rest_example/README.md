# LLMProxy Example Code RESTAPI

This folder contains example code (written in both C and Python) that demonstrates how to dispatch requests to `LLMProxy` using a RESTful API.
The program will make a single request and print out the response.
Once you are comfortable with it, you can add port the relevant code into your proxy.

---

## Getting Started

### Running the C Example
1. Add your API access key to example.c (line 11)
2. Use the `Makefile` to compile the program:
    ```
    make clean
    make
    ```
3. Run the executable:
    ```
    ./example
    ```

---

### Running the Python Example
1. Install Python 3.x and required dependencies by running the setup script:
    ```
    bash setup.sh
    ```
2. Add your API access key to example.py (line 11)
3. Execute the example Python script:
    ```
    python3 example.py
    ```

### Changing Request Parameters
You can change the request parameters (line 38-46 in `example.c` and line 22-29 in `example.py`).
For the `model` parameter the following options are available:
1. `4o-mini`
2. `anthropic.claude-3-haiku-20240307-v1:0`
3. `azure-phi3`
---