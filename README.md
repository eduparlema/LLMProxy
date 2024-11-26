# LLMProxy
HTTPS Proxy Powered by LLMs


**Link to Abdullah's doc:**
    [Google Doc](https://docs.google.com/document/d/1X1WJ0ltqt4fCOdqxOPRBeEen9a5kgZQxWjJVDu-qZHg/edit?pli=1&tab=t.0#heading=h.o6ugh4x3ywen)


**Commands to run to generate a CA and root key:**
    Certificate: `ca.crt`
    Key: `ca.key`

    This step is performed once, before starting the proxy, using OpenSSL:

    ```bash
    openssl genrsa -out ca.key 2048
    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=EduIsma"
    ```


**CURL Commands I'm using to test**
```bash
# ONLY HTML
curl --proxy 10.243.75.21:9100 --cacert ca.crt https://en.wikipedia.org/wiki/Monty_Python%27s_The_Meaning_of_Life -v

# JPG 10MB
curl --proxy 10.243.75.21:9100 --cacert ca.crt --output Pizigani_1367_Chart_10MB.jpg --progress-bar https://upload.wikimedia.org/wikipedia/commons/f/ff/Pizigani_1367_Chart_10MB.jpg -v

# Headshot JPG
curl --proxy 10.243.75.21:9100 --cacert ca.crt --output dga-headshot.jpg --progress-bar https://www.cs.cmu.edu/\~dga/dga-headshot.jpg -v
```
