src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = clang
CFLAGS = -I/opt/homebrew/Cellar/gumbo-parser/0.12.2/include -I/opt/homebrew/Cellar/json-c/0.18/include -I/opt/homebrew/opt/openssl@3/include -fsanitize=address -g
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lz  -L/opt/homebrew/Cellar/gumbo-parser/0.12.2/lib -lgumbo -L/opt/homebrew/Cellar/json-c/0.18/lib -ljson-c -fsanitize=address

# Libraries
LIBS = -lcurl

# Change the C / LD flags with the path to your openssl eduardito
# I kept fsanitize address to debug issues with memory



a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
