src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = clang
CFLAGS = -I/opt/homebrew/opt/openssl@3/include -fsanitize=address -g
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -fsanitize=address
# Change the C / LD flags with the path to your openssl eduardito
# I kept fsanitize address to debug issues with memory

a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
