# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Libraries
LIBS = -lcurl

# Target executable name
TARGET = example

# Source file
SRC = example.c

# Build the executable
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

# Clean up build files
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: clean
