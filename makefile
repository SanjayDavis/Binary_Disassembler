# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
DEBUG_FLAGS = -g -DDEBUG

# Target executable
TARGET = reverse.exe

# Source files
SOURCES = reverse.c

# Default target
all: $(TARGET)

$(TARGET): $(SOURCES) inst.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) reverse.exe

# Rebuild from scratch
rebuild: clean all

.PHONY: all clean debug rebuild