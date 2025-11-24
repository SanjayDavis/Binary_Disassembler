# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
DEBUG_FLAGS = -g -DDEBUG

# Target executable
TARGET = reverse

# Source files
SOURCES = reverse.c
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

# Compile source files to object files
%.o: %.c inst.h
	$(CC) $(CFLAGS) -c $< -o $@

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(OBJECTS) $(TARGET).exe *.o

# Rebuild from scratch
rebuild: clean all

.PHONY: all clean debug rebuild