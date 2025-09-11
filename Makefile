############## LLM Generated Code Begins ################
# POSIX-compliant Makefile for Shell
# Target: shell.out
# Standard: C99 with POSIX.1-2008 compliance

CC = gcc
CFLAGS = -std=c99 \
	-D_POSIX_C_SOURCE=200809L \
	-D_XOPEN_SOURCE=700 \
	-Wall -Wextra -Werror \
	-Wno-unused-parameter \
	-fno-asm

SRCDIR = src
INCDIR = include
TARGET = shell.out

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)

# Object files
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Build the shell executable
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

# Compile source files to object files
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(SRCDIR)/*.o $(TARGET)

# Rebuild everything
rebuild: clean all

# Install (copy to current directory for convenience)
install: $(TARGET)
	cp $(TARGET) ./shell

# Test the shell
test: $(TARGET)
	./$(TARGET)

# Show help
help:
	@echo "Available targets:"
	@echo "  all     - Build the shell (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  rebuild - Clean and build"
	@echo "  install - Copy shell.out to ./shell"
	@echo "  test    - Run the shell"
	@echo "  help    - Show this help"

# Mark phony targets
.PHONY: all clean rebuild install test help

############## LLM Generated Code Ends ################ 