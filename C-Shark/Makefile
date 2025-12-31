CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap
TARGET = cshark
SRC = cshark.c

# Default target: build the executable
all: $(TARGET)

# Compile the C source file and link with libpcap
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Clean up compiled files
clean:
	rm -f $(TARGET)

# Run the program (requires sudo)
run: $(TARGET)
	sudo ./$(TARGET)

# Install libpcap development files (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libpcap-dev

# Help message
help:
	@echo "C-Shark Makefile"
	@echo "================"
	@echo "Targets:"
	@echo "  all          - Build the cshark executable (default)"
	@echo "  clean        - Remove compiled files"
	@echo "  run          - Build and run cshark with sudo"
	@echo "  install-deps - Install libpcap-dev on Ubuntu/Debian"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build the program"
	@echo "  sudo ./cshark     # Run the program"

.PHONY: all clean run install-deps help
