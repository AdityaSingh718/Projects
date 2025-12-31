CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = -lcrypto
TARGETS = client server sham_test

all: $(TARGETS)

# SHAM protocol library
sham.o: sham.c sham.h
	$(CC) $(CFLAGS) -c sham.c -o sham.o

# Test program for SHAM logging
sham_test: test_sham.c sham.o
	$(CC) $(CFLAGS) test_sham.c sham.o -o sham_test $(LDFLAGS)

# Client program
client: client.c sham.o
	$(CC) $(CFLAGS) client.c sham.o -o client $(LDFLAGS)

# Server program  
server: server.c sham.o
	$(CC) $(CFLAGS) server.c sham.o -o server $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f *.o $(TARGETS) client_log.txt server_log.txt rudp_log.txt received_file.dat

# Test the logging system
test_logging:
	@echo "Testing logging system..."
	@export RUDP_LOG=1 && ./sham_test
	@echo "Check client_log.txt for log output"

# Test the complete handshake
test_handshake: $(TARGETS)
	@echo "Testing SHAM protocol handshake..."
	@./test_handshake.sh

# Test file transfer
test_transfer: $(TARGETS)
	@echo "Testing SHAM protocol file transfer..."
	@./test_file_transfer.sh

# Test file transfer with packet loss
test_transfer_loss: $(TARGETS)
	@echo "Testing SHAM protocol file transfer with packet loss..."
	@./test_file_transfer.sh with_loss

.PHONY: all clean test_logging test_handshake test_transfer test_transfer_loss