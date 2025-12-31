# SHAM Protocol Implementation

This directory contains the implementation of the SHAM (Simple Header And Message) protocol with a comprehensive logging system, complete handshake mechanisms, reliable file transfer with sliding window protocol, **enhanced flow control**, **MD5 checksum verification**, and **interactive Chat Mode**.

## Files

- `sham.h` - Header file containing the SHAM protocol structures and function declarations
- `sham.c` - Implementation of the logging system, sliding window protocol, flow control, and chat mode
- `client.c` - Client program supporting both file transfer and chat modes
- `server.c` - Server program supporting both file transfer and chat modes
- `test_sham.c` - Test program demonstrating the logging functionality
- `test_handshake.sh` - Script to demonstrate handshake process
- `test_file_transfer.sh` - Script to demonstrate file transfer with optional packet loss
- `test_enhanced_transfer.sh` - Script to demonstrate enhanced flow control and MD5 features
- `test_chat_mode.sh` - Interactive script to test chat mode functionality
- `test_chat_demo.sh` - Automated demo of chat mode functionality
- `BUILD_INSTRUCTIONS.md` - Detailed compilation instructions for Linux environment
- `Makefile` - Build configuration with OpenSSL crypto library support

## SHAM Header Structure

```c
struct sham_header {
    uint32_t seq_num;       // Sequence Number
    uint32_t ack_num;       // Acknowledgment Number
    uint16_t flags;         // Control flags (SYN, ACK, FIN, DATA)
    uint16_t window_size;   // Flow control window size
};

struct sham_data_packet {
    struct sham_header header;
    uint16_t data_len;      // Length of data in this packet
    char data[1024];        // Data payload (max 1024 bytes)
};
```

### Control Flags
- `SHAM_SYN` (0x0001) - Synchronize flag
- `SHAM_ACK` (0x0002) - Acknowledgment flag
- `SHAM_FIN` (0x0004) - Finish flag
- `SHAM_DATA` (0x0008) - Data packet flag
- `SHAM_CHAT` (0x0010) - Chat message flag

## Protocol Features

### Handshake Mechanisms
**Three-Way Handshake (Connection Establishment):**
1. **Client → Server**: SYN (seq=x)
2. **Server → Client**: SYN-ACK (seq=y, ack=x+1)
3. **Client → Server**: ACK (seq=x+1, ack=y+1)

**Four-Way Handshake (Connection Termination):**
1. **Client → Server**: FIN (seq=x)
2. **Server → Client**: ACK (ack=x+1)
3. **Server → Client**: FIN (seq=y)
4. **Client → Server**: ACK (ack=y+1)

### File Transfer Protocol
- **Sliding Window**: Fixed window size of 10 packets (sender-side limit)
- **Flow Control**: Dynamic receiver window (0-20 slots) advertised in every ACK
- **Effective Window**: Minimum of sender window (10) and receiver window (0-20)
- **Packet Size**: Maximum 1024 bytes per data packet
- **Cumulative ACKs**: Server sends cumulative acknowledgments with current buffer space
- **Reorder Buffering**: Server can handle out-of-order packets (20-slot buffer)
- **Retransmission**: 500ms timeout (RTO) with up to 5 retries
- **Packet Loss Simulation**: Optional loss rate parameter (0.0 to 1.0)
- **MD5 Checksum**: Real-time calculation and verification of received files

### Chat Mode Protocol
- **Interactive Communication**: Real-time bidirectional messaging
- **Select() System Call**: Non-blocking I/O monitoring stdin and network socket
- **Chat Packets**: Messages sent within SHAM_CHAT packets (max 512 bytes)
- **Quit Command**: `/quit` triggers four-way FIN handshake
- **Connection Management**: Same three-way handshake for establishment
- **Concurrent Input**: Handle keyboard input and network messages simultaneously

## Logging System

The logging system provides microsecond-precision timestamps and writes to separate files:

- Client programs → `client_log.txt`
- Server programs → `server_log.txt`
- Other programs → `rudp_log.txt`

### Enabling Logging

Set the environment variable `RUDP_LOG=1` to enable logging:

```bash
export RUDP_LOG=1
./client 127.0.0.1 8080 filename.txt
```

### Log Format

```
[YYYY-MM-DD HH:MM:SS.microseconds] [LOG] Event description
```

### Protocol Log Messages

**Connection Establishment:**
```
[timestamp] [LOG] SND SYN SEQ=<num>
[timestamp] [LOG] RCV SYN SEQ=<num> from <ip>:<port>
[timestamp] [LOG] SND SYN-ACK SEQ=<num> ACK=<num>
[timestamp] [LOG] RCV SYN-ACK SEQ=<num> ACK=<num>
[timestamp] [LOG] SND ACK SEQ=<num> ACK=<num>
[timestamp] [LOG] RCV ACK FOR SYN SEQ=<num> ACK=<num>
```

**Data Transmission:**
```
[timestamp] [LOG] SND DATA SEQ=<num> LEN=<bytes>
[timestamp] [LOG] RCV DATA SEQ=<num> LEN=<bytes>
[timestamp] [LOG] SND ACK=<num> WIN=<window_size>
[timestamp] [LOG] RCV ACK=<num>
[timestamp] [LOG] UPDATE WINDOW receiver_window=<size> effective_window=<size>
```

**Retransmission:**
```
[timestamp] [LOG] TIMEOUT SEQ=<num>
[timestamp] [LOG] RETX DATA SEQ=<num> LEN=<bytes>
```

**Packet Loss Simulation:**
```
[timestamp] [LOG] DROP DATA SEQ=<num>
```

**Chat Messages:**
```
[timestamp] [LOG] SND CHAT SEQ=<num> LEN=<bytes>
[timestamp] [LOG] RCV CHAT SEQ=<num> LEN=<bytes> from <ip>:<port>
[timestamp] [LOG] User initiated chat termination
```

**Connection Termination:**
```
[timestamp] [LOG] SND FIN SEQ=<num>
[timestamp] [LOG] RCV FIN SEQ=<num>
[timestamp] [LOG] SND ACK FOR FIN SEQ=<num> ACK=<num>
[timestamp] [LOG] RCV ACK FOR FIN SEQ=<num> ACK=<num>
```

## Usage

### Command-Line Interface

**Client Programs:**
```bash
# File Transfer Mode
RUDP_LOG=1 ./client <server_ip> <server_port> <input_file> [loss_rate]

# Chat Mode
RUDP_LOG=1 ./client <server_ip> <server_port> --chat [loss_rate]
```

**Server Programs:**
```bash
# File Transfer Mode
RUDP_LOG=1 ./server <port> [output_filename] [loss_rate]

# Chat Mode
RUDP_LOG=1 ./server <port> --chat [loss_rate]
```

### File Transfer

**Server:**
```bash
RUDP_LOG=1 ./server <port> [output_filename]
```

**Client:**
```bash
RUDP_LOG=1 ./client <server_ip> <server_port> <filename> [loss_rate]
```

**Examples:**
```bash
# Terminal 1: Start server
RUDP_LOG=1 ./server 8080 received_file.dat

# Terminal 2: Transfer file without packet loss
RUDP_LOG=1 ./client 127.0.0.1 8080 myfile.txt

# Terminal 2: Transfer file with 5% packet loss
RUDP_LOG=1 ./client 127.0.0.1 8080 myfile.txt 0.05
```

### Chat Mode

**Start Server:**
```bash
RUDP_LOG=1 ./server 8080 --chat
```

**Connect Client:**
```bash
RUDP_LOG=1 ./client 127.0.0.1 8080 --chat
```

**Chat Commands:**
- Type any message and press Enter to send
- Type `/quit` to exit the chat (triggers FIN handshake)
- Both sides can send and receive messages concurrently

**Example Chat Session:**
```
# Terminal 1 (Server)
$ RUDP_LOG=1 ./server 8080 --chat
Chat mode started. Type messages and press Enter. Type '/quit' to exit.
Remote: Hello from client!
Server response message
Remote: Thanks for the response
/quit

# Terminal 2 (Client)  
$ RUDP_LOG=1 ./client 127.0.0.1 8080 --chat
Chat mode started. Type messages and press Enter. Type '/quit' to exit.
Hello from client!
Remote: Server response message
Thanks for the response
Remote: Server has quit the chat
```

## Building

**Prerequisites:**
```bash
# Install OpenSSL development libraries
sudo apt-get install libssl-dev  # Ubuntu/Debian
sudo yum install openssl-devel   # CentOS/RHEL
```

**Compilation:**
```bash
# Build all programs
make all

# Build individual components
make client
make server
make sham_test

# Clean build artifacts
make clean

# Test logging system
make test_logging

# Test handshake only
make test_handshake

# Test file transfer
make test_transfer

# Test file transfer with packet loss
make test_transfer_loss

# Test enhanced features (flow control + MD5)
./test_enhanced_transfer.sh

# Test chat mode (automated demo)
./test_chat_demo.sh

# Test chat mode (interactive)
./test_chat_mode.sh
```

**Manual Compilation:**
```bash
gcc -Wall -Wextra -std=c99 -g -c sham.c -o sham.o
gcc -Wall -Wextra -std=c99 -g client.c sham.o -o client -lcrypto
gcc -Wall -Wextra -std=c99 -g server.c sham.o -o server -lcrypto
```

## Testing

### Chat Mode Test
```bash
./test_chat_demo.sh
```

This will:
1. Start server and client in chat mode with packet loss simulation
2. Automatically exchange several chat messages
3. Demonstrate `/quit` command functionality  
4. Show complete three-way and four-way handshakes
5. Display all SHAM_CHAT packet exchanges
6. Verify proper connection termination

Example output:
```
SND CHAT SEQ=1001 LEN=18
RCV CHAT SEQ=2001 LEN=18 from 127.0.0.1:8080
User initiated chat termination
SND FIN SEQ=1100
RCV ACK FOR FIN SEQ=2100 ACK=1101
Connection terminated successfully
```

### Enhanced File Transfer Test
```bash
./test_enhanced_transfer.sh
```

This will:
1. Create a 5KB test file with random data
2. Start the server with flow control and MD5 calculation
3. Transfer the file with 5% packet loss simulation
4. Verify file integrity and compare MD5 checksums
5. Display flow control window size adjustments
6. Show real-time buffer space management

Example output:
```
Original file MD5: 79d3588b7c1ef68de9d5448894f6682c
MD5: 79d3588b7c1ef68de9d5448894f6682c
✓ File contents match perfectly
UPDATE WINDOW receiver_window=19 effective_window=10
SND ACK=1004 WIN=19
```

### File Transfer with Packet Loss
```bash
make test_transfer_loss
```

This tests the protocol's reliability with 10% simulated packet loss.

### Manual Testing

1. **Create a test file:**
   ```bash
   echo "Hello SHAM Protocol!" > test.txt
   ```

2. **Start server:**
   ```bash
   RUDP_LOG=1 ./server 8080 output.txt
   ```

3. **In another terminal, transfer file:**
   ```bash
   RUDP_LOG=1 ./client 127.0.0.1 8080 test.txt
   ```

4. **Verify transfer with MD5:**
   ```bash
   cmp test.txt output.txt && echo "Success!" || echo "Failed!"
   # MD5 checksum will be automatically printed by server:
   # MD5: a1b2c3d4e5f6...
   ```

## Protocol Implementation Details

### Sliding Window Protocol with Flow Control
- **Sender Window**: Fixed size of 10 packets (MAX_WINDOW_SIZE)
- **Receiver Window**: Dynamic size (0-20 slots) based on available buffer space
- **Effective Window**: min(sender_window, receiver_window) for actual flow control
- **Sequence Numbers**: 32-bit, starts from 1000 for client
- **Cumulative ACKs**: Receiver acknowledges highest consecutive sequence
- **Go-Back-N**: Sender retransmits from first unacknowledged packet on timeout
- **Buffer Management**: Receiver maintains 20-slot reorder buffer with real-time space tracking

### Reliability Features
- **Timeout & Retransmission**: 500ms RTO with exponential backoff
- **Maximum Retries**: 5 attempts before giving up
- **Packet Loss Detection**: Timeout-based detection
- **Flow Control**: Dynamic window sizing prevents buffer overflow
- **Reorder Buffering**: Receiver can handle out-of-order delivery
- **Integrity Verification**: MD5 checksum calculation and validation
- **Chat Mode**: Real-time bidirectional messaging with select() I/O multiplexing

### Example Enhanced Transfer Log
```
[2025-09-09 21:03:14.098224] [LOG] SND ACK=1003 WIN=20
[2025-09-09 21:03:14.098449] [LOG] UPDATE WINDOW receiver_window=20 effective_window=10
[2025-09-09 21:03:14.101022] [LOG] UPDATE WINDOW receiver_window=19 effective_window=10
[2025-09-09 21:03:14.102157] [LOG] SND ACK=1004 WIN=18
MD5: 79d3588b7c1ef68de9d5448894f6682c
```

### Example Chat Mode Log
```
[2025-09-09 21:23:08.241349] [LOG] Connection established successfully
[2025-09-09 21:23:08.241366] [LOG] Entering chat mode...
[2025-09-09 21:23:09.241583] [LOG] SND CHAT SEQ=1001 LEN=18
[2025-09-09 21:23:09.241788] [LOG] RCV CHAT SEQ=2001 LEN=18 from 127.0.0.1:8080
[2025-09-09 21:23:13.257833] [LOG] User initiated chat termination
[2025-09-09 21:23:13.258140] [LOG] SND FIN SEQ=1100
[2025-09-09 21:23:13.259163] [LOG] Connection terminated successfully
```

## Features

- ✅ Complete SHAM protocol header structure with data packets
- ✅ Three-way handshake for connection establishment
- ✅ Four-way handshake for graceful connection termination
- ✅ **Enhanced sliding window protocol with dynamic flow control**
- ✅ **Receiver buffer space advertisement in every ACK packet**
- ✅ **Sender respects receiver's window size to prevent overflow**
- ✅ File transfer with 1024-byte packet segmentation
- ✅ Cumulative acknowledgments with buffer space information
- ✅ Retransmission timeout (500ms RTO)
- ✅ Packet loss simulation with configurable loss rate
- ✅ **20-slot reorder buffer with real-time space management**
- ✅ **MD5 checksum calculation and verification of received files**
- ✅ **Interactive Chat Mode with select() system call**
- ✅ **Non-blocking I/O monitoring stdin and network socket**
- ✅ **Chat messages sent within SHAM_CHAT packets (max 512 bytes)**
- ✅ **/quit command triggers four-way FIN handshake**
- ✅ **Concurrent keyboard input and network message handling**
- ✅ UDP socket communication with proper error handling
- ✅ Microsecond-precision logging with specified format
- ✅ Command-line argument support for IP, port, filename, and loss rate
- ✅ Network byte order handling (htonl/ntohl)
- ✅ Proper sequence number management
- ✅ Automated testing scripts for various scenarios
- ✅ **OpenSSL crypto library integration for MD5 hashing**
- ✅ **Flow control logging with window size updates**
- ✅ **Dual-mode operation: File Transfer and Chat Mode**
