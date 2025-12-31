#!/bin/bash

# SHAM Protocol Handshake Test Script

echo "=== SHAM Protocol Handshake Demonstration ==="
echo

# Clean previous logs and output files
rm -f client_log.txt server_log.txt handshake_test.txt received_file.dat

# Create a small test file for the handshake test
echo "This is a small test file for handshake demonstration." > handshake_test.txt

# Set logging environment variable
export RUDP_LOG=1

echo "1. Starting server on port 8080..."
./server 8080 received_file.dat &
SERVER_PID=$!

# Give server time to start
sleep 2

echo "2. Running client to connect to server and demonstrate handshake..."
./client 127.0.0.1 8080 handshake_test.txt

# Wait for server to finish
wait $SERVER_PID

echo "3. Handshake and file transfer complete!"
echo "   Original file: $(wc -c < handshake_test.txt) bytes"
if [ -f received_file.dat ]; then
    echo "   Received file: $(wc -c < received_file.dat) bytes"
    
    if cmp -s handshake_test.txt received_file.dat; then
        echo "   ✅ Files match - handshake and transfer successful!"
    else
        echo "   ❌ Files differ - there was an issue"
    fi
else
    echo "   ❌ No received file found"
fi

echo
echo "4. Protocol logs showing handshake sequence:"
echo

echo "=== CLIENT LOG ==="
cat client_log.txt
echo

echo "=== SERVER LOG ==="
cat server_log.txt
echo

echo "=== HANDSHAKE ANALYSIS ==="
echo "Looking for three-way handshake sequence:"
echo

echo "Step 1 - Client sends SYN:"
grep "SND SYN" client_log.txt 2>/dev/null || echo "  ❌ SYN not found in client log"

echo "Step 2 - Server receives SYN and sends SYN-ACK:"
grep "RCV SYN" server_log.txt 2>/dev/null || echo "  ❌ SYN reception not found in server log"
grep "SND SYN-ACK" server_log.txt 2>/dev/null || echo "  ❌ SYN-ACK not found in server log"

echo "Step 3 - Client receives SYN-ACK and sends ACK:"
grep "RCV SYN-ACK" client_log.txt 2>/dev/null || echo "  ❌ SYN-ACK reception not found in client log"
grep "SND ACK" client_log.txt 2>/dev/null || echo "  ❌ ACK not found in client log"

echo "Step 4 - Server receives ACK:"
grep "RCV ACK FOR SYN" server_log.txt 2>/dev/null || echo "  ❌ ACK reception not found in server log"

echo "Connection establishment:"
grep "Connection established" client_log.txt server_log.txt 2>/dev/null || echo "  ❌ Connection establishment not confirmed"

# Clean up test file
rm -f handshake_test.txt

echo
echo "=== Handshake test completed! ==="
