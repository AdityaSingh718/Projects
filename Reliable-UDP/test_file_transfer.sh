#!/bin/bash

# SHAM Protocol File Transfer Test Script

echo "=== SHAM Protocol File Transfer Demonstration ==="
echo

# Clean previous logs and output files
rm -f client_log.txt server_log.txt received_file.dat

# Set logging environment variable
export RUDP_LOG=1

echo "1. Starting server on port 8080..."
./server 8080 received_file.dat &
SERVER_PID=$!

# Give server time to start
sleep 1

echo "2. Running client to transfer test_file.txt..."
echo "   File size: $(wc -c < test_file.txt) bytes"

if [ "$1" = "with_loss" ]; then
    echo "   Testing with 10% packet loss..."
    ./client 127.0.0.1 8080 test_file.txt 0.1
else
    echo "   Testing without packet loss..."
    ./client 127.0.0.1 8080 test_file.txt
fi

# Wait for server to finish
wait $SERVER_PID

echo "3. File transfer complete! Comparing files:"
echo

if cmp -s test_file.txt received_file.dat; then
    echo "✅ SUCCESS: Files are identical!"
    echo "   Original:  $(wc -c < test_file.txt) bytes"
    echo "   Received:  $(wc -c < received_file.dat) bytes"
else
    echo "❌ ERROR: Files differ!"
    echo "   Original:  $(wc -c < test_file.txt) bytes"
    echo "   Received:  $(wc -c < received_file.dat) bytes"
fi

echo
echo "4. Transfer logs:"
echo

echo "=== CLIENT LOG (Last 20 lines) ==="
tail -20 client_log.txt
echo

echo "=== SERVER LOG (Last 20 lines) ==="
tail -20 server_log.txt
echo

echo "=== Test completed! ==="
echo "To test with packet loss: $0 with_loss"
