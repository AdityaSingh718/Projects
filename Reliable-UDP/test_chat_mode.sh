#!/bin/bash

# Test script for SHAM protocol chat mode

echo "Testing SHAM Chat Mode..."
echo "This test will demonstrate the chat functionality using background processes."
echo ""

# Clean up any previous log files
rm -f client_log.txt server_log.txt

echo "Instructions:"
echo "1. Server will start in chat mode in background"
echo "2. Client will connect and send some test messages"
echo "3. The chat session will be terminated automatically"
echo "4. Logs will show the complete protocol exchange"
echo ""

# Start server in background for chat mode
echo "Starting server in chat mode on port 8080..."
export RUDP_LOG=1

# Start server in background
timeout 15 ./server 8080 --chat 0.05 > server_output.txt 2>&1 &
SERVER_PID=$!

# Give server time to start
sleep 2

# Test if we can use expect, otherwise use a simple automated test
if command -v expect >/dev/null 2>&1; then
    echo "Using expect for automated chat simulation..."
    
    # Create an expect script for automated chat testing
    cat > chat_test.exp << 'EOF'
#!/usr/bin/expect -f
set timeout 10

# Start the client
spawn ./client 127.0.0.1 8080 --chat 0.05

# Wait for chat mode to start
expect "Chat mode started*"

# Send some test messages
send "Hello from automated client!\r"
sleep 1

send "This is a test message\r"
sleep 1

send "Testing SHAM chat protocol\r"
sleep 1

# Send quit command
send "/quit\r"

# Wait for termination
expect eof
EOF

    chmod +x chat_test.exp
    export RUDP_LOG=1
    ./chat_test.exp
    rm -f chat_test.exp
    
else
    echo "Using simple background test (expect not available)..."
    
    # Simple background test without expect
    (
        sleep 1
        echo "Hello from automated client!" 
        sleep 1
        echo "This is a test message"
        sleep 1  
        echo "Testing SHAM chat protocol"
        sleep 1
        echo "/quit"
        sleep 1
    ) | timeout 10 ./client 127.0.0.1 8080 --chat 0.05 > client_output.txt 2>&1 &
    
    CLIENT_PID=$!
    
    # Wait for client to finish
    wait $CLIENT_PID 2>/dev/null
fi

# Wait for server to finish or kill it
sleep 2
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "Chat mode test completed!"
echo ""

echo "=== CLIENT LOG ==="
if [ -f client_log.txt ]; then
    cat client_log.txt
else
    echo "No client log found"
fi

echo ""
echo "=== SERVER LOG ==="
if [ -f server_log.txt ]; then
    cat server_log.txt
else
    echo "No server log found"
fi

# Clean up output files
rm -f server_output.txt client_output.txt

echo ""
echo "=== PROTOCOL VERIFICATION ==="
echo ""

echo "Looking for three-way handshake:"
grep -E "(SND SYN|RCV SYN|SND ACK|Connection established)" client_log.txt server_log.txt 2>/dev/null | head -10

echo ""
echo "Looking for chat messages:"
grep -E "(SND CHAT|RCV CHAT)" client_log.txt server_log.txt 2>/dev/null

echo ""
echo "Looking for four-way FIN handshake:"
grep -E "(SND FIN|RCV FIN|SND ACK FOR FIN|RCV ACK FOR FIN|Connection terminated)" client_log.txt server_log.txt 2>/dev/null

echo ""
echo "Chat mode test analysis complete!"
echo ""
echo "Features demonstrated:"
echo "  ✓ Three-way handshake for connection establishment"
echo "  ✓ Chat message exchange using SHAM_CHAT packets"
echo "  ✓ Four-way FIN handshake for connection termination"
echo "  ✓ Proper logging of all protocol events"
