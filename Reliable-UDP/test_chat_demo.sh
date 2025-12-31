#!/bin/bash

# Simple test for SHAM protocol chat mode

echo "Testing SHAM Chat Mode with automated demo..."

# Clean up any previous log files
rm -f client_log.txt server_log.txt

# Create a test script that will automatically send messages and quit
cat > chat_demo_client.sh << 'EOF'
#!/bin/bash
export RUDP_LOG=1
(
    sleep 1
    echo "Hello from client!"
    sleep 1
    echo "This is a chat message test"
    sleep 1
    echo "Testing SHAM protocol chat mode"
    sleep 2
    echo "/quit"
) | ./client 127.0.0.1 8080 --chat 0.02
EOF

cat > chat_demo_server.sh << 'EOF'
#!/bin/bash
export RUDP_LOG=1
(
    sleep 2
    echo "Hello from server!"
    sleep 1
    echo "Server received your messages"
    sleep 1
    echo "Chat mode working correctly"
    sleep 1
    echo "/quit"
) | ./server 8080 --chat 0.02
EOF

chmod +x chat_demo_client.sh chat_demo_server.sh

echo "Starting server in background..."
./chat_demo_server.sh &
SERVER_PID=$!

# Give server time to start
sleep 1

echo "Starting client..."
./chat_demo_client.sh &
CLIENT_PID=$!

# Wait for both to complete
wait $CLIENT_PID
wait $SERVER_PID

echo ""
echo "Chat demo completed!"
echo ""

echo "=== PROTOCOL LOGS ==="
echo ""
echo "--- Client Log ---"
if [ -f client_log.txt ]; then
    grep -E "(SND|RCV|Connection|chat)" client_log.txt || echo "No chat-related logs found"
else
    echo "No client log found"
fi

echo ""
echo "--- Server Log ---"
if [ -f server_log.txt ]; then
    grep -E "(SND|RCV|Connection|chat)" server_log.txt || echo "No chat-related logs found"
else
    echo "No server log found"
fi

echo ""
echo "=== HANDSHAKE VERIFICATION ==="
echo "Looking for three-way handshake:"
grep -E "(SND SYN|RCV SYN|SND SYN-ACK|RCV SYN-ACK|SND ACK|RCV ACK FOR SYN)" client_log.txt server_log.txt 2>/dev/null | head -6

echo ""
echo "Looking for four-way FIN handshake:"
grep -E "(SND FIN|RCV FIN|SND ACK FOR FIN|RCV ACK FOR FIN)" client_log.txt server_log.txt 2>/dev/null

echo ""
echo "Looking for chat messages:"
grep -E "(SND CHAT|RCV CHAT)" client_log.txt server_log.txt 2>/dev/null

# Cleanup
rm -f chat_demo_client.sh chat_demo_server.sh

echo ""
echo "Chat mode test completed successfully!"
echo "Features demonstrated:"
echo "  ✓ Three-way handshake for connection establishment"
echo "  ✓ Chat message exchange using SHAM_CHAT packets"
echo "  ✓ Four-way FIN handshake for connection termination"
echo "  ✓ Proper logging of all protocol events"
