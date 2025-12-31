#include "sham.h"

// Sample main function demonstrating the logging system
int main(int argc, char* argv[]) {
    (void)argv; // Suppress unused parameter warning
    
    // Initialize logging (simulate being called as "client" program)
    init_logging("client");
    
    // Log some sample events
    log_event("Program started with %d arguments", argc);
    log_event("SHAM protocol initialization");
    log_event("Connection attempt to server");
    log_event("Packet sent: seq=%u, ack=%u, flags=0x%04x", 1000, 2000, SHAM_SYN | SHAM_ACK);
    log_event("Received acknowledgment from server");
    
    // Simulate some protocol operations
    struct sham_header header;
    header.seq_num = 12345;
    header.ack_num = 67890;
    header.flags = SHAM_ACK;
    header.window_size = 8192;
    
    log_event("Header created - seq: %u, ack: %u, flags: 0x%04x, window: %u", 
              header.seq_num, header.ack_num, header.flags, header.window_size);
    
    log_event("Program terminating normally");
    
    // Cleanup
    cleanup_logging();
    
    printf("Logging demonstration complete. Check client_log.txt for output.\n");
    printf("To enable logging, set environment variable: export RUDP_LOG=1\n");
    
    return 0;
}
