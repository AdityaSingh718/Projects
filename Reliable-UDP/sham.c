/* ############## LLM Generated Code Begins ################ */
#define _GNU_SOURCE
#include "sham.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

// Global log file pointer
FILE *log_file = NULL;

// Initialize logging system
void init_logging(const char* program_name) {
    // Check if logging is enabled via environment variable
    char* log_env = getenv("RUDP_LOG");
    if (log_env == NULL || strcmp(log_env, "1") != 0) {
        return; // Logging disabled
    }
    
    // Determine log file name based on program name
    char log_filename[256];
    if (strstr(program_name, "client") != NULL) {
        strcpy(log_filename, "client_log.txt");
    } else if (strstr(program_name, "server") != NULL) {
        strcpy(log_filename, "server_log.txt");
    } else {
        strcpy(log_filename, "rudp_log.txt"); // Default fallback
    }
    
    // Open log file in append mode
    log_file = fopen(log_filename, "a");
    if (log_file == NULL) {
        fprintf(stderr, "Warning: Could not open log file %s\n", log_filename);
    }
}

// Log an event with timestamp
void log_event(const char* format, ...) {
    // Check if logging is enabled and file is open
    if (log_file == NULL) {
        return;
    }
    
    // Get current time with microsecond precision
    char time_buffer[30];
    struct timeval tv;
    time_t curtime;
    
    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec;
    
    // Format the time part
    strftime(time_buffer, 30, "%Y-%m-%d %H:%M:%S", localtime(&curtime));
    
    // Write timestamp to log file
    fprintf(log_file, "[%s.%06ld] [LOG] ", time_buffer, tv.tv_usec);
    
    // Write the actual log message using variable arguments
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    // Add newline if not present
    if (format[strlen(format) - 1] != '\n') {
        fprintf(log_file, "\n");
    }
    
    // Flush to ensure immediate writing
    fflush(log_file);
}

// Cleanup logging system
void cleanup_logging() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

// Initialize sliding window with flow control
void init_sliding_window(struct sliding_window* window, uint32_t initial_seq) {
    window->base = initial_seq;
    window->next_seq = initial_seq;
    window->current_window_size = MAX_WINDOW_SIZE;
    window->receiver_window = MAX_WINDOW_SIZE;
    
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        window->slots[i].acked = 1; // Mark as available
        window->slots[i].retries = 0;
    }
}

// Update window size based on receiver's advertised window
void update_window_size(struct sliding_window* window, uint16_t receiver_window) {
    window->receiver_window = receiver_window;
    // Current effective window size is minimum of our window and receiver's window
    window->current_window_size = (MAX_WINDOW_SIZE < receiver_window) ? MAX_WINDOW_SIZE : receiver_window;
    
    log_event("UPDATE WINDOW receiver_window=%d effective_window=%d", 
              receiver_window, window->current_window_size);
}

// Check if more packets can be sent (flow control)
int can_send_more(struct sliding_window* window) {
    uint32_t unacked_count = window->next_seq - window->base;
    return unacked_count < window->current_window_size;
}

// Utility function to check if packet should be dropped (loss simulation)
int should_drop_packet(float loss_rate) {
    if (loss_rate <= 0.0) return 0;
    return (rand() / (float)RAND_MAX) < loss_rate;
}

// Get current time in milliseconds
uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

// Check if a packet has timed out
int has_timed_out(struct timeval* send_time, int timeout_ms) {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    uint64_t send_ms = (uint64_t)(send_time->tv_sec) * 1000 + (uint64_t)(send_time->tv_usec) / 1000;
    uint64_t now_ms = (uint64_t)(now.tv_sec) * 1000 + (uint64_t)(now.tv_usec) / 1000;
    
    return (now_ms - send_ms) >= (uint64_t)timeout_ms;
}

// Send a data packet
int send_data_packet(int sockfd, struct sockaddr_in* addr, struct sliding_window* window,
                     const char* data, int len, uint32_t seq, float loss_rate) {
    
    int slot_index = (seq - window->base) % MAX_WINDOW_SIZE;
    struct window_slot* slot = &window->slots[slot_index];
    
    // Prepare data packet
    slot->packet.header.seq_num = htonl(seq);
    slot->packet.header.ack_num = htonl(0);
    slot->packet.header.flags = htons(SHAM_DATA);
    slot->packet.header.window_size = htons(MAX_WINDOW_SIZE); // Sender's window size
    slot->packet.data_len = htons(len);
    memcpy(slot->packet.data, data, len);
    
    // Record send time
    gettimeofday(&slot->send_time, NULL);
    slot->acked = 0;
    
    // Simulate packet loss
    if (should_drop_packet(loss_rate)) {
        log_event("DROP DATA SEQ=%u", seq);
        return 0; // Packet "dropped"
    }
    
    // Send packet
    ssize_t sent = sendto(sockfd, &slot->packet, sizeof(struct sham_header) + sizeof(uint16_t) + len, 0,
                         (struct sockaddr*)addr, sizeof(*addr));
    
    if (sent < 0) {
        log_event("ERROR: Failed to send data packet - %s", strerror(errno));
        return -1;
    }
    
    log_event("SND DATA SEQ=%u LEN=%d", seq, len);
    return 0;
}

// Handle acknowledgment with flow control
void handle_ack(struct sliding_window* window, uint32_t ack_num, uint16_t receiver_window) {
    log_event("RCV ACK=%u", ack_num);
    
    // Update receiver's window size for flow control
    update_window_size(window, receiver_window);
    
    // Mark packets as acknowledged (cumulative ACK)
    while (window->base < ack_num) {
        int slot_index = (window->base - window->base) % MAX_WINDOW_SIZE;
        window->slots[slot_index].acked = 1;
        window->base++;
    }
}

// Check for timeouts and retransmit if necessary
int check_timeouts(int sockfd, struct sockaddr_in* addr, struct sliding_window* window, float loss_rate) {
    int retransmitted = 0;
    
    for (uint32_t seq = window->base; seq < window->next_seq; seq++) {
        int slot_index = (seq - window->base) % MAX_WINDOW_SIZE;
        struct window_slot* slot = &window->slots[slot_index];
        
        if (!slot->acked && has_timed_out(&slot->send_time, RTO_MS)) {
            log_event("TIMEOUT SEQ=%u", seq);
            
            if (slot->retries < MAX_RETRIES) {
                // Retransmit
                gettimeofday(&slot->send_time, NULL);
                slot->retries++;
                
                // Simulate packet loss for retransmission too
                if (should_drop_packet(loss_rate)) {
                    log_event("DROP DATA SEQ=%u", seq);
                    continue;
                }
                
                ssize_t sent = sendto(sockfd, &slot->packet, 
                                    sizeof(struct sham_header) + sizeof(uint16_t) + ntohs(slot->packet.data_len), 0,
                                    (struct sockaddr*)addr, sizeof(*addr));
                
                if (sent >= 0) {
                    log_event("RETX DATA SEQ=%u LEN=%d", seq, ntohs(slot->packet.data_len));
                    retransmitted = 1;
                }
            } else {
                log_event("ERROR: Max retries exceeded for SEQ=%u", seq);
                return -1;
            }
        }
    }
    
    return retransmitted;
}

// Initialize receive buffer with MD5 context
void init_receive_buffer(struct receive_buffer* buffer, FILE* output_file) {
    buffer->expected_seq = 1001; // Start after handshake
    buffer->available_space = RECEIVER_BUFFER_SIZE;
    buffer->output_file = output_file;
    
    // Initialize MD5 context
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    MD5_Init(&buffer->md5_context);
#pragma GCC diagnostic pop
    
    for (int i = 0; i < RECEIVER_BUFFER_SIZE; i++) {
        buffer->received[i] = 0;
    }
}

// Handle incoming data packet with flow control
void handle_data_packet(struct receive_buffer* buffer, struct sham_data_packet* packet,
                       int sockfd, struct sockaddr_in* addr) {
    
    uint32_t seq = ntohl(packet->header.seq_num);
    uint16_t data_len = ntohs(packet->data_len);
    
    log_event("RCV DATA SEQ=%u LEN=%d", seq, data_len);
    
    // Check if packet is within receive window
    if (seq >= buffer->expected_seq && seq < buffer->expected_seq + RECEIVER_BUFFER_SIZE) {
        int slot_index = (seq - buffer->expected_seq) % RECEIVER_BUFFER_SIZE;
        
        // Only store if not already received and we have space
        if (!buffer->received[slot_index] && buffer->available_space > 0) {
            buffer->packets[slot_index] = *packet;
            buffer->received[slot_index] = 1;
            buffer->available_space--;
            
            // Try to deliver consecutive packets
            while (buffer->received[0]) {
                struct sham_data_packet* deliver_packet = &buffer->packets[0];
                uint16_t deliver_len = ntohs(deliver_packet->data_len);
                
                if (buffer->output_file && deliver_len > 0) {
                    fwrite(deliver_packet->data, 1, deliver_len, buffer->output_file);
                    fflush(buffer->output_file);
                    
                    // Update MD5 hash
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                    MD5_Update(&buffer->md5_context, deliver_packet->data, deliver_len);
#pragma GCC diagnostic pop
                }
                
                // Shift buffer
                for (int i = 0; i < RECEIVER_BUFFER_SIZE - 1; i++) {
                    buffer->packets[i] = buffer->packets[i + 1];
                    buffer->received[i] = buffer->received[i + 1];
                }
                buffer->received[RECEIVER_BUFFER_SIZE - 1] = 0;
                buffer->expected_seq++;
                buffer->available_space++;
            }
        }
    }
    
    // Send cumulative ACK with current available buffer space
    send_ack(sockfd, addr, buffer->expected_seq, buffer->available_space);
}

// Send acknowledgment with flow control window
int send_ack(int sockfd, struct sockaddr_in* addr, uint32_t ack_num, uint16_t window_size) {
    struct sham_header ack_packet;
    ack_packet.seq_num = htonl(0);
    ack_packet.ack_num = htonl(ack_num);
    ack_packet.flags = htons(SHAM_ACK);
    ack_packet.window_size = htons(window_size);
    
    ssize_t sent = sendto(sockfd, &ack_packet, sizeof(ack_packet), 0,
                         (struct sockaddr*)addr, sizeof(*addr));
    
    if (sent < 0) {
        log_event("ERROR: Failed to send ACK - %s", strerror(errno));
        return -1;
    }
    
    log_event("SND ACK=%u WIN=%u", ack_num, window_size);
    return 0;
}

// Finalize MD5 checksum and print to stdout
void finalize_md5_checksum(struct receive_buffer* buffer) {
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    MD5_Final(md5_hash, &buffer->md5_context);
#pragma GCC diagnostic pop
    
    printf("MD5: ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", md5_hash[i]);
    }
    printf("\n");
    fflush(stdout);
}

// Send a chat message
int send_chat_message(int sockfd, struct sockaddr_in* addr, const char* message, uint32_t seq, float loss_rate) {
    if (should_drop_packet(loss_rate)) {
        log_event("DROP CHAT SEQ=%u", seq);
        return 0; // Simulate packet drop
    }
    
    struct sham_chat_packet packet;
    packet.header.seq_num = htonl(seq);
    packet.header.ack_num = 0;
    packet.header.flags = htons(SHAM_CHAT);
    packet.header.window_size = htons(MAX_WINDOW_SIZE);
    
    int msg_len = strlen(message);
    if (msg_len > MAX_CHAT_MESSAGE - 1) {
        msg_len = MAX_CHAT_MESSAGE - 1;
    }
    
    packet.message_len = htons(msg_len);
    strncpy(packet.message, message, msg_len);
    packet.message[msg_len] = '\0';
    
    ssize_t sent = sendto(sockfd, &packet, sizeof(struct sham_header) + sizeof(uint16_t) + msg_len,
                          0, (struct sockaddr*)addr, sizeof(*addr));
    
    if (sent > 0) {
        log_event("SND CHAT SEQ=%u LEN=%d", seq, msg_len);
        return 1;
    }
    return 0;
}

// Handle incoming chat packet
void handle_chat_packet(struct sham_chat_packet* packet, struct sockaddr_in* addr) {
    uint32_t seq = ntohl(packet->header.seq_num);
    uint16_t msg_len = ntohs(packet->message_len);
    
    log_event("RCV CHAT SEQ=%u LEN=%d from %s:%d", seq, msg_len, 
              inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    
    // Null-terminate the message
    packet->message[msg_len] = '\0';
    
    printf("Remote: %s\n", packet->message);
    fflush(stdout);
}

// Chat mode for client
int chat_mode_client(int sockfd, struct sockaddr_in* server_addr, float loss_rate) {
    fd_set read_fds;
    char input_buffer[MAX_CHAT_MESSAGE];
    uint32_t seq_num = 1001; // Start after handshake
    
    printf("Chat mode started. Type messages and press Enter. Type '/quit' to exit.\n");
    fflush(stdout);
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sockfd, &read_fds);
        
        int max_fd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;
        
        // Use select to monitor both stdin and socket
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        
        if (activity < 0) {
            log_event("ERROR: select() failed - %s", strerror(errno));
            return -1;
        }
        
        // Check for keyboard input
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
                // Remove newline character
                input_buffer[strcspn(input_buffer, "\n")] = '\0';
                
                // Check for quit command
                if (strcmp(input_buffer, "/quit") == 0) {
                    log_event("User initiated chat termination");
                    return 0; // Exit chat mode to trigger FIN handshake
                }
                
                // Send chat message
                if (strlen(input_buffer) > 0) {
                    send_chat_message(sockfd, server_addr, input_buffer, seq_num++, loss_rate);
                }
            }
        }
        
        // Check for incoming messages
        if (FD_ISSET(sockfd, &read_fds)) {
            struct sham_chat_packet chat_packet;
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);
            
            ssize_t received = recvfrom(sockfd, &chat_packet, sizeof(chat_packet), 0,
                                       (struct sockaddr*)&recv_addr, &addr_len);
            
            if (received > 0) {
                uint16_t flags = ntohs(chat_packet.header.flags);
                
                if (flags & SHAM_CHAT) {
                    handle_chat_packet(&chat_packet, &recv_addr);
                } else if (flags & SHAM_FIN) {
                    log_event("RCV FIN - remote user quit chat");
                    return 0; // Remote user quit
                }
            }
        }
    }
    
    return 0;
}

// Chat mode for server
int chat_mode_server(int sockfd, struct sockaddr_in* client_addr, float loss_rate) {
    fd_set read_fds;
    char input_buffer[MAX_CHAT_MESSAGE];
    uint32_t seq_num = 2001; // Start after handshake
    
    printf("Chat mode started. Type messages and press Enter. Type '/quit' to exit.\n");
    fflush(stdout);
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sockfd, &read_fds);
        
        int max_fd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;
        
        // Use select to monitor both stdin and socket
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        
        if (activity < 0) {
            log_event("ERROR: select() failed - %s", strerror(errno));
            return -1;
        }
        
        // Check for keyboard input
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
                // Remove newline character
                input_buffer[strcspn(input_buffer, "\n")] = '\0';
                
                // Check for quit command
                if (strcmp(input_buffer, "/quit") == 0) {
                    log_event("User initiated chat termination");
                    return 0; // Exit chat mode to trigger FIN handshake
                }
                
                // Send chat message
                if (strlen(input_buffer) > 0) {
                    send_chat_message(sockfd, client_addr, input_buffer, seq_num++, loss_rate);
                }
            }
        }
        
        // Check for incoming messages
        if (FD_ISSET(sockfd, &read_fds)) {
            struct sham_chat_packet chat_packet;
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);
            
            ssize_t received = recvfrom(sockfd, &chat_packet, sizeof(chat_packet), 0,
                                       (struct sockaddr*)&recv_addr, &addr_len);
            
            if (received > 0) {
                uint16_t flags = ntohs(chat_packet.header.flags);
                
                if (flags & SHAM_CHAT) {
                    handle_chat_packet(&chat_packet, &recv_addr);
                } else if (flags & SHAM_FIN) {
                    log_event("RCV FIN - remote user quit chat");
                    return 0; // Remote user quit
                }
            }
        }
    }
    
    return 0;
}
/* ############## LLM Generated Code Begins ################ */