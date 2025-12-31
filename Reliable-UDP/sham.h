/* ############## LLM Generated Code Begins ################ */
#ifndef SHAM_H
#define SHAM_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/md5.h>

// Protocol constants
#define MAX_DATA_SIZE 1024
#define MAX_WINDOW_SIZE 10
#define RTO_MS 500
#define MAX_RETRIES 5
#define RECEIVER_BUFFER_SIZE 20  // Receiver buffer size for flow control
#define MAX_CHAT_MESSAGE 512     // Maximum chat message length

// Control flags for SHAM protocol
#define SHAM_SYN 0x0001
#define SHAM_ACK 0x0002
#define SHAM_FIN 0x0004
#define SHAM_DATA 0x0008
#define SHAM_CHAT 0x0010  // Chat message flag

// SHAM Protocol Header Structure
struct sham_header {
    uint32_t seq_num;       // Sequence Number
    uint32_t ack_num;       // Acknowledgment Number
    uint16_t flags;         // Control flags (SYN, ACK, FIN, DATA)
    uint16_t window_size;   // Flow control window size (receiver's available buffer)
};

// Data packet structure
struct sham_data_packet {
    struct sham_header header;
    uint16_t data_len;      // Length of data in this packet
    char data[1024];        // Data payload (max 1024 bytes)
};

// Chat packet structure
struct sham_chat_packet {
    struct sham_header header;
    uint16_t message_len;   // Length of chat message
    char message[MAX_CHAT_MESSAGE]; // Chat message payload
};

// Sliding window structures
struct window_slot {
    struct sham_data_packet packet;
    struct timeval send_time;
    int retries;
    int acked;
};

struct sliding_window {
    struct window_slot slots[MAX_WINDOW_SIZE];
    uint32_t base;          // First unacknowledged sequence number
    uint32_t next_seq;      // Next sequence number to send
    uint16_t current_window_size; // Current effective window size (min of our window and receiver's)
    uint16_t receiver_window; // Receiver's advertised window size
};

// Receiver buffer for reordering with flow control
struct receive_buffer {
    struct sham_data_packet packets[RECEIVER_BUFFER_SIZE];
    int received[RECEIVER_BUFFER_SIZE];
    uint32_t expected_seq;
    uint16_t available_space; // Available buffer space for flow control
    FILE* output_file;
    MD5_CTX md5_context;     // MD5 context for checksum calculation
};

// Global log file pointer
extern FILE *log_file;

// Function declarations
void init_logging(const char* program_name);
void log_event(const char* format, ...);
void cleanup_logging();

// Sliding window functions
void init_sliding_window(struct sliding_window* window, uint32_t initial_seq);
int send_data_packet(int sockfd, struct sockaddr_in* addr, struct sliding_window* window,
                     const char* data, int len, uint32_t seq, float loss_rate);
void handle_ack(struct sliding_window* window, uint32_t ack_num, uint16_t receiver_window);
int check_timeouts(int sockfd, struct sockaddr_in* addr, struct sliding_window* window, float loss_rate);
int can_send_more(struct sliding_window* window);
void update_window_size(struct sliding_window* window, uint16_t receiver_window);

// Receiver functions
void init_receive_buffer(struct receive_buffer* buffer, FILE* output_file);
void handle_data_packet(struct receive_buffer* buffer, struct sham_data_packet* packet,
                       int sockfd, struct sockaddr_in* addr);
int send_ack(int sockfd, struct sockaddr_in* addr, uint32_t ack_num, uint16_t window_size);
void finalize_md5_checksum(struct receive_buffer* buffer);

// Utility functions
int should_drop_packet(float loss_rate);
uint64_t get_time_ms(void);
int has_timed_out(struct timeval* send_time, int timeout_ms);

// Chat mode functions
int send_chat_message(int sockfd, struct sockaddr_in* addr, const char* message, uint32_t seq, float loss_rate);
void handle_chat_packet(struct sham_chat_packet* packet, struct sockaddr_in* addr);
int chat_mode_client(int sockfd, struct sockaddr_in* server_addr, float loss_rate);
int chat_mode_server(int sockfd, struct sockaddr_in* client_addr, float loss_rate);

#endif // SHAM_H
/* ############## LLM Generated Code Begins ################ */