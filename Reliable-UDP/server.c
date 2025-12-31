/* ############## LLM Generated Code Begins ################ */
#define _GNU_SOURCE
#include "sham.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#define TIMEOUT_SEC 30

// Function to perform three-way handshake
int perform_handshake(int sockfd, struct sockaddr_in* client_addr) {
    uint32_t server_seq = 2000;
    
    // Step 1: Receive SYN
    struct sham_header syn_packet;
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    
    ssize_t received = recvfrom(sockfd, &syn_packet, sizeof(syn_packet), 0,
                               (struct sockaddr*)&recv_addr, &addr_len);
    if (received < 0) {
        log_event("ERROR: Failed to receive SYN - %s", strerror(errno));
        return -1;
    }
    
    uint32_t client_seq = ntohl(syn_packet.seq_num);
    uint16_t flags = ntohs(syn_packet.flags);
    
    if (!(flags & SHAM_SYN)) {
        log_event("ERROR: Invalid SYN packet");
        return -1;
    }
    
    // Store client address
    *client_addr = recv_addr;
    log_event("RCV SYN SEQ=%u from %s:%d", client_seq, 
              inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    
    // Step 2: Send SYN-ACK
    struct sham_header synack_packet;
    synack_packet.seq_num = htonl(server_seq);
    synack_packet.ack_num = htonl(client_seq + 1);
    synack_packet.flags = htons(SHAM_SYN | SHAM_ACK);
    synack_packet.window_size = htons(MAX_WINDOW_SIZE);
    
    ssize_t sent = sendto(sockfd, &synack_packet, sizeof(synack_packet), 0,
                         (struct sockaddr*)client_addr, sizeof(*client_addr));
    if (sent < 0) {
        log_event("ERROR: Failed to send SYN-ACK - %s", strerror(errno));
        return -1;
    }
    
    log_event("SND SYN-ACK SEQ=%u ACK=%u", server_seq, client_seq + 1);
    
    // Step 3: Receive ACK
    struct sham_header ack_packet;
    received = recvfrom(sockfd, &ack_packet, sizeof(ack_packet), 0,
                       (struct sockaddr*)&recv_addr, &addr_len);
    if (received < 0) {
        log_event("ERROR: Failed to receive ACK - %s", strerror(errno));
        return -1;
    }
    
    uint32_t ack_seq = ntohl(ack_packet.seq_num);
    uint32_t ack_ack = ntohl(ack_packet.ack_num);
    flags = ntohs(ack_packet.flags);
    
    if (!(flags & SHAM_ACK) || ack_ack != server_seq + 1) {
        log_event("ERROR: Invalid ACK packet");
        return -1;
    }
    
    log_event("RCV ACK FOR SYN SEQ=%u ACK=%u", ack_seq, ack_ack);
    log_event("Connection established successfully");
    
    return 0;
}

// Function to perform four-way FIN handshake
int perform_fin_handshake(int sockfd, struct sockaddr_in* client_addr) {
    uint32_t server_seq = 2100; // Use a higher sequence number for FIN
    
    // Step 1: Receive FIN from client
    struct sham_header fin_packet;
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    
    ssize_t received = recvfrom(sockfd, &fin_packet, sizeof(fin_packet), 0,
                               (struct sockaddr*)&recv_addr, &addr_len);
    if (received > 0) {
        uint32_t client_fin_seq = ntohl(fin_packet.seq_num);
        uint16_t flags = ntohs(fin_packet.flags);
        
        if (flags & SHAM_FIN) {
            log_event("RCV FIN SEQ=%u", client_fin_seq);
            
            // Step 2: Send ACK for client's FIN
            struct sham_header fin_ack;
            fin_ack.seq_num = htonl(server_seq);
            fin_ack.ack_num = htonl(client_fin_seq + 1);
            fin_ack.flags = htons(SHAM_ACK);
            fin_ack.window_size = htons(MAX_WINDOW_SIZE);
            
            ssize_t sent = sendto(sockfd, &fin_ack, sizeof(fin_ack), 0,
                                 (struct sockaddr*)client_addr, sizeof(*client_addr));
            if (sent >= 0) {
                log_event("SND ACK FOR FIN SEQ=%u ACK=%u", server_seq, client_fin_seq + 1);
            }
            
            // Step 3: Send FIN to client
            struct sham_header server_fin;
            server_fin.seq_num = htonl(server_seq + 1);
            server_fin.ack_num = 0;
            server_fin.flags = htons(SHAM_FIN);
            server_fin.window_size = htons(MAX_WINDOW_SIZE);
            
            sent = sendto(sockfd, &server_fin, sizeof(server_fin), 0,
                         (struct sockaddr*)client_addr, sizeof(*client_addr));
            if (sent >= 0) {
                log_event("SND FIN SEQ=%u", server_seq + 1);
            }
            
            // Step 4: Receive ACK for our FIN (optional, with timeout)
            struct timeval old_timeout;
            socklen_t timeout_len = sizeof(old_timeout);
            getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &old_timeout, &timeout_len);
            
            struct timeval short_timeout = {1, 0}; // 1 second timeout
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &short_timeout, sizeof(short_timeout));
            
            received = recvfrom(sockfd, &fin_ack, sizeof(fin_ack), 0,
                               (struct sockaddr*)&recv_addr, &addr_len);
            if (received > 0) {
                uint32_t final_ack_seq = ntohl(fin_ack.seq_num);
                uint32_t final_ack_ack = ntohl(fin_ack.ack_num);
                uint16_t final_flags = ntohs(fin_ack.flags);
                
                if (final_flags & SHAM_ACK) {
                    log_event("RCV ACK FOR FIN SEQ=%u ACK=%u", final_ack_seq, final_ack_ack);
                }
            }
            
            // Restore original timeout
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &old_timeout, sizeof(old_timeout));
        }
    }
    
    log_event("Connection terminated successfully");
    return 0;
}

int main(int argc, char* argv[]) {
    // Initialize logging for server
    init_logging("server");
    
    // Parse command line arguments
    int chat_mode = 0;
    int server_port;
    char* output_filename = "received_file.dat";
    float loss_rate = 0.0;
    
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  File Transfer: %s <port> [output_filename] [loss_rate]\n", argv[0]);
        fprintf(stderr, "  Chat Mode:     %s <port> --chat [loss_rate]\n", argv[0]);
        cleanup_logging();
        return 1;
    }
    
    server_port = atoi(argv[1]);
    
    // Parse additional arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--chat") == 0) {
            chat_mode = 1;
        } else if (strstr(argv[i], ".") != NULL) {
            // Argument contains a dot, likely a loss rate
            float rate = atof(argv[i]);
            if (rate >= 0.0 && rate <= 1.0) {
                loss_rate = rate;
            } else {
                // Not a valid loss rate, treat as filename
                if (!chat_mode) {
                    output_filename = argv[i];
                }
            }
        } else {
            // No dot, treat as filename if not in chat mode
            if (!chat_mode) {
                output_filename = argv[i];
            }
        }
    }
    
    if (chat_mode) {
        log_event("Server program started in CHAT MODE - listening on port %d", server_port);
    } else {
        log_event("Server program started in FILE TRANSFER MODE - listening on port %d", server_port);
        log_event("Output file: %s", output_filename);
    }
    
    // Seed random number generator for packet loss simulation
    srand(time(NULL));
    
    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_event("ERROR: Failed to create socket - %s", strerror(errno));
        cleanup_logging();
        return 1;
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);
    
    // Bind socket
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_event("ERROR: Failed to bind socket - %s", strerror(errno));
        close(sockfd);
        cleanup_logging();
        return 1;
    }
    
    log_event("Server listening for connections...");
    
    // Perform three-way handshake
    struct sockaddr_in client_addr;
    if (perform_handshake(sockfd, &client_addr) < 0) {
        log_event("ERROR: Handshake failed");
        close(sockfd);
        cleanup_logging();
        return 1;
    }
    
    if (chat_mode) {
        // Enter chat mode
        log_event("Entering chat mode...");
        int chat_result = chat_mode_server(sockfd, &client_addr, loss_rate);
        
        if (chat_result == 0) {
            // Perform four-way FIN handshake
            perform_fin_handshake(sockfd, &client_addr);
        }
    } else {
        // File transfer mode (existing implementation)
        log_event("Starting file reception...");
        
        // Open output file
        FILE* output_file = fopen(output_filename, "wb");
        if (!output_file) {
            log_event("ERROR: Cannot open output file %s - %s", output_filename, strerror(errno));
            close(sockfd);
            cleanup_logging();
            return 1;
        }
        
        // Initialize receive buffer
        struct receive_buffer buffer;
        init_receive_buffer(&buffer, output_file);
        
        long total_bytes = 0;
        
        // Receive file data
        while (1) {
            struct sham_data_packet data_packet;
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);
            
            ssize_t received = recvfrom(sockfd, &data_packet, sizeof(data_packet), 0,
                                       (struct sockaddr*)&recv_addr, &addr_len);
            
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    log_event("Timeout waiting for data - connection may be closed");
                    break;
                }
                log_event("ERROR: recvfrom failed - %s", strerror(errno));
                break;
            }
            
            uint16_t flags = ntohs(data_packet.header.flags);
            
            if (flags & SHAM_DATA) {
                handle_data_packet(&buffer, &data_packet, sockfd, &recv_addr);
                total_bytes += ntohs(data_packet.data_len);
            } else if (flags & SHAM_FIN) {
                log_event("Received FIN - file transfer complete");
                break;
            }
        }
        
        log_event("File reception complete - %lu bytes received", total_bytes);
        
        // Calculate and print MD5 checksum
        finalize_md5_checksum(&buffer);
        
        // Close output file
        fclose(output_file);
        
        // Perform four-way FIN handshake
        perform_fin_handshake(sockfd, &client_addr);
    }
    
    log_event("Server program terminating");
    
    // Cleanup
    close(sockfd);
    cleanup_logging();
    
    return 0;
}
/* ############## LLM Generated Code Begins ################ */