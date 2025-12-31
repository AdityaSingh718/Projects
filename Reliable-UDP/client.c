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

#define TIMEOUT_SEC 5

// Function to perform three-way handshake
int perform_handshake(int sockfd, struct sockaddr_in* server_addr) {
    uint32_t client_seq = 1000;
    uint32_t server_seq, server_ack;
    
    // Step 1: Send SYN
    struct sham_header syn_packet;
    syn_packet.seq_num = htonl(client_seq);
    syn_packet.ack_num = 0;
    syn_packet.flags = htons(SHAM_SYN);
    syn_packet.window_size = htons(MAX_WINDOW_SIZE);
    
    ssize_t sent = sendto(sockfd, &syn_packet, sizeof(syn_packet), 0,
                         (struct sockaddr*)server_addr, sizeof(*server_addr));
    if (sent < 0) {
        log_event("ERROR: Failed to send SYN - %s", strerror(errno));
        return -1;
    }
    
    log_event("SND SYN SEQ=%u", client_seq);
    
    // Step 2: Receive SYN-ACK
    struct sham_header synack_packet;
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    
    ssize_t received = recvfrom(sockfd, &synack_packet, sizeof(synack_packet), 0,
                               (struct sockaddr*)&recv_addr, &addr_len);
    if (received < 0) {
        log_event("ERROR: Failed to receive SYN-ACK - %s", strerror(errno));
        return -1;
    }
    
    server_seq = ntohl(synack_packet.seq_num);
    server_ack = ntohl(synack_packet.ack_num);
    uint16_t flags = ntohs(synack_packet.flags);
    
    if (!(flags & SHAM_SYN) || !(flags & SHAM_ACK) || server_ack != client_seq + 1) {
        log_event("ERROR: Invalid SYN-ACK packet");
        return -1;
    }
    
    log_event("RCV SYN-ACK SEQ=%u ACK=%u", server_seq, server_ack);
    
    // Step 3: Send ACK
    struct sham_header ack_packet;
    ack_packet.seq_num = htonl(client_seq + 1);
    ack_packet.ack_num = htonl(server_seq + 1);
    ack_packet.flags = htons(SHAM_ACK);
    ack_packet.window_size = htons(MAX_WINDOW_SIZE);
    
    sent = sendto(sockfd, &ack_packet, sizeof(ack_packet), 0,
                 (struct sockaddr*)server_addr, sizeof(*server_addr));
    if (sent < 0) {
        log_event("ERROR: Failed to send ACK - %s", strerror(errno));
        return -1;
    }
    
    log_event("SND ACK SEQ=%u ACK=%u", client_seq + 1, server_seq + 1);
    log_event("Connection established successfully");
    
    return 0;
}

// Function to perform four-way FIN handshake
int perform_fin_handshake(int sockfd, struct sockaddr_in* server_addr) {
    uint32_t client_seq = 1100; // Use a higher sequence number for FIN
    
    // Step 1: Send FIN
    struct sham_header fin_packet;
    fin_packet.seq_num = htonl(client_seq);
    fin_packet.ack_num = 0;
    fin_packet.flags = htons(SHAM_FIN);
    fin_packet.window_size = htons(MAX_WINDOW_SIZE);
    
    ssize_t sent = sendto(sockfd, &fin_packet, sizeof(fin_packet), 0,
                         (struct sockaddr*)server_addr, sizeof(*server_addr));
    if (sent < 0) {
        log_event("ERROR: Failed to send FIN - %s", strerror(errno));
        return -1;
    }
    
    log_event("SND FIN SEQ=%u", client_seq);
    
    // Step 2: Receive ACK for FIN
    struct sham_header fin_ack_packet;
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    
    ssize_t received = recvfrom(sockfd, &fin_ack_packet, sizeof(fin_ack_packet), 0,
                               (struct sockaddr*)&recv_addr, &addr_len);
    if (received > 0) {
        uint32_t fin_ack_seq = ntohl(fin_ack_packet.seq_num);
        uint32_t fin_ack_ack = ntohl(fin_ack_packet.ack_num);
        uint16_t flags = ntohs(fin_ack_packet.flags);
        
        if (flags & SHAM_ACK) {
            log_event("RCV ACK FOR FIN SEQ=%u ACK=%u", fin_ack_seq, fin_ack_ack);
        }
    }
    
    // Step 3: Receive FIN from server
    received = recvfrom(sockfd, &fin_ack_packet, sizeof(fin_ack_packet), 0,
                       (struct sockaddr*)&recv_addr, &addr_len);
    if (received > 0) {
        uint32_t server_fin_seq = ntohl(fin_ack_packet.seq_num);
        uint16_t flags = ntohs(fin_ack_packet.flags);
        
        if (flags & SHAM_FIN) {
            log_event("RCV FIN SEQ=%u", server_fin_seq);
            
            // Step 4: Send ACK for server's FIN
            struct sham_header final_ack;
            final_ack.seq_num = htonl(client_seq + 1);
            final_ack.ack_num = htonl(server_fin_seq + 1);
            final_ack.flags = htons(SHAM_ACK);
            final_ack.window_size = htons(MAX_WINDOW_SIZE);
            
            sent = sendto(sockfd, &final_ack, sizeof(final_ack), 0,
                         (struct sockaddr*)server_addr, sizeof(*server_addr));
            if (sent >= 0) {
                log_event("SND ACK FOR FIN SEQ=%u ACK=%u", client_seq + 1, server_fin_seq + 1);
            }
        }
    }
    
    log_event("Connection terminated successfully");
    return 0;
}

int main(int argc, char* argv[]) {
    // Initialize logging for client
    init_logging("client");
    
    // Parse command line arguments
    int chat_mode = 0;
    char* server_ip;
    int server_port;
    char* input_filename = NULL;
    float loss_rate = 0.0;
    
    if (argc < 3) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  File Transfer: %s <server_ip> <server_port> <input_file> [loss_rate]\n", argv[0]);
        fprintf(stderr, "  Chat Mode:     %s <server_ip> <server_port> --chat [loss_rate]\n", argv[0]);
        cleanup_logging();
        return 1;
    }
    
    server_ip = argv[1];
    server_port = atoi(argv[2]);
    
    // Check for chat mode
    if (argc >= 4 && strcmp(argv[3], "--chat") == 0) {
        chat_mode = 1;
        if (argc >= 5) {
            loss_rate = atof(argv[4]);
            if (loss_rate < 0.0 || loss_rate > 1.0) {
                fprintf(stderr, "Loss rate must be between 0.0 and 1.0\n");
                cleanup_logging();
                return 1;
            }
        }
        log_event("Client program started in CHAT MODE - connecting to %s:%d", server_ip, server_port);
    } else {
        // File transfer mode
        if (argc < 4) {
            fprintf(stderr, "File transfer mode requires: %s <server_ip> <server_port> <input_file> [loss_rate]\n", argv[0]);
            cleanup_logging();
            return 1;
        }
        
        input_filename = argv[3];
        
        if (argc >= 5) {
            loss_rate = atof(argv[4]);
            if (loss_rate < 0.0 || loss_rate > 1.0) {
                fprintf(stderr, "Loss rate must be between 0.0 and 1.0\n");
                cleanup_logging();
                return 1;
            }
        }
        
        log_event("Client program started in FILE TRANSFER MODE - connecting to %s:%d", server_ip, server_port);
        log_event("File transfer: %s (loss_rate=%.2f)", input_filename, loss_rate);
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
    server_addr.sin_port = htons(server_port);
    if (inet_aton(server_ip, &server_addr.sin_addr) == 0) {
        log_event("ERROR: Invalid server IP address");
        close(sockfd);
        cleanup_logging();
        return 1;
    }
    
    // Perform three-way handshake
    if (perform_handshake(sockfd, &server_addr) < 0) {
        log_event("ERROR: Handshake failed");
        close(sockfd);
        cleanup_logging();
        return 1;
    }
    
    if (chat_mode) {
        // Enter chat mode
        log_event("Entering chat mode...");
        int chat_result = chat_mode_client(sockfd, &server_addr, loss_rate);
        
        if (chat_result == 0) {
            // Perform four-way FIN handshake
            perform_fin_handshake(sockfd, &server_addr);
        }
    } else {
        // File transfer mode (existing implementation)
        FILE* input_file = fopen(input_filename, "rb");
        if (!input_file) {
            log_event("ERROR: Cannot open file %s - %s", input_filename, strerror(errno));
            close(sockfd);
            cleanup_logging();
            return 1;
        }
        
        // Get file size
        fseek(input_file, 0, SEEK_END);
        long file_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);
        
        log_event("File size: %ld bytes", file_size);
        log_event("Starting file transfer...");
        
        // Initialize sliding window
        struct sliding_window window;
        init_sliding_window(&window, 1001);
        
        char buffer[MAX_DATA_SIZE];
        int bytes_read;
        long total_bytes = 0;
        
        // Send file data
        while ((bytes_read = fread(buffer, 1, MAX_DATA_SIZE, input_file)) > 0) {
            while (!can_send_more(&window)) {
                // Check for ACKs
                struct sockaddr_in recv_addr;
                socklen_t addr_len = sizeof(recv_addr);
                
                struct sham_header ack_packet;
                ssize_t received = recvfrom(sockfd, &ack_packet, sizeof(ack_packet), MSG_DONTWAIT,
                                           (struct sockaddr*)&recv_addr, &addr_len);
                
                if (received > 0) {
                    uint16_t flags = ntohs(ack_packet.flags);
                    if (flags & SHAM_ACK) {
                        uint32_t ack_num = ntohl(ack_packet.ack_num);
                        uint16_t receiver_window = ntohs(ack_packet.window_size);
                        handle_ack(&window, ack_num, receiver_window);
                    }
                }
                
                // Check for timeouts and retransmit
                int timeout_result = check_timeouts(sockfd, &server_addr, &window, loss_rate);
                if (timeout_result < 0) {
                    log_event("ERROR: File transfer failed due to excessive packet loss");
                    fclose(input_file);
                    close(sockfd);
                    cleanup_logging();
                    return 1;
                }
                
                // Small delay to prevent busy waiting
                usleep(1000); // 1ms
            }
            
            // Send data packet
            send_data_packet(sockfd, &server_addr, &window, buffer, bytes_read, window.next_seq, loss_rate);
            window.next_seq++;
            total_bytes += bytes_read;
        }
        
        log_event("File transfer complete - %ld bytes sent", total_bytes);
        
        // Wait for all ACKs
        while (window.base < window.next_seq) {
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);
            
            struct sham_header ack_packet;
            ssize_t received = recvfrom(sockfd, &ack_packet, sizeof(ack_packet), 0,
                                       (struct sockaddr*)&recv_addr, &addr_len);
            
            if (received > 0) {
                uint16_t flags = ntohs(ack_packet.flags);
                if (flags & SHAM_ACK) {
                    uint32_t ack_num = ntohl(ack_packet.ack_num);
                    uint16_t receiver_window = ntohs(ack_packet.window_size);
                    handle_ack(&window, ack_num, receiver_window);
                }
            }
            
            // Check for timeouts and retransmit
            int timeout_result = check_timeouts(sockfd, &server_addr, &window, loss_rate);
            if (timeout_result < 0) {
                log_event("ERROR: File transfer failed due to excessive packet loss");
                fclose(input_file);
                close(sockfd);
                cleanup_logging();
                return 1;
            }
            
            // Small delay to prevent busy waiting
            usleep(1000); // 1ms
        }
        
        log_event("All data acknowledged successfully");
        fclose(input_file);
        
        // Perform four-way FIN handshake
        perform_fin_handshake(sockfd, &server_addr);
    }
    
    log_event("Client program terminating");
    
    // Cleanup
    close(sockfd);
    cleanup_logging();
    
    return 0;
}
/* ############## LLM Generated Code Ends ################ */