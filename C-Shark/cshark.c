#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>  // For ARP structures
#include <arpa/inet.h>
// LLM generated code begins
// Global variables for packet capture control
pcap_t *handle = NULL;              // Session handle for pcap library
volatile sig_atomic_t stop_flag = 0; // Flag to stop packet capture on Ctrl+C (volatile for signal safety)
int packet_counter = 0;              // Global packet counter that persists across capture sessions

// Filter variables for Phase 3
#define FILTER_NONE 0
#define FILTER_HTTP 1
#define FILTER_HTTPS 2
#define FILTER_DNS 3
#define FILTER_ARP 4
#define FILTER_TCP 5
#define FILTER_UDP 6

int active_filter = FILTER_NONE;    // Current filter mode

// Phase 4: Packet storage configuration
#define MAX_PACKETS 10000               // Maximum packets to store per session

// Stored packet structure
typedef struct {
    int packet_id;                      // Packet number in session
    struct timeval timestamp;           // Capture timestamp
    u_int32_t length;                   // Packet length
    u_char *data;                       // Raw packet data (dynamically allocated)
} stored_packet_t;

// Packet storage globals
stored_packet_t *packet_storage = NULL; // Array of stored packets
int stored_packet_count = 0;            // Number of packets currently stored

// EtherType constants - These identify the protocol encapsulated in the Ethernet frame
#define ETHERTYPE_IPV4 0x0800           // IPv4 protocol (0x0800)
#define ETHERTYPE_ARP  0x0806            // ARP protocol (0x0806)
// Note: ETHERTYPE_IPV6 (0x86DD) is already defined in <net/ethernet.h>

/*
 * Signal handler for Ctrl+C (SIGINT)
 * Stops the packet capture loop without terminating the program
 * This allows users to return to the main menu after stopping capture
 */
void sigint_handler(int sig) {
    (void)sig; // Unused parameter
    stop_flag = 1;
    if (handle) {
        // pcap_breakloop() safely breaks out of pcap_loop() packet processing
        // This is the proper way to stop packet capture from a signal handler
        pcap_breakloop(handle);
    }
}

/*
 * Phase 4: Free memory from previous packet storage session
 * Prevents memory leaks by deallocating all stored packet data
 */
void free_packet_storage() {
    if (packet_storage != NULL) {
        // Free each packet's data buffer
        for (int i = 0; i < stored_packet_count; i++) {
            if (packet_storage[i].data != NULL) {
                free(packet_storage[i].data);
                packet_storage[i].data = NULL;
            }
        }
        // Free the storage array itself
        free(packet_storage);
        packet_storage = NULL;
    }
    stored_packet_count = 0;
}

/*
 * Phase 4: Initialize storage for a new capture session
 * Allocates memory for storing up to MAX_PACKETS packets
 */
int initialize_packet_storage() {
    // Free any previous session data first
    free_packet_storage();
    
    // Allocate array for storing packets
    packet_storage = (stored_packet_t *)calloc(MAX_PACKETS, sizeof(stored_packet_t));
    if (packet_storage == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for packet storage\n");
        return -1;
    }
    
    stored_packet_count = 0;
    return 0;
}

/*
 * Phase 4: Store a captured packet for later inspection
 * Returns 0 on success, -1 if storage is full
 */
int store_packet(int packet_id, const struct pcap_pkthdr *header, const u_char *packet) {
    // Check if storage is full
    if (stored_packet_count >= MAX_PACKETS) {
        return -1;  // Storage full
    }
    
    // Allocate memory for packet data
    u_char *packet_copy = (u_char *)malloc(header->len);
    if (packet_copy == NULL) {
        fprintf(stderr, "Warning: Failed to allocate memory for packet %d\n", packet_id);
        return -1;
    }
    
    // Copy packet data
    memcpy(packet_copy, packet, header->len);
    
    // Store packet information
    packet_storage[stored_packet_count].packet_id = packet_id;
    packet_storage[stored_packet_count].timestamp = header->ts;
    packet_storage[stored_packet_count].length = header->len;
    packet_storage[stored_packet_count].data = packet_copy;
    
    stored_packet_count++;
    return 0;
}

/*
 * Setup signal handlers for graceful program control
 * SIGINT (Ctrl+C): Stops packet capture and returns to menu
 * Note: Ctrl+D (EOF) is handled in main_menu() through feof() check
 */
void setup_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);      // No signals blocked during handler execution
    sa.sa_flags = 0;                // No special flags
    sigaction(SIGINT, &sa, NULL);   // Register the handler for SIGINT
}

/*
 * Task 1.1: Device Discovery
 * Scans for all available network interfaces and presents them to the user
 * Returns: The selected device name, or NULL on error
 */
char* select_interface() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    int choice;
    char *selected_dev;
    
    printf("[C-Shark] Searching for available interfaces... ");
    
    // pcap_findalldevs() retrieves a list of all network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error!\n");
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }
    
    printf("Found!\n\n");
    
    // Display all available interfaces
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    
    if (i == 0) {
        printf("No interfaces found! Make sure pcap is installed correctly.\n");
        return NULL;
    }
    
    // Get user's choice
    printf("\nSelect an interface to sniff (1-%d): ", i);
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > i) {
        printf("Invalid selection.\n");
        pcap_freealldevs(alldevs);
        return NULL;
    }
    
    // Clear input buffer
    while (getchar() != '\n');
    
    // Find the selected device
    d = alldevs;
    for (i = 1; i < choice; i++) {
        d = d->next;
    }
    
    // Allocate memory and copy the device name
    selected_dev = strdup(d->name);
    
    // Free the device list
    pcap_freealldevs(alldevs);
    
    return selected_dev;
}

/*
 * Convert MAC address bytes to human-readable format
 * Takes 6 bytes and formats them as XX:XX:XX:XX:XX:XX
 */
void format_mac_address(const u_char *mac, char *buffer) {
    sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Get the name of a well-known port
 * Returns NULL if the port is not recognized
 * This helps identify common services like HTTP, HTTPS, DNS, etc.
 */
const char* get_port_name(u_short port) {
    switch(port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 3306: return "MySQL";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-Alt";
        default: return NULL;
    }
}

/*
 * Format port with name if known
 * Creates a string like "443 (HTTPS)" or just "12345" for unknown ports
 */
void format_port(u_short port, char *buffer) {
    const char *name = get_port_name(port);
    if (name) {
        sprintf(buffer, "%d (%s)", port, name);
    } else {
        sprintf(buffer, "%d", port);
    }
}

/*
 * Display hex dump of payload data (first 64 bytes)
 * Shows both hex values and ASCII representation
 * Format: 16 bytes per line with hex on left, ASCII on right
 * Non-printable characters are shown as '.'
 */
void print_hex_dump(const u_char *data, int length) {
    int i;
    int display_len = (length > 64) ? 64 : length;  // Limit to first 64 bytes as per requirement
    
    for (i = 0; i < display_len; i++) {
        // Print hex value (2 digits with leading zero)
        printf("%02X ", data[i]);
        
        // Every 16 bytes, print ASCII representation on the right
        if ((i + 1) % 16 == 0) {
            printf("  ");  // Two spaces before ASCII
            for (int j = i - 15; j <= i; j++) {
                // isprint() checks if character is printable, otherwise show '.'
                printf("%c", isprint(data[j]) ? data[j] : '.');
            }
            printf("\n");
        }
    }
    
    // Handle remaining bytes if not multiple of 16
    // This ensures the last line is properly formatted even with fewer than 16 bytes
    if (display_len % 16 != 0) {
        int remaining = display_len % 16;
        // Pad with spaces to align ASCII column (3 chars per missing byte: "XX ")
        for (i = 0; i < (16 - remaining); i++) {
            printf("   ");
        }
        printf("  ");
        // Print ASCII for remaining bytes
        for (i = display_len - remaining; i < display_len; i++) {
            printf("%c", isprint(data[i]) ? data[i] : '.');
        }
        printf("\n");
    }
}

/*
 * Decode and display IPv4 header information (Layer 3)
 * Processes the IPv4 packet and calls appropriate Layer 4 handlers
 */
void process_ipv4(const u_char *packet, int offset) {
    struct ip *ip_header = (struct ip *)(packet + offset);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    // inet_ntop() converts binary IP address to text format (network to presentation)
    // AF_INET specifies IPv4 address family
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    // Identify the protocol in the IP payload (Layer 4)
    const char *protocol_name;
    switch(ip_header->ip_p) {
        case IPPROTO_TCP: protocol_name = "TCP"; break;
        case IPPROTO_UDP: protocol_name = "UDP"; break;
        case IPPROTO_ICMP: protocol_name = "ICMP"; break;
        default: protocol_name = "Unknown"; break;
    }
    
    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) | TTL: %d\n",
           src_ip, dst_ip, protocol_name, ip_header->ip_p, ip_header->ip_ttl);
    
    // ntohs() converts network byte order (big-endian) to host byte order
    // ip_hl is header length in 32-bit words, multiply by 4 for bytes
    printf("           ID: 0x%04X | Total Length: %d | Header Length: %d bytes\n",
           ntohs(ip_header->ip_id), ntohs(ip_header->ip_len), ip_header->ip_hl * 4);
    
    // Decode IPv4 flags (Don't Fragment, More Fragments)
    // ip_off contains both flags and fragment offset
    u_short flags_offset = ntohs(ip_header->ip_off);
    if (flags_offset & IP_DF) {
        printf("           Flags: Don't Fragment\n");
    }
    if (flags_offset & IP_MF) {
        printf("           Flags: More Fragments\n");
    }
    
    // Process Layer 4 (TCP/UDP) based on protocol field
    int ip_header_len = ip_header->ip_hl * 4;
    offset += ip_header_len;
    
    if (ip_header->ip_p == IPPROTO_TCP) {
        // === TCP PROCESSING ===
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + offset);
        char src_port[32], dst_port[32];
        // Format ports with service names if known (e.g., "443 (HTTPS)")
        format_port(ntohs(tcp_header->th_sport), src_port);
        format_port(ntohs(tcp_header->th_dport), dst_port);
        
        printf("L4 (TCP): Src Port: %s | Dst Port: %s | Seq: %u | Ack: %u | Flags: [",
               src_port, dst_port,
               ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack));  // ntohl for 32-bit values
        
        // Decode TCP flags (control bits in the TCP header)
        // Each flag has a specific purpose in TCP connection management
        int flag_count = 0;
        if (tcp_header->th_flags & TH_FIN) { printf("%sFIN", flag_count++ ? "," : ""); }  // Finish connection
        if (tcp_header->th_flags & TH_SYN) { printf("%sSYN", flag_count++ ? "," : ""); }  // Synchronize sequences
        if (tcp_header->th_flags & TH_RST) { printf("%sRST", flag_count++ ? "," : ""); }  // Reset connection
        if (tcp_header->th_flags & TH_PUSH) { printf("%sPSH", flag_count++ ? "," : ""); } // Push data
        if (tcp_header->th_flags & TH_ACK) { printf("%sACK", flag_count++ ? "," : ""); }  // Acknowledgment
        if (tcp_header->th_flags & TH_URG) { printf("%sURG", flag_count++ ? "," : ""); }  // Urgent pointer
        
        printf("]\n");
        // th_off is TCP header length in 32-bit words
        printf("          Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
               ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum), tcp_header->th_off * 4);
        
        // === Layer 7 - TCP Payload Processing ===
        int tcp_header_len = tcp_header->th_off * 4;
        int payload_offset = offset + tcp_header_len;
        int total_len = ntohs(ip_header->ip_len);
        int payload_len = total_len - ip_header_len - tcp_header_len;
        
        if (payload_len > 0) {
            // Identify application protocol based on port numbers
            const char *app_proto = "Unknown";
            u_short dport = ntohs(tcp_header->th_dport);
            u_short sport = ntohs(tcp_header->th_sport);
            
            if (dport == 80 || sport == 80) app_proto = "HTTP";
            else if (dport == 443 || sport == 443) app_proto = "HTTPS/TLS";
            else if (dport == 53 || sport == 53) app_proto = "DNS";
            
            printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                   app_proto, (dport == 443 || dport == 80 || dport == 53) ? dport : sport,
                   payload_len);
            
            printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
            print_hex_dump(packet + payload_offset, payload_len);
        }
        
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        // === UDP PROCESSING ===
        struct udphdr *udp_header = (struct udphdr *)(packet + offset);
        char src_port[32], dst_port[32];
        format_port(ntohs(udp_header->uh_sport), src_port);
        format_port(ntohs(udp_header->uh_dport), dst_port);
        
        printf("L4 (UDP): Src Port: %s | Dst Port: %s | Length: %d | Checksum: 0x%04X\n",
               src_port, dst_port,
               ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum));
        
        // === Layer 7 - UDP Payload Processing ===
        int payload_offset = offset + 8; // UDP header is always 8 bytes
        int payload_len = ntohs(udp_header->uh_ulen) - 8;
        
        if (payload_len > 0) {
            // Identify application protocol (primarily DNS for UDP)
            const char *app_proto = "Unknown";
            u_short dport = ntohs(udp_header->uh_dport);
            u_short sport = ntohs(udp_header->uh_sport);
            
            if (dport == 53 || sport == 53) app_proto = "DNS";
            
            printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                   app_proto, (dport == 53) ? dport : sport, payload_len);
            
            printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
            print_hex_dump(packet + payload_offset, payload_len);
        }
    }
}

/*
 * Decode and display IPv6 header information (Layer 3)
 */
void process_ipv6(const u_char *packet, int offset) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + offset);
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    
    // inet_ntop() converts binary IPv6 address to text format
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    
    const char *protocol_name;
    switch(ip6_header->ip6_nxt) {
        case IPPROTO_TCP: protocol_name = "TCP"; break;
        case IPPROTO_UDP: protocol_name = "UDP"; break;
        case 58: protocol_name = "ICMPv6"; break;  // IPPROTO_ICMPV6
        default: protocol_name = "Unknown"; break;
    }
    
    printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip, dst_ip);
    
    // Extract traffic class and flow label from IPv6 header
    u_int32_t flow = ntohl(ip6_header->ip6_flow);
    u_int8_t traffic_class = (flow >> 20) & 0xFF;
    u_int32_t flow_label = flow & 0xFFFFF;
    
    printf("           Next Header: %s (%d) | Hop Limit: %d | Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
           protocol_name, ip6_header->ip6_nxt, ip6_header->ip6_hlim,
           traffic_class, flow_label, ntohs(ip6_header->ip6_plen));
    
    // Process Layer 4 (TCP/UDP)
    offset += 40; // IPv6 header is always 40 bytes
    
    if (ip6_header->ip6_nxt == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + offset);
        char src_port[32], dst_port[32];
        format_port(ntohs(tcp_header->th_sport), src_port);
        format_port(ntohs(tcp_header->th_dport), dst_port);
        
        printf("L4 (TCP): Src Port: %s | Dst Port: %s | Seq: %u | Ack: %u | Flags: [",
               src_port, dst_port,
               ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack));
        
        // Decode TCP flags
        int flag_count = 0;
        if (tcp_header->th_flags & TH_FIN) { printf("%sFIN", flag_count++ ? "," : ""); }
        if (tcp_header->th_flags & TH_SYN) { printf("%sSYN", flag_count++ ? "," : ""); }
        if (tcp_header->th_flags & TH_RST) { printf("%sRST", flag_count++ ? "," : ""); }
        if (tcp_header->th_flags & TH_PUSH) { printf("%sPSH", flag_count++ ? "," : ""); }
        if (tcp_header->th_flags & TH_ACK) { printf("%sACK", flag_count++ ? "," : ""); }
        if (tcp_header->th_flags & TH_URG) { printf("%sURG", flag_count++ ? "," : ""); }
        
        printf("]\n");
        printf("          Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
               ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum), tcp_header->th_off * 4);
        
        // Layer 7 - Payload
        int tcp_header_len = tcp_header->th_off * 4;
        int payload_offset = offset + tcp_header_len;
        int payload_len = ntohs(ip6_header->ip6_plen) - tcp_header_len;
        
        if (payload_len > 0) {
            const char *app_proto = "Unknown";
            u_short dport = ntohs(tcp_header->th_dport);
            u_short sport = ntohs(tcp_header->th_sport);
            
            if (dport == 80 || sport == 80) app_proto = "HTTP";
            else if (dport == 443 || sport == 443) app_proto = "HTTPS/TLS";
            else if (dport == 53 || sport == 53) app_proto = "DNS";
            
            printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                   app_proto, (dport == 443 || dport == 80 || dport == 53) ? dport : sport,
                   payload_len);
            
            printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
            print_hex_dump(packet + payload_offset, payload_len);
        }
        
    } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + offset);
        char src_port[32], dst_port[32];
        format_port(ntohs(udp_header->uh_sport), src_port);
        format_port(ntohs(udp_header->uh_dport), dst_port);
        
        printf("L4 (UDP): Src Port: %s | Dst Port: %s | Length: %d | Checksum: 0x%04X\n",
               src_port, dst_port,
               ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum));
        
        // Layer 7 - Payload
        int payload_offset = offset + 8; // UDP header is 8 bytes
        int payload_len = ntohs(udp_header->uh_ulen) - 8;
        
        if (payload_len > 0) {
            const char *app_proto = "Unknown";
            u_short dport = ntohs(udp_header->uh_dport);
            u_short sport = ntohs(udp_header->uh_sport);
            
            if (dport == 53 || sport == 53) app_proto = "DNS";
            
            printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                   app_proto, (dport == 53) ? dport : sport, payload_len);
            
            printf("Data (first %d bytes):\n", (payload_len > 64) ? 64 : payload_len);
            print_hex_dump(packet + payload_offset, payload_len);
        }
    }
}

/*
 * Decode and display ARP packet information (Layer 3)
 * ARP (Address Resolution Protocol) maps IP addresses to MAC addresses
 */
void process_arp(const u_char *packet, int offset) {
    struct ether_arp *arp_header = (struct ether_arp *)(packet + offset);
    
    // Determine operation type (Request or Reply)
    // ntohs() needed because operation field is in network byte order
    u_short op = ntohs(arp_header->ea_hdr.ar_op);
    const char *op_name;
    switch(op) {
        case ARPOP_REQUEST: op_name = "Request"; break;  // Who has IP X?
        case ARPOP_REPLY: op_name = "Reply"; break;      // IP X is at MAC Y
        default: op_name = "Unknown"; break;
    }
    
    // Extract IP addresses from ARP packet
    // arp_spa = sender protocol address (IP), arp_tpa = target protocol address
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);
    
    // Extract MAC addresses from ARP packet
    // arp_sha = sender hardware address (MAC), arp_tha = target hardware address
    char sender_mac[18], target_mac[18];
    format_mac_address(arp_header->arp_sha, sender_mac);
    format_mac_address(arp_header->arp_tha, target_mac);
    
    printf("L3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
           op_name, op, sender_ip, target_ip);
    printf("          Sender MAC: %s | Target MAC: %s\n",
           sender_mac, target_mac);
    // Display ARP header fields:
    // ar_hrd = hardware type (1 = Ethernet), ar_pro = protocol type (0x0800 = IPv4)
    // ar_hln = hardware address length (6 bytes for MAC), ar_pln = protocol address length (4 bytes for IPv4)
    printf("          HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
           ntohs(arp_header->ea_hdr.ar_hrd), ntohs(arp_header->ea_hdr.ar_pro),
           arp_header->ea_hdr.ar_hln, arp_header->ea_hdr.ar_pln);
}

/*
 * Check if the current packet matches the active filter
 * Returns 1 if packet should be displayed, 0 if it should be filtered out
 */
int matches_filter(const u_char *packet, u_short ether_type) {
    // If no filter is active, show all packets
    if (active_filter == FILTER_NONE) {
        return 1;
    }
    
    // Filter by ARP at Layer 2/3
    if (active_filter == FILTER_ARP) {
        return (ether_type == ETHERTYPE_ARP);
    }
    
    // For other filters, we need to check Layer 3/4
    if (ether_type == ETHERTYPE_IPV4) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // Filter by TCP protocol
        if (active_filter == FILTER_TCP) {
            return (ip_header->ip_p == IPPROTO_TCP);
        }
        
        // Filter by UDP protocol
        if (active_filter == FILTER_UDP) {
            return (ip_header->ip_p == IPPROTO_UDP);
        }
        
        // For HTTP/HTTPS/DNS, check TCP/UDP ports
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
            u_short sport = ntohs(tcp_header->th_sport);
            u_short dport = ntohs(tcp_header->th_dport);
            
            if (active_filter == FILTER_HTTP) {
                return (sport == 80 || dport == 80);
            }
            if (active_filter == FILTER_HTTPS) {
                return (sport == 443 || dport == 443);
            }
            if (active_filter == FILTER_DNS) {
                return (sport == 53 || dport == 53);
            }
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
            u_short sport = ntohs(udp_header->uh_sport);
            u_short dport = ntohs(udp_header->uh_dport);
            
            if (active_filter == FILTER_DNS) {
                return (sport == 53 || dport == 53);
            }
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        
        // Filter by TCP protocol
        if (active_filter == FILTER_TCP) {
            return (ip6_header->ip6_nxt == IPPROTO_TCP);
        }
        
        // Filter by UDP protocol
        if (active_filter == FILTER_UDP) {
            return (ip6_header->ip6_nxt == IPPROTO_UDP);
        }
        
        // For HTTP/HTTPS/DNS, check TCP/UDP ports
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + 40);
            u_short sport = ntohs(tcp_header->th_sport);
            u_short dport = ntohs(tcp_header->th_dport);
            
            if (active_filter == FILTER_HTTP) {
                return (sport == 80 || dport == 80);
            }
            if (active_filter == FILTER_HTTPS) {
                return (sport == 443 || dport == 443);
            }
            if (active_filter == FILTER_DNS) {
                return (sport == 53 || dport == 53);
            }
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + 40);
            u_short sport = ntohs(udp_header->uh_sport);
            u_short dport = ntohs(udp_header->uh_dport);
            
            if (active_filter == FILTER_DNS) {
                return (sport == 53 || dport == 53);
            }
        }
    }
    
    // Packet doesn't match the filter
    return 0;
}

/*
 * Packet handler callback function
 * Called by pcap_loop() for each captured packet
 * This is the main entry point for packet processing
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Unused parameter
    
    // === PHASE 3: CHECK FILTER FIRST (before counting or displaying) ===
    struct ether_header *eth_header = (struct ether_header *)packet;
    u_short ether_type = ntohs(eth_header->ether_type);
    
    // If packet doesn't match the active filter, skip it entirely
    if (!matches_filter(packet, ether_type)) {
        return;  // Don't count, don't display, don't store
    }
    
    // Only increment counter for packets that pass the filter
    packet_counter++;
    
    // === PHASE 4: STORE PACKET (after filter check, before display) ===
    if (store_packet(packet_counter, header, packet) == -1) {
        // Only warn once if storage is full
        if (stored_packet_count >= MAX_PACKETS) {
            static int warning_shown = 0;
            if (!warning_shown) {
                fprintf(stderr, "\n[Warning] Packet storage full (%d packets). New packets won't be stored but will still be displayed.\n\n", MAX_PACKETS);
                warning_shown = 1;
            }
        }
    }
    
    // Print packet separator for readability
    printf("-----------------------------------------\n");
    
    // Display packet basic information (Phase 1 requirement)
    // header->ts = timestamp structure with tv_sec and tv_usec
    // header->len = actual packet length
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
           packet_counter, header->ts.tv_sec, header->ts.tv_usec, header->len);
    
    // === Task 2.1: Decode Ethernet header (Layer 2) ===
    char src_mac[18], dst_mac[18];
    format_mac_address(eth_header->ether_shost, src_mac);  // Source MAC
    format_mac_address(eth_header->ether_dhost, dst_mac);  // Destination MAC
    
    const char *ether_type_name;
    switch(ether_type) {
        case ETHERTYPE_IPV4: ether_type_name = "IPv4"; break;
        case ETHERTYPE_IPV6: ether_type_name = "IPv6"; break;
        case ETHERTYPE_ARP: ether_type_name = "ARP"; break;
        default: ether_type_name = "Unknown"; break;
    }
    
    printf("L2 (Ethernet): Dst MAC: %s | Src MAC: %s | EtherType: %s (0x%04X)\n",
           dst_mac, src_mac, ether_type_name, ether_type);
    
    // === Task 2.2 & 2.3: Decode Layer 3 and Layer 4 based on EtherType ===
    // Calculate offset to skip Ethernet header
    int offset = sizeof(struct ether_header);
    
    // Dispatch to appropriate Layer 3 handler based on EtherType
    switch(ether_type) {
        case ETHERTYPE_IPV4:
            process_ipv4(packet, offset);  // IPv4 + Layer 4 (TCP/UDP)
            break;
        case ETHERTYPE_IPV6:
            process_ipv6(packet, offset);  // IPv6 + Layer 4 (TCP/UDP)
            break;
        case ETHERTYPE_ARP:
            process_arp(packet, offset);   // ARP (no Layer 4)
            break;
        default:
            // Unknown protocol, don't decode further
            break;
    }
    
    printf("\n");  // Blank line between packets
}

/*
 * Phase 5: Display full hex dump of entire packet frame
 * Shows 16 bytes per line with hex values and ASCII representation
 */
void print_full_hex_dump(const u_char *data, int length) {
    printf("\n📦 COMPLETE FRAME HEX DUMP\n");
    printf("─────────────────────────────────────────────────────────────────────────────────\n");
    printf("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
    
    for (int i = 0; i < length; i += 16) {
        // Print offset
        printf("%04X ", i);
        
        // Print hex bytes
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");  // Padding for incomplete lines
            }
        }
        
        printf("    ");
        
        // Print ASCII representation
        for (int j = 0; j < 16 && i + j < length; j++) {
            printf("%c", isprint(data[i + j]) ? data[i + j] : '.');
        }
        
        printf("\n");
    }
    printf("─────────────────────────────────────────────────────────────────────────────────\n");
}

/*
 * Phase 5: Detailed inspection of a single stored packet
 * Provides comprehensive layer-by-layer analysis with hex values
 */
void inspect_packet_detailed(int packet_index) {
    if (packet_index < 0 || packet_index >= stored_packet_count) {
        printf("Error: Invalid packet index.\n");
        return;
    }
    
    stored_packet_t *pkt = &packet_storage[packet_index];
    const u_char *packet = pkt->data;
    
    // Clear screen effect
    printf("\n\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n");
    printf("                     C-SHARK DETAILED PACKET ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n\n");
    
    // === PACKET SUMMARY ===
    printf("🦈 PACKET SUMMARY\n\n");
    printf("Packet ID:       #%d\n", pkt->packet_id);
    printf("Timestamp:       %ld.%06ld\n", pkt->timestamp.tv_sec, pkt->timestamp.tv_usec);
    printf("Frame Length:    %d bytes\n", pkt->length);
    printf("Captured:        %d bytes\n\n", pkt->length);
    
    // Display full hex dump first
    print_full_hex_dump(packet, pkt->length);
    
    printf("\n═══════════════════════════════════════════════════════════════════════════════\n");
    printf("                        LAYER-BY-LAYER ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n\n");
    
    // === ETHERNET II FRAME (Layer 2) ===
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    printf("🔗 ETHERNET II FRAME (Layer 2)\n\n");
    
    char dst_mac[18], src_mac[18];
    format_mac_address(eth_header->ether_dhost, dst_mac);
    format_mac_address(eth_header->ether_shost, src_mac);
    
    printf("Destination MAC:    %s (Bytes 0-5)\n", dst_mac);
    printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    
    printf("Source MAC:         %s (Bytes 6-11)\n", src_mac);
    printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    
    u_short ether_type = ntohs(eth_header->ether_type);
    const char *ether_type_name;
    switch(ether_type) {
        case ETHERTYPE_IPV4: ether_type_name = "IPv4"; break;
        case ETHERTYPE_IPV6: ether_type_name = "IPv6"; break;
        case ETHERTYPE_ARP: ether_type_name = "ARP"; break;
        default: ether_type_name = "Unknown"; break;
    }
    
    printf("EtherType:          0x%04X (%s) (Bytes 12-13)\n", ether_type, ether_type_name);
    printf("  └─ Hex: %02X %02X\n\n", packet[12], packet[13]);
    
    int offset = sizeof(struct ether_header);
    
    // === LAYER 3 PROCESSING ===
    if (ether_type == ETHERTYPE_IPV4) {
        struct ip *ip_header = (struct ip *)(packet + offset);
        
        printf("🌐 IPv4 HEADER (Layer 3)\n\n");
        printf("Version:            %d (4-bit field in byte %d)\n", ip_header->ip_v, offset);
        printf("  └─ Hex: %02X (upper 4 bits = %d)\n", packet[offset], ip_header->ip_v);
        
        printf("Header Length:      %d bytes (5 * 4) (4-bit field in byte %d)\n", 
               ip_header->ip_hl * 4, offset);
        printf("  └─ Hex: %02X (lower 4 bits = %d)\n", packet[offset], ip_header->ip_hl);
        
        printf("Type of Service:    0x%02X (Byte %d)\n", ip_header->ip_tos, offset + 1);
        printf("  └─ DSCP: %d, ECN: %d\n", ip_header->ip_tos >> 2, ip_header->ip_tos & 0x03);
        
        printf("Total Length:       %d bytes (Bytes %d-%d)\n", 
               ntohs(ip_header->ip_len), offset + 2, offset + 3);
        printf("  └─ Hex: %02X %02X\n", packet[offset + 2], packet[offset + 3]);
        
        printf("Identification:     0x%04X (%d) (Bytes %d-%d)\n", 
               ntohs(ip_header->ip_id), ntohs(ip_header->ip_id), offset + 4, offset + 5);
        printf("  └─ Hex: %02X %02X\n", packet[offset + 4], packet[offset + 5]);
        
        u_short flags_offset = ntohs(ip_header->ip_off);
        printf("Flags:              0x%04X (Byte %d-)\n", flags_offset, offset + 6);
        if (flags_offset & IP_DF) {
            printf("  └─ Reserved: 0, Don't Fragment: 1, More Fragments: %d\n", (flags_offset & IP_MF) ? 1 : 0);
        }
        printf("  └─ Fragment Offset: %d bytes\n", (flags_offset & 0x1FFF) * 8);
        
        printf("Time to Live:       %d (Byte %d)\n", ip_header->ip_ttl, offset + 8);
        printf("  └─ Hex: %02X\n", packet[offset + 8]);
        
        const char *proto_name;
        switch(ip_header->ip_p) {
            case IPPROTO_TCP: proto_name = "TCP"; break;
            case IPPROTO_UDP: proto_name = "UDP"; break;
            case IPPROTO_ICMP: proto_name = "ICMP"; break;
            default: proto_name = "Unknown"; break;
        }
        printf("Protocol:           %d (%s) (Byte %d)\n", ip_header->ip_p, proto_name, offset + 9);
        printf("  └─ Hex: %02X\n", packet[offset + 9]);
        
        printf("Header Checksum:    0x%04X (Bytes %d-%d)\n", 
               ntohs(ip_header->ip_sum), offset + 10, offset + 11);
        printf("  └─ Hex: %02X %02X\n", packet[offset + 10], packet[offset + 11]);
        
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        printf("Source IP:          %s (Bytes %d-%d)\n", src_ip, offset + 12, offset + 15);
        printf("  └─ Hex: %02X %02X %02X %02X\n", 
               packet[offset + 12], packet[offset + 13], packet[offset + 14], packet[offset + 15]);
        
        printf("Destination IP:     %s (Bytes %d-%d)\n", dst_ip, offset + 16, offset + 19);
        printf("  └─ Hex: %02X %02X %02X %02X\n\n", 
               packet[offset + 16], packet[offset + 17], packet[offset + 18], packet[offset + 19]);
        
        int ip_header_len = ip_header->ip_hl * 4;
        offset += ip_header_len;
        
        // === LAYER 4 (TCP/UDP) ===
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + offset);
            
            printf("🔌 TCP HEADER (Layer 4)\n\n");
            
            char src_port[32], dst_port[32];
            format_port(ntohs(tcp_header->th_sport), src_port);
            format_port(ntohs(tcp_header->th_dport), dst_port);
            
            printf("Source Port:        %s (Bytes %d-%d)\n", src_port, offset, offset + 1);
            printf("  └─ Hex: %02X %02X\n", packet[offset], packet[offset + 1]);
            
            printf("Destination Port:   %s (Bytes %d-%d)\n", dst_port, offset + 2, offset + 3);
            printf("  └─ Hex: %02X %02X\n", packet[offset + 2], packet[offset + 3]);
            
            printf("Sequence Number:    %u (Bytes %d-%d)\n", 
                   ntohl(tcp_header->th_seq), offset + 4, offset + 7);
            printf("  └─ Hex: %02X %02X %02X %02X\n", 
                   packet[offset + 4], packet[offset + 5], packet[offset + 6], packet[offset + 7]);
            
            printf("Acknowledgment:     %u (Bytes %d-%d)\n", 
                   ntohl(tcp_header->th_ack), offset + 8, offset + 11);
            printf("  └─ Hex: %02X %02X %02X %02X\n", 
                   packet[offset + 8], packet[offset + 9], packet[offset + 10], packet[offset + 11]);
            
            printf("Header Length:      %d bytes (8 * 4) (Upper 4 bits of byte %d)\n", 
                   tcp_header->th_off * 4, offset + 12);
            printf("  └─ Hex: %02X (Upper 4 bits = %d)\n", packet[offset + 12], tcp_header->th_off);
            
            printf("Flags:              0x%02X (Byte %d)\n", tcp_header->th_flags, offset + 13);
            printf("  └─ URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
                   (tcp_header->th_flags & TH_URG) ? 1 : 0,
                   (tcp_header->th_flags & TH_ACK) ? 1 : 0,
                   (tcp_header->th_flags & TH_PUSH) ? 1 : 0,
                   (tcp_header->th_flags & TH_RST) ? 1 : 0,
                   (tcp_header->th_flags & TH_SYN) ? 1 : 0,
                   (tcp_header->th_flags & TH_FIN) ? 1 : 0);
            
            printf("Window Size:        %d (Bytes %d-%d)\n", 
                   ntohs(tcp_header->th_win), offset + 14, offset + 15);
            printf("  └─ Hex: %02X %02X\n", packet[offset + 14], packet[offset + 15]);
            
            printf("Checksum:           0x%04X (Bytes %d-%d)\n", 
                   ntohs(tcp_header->th_sum), offset + 16, offset + 17);
            printf("  └─ Hex: %02X %02X\n", packet[offset + 16], packet[offset + 17]);
            
            printf("Urgent Pointer:     %d (Bytes %d-%d)\n", 
                   ntohs(tcp_header->th_urp), offset + 18, offset + 19);
            printf("  └─ Hex: %02X %02X\n", packet[offset + 18], packet[offset + 19]);
            
            if (tcp_header->th_off > 5) {
                printf("TCP Options:        %d bytes (Bytes %d-%d)\n", 
                       (tcp_header->th_off - 5) * 4, offset + 20, offset + tcp_header->th_off * 4 - 1);
                printf("  └─ Hex: ");
                for (int i = 20; i < tcp_header->th_off * 4; i++) {
                    printf("%02X ", packet[offset + i]);
                }
                printf("\n");
            }
            
            printf("\n");
            
            // === LAYER 5-7 (APPLICATION DATA) ===
            int tcp_header_len = tcp_header->th_off * 4;
            int payload_offset = offset + tcp_header_len;
            int total_len = ntohs(ip_header->ip_len);
            int payload_len = total_len - ip_header_len - tcp_header_len;
            
            if (payload_len > 0) {
                printf("📊 APPLICATION DATA (Layer 5-7)\n\n");
                printf("Payload Length:     %d bytes (Bytes %d-%d)\n", 
                       payload_len, payload_offset, payload_offset + payload_len - 1);
                
                u_short dport = ntohs(tcp_header->th_dport);
                u_short sport = ntohs(tcp_header->th_sport);
                const char *proto = "Unknown/Custom";
                if (dport == 80 || sport == 80) proto = "HTTP";
                else if (dport == 443 || sport == 443) proto = "HTTPS/TLS";
                else if (dport == 53 || sport == 53) proto = "DNS";
                
                printf("Protocol:           %s (Port %d)\n\n", proto, (dport == 80 || dport == 443 || dport == 53) ? dport : sport);
                
                printf("First 64 bytes of payload:\n");
                printf("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
                
                int display_len = (payload_len > 64) ? 64 : payload_len;
                for (int i = 0; i < display_len; i += 16) {
                    printf("%04X ", payload_offset + i);
                    for (int j = 0; j < 16; j++) {
                        if (i + j < display_len) {
                            printf("%02X ", packet[payload_offset + i + j]);
                        } else {
                            printf("   ");
                        }
                    }
                    printf("    ");
                    for (int j = 0; j < 16 && i + j < display_len; j++) {
                        printf("%c", isprint(packet[payload_offset + i + j]) ? packet[payload_offset + i + j] : '.');
                    }
                    printf("\n");
                }
                
                if (payload_len > 64) {
                    printf("\n... and %d more bytes\n", payload_len - 64);
                }
            }
            
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + offset);
            
            printf("🔌 UDP HEADER (Layer 4)\n\n");
            
            char src_port[32], dst_port[32];
            format_port(ntohs(udp_header->uh_sport), src_port);
            format_port(ntohs(udp_header->uh_dport), dst_port);
            
            printf("Source Port:        %s (Bytes %d-%d)\n", src_port, offset, offset + 1);
            printf("  └─ Hex: %02X %02X\n", packet[offset], packet[offset + 1]);
            
            printf("Destination Port:   %s (Bytes %d-%d)\n", dst_port, offset + 2, offset + 3);
            printf("  └─ Hex: %02X %02X\n", packet[offset + 2], packet[offset + 3]);
            
            printf("Length:             %d (Bytes %d-%d)\n", 
                   ntohs(udp_header->uh_ulen), offset + 4, offset + 5);
            printf("  └─ Hex: %02X %02X\n", packet[offset + 4], packet[offset + 5]);
            
            printf("Checksum:           0x%04X (Bytes %d-%d)\n", 
                   ntohs(udp_header->uh_sum), offset + 6, offset + 7);
            printf("  └─ Hex: %02X %02X\n\n", packet[offset + 6], packet[offset + 7]);
            
            // === APPLICATION DATA ===
            int payload_offset = offset + 8;
            int payload_len = ntohs(udp_header->uh_ulen) - 8;
            
            if (payload_len > 0) {
                printf("📊 APPLICATION DATA (Layer 5-7)\n\n");
                printf("Payload Length:     %d bytes (Bytes %d-%d)\n", 
                       payload_len, payload_offset, payload_offset + payload_len - 1);
                
                u_short dport = ntohs(udp_header->uh_dport);
                u_short sport = ntohs(udp_header->uh_sport);
                const char *proto = "Unknown/Custom";
                if (dport == 53 || sport == 53) proto = "DNS";
                
                printf("Protocol:           %s (Port %d)\n\n", proto, (dport == 53) ? dport : sport);
                
                printf("First 64 bytes of payload:\n");
                printf("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
                
                int display_len = (payload_len > 64) ? 64 : payload_len;
                for (int i = 0; i < display_len; i += 16) {
                    printf("%04X ", payload_offset + i);
                    for (int j = 0; j < 16; j++) {
                        if (i + j < display_len) {
                            printf("%02X ", packet[payload_offset + i + j]);
                        } else {
                            printf("   ");
                        }
                    }
                    printf("    ");
                    for (int j = 0; j < 16 && i + j < display_len; j++) {
                        printf("%c", isprint(packet[payload_offset + i + j]) ? packet[payload_offset + i + j] : '.');
                    }
                    printf("\n");
                }
                
                if (payload_len > 64) {
                    printf("\n... and %d more bytes\n", payload_len - 64);
                }
            }
        }
        
    } else if (ether_type == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *)(packet + offset);
        
        printf("🔗 ARP HEADER (Layer 2/3)\n\n");
        
        printf("Hardware Type:      %d (Ethernet) (Bytes %d-%d)\n", 
               ntohs(arp_header->ea_hdr.ar_hrd), offset, offset + 1);
        printf("  └─ Hex: %02X %02X\n", packet[offset], packet[offset + 1]);
        
        printf("Protocol Type:      0x%04X (IPv4) (Bytes %d-%d)\n", 
               ntohs(arp_header->ea_hdr.ar_pro), offset + 2, offset + 3);
        printf("  └─ Hex: %02X %02X\n", packet[offset + 2], packet[offset + 3]);
        
        printf("HW Address Length:  %d bytes (Byte %d)\n", 
               arp_header->ea_hdr.ar_hln, offset + 4);
        printf("  └─ Hex: %02X\n", packet[offset + 4]);
        
        printf("Proto Address Len:  %d bytes (Byte %d)\n", 
               arp_header->ea_hdr.ar_pln, offset + 5);
        printf("  └─ Hex: %02X\n", packet[offset + 5]);
        
        u_short op = ntohs(arp_header->ea_hdr.ar_op);
        const char *op_name = (op == ARPOP_REQUEST) ? "Request" : (op == ARPOP_REPLY) ? "Reply" : "Unknown";
        printf("Operation:          %d (%s) (Bytes %d-%d)\n", op, op_name, offset + 6, offset + 7);
        printf("  └─ Hex: %02X %02X\n", packet[offset + 6], packet[offset + 7]);
        
        char sender_mac[18], target_mac[18];
        format_mac_address(arp_header->arp_sha, sender_mac);
        format_mac_address(arp_header->arp_tha, target_mac);
        
        printf("Sender MAC:         %s (Bytes %d-%d)\n", sender_mac, offset + 8, offset + 13);
        printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
               packet[offset + 8], packet[offset + 9], packet[offset + 10],
               packet[offset + 11], packet[offset + 12], packet[offset + 13]);
        
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);
        
        printf("Sender IP:          %s (Bytes %d-%d)\n", sender_ip, offset + 14, offset + 17);
        printf("  └─ Hex: %02X %02X %02X %02X\n",
               packet[offset + 14], packet[offset + 15], packet[offset + 16], packet[offset + 17]);
        
        printf("Target MAC:         %s (Bytes %d-%d)\n", target_mac, offset + 18, offset + 23);
        printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
               packet[offset + 18], packet[offset + 19], packet[offset + 20],
               packet[offset + 21], packet[offset + 22], packet[offset + 23]);
        
        printf("Target IP:          %s (Bytes %d-%d)\n", target_ip, offset + 24, offset + 27);
        printf("  └─ Hex: %02X %02X %02X %02X\n\n",
               packet[offset + 24], packet[offset + 25], packet[offset + 26], packet[offset + 27]);
    }
    
    printf("\n═══════════════════════════════════════════════════════════════════════════════\n");
    printf("                          END OF PACKET ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n\n");
    printf("Press Enter to continue...");
    getchar();
}

/*
 * Phase 5: Display summary list of all stored packets
 * Shows ID, timestamp, length, and basic protocol information
 */
void list_stored_packets() {
    if (stored_packet_count == 0) {
        printf("\n[C-Shark] No packets in storage. Please run a sniffing session first.\n");
        return;
    }
    
    printf("\n═══════════════════════════════════════════════════════════════════════════════\n");
    printf("                        STORED PACKETS SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════════════════════\n\n");
    printf("Total packets stored: %d (Max capacity: %d)\n\n", stored_packet_count, MAX_PACKETS);
    
    printf("%-6s %-20s %-8s %-10s %-15s %-15s\n", 
           "ID", "Timestamp", "Length", "L2/L3", "Source", "Destination");
    printf("─────────────────────────────────────────────────────────────────────────────────\n");
    
    for (int i = 0; i < stored_packet_count; i++) {
        stored_packet_t *pkt = &packet_storage[i];
        const u_char *packet = pkt->data;
        
        struct ether_header *eth_header = (struct ether_header *)packet;
        u_short ether_type = ntohs(eth_header->ether_type);
        
        const char *proto = "Unknown";
        char src[32] = "";
        char dst[32] = "";
        
        if (ether_type == ETHERTYPE_IPV4) {
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
            proto = (ip_header->ip_p == IPPROTO_TCP) ? "IPv4/TCP" : 
                    (ip_header->ip_p == IPPROTO_UDP) ? "IPv4/UDP" : "IPv4";
            
            inet_ntop(AF_INET, &(ip_header->ip_src), src, sizeof(src));
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst, sizeof(dst));
            
        } else if (ether_type == ETHERTYPE_IPV6) {
            proto = "IPv6";
            strcpy(src, "[IPv6]");
            strcpy(dst, "[IPv6]");
        } else if (ether_type == ETHERTYPE_ARP) {
            proto = "ARP";
            struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
            inet_ntop(AF_INET, arp_header->arp_spa, src, sizeof(src));
            inet_ntop(AF_INET, arp_header->arp_tpa, dst, sizeof(dst));
        }
        
        printf("%-6d %ld.%06ld %-8d %-10s %-15s %-15s\n",
               pkt->packet_id, pkt->timestamp.tv_sec, pkt->timestamp.tv_usec,
               pkt->length, proto, src, dst);
    }
    
    printf("─────────────────────────────────────────────────────────────────────────────────\n");
}

/*
 * Phase 5: Inspect last session - main menu handler
 * Lists packets and allows detailed inspection of selected packet
 */
void inspect_last_session() {
    if (stored_packet_count == 0) {
        printf("\n[C-Shark] No packets in storage. Please run a sniffing session first.\n");
        return;
    }
    
    while (1) {
        list_stored_packets();
        
        printf("\nEnter packet ID to inspect (or 0 to return): ");
        int packet_id;
        
        if (scanf("%d", &packet_id) != 1) {
            // Handle Ctrl+D or invalid input
            if (feof(stdin)) {
                printf("\n[C-Shark] Returning to main menu...\n");
                clearerr(stdin);
                return;
            }
            while (getchar() != '\n');
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        
        while (getchar() != '\n');  // Clear input buffer
        
        if (packet_id == 0) {
            return;  // Return to main menu
        }
        
        // Find packet by ID
        int found = -1;
        for (int i = 0; i < stored_packet_count; i++) {
            if (packet_storage[i].packet_id == packet_id) {
                found = i;
                break;
            }
        }
        
        if (found == -1) {
            printf("\n[Error] Packet ID #%d not found in storage.\n", packet_id);
            printf("Press Enter to continue...");
            getchar();
        } else {
            inspect_packet_detailed(found);
        }
    }
}

/*
 * Phase 3: Display filter menu and get user's filter choice
 * Returns the selected filter constant (FILTER_HTTP, FILTER_HTTPS, etc.)
 */
int select_filter() {
    int choice;
    
    printf("\n[C-Shark] Select a filter:\n\n");
    printf("1. HTTP (Port 80)\n");
    printf("2. HTTPS (Port 443)\n");
    printf("3. DNS (Port 53)\n");
    printf("4. ARP (Address Resolution Protocol)\n");
    printf("5. TCP (All TCP packets)\n");
    printf("6. UDP (All UDP packets)\n");
    printf("7. No Filter (Show all packets)\n\n");
    printf("Enter your choice (1-7): ");
    
    if (scanf("%d", &choice) != 1) {
        // Clear invalid input
        while (getchar() != '\n');
        return FILTER_NONE;
    }
    
    // Clear input buffer
    while (getchar() != '\n');
    
    // Map choice to filter constant
    switch(choice) {
        case 1: return FILTER_HTTP;
        case 2: return FILTER_HTTPS;
        case 3: return FILTER_DNS;
        case 4: return FILTER_ARP;
        case 5: return FILTER_TCP;
        case 6: return FILTER_UDP;
        case 7: return FILTER_NONE;
        default:
            printf("Invalid choice. Using no filter.\n");
            return FILTER_NONE;
    }
}

/*
 * Get filter name for display purposes
 */
const char* get_filter_name(int filter) {
    switch(filter) {
        case FILTER_HTTP: return "HTTP";
        case FILTER_HTTPS: return "HTTPS";
        case FILTER_DNS: return "DNS";
        case FILTER_ARP: return "ARP";
        case FILTER_TCP: return "TCP";
        case FILTER_UDP: return "UDP";
        case FILTER_NONE: return "None";
        default: return "Unknown";
    }
}

/*
 * Start packet capture on the selected interface
 * Opens the interface, configures capture, and starts the packet processing loop
 */
void start_sniffing(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Phase 4: Initialize storage for new session (frees previous session)
    if (initialize_packet_storage() == -1) {
        fprintf(stderr, "Failed to initialize packet storage. Aborting capture.\n");
        return;
    }
    
    printf("\n[C-Shark] Opening interface '%s' for capture...\n", device);
    if (active_filter != FILTER_NONE) {
        printf("[C-Shark] Active Filter: %s\n", get_filter_name(active_filter));
    }
    printf("[C-Shark] Press Ctrl+C to stop sniffing and return to menu.\n\n");
    
    // pcap_open_live() opens a network device for packet capture
    // Parameters:
    //   - device: network interface name (e.g., "wlan0")
    //   - snaplen: maximum bytes to capture per packet (BUFSIZ = usually 8192 bytes)
    //   - promisc: 1 = promiscuous mode (capture all packets, not just those destined for this host)
    //   - to_ms: read timeout in milliseconds (1000ms = 1 second)
    //   - errbuf: buffer for error messages
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        fprintf(stderr, "Note: You may need to run this program with sudo.\n");
        return;
    }
    
    // Reset state for new capture session
    stop_flag = 0;
    packet_counter = 0;  // Reset counter for each capture session
    
    // pcap_loop() processes packets from the network
    // Parameters:
    //   - handle: pcap session handle
    //   - cnt: number of packets to capture (-1 = infinite loop until error or pcap_breakloop)
    //   - callback: function to call for each packet (packet_handler)
    //   - user: user data to pass to callback (NULL = not used)
    // This call blocks until stopped by Ctrl+C (which calls pcap_breakloop)
    pcap_loop(handle, -1, packet_handler, NULL);
    
    // Close the pcap session and free resources
    pcap_close(handle);
    handle = NULL;
    
    printf("\n[C-Shark] Capture stopped. %d packets captured.\n", packet_counter);
}

/*
 * Task 1.2: Display main menu and handle user choices
 * This function loops until user chooses to exit (option 4)
 */
void main_menu(const char *device) {
    int choice;
    
    while (1) {
        printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", device);
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Inspect Last Session\n");
        printf("4. Exit C-Shark\n\n");
        printf("Enter your choice (1-4): ");
        
        // Read user input and validate
        if (scanf("%d", &choice) != 1) {
            // Handle Ctrl+D (EOF) - graceful exit
            // feof() checks if end-of-file condition is set on stdin
            if (feof(stdin)) {
                printf("\n[C-Shark] Exiting gracefully...\n");
                exit(0);
            }
            // Clear invalid input from buffer
            while (getchar() != '\n');
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        
        // Clear input buffer after successful scanf
        while (getchar() != '\n');
        
        // Process user's menu selection
        switch(choice) {
            case 1:
                active_filter = FILTER_NONE;  // No filter for option 1
                start_sniffing(device);  // Start capturing packets
                break;
            case 2:
                // Phase 3: Start sniffing with filters
                active_filter = select_filter();
                start_sniffing(device);
                break;
            case 3:
                // Phase 5: Inspect last session
                inspect_last_session();
                break;
            case 4:
                printf("\n[C-Shark] Exiting gracefully...\n");
                return;  // Exit menu loop and return to main
            default:
                printf("\nInvalid choice. Please select 1-4.\n");
        }
    }
}

/*
 * Main function - Entry point of the program
 * Coordinates the initialization, interface selection, and main menu
 */
int main(int argc, char *argv[]) {
    (void)argc; // Unused parameter (no command-line arguments used)
    (void)argv; // Unused parameter
    
    char *device;
    
    // Setup signal handlers for graceful exit (Ctrl+C handling)
    setup_signal_handlers();
    
    // Display banner (Phase 1 requirement)
    printf("\n[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    
    // Task 1.1: Device discovery and selection
    // User selects which network interface to monitor
    device = select_interface();
    if (device == NULL) {
        fprintf(stderr, "Failed to select an interface.\n");
        return 1;
    }
    
    // Task 1.2: Main menu
    // Enter interactive menu for packet capture
    main_menu(device);
    
    // Cleanup - free dynamically allocated memory
    free(device);
    free_packet_storage();  // Phase 4: Free stored packets
    
    return 0;
}
// LLM generated code ends