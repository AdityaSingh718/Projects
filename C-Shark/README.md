# C-Shark: The Command-Line Packet Predator

A powerful network packet sniffer built in C using libpcap for comprehensive network traffic analysis.

## 📄 Summary

**C-Shark** is a command-line packet analyzer that captures and dissects network traffic in real-time. It implements a complete 5-phase packet sniffing workflow:

1. **Interface Selection** - Auto-discovers and lists available network interfaces
2. **Layer-by-Layer Dissection** - Decodes Ethernet, IPv4/IPv6, ARP, TCP/UDP protocols
3. **Smart Filtering** - Filters traffic by protocol (HTTP, HTTPS, DNS, ARP, TCP, UDP)
4. **Packet Storage** - Stores up to 10,000 packets per session in memory
5. **Forensic Inspection** - Provides detailed byte-level analysis with hex dumps

**Key Capabilities:**
- ✅ Real-time packet capture with libpcap
- ✅ Multi-layer protocol dissection (L2→L7)
- ✅ Interactive filtering system (7 filter types)
- ✅ In-memory packet storage (10,000 capacity)
- ✅ Detailed forensic inspection with byte offsets
- ✅ Graceful signal handling (Ctrl+C returns to menu)

**Technical Stack:** C, libpcap, standard POSIX networking libraries  
**Lines of Code:** 1,476 | **Binary Size:** 39KB  
**Supported Protocols:** IPv4, IPv6, ARP, TCP, UDP, HTTP, HTTPS, DNS

---

## 🦈 Features

### Phase 1: Interface & Basic Capture
- **Device Discovery**: Automatically scans and lists all available network interfaces
- **Interactive Selection**: User-friendly interface selection menu
- **Live Packet Capture**: Real-time packet monitoring with basic information display
- **Graceful Controls**: 
  - `Ctrl+C`: Stop capture and return to menu (doesn't exit program)
  - `Ctrl+D`: Clean exit from anywhere in the application

### Phase 2: Layer-by-Layer Dissection

#### Layer 2 (Data Link)
- Ethernet frame analysis
- Source and destination MAC addresses
- EtherType identification (IPv4, IPv6, ARP)

#### Layer 3 (Network)
**IPv4 Support:**
- Source and destination IP addresses
- Protocol identification (TCP, UDP, ICMP)
- TTL, Packet ID, Total Length, Header Length
- Flag decoding (Don't Fragment, More Fragments)

**IPv6 Support:**
- Source and destination IPv6 addresses
- Next Header protocol identification
- Hop Limit, Traffic Class, Flow Label
- Payload Length

**ARP Support:**
- Operation type (Request/Reply)
- Sender and target IP/MAC addresses
- Hardware and protocol type information

#### Layer 4 (Transport)
**TCP Support:**
- Source and destination ports (with common port identification)
- Sequence and acknowledgment numbers
- Flag decoding (SYN, ACK, FIN, RST, PSH, URG)
- Window size, checksum, header length

**UDP Support:**
- Source and destination ports
- Length and checksum

#### Layer 7 (Application/Payload)
- Application protocol identification (HTTP, HTTPS, DNS)
- Payload length display
- Hex dump of first 64 bytes
- Combined hex and ASCII representation

### Phase 3: Precision Hunting - Filtering
- **Interactive Filter Menu**: Choose from 7 filter options
- **Protocol-Based Filtering**:
  - HTTP (Port 80) - Show only HTTP traffic
  - HTTPS (Port 443) - Show only HTTPS/TLS traffic
  - DNS (Port 53) - Show DNS queries/responses (TCP/UDP)
  - ARP - Show only Address Resolution Protocol packets
  - TCP - Show all TCP packets regardless of port
  - UDP - Show all UDP packets regardless of port
- **Multi-Layer Filtering**: Works across IPv4 and IPv6
- **Efficient Processing**: Filtered packets skip unnecessary decoding

### Phase 4: The Packet Aquarium - Saving Your Catch
- **Packet Storage**: Automatically stores captured packets in memory
- **Session Management**: Up to 10,000 packets per session
- **Automatic Cleanup**: Previous session cleared on new capture
- **Memory Safe**: Proper allocation and deallocation
- **Filtered Storage**: Only matching packets stored when filter active

### Phase 5: The Digital Forensics Lab - In-Depth Inspection
- **Packet List View**: Summary table of all stored packets
- **Interactive Selection**: Choose packet by ID for detailed analysis
- **Complete Hex Dump**: Full packet frame in hex format
- **Layer-by-Layer Breakdown**: Comprehensive field-by-field analysis
- **Byte-Level Details**: Raw hex values with byte offsets
- **Field Interpretation**: Human-readable explanations
- **Payload Inspection**: First 64 bytes with hex/ASCII display
- **Protocol Detection**: Automatic identification (HTTP/HTTPS/DNS/etc.)

## 📋 Requirements

- **Operating System**: Linux (tested on Ubuntu/Debian)
- **Libraries**: libpcap development library
- **Permissions**: Root/sudo access (required for packet capture)
- **Compiler**: GCC

## 🔧 Installation

### Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y libpcap-dev gcc make

# Or use the Makefile
make install-deps
```

### Build the Project

```bash
make
```

This will compile `cshark.c` and create the `cshark` executable.

## 🚀 Usage

### Run C-Shark

```bash
sudo ./cshark
```

**Note:** Root privileges are required for packet capture.

### Quick Start

1. **Launch the program**: `sudo ./cshark`
2. **Select an interface**: Choose from the numbered list (e.g., wlan0, eth0)
3. **Choose mode**:
   - **Option 1**: Capture all packets without filter
   - **Option 2**: Capture with filter (HTTP, HTTPS, DNS, ARP, TCP, UDP)
   - **Option 3**: Inspect packets from last session
   - **Option 4**: Exit program
4. **Stop capture**: Press `Ctrl+C` to return to menu
5. **View stored packets**: Select option 3 to browse and inspect captured packets

## 📊 Example Output

### Live Packet Capture with HTTPS Filter
```
[C-Shark] The Command-Line Packet Predator
==============================================
[C-Shark] Searching for available interfaces... Found!

1. wlan0
2. any (Pseudo-device that captures on all interfaces)
3. lo

Select an interface to sniff (1-3): 1

[C-Shark] Interface 'wlan0' selected. What's next?

1. Start Sniffing (All Packets)
2. Start Sniffing (With Filters)
3. Inspect Last Session <-- Not implemented yet
4. Exit C-Shark

Enter your choice (1-4): 2

[C-Shark] Select a filter:

1. HTTP (Port 80)
2. HTTPS (Port 443)
3. DNS (Port 53)
4. ARP (Address Resolution Protocol)
5. TCP (All TCP packets)
6. UDP (All UDP packets)
7. No Filter (Show all packets)

Enter your choice (1-7): 2

[C-Shark] Opening interface 'wlan0' for capture...
[C-Shark] Active Filter: HTTPS
[C-Shark] Press Ctrl+C to stop sniffing and return to menu.

-----------------------------------------
Packet #1 | Timestamp: 1757370992.553060 | Length: 66 bytes
L2 (Ethernet): Dst MAC: E6:51:4A:2D:B0:F9 | Src MAC: B4:8C:9D:5D:86:A1 | EtherType: IPv4 (0x0800)
L3 (IPv4): Src IP: 192.168.1.1 | Dst IP: 192.168.1.100 | Protocol: TCP (6) | TTL: 64
           ID: 0xA664 | Total Length: 52 | Header Length: 20 bytes
L4 (TCP): Src Port: 443 (HTTPS) | Dst Port: 54321 | Seq: 123456789 | Ack: 987654321 | Flags: [ACK]
          Window: 65535 | Checksum: 0x1234 | Header Length: 20 bytes
```

### Forensic Inspection Example
```
═══════════════════════════════════════════════════════════════════════════════
                     C-SHARK DETAILED PACKET ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

🦈 PACKET SUMMARY

Packet ID:       #42
Timestamp:       1757370992.553060
Frame Length:    66 bytes

📦 COMPLETE FRAME HEX DUMP
─────────────────────────────────────────────────────────────────────────────────
     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII
0000 E6 51 4A 2D B0 F9 B4 8C 9D 5D 86 A1 08 00 45 00     .QJ-.....]....E.
0010 00 34 A6 64 40 00 40 06 12 34 C0 A8 01 01 C0 A8     .4.d@.@..4......

🔗 ETHERNET II FRAME (Layer 2)

Destination MAC:    E6:51:4A:2D:B0:F9 (Bytes 0-5)
  └─ Hex: E6 51 4A 2D B0 F9
Source MAC:         B4:8C:9D:5D:86:A1 (Bytes 6-11)
  └─ Hex: B4 8C 9D 5D 86 A1
EtherType:          0x0800 (IPv4) (Bytes 12-13)
  └─ Hex: 08 00

🌐 IPv4 HEADER (Layer 3)

Version:            4 (4-bit field in byte 14)
Header Length:      20 bytes (5 * 4)
Protocol:           6 (TCP) (Byte 23)
Source IP:          192.168.1.1 (Bytes 26-29)
Destination IP:     192.168.1.100 (Bytes 30-33)

🔌 TCP HEADER (Layer 4)

Source Port:        443 (HTTPS) (Bytes 34-35)
Destination Port:   54321 (Bytes 36-37)
Flags:              0x10 (Byte 47)
  └─ URG:0 ACK:1 PSH:0 RST:0 SYN:0 FIN:0
```

## 🏗️ Architecture

### Code Structure (1,476 lines)

```
cshark.c
├── Phase 1 & 2: Core Capture (863 lines)
│   ├── Signal Handlers (Ctrl+C, Ctrl+D)
│   ├── Device Discovery (select_interface)
│   ├── Packet Handler (packet_handler)
│   ├── Layer 2 Processing (Ethernet)
│   ├── Layer 3 Processing (IPv4, IPv6, ARP)
│   └── Layer 4 Processing (TCP, UDP)
├── Phase 3: Filtering System (+170 lines)
│   ├── matches_filter() - Multi-protocol filter logic
│   ├── select_filter() - Interactive filter menu
│   └── get_filter_name() - Display helper
├── Phase 4: Packet Storage (+80 lines)
│   ├── initialize_packet_storage() - Allocate memory
│   ├── store_packet() - Store individual packets
│   └── free_packet_storage() - Cleanup
└── Phase 5: Forensic Inspection (+525 lines)
    ├── list_stored_packets() - Summary table
    ├── inspect_packet_detailed() - 359-line analysis function
    ├── print_full_hex_dump() - Complete frame hex display
    └── inspect_last_session() - Interactive menu
```

### Implementation Details

**Core Components:**
- **30+ functions** organized by protocol layer
- **Filter integration** at packet_handler entry point (early rejection)
- **Dynamic memory** management for packet storage (malloc/free)
- **Static warning flags** to prevent repeated error messages
- **Signal-safe** Ctrl+C handling with pcap_breakloop()

**Key Functions:**
- `packet_handler()` - Main callback with filter check + storage integration
- `matches_filter()` - Multi-layer protocol matching (95 lines)
- `store_packet()` - Memory allocation and packet copying
- `inspect_packet_detailed()` - Comprehensive 359-line analysis function
- `process_ipv4()/process_ipv6()/process_arp()` - Layer 3 decoders

**Data Flow:**
```
pcap_loop() → packet_handler()
    ↓
1. Check matches_filter() → Return if no match
2. Increment packet_counter
3. Call store_packet()
4. Display packet info
5. Decode layers (L2→L3→L4→L7)
```

## 🛠️ Makefile Targets

```bash
make              # Build the executable
make clean        # Remove compiled files
make run          # Build and run with sudo
make install-deps # Install libpcap-dev
make help         # Show help message
```

## 🔒 Security & Ethics

**Important Notes:**
- This tool is for **educational purposes** and network analysis only
- Only use on networks you own or have explicit permission to monitor
- The program is **read-only** - it strictly captures packets without modifying or injecting traffic
- Requires root access due to raw socket operations
- Unauthorized network sniffing may be illegal in your jurisdiction

## 🐛 Troubleshooting

### "Couldn't open device" Error
- Make sure you're running with `sudo`
- Check if the selected interface exists: `ip link show`

### "Cannot open source file pcap.h"
- Install libpcap development files: `sudo apt-get install libpcap-dev`

### No Packets Captured
- Ensure the interface is up: `sudo ip link set <interface> up`
- Try a different interface (e.g., `any` for all interfaces)
- Check if there's actual traffic on the interface

## 📚 Technical Implementation

### Development Environment
- **Language:** C (C99 standard)
- **Compiler:** GCC with flags: `-Wall -Wextra -O2`
- **Dependencies:** libpcap-dev
- **Platform:** Linux (POSIX-compliant)
- **Build System:** Makefile

### Libraries & Headers
- `<pcap.h>`: libpcap packet capture library
- `<net/ethernet.h>`: Ethernet frame structures (struct ether_header)
- `<netinet/ip.h>`: IPv4 structures (struct ip)
- `<netinet/ip6.h>`: IPv6 structures (struct ip6_hdr)
- `<netinet/tcp.h>`: TCP structures (struct tcphdr)
- `<netinet/udp.h>`: UDP structures (struct udphdr)
- `<netinet/if_ether.h>`: ARP structures (struct ether_arp)
- `<arpa/inet.h>`: Address conversion (inet_ntop)

### Byte Order & Address Handling
The program uses proper network-to-host byte order conversions:
- `ntohs()` - Network to host short (16-bit): ports, lengths, checksums
- `ntohl()` - Network to host long (32-bit): sequence numbers, IP IDs
- `inet_ntop()` - Binary to presentation format for IP addresses (IPv4/IPv6)

### Memory Management
- **Dynamic Allocation:** `malloc()` for packet data, `calloc()` for storage array
- **Proper Cleanup:** `free()` for all allocated memory, session-based cleanup
- **Capacity Control:** MAX_PACKETS (10,000) enforced with storage full detection
- **Memory Safety:** NULL checks, bounds validation, no memory leaks

### Performance Characteristics
- **Packet Processing:** O(1) filter check per packet
- **Storage Operation:** O(1) append with memcpy()
- **Inspection Search:** O(n) linear search by packet ID
- **Memory Footprint:** ~15MB maximum (10,000 packets × ~1.5KB average)
- **Filter Efficiency:** Early return avoids unnecessary processing

---

## 📄 Project Statistics

| Metric | Value |
|--------|-------|
| **Total Lines** | 1,476 |
| **Binary Size** | 39 KB |
| **Functions** | 30+ |
| **Protocols Supported** | IPv4, IPv6, ARP, TCP, UDP, ICMP |
| **Filter Types** | 7 (HTTP, HTTPS, DNS, ARP, TCP, UDP, None) |
| **Storage Capacity** | 10,000 packets/session |
| **Compilation Warnings** | 0 |
| **Memory Leaks** | 0 |

---

## 📖 Additional Documentation

- **BUG_FIX_REPORT.md** - Details of Phase 4/5 integration fix
- **PHASE4_PHASE5_IMPLEMENTATION.md** - Technical implementation guide
- **PROJECT_COMPLETE.md** - Complete project summary
- **QUICK_START.md** - Quick reference card

---

## 👨‍💻 Author & License

**C-Shark** - Built for educational purposes and network analysis.  
Licensed under standard academic use terms.

**Disclaimer:** This tool is for authorized network analysis only. Unauthorized packet sniffing may violate laws in your jurisdiction.