#ifndef TCP_IP_HEADERS_H
#define TCP_IP_HEADERS_H

#include <cstddef>
#include <cstdint>

// Headers are read byte by byte in network order, so the code does not depend on the
// host's endianness or on how a compiler lays out bit fields.

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10

inline uint16_t ReadBe16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t ReadBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

// Link-layer header types (https://www.tcpdump.org/linktypes.html) that carry IPv4.
enum LinkType : uint32_t {
    kLinkNull = 0,         // BSD loopback, host-order address family
    kLinkEthernet = 1,
    kLinkRawOld = 12,      // raw IP, as some systems wrote it
    kLinkRaw = 101,        // raw IP
    kLinkLoop = 108,       // OpenBSD loopback, network-order address family
    kLinkLinuxSll = 113,   // Linux cooked capture ("tcpdump -i any")
    kLinkIpv4 = 228,       // raw IPv4
    kLinkLinuxSll2 = 276,  // Linux cooked capture v2
};

inline bool IsSupportedLinkType(uint32_t link_type) {
    switch (link_type) {
        case kLinkNull: case kLinkEthernet: case kLinkRawOld: case kLinkRaw:
        case kLinkLoop: case kLinkLinuxSll: case kLinkIpv4: case kLinkLinuxSll2:
            return true;
    }
    return false;
}

// Offset of the IPv4 header in a frame, or -1 if the frame does not carry IPv4.
inline long IpOffset(uint32_t link_type, const uint8_t* frame, size_t length) {
    const uint16_t kEtherTypeIpv4 = 0x0800;
    switch (link_type) {
        case kLinkEthernet: {
            size_t offset = 12;  // destination + source MAC
            for (int tags = 0; tags <= 2; ++tags) {
                if (length < offset + 2) return -1;
                uint16_t ether_type = ReadBe16(frame + offset);
                if (ether_type == kEtherTypeIpv4) return static_cast<long>(offset + 2);
                if (ether_type != 0x8100 && ether_type != 0x88A8 && ether_type != 0x9100) return -1;
                offset += 4;  // skip a VLAN tag
            }
            return -1;
        }
        case kLinkLinuxSll:
            return length >= 16 && ReadBe16(frame + 14) == kEtherTypeIpv4 ? 16 : -1;
        case kLinkLinuxSll2:
            return length >= 20 && ReadBe16(frame) == kEtherTypeIpv4 ? 20 : -1;
        case kLinkRawOld: case kLinkRaw: case kLinkIpv4:
            return length >= 1 && (frame[0] >> 4) == 4 ? 0 : -1;
        case kLinkNull: case kLinkLoop: {
            if (length < 4) return -1;
            uint32_t family = ReadBe32(frame);
            return family == 2 || family == 0x02000000 ? 4 : -1;  // AF_INET in either byte order
        }
    }
    return -1;
}

struct TcpPacketInfo {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t flags;
};

// Parses an IPv4 packet carrying TCP. Returns false for anything else, including IP
// fragments other than the first one (they don't start with a TCP header).
inline bool ParseIpv4Tcp(const uint8_t* ip, size_t length, TcpPacketInfo& info) {
    const size_t kMinIpHeader = 20;
    const size_t kTcpHeader = 20;
    const uint8_t kProtocolTcp = 6;
    if (length < kMinIpHeader || (ip[0] >> 4) != 4) return false;
    size_t ip_header_length = static_cast<size_t>(ip[0] & 0x0F) * 4;
    if (ip_header_length < kMinIpHeader || ip[9] != kProtocolTcp) return false;
    if ((ReadBe16(ip + 6) & 0x1FFF) != 0) return false;  // fragment offset
    if (length < ip_header_length + kTcpHeader) return false;

    const uint8_t* tcp = ip + ip_header_length;
    info.src_ip = ReadBe32(ip + 12);
    info.dst_ip = ReadBe32(ip + 16);
    info.src_port = ReadBe16(tcp);
    info.dst_port = ReadBe16(tcp + 2);
    info.flags = tcp[13];
    return true;
}

#endif // TCP_IP_HEADERS_H
