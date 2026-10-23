#ifndef TCP_IP_HEADERS_H
#define TCP_IP_HEADERS_H

#include <cstdint>

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10
#define ETHERTYPE_IP 0x0800

#pragma pack(push, 1)
struct ip {
    uint8_t ip_hl : 4, ip_v : 4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

struct tcphdr_session {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_off : 4;
    uint8_t reserved1_padding : 4;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};
#pragma pack(pop)

#endif // TCP_IP_HEADERS_H