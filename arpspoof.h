#include<stdint.h>
#ifndef ARPSPOOF_H
#define ARPSPOOF_H
#endif // ARPSPOOF_H

#pragma pack(push,1)
struct ethernet_header{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct arp_header{
    uint16_t hd_type;
    uint16_t proto_type;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};

struct arp_packet{
    struct ethernet_header eth;
    struct arp_header arp;
};

struct session{
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
    struct arp_packet * request_st;
    struct arp_packet * request_ts;
    bool check;
};





#pragma pack(pop)
