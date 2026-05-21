#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stdio.h>

#define ETH_HDR_LEN 14

typedef struct {
    uint16_t magic;
    uint16_t major, minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} PcapGlobalHeader;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} PcapRecordHeader;

typedef struct {
    double   timestamp;
    int      eth_type;       /* 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6 */
    int      ip_proto;       /* 6=TCP, 17=UDP, 1=ICMP, -1 = N/A           */
    char     src_ip[40];
    char     dst_ip[40];
    int      src_port;
    int      dst_port;
    uint32_t length;
    uint8_t  tcp_flags;
} ParsedPacket;

int parse_pcap(const char *path,
               int (*on_packet)(const ParsedPacket *, void *),
               void *user);

#endif
