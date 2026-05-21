#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

static uint16_t be16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

int parse_pcap(const char *path,
               int (*on_packet)(const ParsedPacket *, void *),
               void *user) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }

    PcapGlobalHeader gh;
    if (fread(&gh, sizeof(gh), 1, f) != 1) {
        fprintf(stderr, "Truncated pcap\n"); fclose(f); return -1;
    }

    int swap = (gh.magic == 0xd4c3b2a1);
    if (gh.magic != 0xa1b2c3d4 && gh.magic != 0xd4c3b2a1) {
        fprintf(stderr, "Not a libpcap file (magic=0x%08x)\n", gh.magic);
        fclose(f);
        return -1;
    }

    int network = swap ? __builtin_bswap32(gh.network) : gh.network;
    if (network != 1) {  /* DLT_EN10MB */
        fprintf(stderr, "Only Ethernet pcaps supported (got DLT=%d)\n", network);
        fclose(f); return -1;
    }

    uint8_t buf[65536];
    int n_packets = 0;

    PcapRecordHeader rh;
    while (fread(&rh, sizeof(rh), 1, f) == 1) {
        uint32_t inc = swap ? __builtin_bswap32(rh.incl_len) : rh.incl_len;
        uint32_t sec = swap ? __builtin_bswap32(rh.ts_sec)   : rh.ts_sec;
        uint32_t us  = swap ? __builtin_bswap32(rh.ts_usec)  : rh.ts_usec;
        if (inc > sizeof(buf)) { fseek(f, inc, SEEK_CUR); continue; }
        if (fread(buf, 1, inc, f) != inc) break;

        if (inc < ETH_HDR_LEN) continue;

        ParsedPacket p;
        memset(&p, 0, sizeof(p));
        p.timestamp = (double)sec + us / 1e6;
        p.length    = inc;
        p.src_port  = p.dst_port = -1;
        p.ip_proto  = -1;
        p.eth_type  = be16(&buf[12]);

        if (p.eth_type == 0x0800 && inc >= 14 + 20) {   /* IPv4 */
            const uint8_t *ip = buf + 14;
            int ihl = (ip[0] & 0xF) * 4;
            p.ip_proto = ip[9];
            snprintf(p.src_ip, sizeof(p.src_ip), "%u.%u.%u.%u",
                     ip[12], ip[13], ip[14], ip[15]);
            snprintf(p.dst_ip, sizeof(p.dst_ip), "%u.%u.%u.%u",
                     ip[16], ip[17], ip[18], ip[19]);
            if ((p.ip_proto == 6 || p.ip_proto == 17) &&
                inc >= (uint32_t)(14 + ihl + 4)) {
                const uint8_t *l4 = ip + ihl;
                p.src_port = be16(l4);
                p.dst_port = be16(l4 + 2);
                if (p.ip_proto == 6 && inc >= (uint32_t)(14 + ihl + 14))
                    p.tcp_flags = l4[13];
            }
        } else if (p.eth_type == 0x86DD && inc >= 14 + 40) { /* IPv6 */
            const uint8_t *ip = buf + 14;
            p.ip_proto = ip[6];
            char tmp[40];
            inet_ntop(AF_INET6, ip + 8,  tmp, sizeof(tmp));
            snprintf(p.src_ip, sizeof(p.src_ip), "%s", tmp);
            inet_ntop(AF_INET6, ip + 24, tmp, sizeof(tmp));
            snprintf(p.dst_ip, sizeof(p.dst_ip), "%s", tmp);
        } else if (p.eth_type == 0x0806) {
            strcpy(p.src_ip, "(arp)"); strcpy(p.dst_ip, "(arp)");
        }

        if (on_packet(&p, user) < 0) break;
        n_packets++;
    }

    fclose(f);
    return n_packets;
}
