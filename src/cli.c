#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"

static const char *proto_name(int p) {
    switch (p) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "?";
    }
}

typedef struct {
    int format_json;
    int count;
} Ctx;

static int on_pkt(const ParsedPacket *p, void *user) {
    Ctx *ctx = user;
    if (ctx->format_json) {
        if (ctx->count) printf(",\n");
        printf("  {\"ts\":%.6f,\"eth\":%d,\"proto\":%d,"
               "\"src\":\"%s\",\"dst\":\"%s\","
               "\"sport\":%d,\"dport\":%d,\"len\":%u,\"flags\":%u}",
               p->timestamp, p->eth_type, p->ip_proto,
               p->src_ip, p->dst_ip, p->src_port, p->dst_port,
               p->length, p->tcp_flags);
    } else {
        printf("%14.6f  %-4s  %-22s -> %-22s  len=%u\n",
               p->timestamp, proto_name(p->ip_proto),
               p->src_port >= 0 ? "" : p->src_ip,
               p->dst_port >= 0 ? "" : p->dst_ip,
               p->length);
        if (p->src_port >= 0)
            printf("%14s  %-4s  %s:%d -> %s:%d\n", "", "",
                   p->src_ip, p->src_port, p->dst_ip, p->dst_port);
    }
    ctx->count++;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s [--json] <file.pcap>\n", argv[0]);
        return 1;
    }
    Ctx ctx = {0};
    const char *path = argv[1];
    if (strcmp(argv[1], "--json") == 0 && argc >= 3) {
        ctx.format_json = 1;
        path = argv[2];
        printf("[\n");
    }

    int n = parse_pcap(path, on_pkt, &ctx);
    if (ctx.format_json) printf("\n]\n");
    if (n < 0) return 1;
    if (!ctx.format_json)
        fprintf(stderr, "\nParsed %d packets from %s\n", n, path);
    return 0;
}
