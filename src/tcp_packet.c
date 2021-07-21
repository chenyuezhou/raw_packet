/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#include <string.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "tcp_packet.h"
#include "raw_socket.h"
#include "lib/checksum.h"

config_t config;

int parser_tcp_packet(void *buffer, char *msg, size_t size,
                      tcp_four_tuple_t *ftuple, int type) {
    struct tcphdr *hdr = buffer;

    memset(hdr, 0, sizeof(struct tcphdr));
    hdr->source = ftuple->source;
    hdr->dest = ftuple->dest;
    hdr->seq = config.seq;
    hdr->ack_seq = config.ack;
    hdr->window = htons(65535);
    hdr->urg_ptr = 0;
    /* without option */
    hdr->doff = sizeof(struct tcphdr) / 4;
    tcp_set_type(hdr, type);

    memcpy(buffer + hdr->doff, msg, size);
    hdr->check = 0;
    hdr->check = tcp_v4_check(ftuple->saddr, ftuple->daddr, hdr->doff * 4 + size,
                              IPPROTO_TCP, (uint16_t *) hdr);

    return hdr->doff * 4;
}
