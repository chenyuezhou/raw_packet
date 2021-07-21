/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "ip_packet.h"
#include "lib/checksum.h"

int parser_ip_packet(void *buffer, uint32_t saddr, uint32_t daddr,
                     uint16_t size) {
    struct iphdr *hdr = buffer;

    memset(hdr, 0, sizeof(struct iphdr));
    hdr->version = 4;
    /* without options */
    hdr->ihl = 5;
    hdr->tot_len = size + hdr->ihl * 4;
    hdr->frag_off = htons(IP_DF);
    hdr->ttl = IPDEFTTL;
    /* /etc/protocols
     * ...
     * tcp     6       TCP             # transmission control protocol
     * ...
     */
    hdr->protocol = IPPROTO_TCP;
    hdr->saddr = saddr;
    hdr->daddr = daddr;
    hdr->check = ip_v4_check(hdr, hdr->ihl * 4);

    return hdr->ihl * 4;
}
