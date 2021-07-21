/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#ifndef TCP_PACKET_H
#define TCP_PACKET_H

typedef struct {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t source;
    uint16_t dest;
} tcp_four_tuple_t;

static inline void tcp_set_type(struct tcphdr *hdr, int type) {
    if (type & TCP_FLAG_CWR)
        hdr->cwr = 1;
    if (type & TCP_FLAG_ECE)
        hdr->ece = 1;
    if (type & TCP_FLAG_URG)
        hdr->urg = 1;
    if (type & TCP_FLAG_ACK)
        hdr->ack = 1;
    if (type & TCP_FLAG_PSH)
        hdr->psh = 1;
    if (type & TCP_FLAG_RST)
        hdr->rst = 1;
    if (type & TCP_FLAG_SYN)
        hdr->syn = 1;
    if (type & TCP_FLAG_FIN)
        hdr->fin = 1;
}

int parser_tcp_packet(void *buffer, char *msg, size_t size,
                      tcp_four_tuple_t *ftuple, int type);

#endif /* TCP_PACKET_H */
