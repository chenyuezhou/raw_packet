/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#define MAX_FRAME 1500
#define MAX_PAYLOAD (1500 - sizeof(struct ethhdr), sizeof(struct iphdr) \
        - sizeof(struct tcphdr))
#define MAX_TCPPAYLOAD (1500 - sizeof(struct tcphdr))

typedef struct {
    uint16_t source;
    uint16_t dest;
    uint32_t saddr;
    uint32_t daddr;
    uint32_t ack;
    uint32_t seq;
    int      type; /* syn, fin, ... */
} config_t;

extern config_t config;

#endif /* RAW_SOCKET_H */
