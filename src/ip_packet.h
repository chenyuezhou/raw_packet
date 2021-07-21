/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#ifndef IP_PACKET_H
#define IP_PACKET_H

int parser_ip_packet(void *buffer, uint32_t saddr, uint32_t daddr,
                     uint16_t size);

#endif /* IP_PACKET_H */
