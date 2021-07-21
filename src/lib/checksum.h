/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#ifndef CHECKSUM_H
#define CHECKSUM_H

static inline uint32_t from64to32(uint64_t x) {
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (uint32_t) x;
}

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

uint16_t ip_v4_check(const void *iph, uint32_t ihl);
uint16_t tcp_v4_check(uint32_t saddr, uint32_t daddr, uint32_t len,
                      uint8_t proto, uint16_t *tcp_pkt);

#endif /* CHECKSUM_H */
