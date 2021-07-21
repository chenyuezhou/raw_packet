/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#include <stdint.h>
#include <endian.h>

#include "checksum.h"

#ifndef __force
#define __force
#endif

static inline uint16_t csum_fold(uint64_t csum) {
    uint32_t sum = (__force uint64_t) csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__force uint16_t)~sum;
}

static inline uint32_t csum_tcpudp_nofold(uint32_t saddr, uint32_t daddr,
                                          uint32_t len, uint8_t proto,
                                          uint32_t sum) {
    uint64_t s = (__force uint32_t) sum;

    s += (__force uint32_t) saddr;
    s += (__force uint32_t) daddr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    s += (proto + len) << 8;
#else
    s += proto + len;
#endif
    return (__force uint32_t) from64to32(s);
}

static inline uint16_t csum_tcpudp_magic(uint32_t saddr, uint32_t daddr,
                                         uint32_t len, uint8_t proto,
                                         uint32_t sum) {
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

uint16_t tcp_v4_check(uint32_t saddr, uint32_t daddr, uint32_t len,
                      uint8_t proto, uint16_t *tcp_pkt) {
    uint32_t csum = 0;
    uint32_t cnt = 0;

    /* tcp hdr and data */
    for (; cnt < len; cnt += 2)
        csum += tcp_pkt[cnt >> 1];

    return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
	unsigned int result = 0;
	int odd;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long)buff;
	if (odd) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff +
						   ((unsigned int)len & ~3);
			unsigned int carry = 0;

			do {
				unsigned int w = *(unsigned int *)buff;

				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
#if __BYTE_ORDER == __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

uint16_t ip_v4_check(const void *iph, uint32_t hsize) {
    return (__force uint16_t)~do_csum(iph, hsize);
}
