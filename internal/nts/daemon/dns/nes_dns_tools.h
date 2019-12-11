/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dns_tools.h
 * @brief Header file for nes_dns_tools
 */

#ifndef NES_DNS_TOOLS_H
#define	NES_DNS_TOOLS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include "nes_common.h"

/**
 * @brief Convert labels from DNS packet to domain
 *
 * @param[in] labels - domain labels
 * @param[in] domain_len - domain length
 * @param[out] domain - created domain
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dns_labels_to_domain(const char *labels, char *domain, uint8_t domain_len);

/**
 * @brief Check if provided mbuf contains IPv4 packet
 *
 * @param[in] m - packet in rte_mbuf
 * @return NES_SUCCESS if provided packet is IPv4 and NES_FAIL otherwise.
 */
static inline int nes_dns_is_ip(struct rte_mbuf *m) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	return eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4) ? NES_SUCCESS : NES_FAIL;
}

/**
 * @brief Check if provided mbuf contains ARP packet
 *
 * @param[in] m - packet in rte_mbuf
 * @return NES_SUCCESS if provided packet is ARP and NES_FAIL otherwise.
 */
static inline int nes_dns_is_arp(struct rte_mbuf *m) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	return eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP) ? NES_SUCCESS : NES_FAIL;
}

/**
 * @brief Update checksum, final step
 *
 * @param[in] partial - partial checksum
 * @return final checksum
 */
static inline uint16_t
nes_dns_recompute_cksum16_finish(uint32_t partial) {
	while (partial >> 16)
		partial = (partial & 0xffff) + (partial >> 16);

	return ~partial;
}

/**
 * @brief Update checksum
 *
 * @param[in] old_csum - old checksum
 * @param[in] old_u16 - two bytes value that changed
 * @param[in] new_u16 - new two bytes value
 * @return final checksum
 */
static inline uint16_t
nes_dns_recompute_cksum16(uint16_t old_csum, uint16_t old_u16, uint16_t new_u16) {
	uint16_t hc_complement = ~old_csum;
	uint16_t m_complement = ~old_u16;
	uint16_t m_prime = new_u16;
	uint32_t sum = hc_complement + m_complement + m_prime;
	return nes_dns_recompute_cksum16_finish(sum);
}

/**
 * @brief Update checksum after changing IP address
 *
 * @param[in] old_csum - old checksum
 * @param[in] old_ip - ip value that changed
 * @param[in] new_ip - new ip value
 * @return final checksum
 */
static inline uint16_t
nes_dns_recompute_cksum_new_ip(uint16_t old_csum, uint32_t old_ip, uint32_t new_ip) {
	return nes_dns_recompute_cksum16(nes_dns_recompute_cksum16(old_csum, old_ip, new_ip),
		old_ip >> 16, new_ip >> 16);
}

/**
 * @brief Update UDP/TCP and IP checksum after changing IP address
 *
 * @param[in] inner_ipv4_hdr - inner IPv4 header
 * @param[in] old_ip - ip value that changed
 * @param[in] new_ip - new ip value
 */
static inline void
nes_dns_recompute_inner_ipv4_checksums(struct ipv4_hdr* inner_ipv4_hdr, uint32_t old_ip,
	uint32_t new_ip) {
	if (inner_ipv4_hdr->next_proto_id == IP_PROTO_UDP) {
		struct udp_hdr* udp_hdr = (struct udp_hdr*) (inner_ipv4_hdr + 1);
		if (udp_hdr->dgram_cksum) {
			udp_hdr->dgram_cksum =
				nes_dns_recompute_cksum_new_ip(udp_hdr->dgram_cksum,
					old_ip, new_ip);
			if (!udp_hdr->dgram_cksum)
				udp_hdr->dgram_cksum = htons(0xffff);
		}
	} else if (inner_ipv4_hdr->next_proto_id == IP_PROTO_TCP) {
		struct tcp_hdr* tcp_hdr = (struct tcp_hdr*) (inner_ipv4_hdr + 1);
		tcp_hdr->cksum = nes_dns_recompute_cksum_new_ip(tcp_hdr->cksum, old_ip, new_ip);
	}
	inner_ipv4_hdr->hdr_checksum = rte_ipv4_cksum(inner_ipv4_hdr);
}

/**
 * @brief Change IP address and recompute IP header checksum
 *
 * @param[in] ipv4_hdr - IPv4 header
 * @param[in] addr - original IP address pointer
 * @param[in] new_addr - new IP address pointer
 */
static inline void
set_new_ipv4_addr(struct ipv4_hdr* ipv4_hdr, uint32_t* addr, uint32_t* new_addr)
{
	*addr = *new_addr;
	ipv4_hdr->hdr_checksum = 0;
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
}

/**
 * @brief Set destination IP address and recompute IP header checksum
 *
 * @param[in] inner_ipv4_hdr - IPv4 header
 * @param[in] new_ip - new IP address pointer
 */
static inline void set_new_ipv4_dst(struct ipv4_hdr* inner_ipv4_hdr, uint32_t* new_ip) {
	set_new_ipv4_addr(inner_ipv4_hdr, &inner_ipv4_hdr->dst_addr, new_ip);
}

/**
 * @brief Set source IP address and recompute IP header checksum
 *
 * @param[in] inner_ipv4_hdr - IPv4 header
 * @param[in] new_ip - new IP address pointer
 */
static inline void set_new_ipv4_src(struct ipv4_hdr* inner_ipv4_hdr, uint32_t* new_ip) {
	set_new_ipv4_addr(inner_ipv4_hdr, &inner_ipv4_hdr->src_addr, new_ip);
}
#ifdef	__cplusplus
}
#endif

#endif	/* NES_DNS_TOOLS_H */
