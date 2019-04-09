/*******************************************************************************
* Copyright 2019 Intel Corporation. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#ifndef PACKET_BURST_GENERATOR_H_
#define PACKET_BURST_GENERATOR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>


#define IPV4_ADDR(a, b, c, d)(((a & 0xff) << 24) | ((b & 0xff) << 16) | \
			      ((c & 0xff) << 8) | (d & 0xff))

#define PACKET_BURST_GEN_PKT_LEN 60
#define PACKET_BURST_GEN_PKT_LEN_128 128

void
initialize_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac,
	struct ether_addr *dst_mac, uint16_t ether_type,
	uint8_t vlan_enabled, uint16_t van_id);

void
initialize_arp_header(struct arp_hdr *arp_hdr, struct ether_addr *src_mac,
	struct ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip,
	uint32_t opcode);

uint16_t
initialize_udp_header(struct udp_hdr *udp_hdr, uint16_t src_port,
	uint16_t dst_port, uint16_t pkt_data_len);

void
initialize_tcp_header(struct tcp_hdr *tcp_hdr, uint16_t src_port,
	uint16_t dst_port);

uint16_t
initialize_ipv6_header(struct ipv6_hdr *ip_hdr, uint8_t *src_addr,
	uint8_t *dst_addr, uint16_t pkt_data_len);

uint16_t
initialize_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
	uint32_t dst_addr, uint16_t pkt_data_len);

uint16_t
initialize_gtpu_packet(struct rte_mbuf *pkt, uint32_t outer_src_addr,
	uint32_t outer_dst_addr, uint32_t inner_src_addr,
	uint32_t inner_dst_addr, uint16_t inner_src_port,
	uint16_t inner_dst_port, uint8_t vlan_enable);

uint16_t
initialize_gtpu_packet_with_ext(struct rte_mbuf *pkt, uint32_t outer_src_addr,
	uint32_t outer_dst_addr, uint32_t inner_src_addr,
	uint32_t inner_dst_addr, uint16_t inner_src_port,
	uint16_t inner_dst_port, uint8_t put_ext);

uint16_t
initialize_ip_packet(struct rte_mbuf *pkt, uint32_t src_addr,
	uint32_t dst_addr, uint16_t src_port,
	uint16_t dst_port, uint8_t vlan_enable);

typedef struct gtpu_hdr_s {
	uint8_t npdu_flag     : 1;
	uint8_t seqnum_flag   : 1;
	uint8_t exthdr_flag   : 1;
	uint8_t reserved      : 1;
	uint8_t pt            : 1;
	uint8_t version       : 3;
	uint8_t  msg_type; /* Must be uint8 - enum is mapped to int */
	uint16_t length;
	uint32_t teid;
} __attribute__ ((__packed__)) gtpu_hdr;

int
generate_packet_burst(struct rte_mempool *mp, struct rte_mbuf **pkts_burst,
	struct ether_hdr *eth_hdr, uint8_t vlan_enabled, void *ip_hdr,
	uint8_t ipv4, struct udp_hdr *udp_hdr, int nb_pkt_per_burst,
	uint8_t pkt_len, uint8_t nb_pkt_segs);

#ifdef __cplusplus
}
#endif


#endif /* PACKET_BURST_GENERATOR_H_ */
