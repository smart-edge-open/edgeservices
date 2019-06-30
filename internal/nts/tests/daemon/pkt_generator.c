/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_byteorder.h>
#include <rte_mbuf.h>

#include "pkt_generator.h"

#define UDP_SRC_PORT 1024
#define UDP_DST_PORT 1024


#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define PKT_RX_IPV4_HDR      (1ULL << 5)
#define PKT_RX_IPV6_HDR      (1ULL << 7)

uint16_t init_gtpu_pkt(struct rte_mbuf *pkt, uint32_t outer_src_addr,
	uint32_t outer_dst_addr, uint32_t inner_src_addr,
	uint32_t inner_dst_addr, uint16_t inner_src_port,
	uint16_t inner_dst_port, uint8_t vlan_enable)
{
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *outer_ip_hdr, *inner_ip_hdr;
	struct udp_hdr *outer_udp_hdr, *inner_udp_hdr;
	gtpu_hdr *gtpuHdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, vlan_enable, 0);
#define GTPU_PORT 2152
	outer_ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	if (0 != vlan_enable)
		outer_ip_hdr = (struct ipv4_hdr *)
			((uint8_t*)outer_ip_hdr + sizeof(struct vlan_hdr));

	init_ipv4_hdr(outer_ip_hdr,
		outer_src_addr, outer_dst_addr, 64); //put it at the end?
	outer_udp_hdr = (struct udp_hdr *)(outer_ip_hdr + 1);
	init_udp_hdr(outer_udp_hdr, GTPU_PORT, GTPU_PORT, 64);
	gtpuHdr = (gtpu_hdr*)(outer_udp_hdr + 1);
	gtpuHdr->npdu_flag   = 0;
	gtpuHdr->seqnum_flag = 0;
	gtpuHdr->exthdr_flag = 0;
	gtpuHdr->reserved    = 0;
	gtpuHdr->pt          = 1;
	gtpuHdr->version     = 1;
	gtpuHdr->msg_type    = 255;
	gtpuHdr->length      = 64;
	inner_ip_hdr = (struct ipv4_hdr *)(gtpuHdr + 1);
	init_ipv4_hdr(inner_ip_hdr, inner_src_addr, inner_dst_addr, 64);
	inner_udp_hdr = (struct udp_hdr *)(inner_ip_hdr + 1);
	init_udp_hdr(inner_udp_hdr, inner_src_port, inner_dst_port, 64);
	rte_pktmbuf_append(pkt, sizeof(struct ether_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) +
		sizeof(gtpu_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) + 64);
	return 0;
}

uint16_t init_gtpu_pkt_with_ext(struct rte_mbuf *pkt, uint32_t outer_src_addr,
	uint32_t outer_dst_addr, uint32_t inner_src_addr,
	uint32_t inner_dst_addr, uint16_t inner_src_port,
	uint16_t inner_dst_port, uint8_t put_ext)
{
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *outer_ip_hdr, *inner_ip_hdr;
	struct udp_hdr *outer_udp_hdr, *inner_udp_hdr;
	gtpu_hdr *gtpuHdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
#define GTPU_PORT 2152
	outer_ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	init_ipv4_hdr(outer_ip_hdr,
		outer_src_addr, outer_dst_addr, 64); //put it at the end?
	outer_udp_hdr = (struct udp_hdr *)(outer_ip_hdr + 1);
	init_udp_hdr(outer_udp_hdr, GTPU_PORT, GTPU_PORT, 64);
	gtpuHdr = (gtpu_hdr*)(outer_udp_hdr + 1);
	gtpuHdr->npdu_flag   = 0;
	gtpuHdr->seqnum_flag = put_ext ? 0 : 1;
	gtpuHdr->exthdr_flag = put_ext ? 1 : 0;
	gtpuHdr->reserved    = 0;
	gtpuHdr->pt          = 1;
	gtpuHdr->version     = 1;
	gtpuHdr->msg_type    = 255;
	gtpuHdr->length      = 64;

	struct gtpuHdrOpt_s {
		/* Optional GTP-U header fields */
		uint16_t seq_num;
		uint8_t  npdu;
		uint8_t  next;
	};

	struct gtpuHdrOpt_s *gtpuHdrOpt = (struct gtpuHdrOpt_s *) (gtpuHdr + 1);
	if (put_ext) {
		uint8_t *ext_hdr = (uint8_t *) (gtpuHdrOpt + 1);
		*ext_hdr = 2;
		*(ext_hdr + 1) = 1;
		*(ext_hdr + 2) = 2;
		*(ext_hdr + 3) = 0;
		inner_ip_hdr = (struct ipv4_hdr *)(ext_hdr + 4);

	} else
		inner_ip_hdr = (struct ipv4_hdr *)(gtpuHdrOpt + 1);

	init_ipv4_hdr(inner_ip_hdr, inner_src_addr, inner_dst_addr, 64);
	inner_udp_hdr = (struct udp_hdr *)(inner_ip_hdr + 1);
	init_udp_hdr(inner_udp_hdr, inner_src_port, inner_dst_port, 64);
	rte_pktmbuf_append(pkt, sizeof(struct ether_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) +
		sizeof(gtpu_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) + 64);
	return 0;
}

void init_eth_hdr(struct ether_hdr *eth_hdr, struct ether_addr *src_mac,
	struct ether_addr *dst_mac, uint16_t ether_type,
	uint8_t vlan_enabled, uint16_t van_id)
{
	ether_addr_copy(dst_mac, &eth_hdr->d_addr);
	ether_addr_copy(src_mac, &eth_hdr->s_addr);

	if (vlan_enabled) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *) ((uint8_t *) eth_hdr +
			sizeof (struct ether_hdr));

		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

		vhdr->eth_proto = rte_cpu_to_be_16(ether_type);
		vhdr->vlan_tci = van_id;
	} else
		eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
}

uint16_t init_udp_hdr(struct udp_hdr *udp_hdr, uint16_t src_port,
	uint16_t dst_port, uint16_t pkt_data_len)
{
	uint16_t pkt_len;

	pkt_len = (uint16_t) (pkt_data_len + sizeof (struct udp_hdr));

	udp_hdr->src_port = rte_cpu_to_be_16(src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len);
	udp_hdr->dgram_cksum = 0; /* No UDP checksum. */

	return pkt_len;
}

void init_tcp_hdr(struct tcp_hdr *tcp_hdr, uint16_t src_port,
	uint16_t dst_port)
{

	tcp_hdr->src_port = rte_cpu_to_be_16(src_port);
	tcp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
	tcp_hdr->cksum = 0; /* No TCP checksum. */
}

uint16_t init_ipv4_hdr(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
	uint32_t dst_addr, uint16_t pkt_data_len)
{
	uint16_t pkt_len;
	uint16_t *ptr16;
	uint32_t ip_cksum;

	/*
	 * Initialize IP header.
	 */
	pkt_len = (uint16_t) (pkt_data_len + sizeof (struct ipv4_hdr));

	ip_hdr->version_ihl = IP_VHL_DEF;
	ip_hdr->type_of_service = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length = rte_cpu_to_be_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(src_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(dst_addr);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (uint16_t *) ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0];
	ip_cksum += ptr16[1];
	ip_cksum += ptr16[2];
	ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6];
	ip_cksum += ptr16[7];
	ip_cksum += ptr16[8];
	ip_cksum += ptr16[9];

	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) + (ip_cksum & 0x0000FFFF);
	ip_cksum %= 65536;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;

	return pkt_len;
}

uint16_t init_ip_pkt(struct rte_mbuf *pkt, uint32_t src_addr,
	uint32_t dst_addr, uint16_t src_port,
	uint16_t dst_port, uint8_t vlan_enable)
{
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *outer_ip_hdr;
	struct udp_hdr *outer_udp_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, vlan_enable, 0);
	outer_ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	if (0 != vlan_enable)
		outer_ip_hdr = (struct ipv4_hdr *)
			((uint8_t*)outer_ip_hdr + sizeof(struct vlan_hdr));

	init_ipv4_hdr(outer_ip_hdr, src_addr, dst_addr, 64); //put it at the end?
	outer_udp_hdr = (struct udp_hdr *)(outer_ip_hdr + 1);
	init_udp_hdr(outer_udp_hdr, src_port, dst_port, 64);
	rte_pktmbuf_append(pkt, sizeof(struct ether_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) + 64);
	return 0;
}
