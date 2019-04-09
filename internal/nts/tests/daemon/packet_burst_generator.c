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

#include <rte_byteorder.h>
#include <rte_mbuf.h>

#include "packet_burst_generator.h"

#define UDP_SRC_PORT 1024
#define UDP_DST_PORT 1024


#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define PKT_RX_IPV4_HDR      (1ULL << 5)
#define PKT_RX_IPV6_HDR      (1ULL << 7)

static void
copy_buf_to_pkt_segs(void *buf, unsigned len, struct rte_mbuf *pkt,
	unsigned offset)
{
	struct rte_mbuf *seg;
	void *seg_buf;
	unsigned copy_len;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod(seg, char *) +offset;
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t) copy_len);
		len -= copy_len;
		buf = ((char *) buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, void *);
	}
	rte_memcpy(seg_buf, buf, (size_t) len);
}

static inline void
copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod(pkt, char *) +offset, buf, (size_t) len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

void
initialize_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac,
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

void
initialize_arp_header(struct arp_hdr *arp_hdr, struct ether_addr *src_mac,
	struct ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip,
	uint32_t opcode)
{
	arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_hdr->arp_hln = ETHER_ADDR_LEN;
	arp_hdr->arp_pln = sizeof (uint32_t);
	arp_hdr->arp_op = rte_cpu_to_be_16(opcode);
	ether_addr_copy(src_mac, &arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = src_ip;
	ether_addr_copy(dst_mac, &arp_hdr->arp_data.arp_tha);
	arp_hdr->arp_data.arp_tip = dst_ip;
}

uint16_t
initialize_udp_header(struct udp_hdr *udp_hdr, uint16_t src_port,
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

void
initialize_tcp_header(struct tcp_hdr *tcp_hdr, uint16_t src_port,
	uint16_t dst_port)
{

	tcp_hdr->src_port = rte_cpu_to_be_16(src_port);
	tcp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
	tcp_hdr->cksum = 0; /* No TCP checksum. */
}

uint16_t
initialize_ipv6_header(struct ipv6_hdr *ip_hdr, uint8_t *src_addr,
	uint8_t *dst_addr, uint16_t pkt_data_len)
{
	ip_hdr->vtc_flow = 0;
	ip_hdr->payload_len = pkt_data_len;
	ip_hdr->proto = IPPROTO_UDP;
	ip_hdr->hop_limits = IP_DEFTTL;

	rte_memcpy(ip_hdr->src_addr, src_addr, sizeof (ip_hdr->src_addr));
	rte_memcpy(ip_hdr->dst_addr, dst_addr, sizeof (ip_hdr->dst_addr));

	return (uint16_t) (pkt_data_len + sizeof (struct ipv6_hdr));
}

uint16_t
initialize_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
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



/*
 * The maximum number of segments per packet is used when creating
 * scattered transmit packets composed of a list of mbufs.
 */
#define RTE_MAX_SEGS_PER_PKT 255 /**< pkt.nb_segs is a 8-bit unsigned char. */

int
generate_packet_burst(struct rte_mempool *mp, struct rte_mbuf **pkts_burst,
	struct ether_hdr *eth_hdr, uint8_t vlan_enabled, void *ip_hdr,
	uint8_t ipv4, struct udp_hdr *udp_hdr, int nb_pkt_per_burst,
	uint8_t pkt_len, uint8_t nb_pkt_segs)
{
	int i, nb_pkt = 0;
	size_t eth_hdr_size;

	struct rte_mbuf *pkt_seg;
	struct rte_mbuf *pkt;

	for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
		pkt = rte_pktmbuf_alloc(mp);
		if (pkt == NULL) {
nomore_mbuf:
			if (nb_pkt == 0)
				return -1;
			break;
		}

		pkt->data_len = pkt_len;
		pkt_seg = pkt;
		for (i = 1; i < nb_pkt_segs; i++) {
			pkt_seg->next = rte_pktmbuf_alloc(mp);
			if (pkt_seg->next == NULL) {
				pkt->nb_segs = i;
				rte_pktmbuf_free(pkt);
				goto nomore_mbuf;
			}
			pkt_seg = pkt_seg->next;
			pkt_seg->data_len = pkt_len;
		}
		pkt_seg->next = NULL; /* Last segment of packet. */

		/*
		 * Copy headers in first packet segment(s).
		 */
		if (vlan_enabled)
			eth_hdr_size = sizeof (struct ether_hdr) + sizeof (struct vlan_hdr);
		else
			eth_hdr_size = sizeof (struct ether_hdr);

		copy_buf_to_pkt(eth_hdr, eth_hdr_size, pkt, 0);

		if (ipv4) {
			copy_buf_to_pkt(ip_hdr, sizeof (struct ipv4_hdr), pkt, eth_hdr_size);
			copy_buf_to_pkt(udp_hdr, sizeof (*udp_hdr), pkt, eth_hdr_size +
				sizeof (struct ipv4_hdr));
		} else {
			copy_buf_to_pkt(ip_hdr, sizeof (struct ipv6_hdr), pkt, eth_hdr_size);
			copy_buf_to_pkt(udp_hdr, sizeof (*udp_hdr), pkt, eth_hdr_size +
				sizeof (struct ipv6_hdr));
		}

		/*
		 * Complete first mbuf of packet and append it to the
		 * burst of packets to be transmitted.
		 */
		pkt->nb_segs = nb_pkt_segs;
		pkt->pkt_len = pkt_len;
		pkt->l2_len = eth_hdr_size;

		if (ipv4) {
			pkt->vlan_tci = ETHER_TYPE_IPv4;
			pkt->l3_len = sizeof (struct ipv4_hdr);

			if (vlan_enabled)
				pkt->ol_flags = PKT_RX_IPV4_HDR | PKT_RX_VLAN;
			else
				pkt->ol_flags = PKT_RX_IPV4_HDR;
		} else {
			pkt->vlan_tci = ETHER_TYPE_IPv6;
			pkt->l3_len = sizeof (struct ipv6_hdr);

			if (vlan_enabled)
				pkt->ol_flags = PKT_RX_IPV6_HDR | PKT_RX_VLAN;
			else
				pkt->ol_flags = PKT_RX_IPV6_HDR;
		}

		pkts_burst[nb_pkt] = pkt;
	}

	return nb_pkt;
}

uint16_t
initialize_gtpu_packet(struct rte_mbuf *pkt, uint32_t outer_src_addr,
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
	initialize_eth_header(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, vlan_enable, 0);
#define GTPU_PORT 2152
	outer_ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	if (0 != vlan_enable)
		outer_ip_hdr = (struct ipv4_hdr *)
			((uint8_t*)outer_ip_hdr + sizeof(struct vlan_hdr));

	initialize_ipv4_header(outer_ip_hdr,
		outer_src_addr, outer_dst_addr, 64); //put it at the end?
	outer_udp_hdr = (struct udp_hdr *)(outer_ip_hdr + 1);
	initialize_udp_header(outer_udp_hdr, GTPU_PORT, GTPU_PORT, 64);
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
	initialize_ipv4_header(inner_ip_hdr, inner_src_addr, inner_dst_addr, 64);
	inner_udp_hdr = (struct udp_hdr *)(inner_ip_hdr + 1);
	initialize_udp_header(inner_udp_hdr, inner_src_port, inner_dst_port, 64);
	rte_pktmbuf_append(pkt, sizeof(struct ether_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) +
		sizeof(gtpu_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) + 64);
	return 0;
}

uint16_t
initialize_gtpu_packet_with_ext(struct rte_mbuf *pkt, uint32_t outer_src_addr,
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
	initialize_eth_header(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
#define GTPU_PORT 2152
	outer_ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	initialize_ipv4_header(outer_ip_hdr,
		outer_src_addr, outer_dst_addr, 64); //put it at the end?
	outer_udp_hdr = (struct udp_hdr *)(outer_ip_hdr + 1);
	initialize_udp_header(outer_udp_hdr, GTPU_PORT, GTPU_PORT, 64);
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

	initialize_ipv4_header(inner_ip_hdr, inner_src_addr, inner_dst_addr, 64);
	inner_udp_hdr = (struct udp_hdr *)(inner_ip_hdr + 1);
	initialize_udp_header(inner_udp_hdr, inner_src_port, inner_dst_port, 64);
	rte_pktmbuf_append(pkt, sizeof(struct ether_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) +
		sizeof(gtpu_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) + 64);
	return 0;
}

uint16_t
initialize_ip_packet(struct rte_mbuf *pkt, uint32_t src_addr,
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
	initialize_eth_header(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, vlan_enable, 0);
	outer_ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	if (0 != vlan_enable)
		outer_ip_hdr = (struct ipv4_hdr *)
			((uint8_t*)outer_ip_hdr + sizeof(struct vlan_hdr));

	initialize_ipv4_header(outer_ip_hdr, src_addr, dst_addr, 64); //put it at the end?
	outer_udp_hdr = (struct udp_hdr *)(outer_ip_hdr + 1);
	initialize_udp_header(outer_udp_hdr, src_port, dst_port, 64);
	rte_pktmbuf_append(pkt, sizeof(struct ether_hdr) +
		sizeof(struct ipv4_hdr) +
		sizeof(struct udp_hdr) + 64);
	return 0;
}
