/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>

#include "test_nes_arp.h"
#include "nes_common.h"
#include "nes_arp.h"
#include "pkt_generator.h"

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define PKTMBUF_POOL_NAME "arp_pktmbuf_pool"

static struct rte_mempool *pkt_pktmbuf_pool;

int
init_suite_nes_arp(void) {
	pkt_pktmbuf_pool = rte_mempool_create(
		PKTMBUF_POOL_NAME,
		1,
		MBUF_SIZE,
		0,
		sizeof(struct rte_pktmbuf_pool_private),
		rte_pktmbuf_pool_init,
		NULL,
		rte_pktmbuf_init,
		NULL,
		rte_socket_id(),
		0);
	if (NULL != pkt_pktmbuf_pool)
		return CUE_SUCCESS;
	else
		return -1;
}

int
cleanup_suite_nes_arp(void) {
	return CUE_SUCCESS;
}

static void
nes_arp_response_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 0);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 0, 0);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct arp_header_ipv4_s *arp_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);

	arp_hdr = (struct arp_header_ipv4_s *) (eth_hdr + 1);
	ether_addr_copy(&mac_src, &arp_hdr->sha);
	arp_hdr->spa = ip_src;
	ether_addr_copy(&mac_dst, &arp_hdr->tha);
	arp_hdr->tpa = ip_dst;

	// invalid HTYPE
	arp_hdr->htype = rte_cpu_to_be_16(HTYPE_ETHER + 1);
	CU_ASSERT_EQUAL(nes_arp_response(pkt, mac_dst), NES_FAIL);

	// invalid ptype
	arp_hdr->htype = rte_cpu_to_be_16(HTYPE_ETHER);
	arp_hdr->ptype = rte_cpu_to_be_16(ETHER_TYPE_IPv4 + 1);
	CU_ASSERT_EQUAL(nes_arp_response(pkt, mac_dst), NES_FAIL);

	// invalid oper
	arp_hdr->ptype = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_hdr->oper = rte_cpu_to_be_16(ARP_REPLY);
	CU_ASSERT_EQUAL(nes_arp_response(pkt, mac_dst), NES_FAIL);

	// valid arp req
	arp_hdr->oper = rte_cpu_to_be_16(ARP_REQUEST);
	CU_ASSERT_EQUAL(nes_arp_response(pkt, mac_dst), NES_SUCCESS);

	rte_pktmbuf_free(pkt);
}

void add_nes_arp_suite_to_registry(void) {
	CU_pSuite nes_arp_suite = CU_add_suite("nes_arp", init_suite_nes_arp, cleanup_suite_nes_arp);

	CU_add_test(nes_arp_suite, "nes_arp_response_test", nes_arp_response_test);
}

