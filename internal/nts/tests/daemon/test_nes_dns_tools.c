/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include "test_nes_dns_tools.h"
#include "dns/nes_dns_tools.h"
#include "pkt_generator.h"
#include "nes_common.h"


#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define PKTMBUF_POOL_NAME "dns_pktmbuf_pool"

static struct rte_mempool *pkt_pktmbuf_pool;

int
init_suite_nes_dns_tools(void) {
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
cleanup_suite_nes_dns_tools(void) {
	return CUE_SUCCESS;
}

static void
nes_dns_labels_to_domain_test(void) {
	char domain[32];
	CU_ASSERT_EQUAL(nes_dns_labels_to_domain("test", NULL, 0), NES_FAIL);
	CU_ASSERT_EQUAL(nes_dns_labels_to_domain("", domain, 32), NES_FAIL);
	CU_ASSERT_EQUAL(nes_dns_labels_to_domain("�", domain, 32), NES_FAIL);
	CU_ASSERT_EQUAL(nes_dns_labels_to_domain("aa", domain, 32), NES_SUCCESS);
	CU_ASSERT_STRING_EQUAL(domain, "aa"); //hex for "aa"
	CU_ASSERT_EQUAL(nes_dns_labels_to_domain("aa�", domain, 32), NES_SUCCESS);
	CU_ASSERT_STRING_EQUAL(domain, "aa"); //hex for "aa"
	const char* label = "wwwwppl";// "3www2wp2pl"
	CU_ASSERT_EQUAL(nes_dns_labels_to_domain(label, domain, 32), NES_SUCCESS);
	CU_ASSERT_STRING_EQUAL(domain, "www.wp.pl");
}

static void
nes_dns_is_ip_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
	CU_ASSERT_EQUAL(nes_dns_is_ip(pkt), NES_SUCCESS);
	eth_hdr->ether_type = 0;
	CU_ASSERT_EQUAL(nes_dns_is_ip(pkt), NES_FAIL);
	rte_pktmbuf_free(pkt);
}

static void
nes_dns_is_arp_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_ARP, 0, 0);
	CU_ASSERT_EQUAL(nes_dns_is_arp(pkt), NES_SUCCESS);
	eth_hdr->ether_type = 0;
	CU_ASSERT_EQUAL(nes_dns_is_arp(pkt), NES_FAIL);
	rte_pktmbuf_free(pkt);
}

static void
nes_dns_recompute_cksum16_finish_test(void) {
	uint32_t p = 2;
	CU_ASSERT_EQUAL(nes_dns_recompute_cksum16_finish(p), 0xFFFF - p);
}

static void
nes_dns_recompute_cksum16_test(void) {
	uint16_t old_csum = 0xAB;
	uint16_t old_u16 = 0xAA;
	uint16_t new_u16 = 0xAA;
	CU_ASSERT_EQUAL(nes_dns_recompute_cksum16(old_csum, old_u16, new_u16), old_csum);
	CU_ASSERT_NOT_EQUAL(nes_dns_recompute_cksum16(old_csum, old_u16, new_u16 + 1), old_csum);
}

static void
nes_dns_recompute_cksum_new_ip_test(void) {
	uint16_t old_csum = 0xAB;
	uint32_t old_ip = 0xAABB;
	uint32_t new_ip = 0xAABB;
	CU_ASSERT_EQUAL(nes_dns_recompute_cksum_new_ip(old_csum, old_ip, new_ip), old_csum);
	CU_ASSERT_NOT_EQUAL(nes_dns_recompute_cksum_new_ip(old_csum, old_ip, new_ip + 1), old_csum);
}

static void
nes_dns_recompute_inner_ipv4_checksums_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 0);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 0, 0);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	struct tcp_hdr *tcp_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
	ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	init_ipv4_hdr(ip_hdr, ip_src, ip_dst, 32);
	udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
	init_udp_hdr(udp_hdr, 0xAA, 0xAB, 10);

	udp_hdr->dgram_cksum = 0;
	uint16_t old_hdr_checksum = ip_hdr->hdr_checksum;
	ip_hdr->hdr_checksum = 0;
	nes_dns_recompute_inner_ipv4_checksums(ip_hdr, ip_src, ip_src);
	CU_ASSERT_EQUAL(ip_hdr->hdr_checksum, old_hdr_checksum);
	CU_ASSERT_EQUAL(udp_hdr->dgram_cksum, 0);

	udp_hdr->dgram_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = 0;
	nes_dns_recompute_inner_ipv4_checksums(ip_hdr, ip_src, ip_src);
	CU_ASSERT_EQUAL(ip_hdr->hdr_checksum, old_hdr_checksum);
	CU_ASSERT_EQUAL(udp_hdr->dgram_cksum, 0xFFFF);

	udp_hdr->dgram_cksum = 0xA;
	ip_hdr->hdr_checksum = 0;
	nes_dns_recompute_inner_ipv4_checksums(ip_hdr, ip_src, ip_src);
	CU_ASSERT_EQUAL(ip_hdr->hdr_checksum, old_hdr_checksum);
	CU_ASSERT_EQUAL(udp_hdr->dgram_cksum, 0xA);

	ip_hdr->next_proto_id = IPPROTO_ICMP;
	ip_hdr->hdr_checksum = 0;
	old_hdr_checksum = rte_ipv4_cksum(ip_hdr);
	nes_dns_recompute_inner_ipv4_checksums(ip_hdr, ip_src, ip_src);
	CU_ASSERT_EQUAL(ip_hdr->hdr_checksum, old_hdr_checksum);

	// TCP
	tcp_hdr = (struct tcp_hdr*)(ip_hdr + 1);
	ip_hdr->next_proto_id = IPPROTO_TCP;
	init_tcp_hdr(tcp_hdr, 0xAA, 0xAB);
	tcp_hdr->cksum = 0xA;
	ip_hdr->hdr_checksum = 0;
	nes_dns_recompute_inner_ipv4_checksums(ip_hdr, ip_src, ip_src);
	CU_ASSERT_EQUAL(tcp_hdr->cksum, 0xA);

	rte_pktmbuf_free(pkt);
}

static void
set_new_ipv4_addr_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 1);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 0, 2);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
	ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	init_ipv4_hdr(ip_hdr, ip_src, ip_dst, 32);

	uint16_t old_cksum = ip_hdr->hdr_checksum;
	uint32_t new_ip = rte_cpu_to_be_32(ip_dst);
	set_new_ipv4_addr(ip_hdr, &ip_hdr->dst_addr, &new_ip);
	CU_ASSERT_EQUAL(ip_hdr->hdr_checksum, old_cksum);

	set_new_ipv4_addr(ip_hdr, &ip_hdr->src_addr, &new_ip);
	CU_ASSERT_NOT_EQUAL(ip_hdr->hdr_checksum, old_cksum);

	rte_pktmbuf_free(pkt);
}

static void
set_new_ipv4_dst_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 1);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 0, 2);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
	ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	init_ipv4_hdr(ip_hdr, ip_src, ip_dst, 32);

	uint16_t old_cksum = ip_hdr->hdr_checksum;
	uint32_t new_ip = rte_cpu_to_be_32(ip_dst);
	set_new_ipv4_dst(ip_hdr, &new_ip);
	CU_ASSERT_EQUAL(ip_hdr->hdr_checksum, old_cksum);
	new_ip = rte_cpu_to_be_32(ip_src);
	set_new_ipv4_dst(ip_hdr, &new_ip);
	CU_ASSERT_NOT_EQUAL(ip_hdr->hdr_checksum, old_cksum);

	rte_pktmbuf_free(pkt);

}

static void
set_new_ipv4_src_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 1);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 0, 2);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
	ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	init_ipv4_hdr(ip_hdr, ip_src, ip_dst, 32);

	uint16_t old_cksum = ip_hdr->hdr_checksum;
	uint32_t new_ip = rte_cpu_to_be_32(ip_src);
	set_new_ipv4_src(ip_hdr, &new_ip);
	CU_ASSERT_EQUAL(ip_hdr->hdr_checksum, old_cksum);
	new_ip = rte_cpu_to_be_32(ip_dst);
	set_new_ipv4_src(ip_hdr, &new_ip);
	CU_ASSERT_NOT_EQUAL(ip_hdr->hdr_checksum, old_cksum);

	rte_pktmbuf_free(pkt);
}

void add_nes_dns_tools_suite_to_registry(void) {
	CU_pSuite nes_dns_tools_suite = CU_add_suite("nes_dns_tools", init_suite_nes_dns_tools, cleanup_suite_nes_dns_tools);

	CU_add_test(nes_dns_tools_suite, "nes_dns_labels_to_domain_test", nes_dns_labels_to_domain_test);
	CU_add_test(nes_dns_tools_suite, "nes_dns_is_ip_test", nes_dns_is_ip_test);
	CU_add_test(nes_dns_tools_suite, "nes_dns_is_arp_test", nes_dns_is_arp_test);
	CU_add_test(nes_dns_tools_suite, "nes_dns_recompute_cksum16_finish_test", nes_dns_recompute_cksum16_finish_test);
	CU_add_test(nes_dns_tools_suite, "nes_dns_recompute_cksum16_test", nes_dns_recompute_cksum16_test);
	CU_add_test(nes_dns_tools_suite, "nes_dns_recompute_cksum_new_ip_test", nes_dns_recompute_cksum_new_ip_test);
	CU_add_test(nes_dns_tools_suite, "nes_dns_recompute_inner_ipv4_checksums_test", nes_dns_recompute_inner_ipv4_checksums_test);
	CU_add_test(nes_dns_tools_suite, "set_new_ipv4_addr_test", set_new_ipv4_addr_test);
	CU_add_test(nes_dns_tools_suite, "set_new_ipv4_dst_test", set_new_ipv4_dst_test);
	CU_add_test(nes_dns_tools_suite, "set_new_ipv4_src_test", set_new_ipv4_src_test);
}

