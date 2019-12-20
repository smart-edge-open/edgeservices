/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>

#include "test_nts_edit.h"
#include "pkt_generator.h"
#include "nts/nts_edit.h"
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "ctrl/nes_ctrl.h"
#include "libnes_cfgfile_def.h"

struct nis_routing_data_key_s;
typedef struct nis_routing_data_key_s nis_routing_data_key_t;

struct nis_routing_data_s;
typedef struct nis_routing_data_s nis_routing_data_t;
int nis_routing_data_get(const nis_routing_data_key_t *key, nis_routing_data_t **data);
int nes_ring_find(nes_ring_t **ring, const char *name);

#include "nts_edit_decl.h"
#include "nis/nis_param.h"

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define PKTMBUF_POOL_NAME "nts_edit_pktmbuf_pool"
#define CFG_ALLOC_SECTION_BATCH 2
#define CFG_ALLOC_ENTRIES_BATCH 8
static struct rte_mempool *pkt_pktmbuf_pool;
struct rte_cfgfile *cfg_bak;
extern struct rte_cfgfile *nes_cfgfile;
static struct rte_cfgfile_section section1;
static struct rte_cfgfile_section section2;

MOCK_INIT(mocked_nis_routing_data_get);
MOCK_INIT(mocked_nes_ring_find);
MOCK_INIT(mocked_nes_lookup_entry_find);
MOCK_INIT(mocked_nes_lookup_bulk_get);
MOCK_INIT(mocked_nes_lookup_entry_add);
MOCK_INIT(mocked_nes_acl_lookup);

static struct rte_cfgfile_entry  entries1[] = {
	{ .name = "name", .value = "ENB", },
	{ .name = "traffic-direction", .value = "both", },
	{ .name = "traffic-type", .value = "mixed", },
	{ .name = "egress-port", .value = "1", },
};

static struct rte_cfgfile_entry  entries2[] = {
	{ .name = "name", .value = "EPC", },
	{ .name = "traffic-direction", .value = "both", },
	{ .name = "traffic-type", .value = "mixed", },
	{ .name = "egress-port", .value = "0", },
};

int
init_suite_nts_edit(void) {
	MOCK_RESET(mocked_nis_routing_data_get);
	MOCK_RESET(mocked_nes_ring_find);
	MOCK_RESET(mocked_nes_lookup_entry_find);
	MOCK_RESET(mocked_nes_lookup_entry_add);
	MOCK_RESET(mocked_nes_acl_lookup);
	MOCK_RESET(mocked_nes_lookup_bulk_get);


	pkt_pktmbuf_pool = rte_mempool_create( PKTMBUF_POOL_NAME, 2, MBUF_SIZE, 0,
		sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL,
		rte_pktmbuf_init, NULL, rte_socket_id(), 0);
	if (NULL == pkt_pktmbuf_pool)
		return -1;

	cfg_bak = nes_cfgfile;

	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	if (!nes_cfgfile)
		return CUE_NOMEMORY;

	nes_cfgfile->sections =
		malloc(sizeof (struct rte_cfgfile_section) * CFG_ALLOC_SECTION_BATCH);

	if (!nes_cfgfile->sections) {
		free(nes_cfgfile);
		return CUE_NOMEMORY;
	}

	strncpy(section1.name, "PORT0", sizeof(section1.name));
	strncpy(section2.name, "PORT1", sizeof(section2.name));
	section1.entries = entries1;
	nes_cfgfile->sections[0] = section1;
	nes_cfgfile->sections[0].num_entries = sizeof(entries1)/sizeof(entries1[0]);

	section2.entries = entries2;
	nes_cfgfile->sections[1] = section2;
	nes_cfgfile->sections[1].num_entries = sizeof(entries2)/sizeof(entries2[0]);

	nes_cfgfile->num_sections = 2;

	return CUE_SUCCESS;
}

int
cleanup_suite_nts_edit(void) {
	MOCK_RESET(mocked_nes_ring_find);
	MOCK_RESET(mocked_nis_routing_data_get);
	MOCK_RESET(mocked_nes_lookup_entry_find);
	MOCK_RESET(mocked_nes_lookup_entry_add);
	MOCK_RESET(mocked_nes_acl_lookup);
	MOCK_RESET(mocked_nes_lookup_bulk_get);
	nes_cfgfile = cfg_bak;
	nes_dev_port_dtor();

	return CUE_SUCCESS;
}

static void
nts_edit_get_outer_ipv4_hdr_test(void) {
	struct rte_mbuf *gtpu_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t outer_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t outer_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);
	init_gtpu_pkt(gtpu_pkt, outer_src_ip, outer_dst_ip, GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1), 0, 0, 0);
	struct ipv4_hdr *ip_hdr = nts_edit_get_outer_ipv4_hdr(gtpu_pkt);
	CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(outer_src_ip));
	CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(outer_dst_ip));
	rte_pktmbuf_free(gtpu_pkt);
}

static void
nts_edit_get_inner_ipv4_hdr_test(void) {
	struct rte_mbuf *gtpu_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t inner_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t inner_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);

	init_gtpu_pkt(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0), GET_IPV4_ADDRESS(192, 168, 0, 1),
		inner_src_ip, inner_dst_ip, 0, 0, 0);
	struct ipv4_hdr *ip_hdr = nts_edit_get_inner_ipv4_hdr(gtpu_pkt);
	CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(inner_src_ip));
	CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(inner_dst_ip));

	init_gtpu_pkt_with_ext(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1), inner_src_ip, inner_dst_ip, 0, 0, 1);
	ip_hdr = nts_edit_get_inner_ipv4_hdr(gtpu_pkt);
	CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(inner_src_ip));
	CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(inner_dst_ip));

	init_gtpu_pkt_with_ext(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1), inner_src_ip, inner_dst_ip, 0, 0, 0);
	ip_hdr = nts_edit_get_inner_ipv4_hdr(gtpu_pkt);
	CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(inner_src_ip));
	CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(inner_dst_ip));

	rte_pktmbuf_free(gtpu_pkt);
}

static int nis_routing_data_get_stub_ret = NES_FAIL;

static int
nis_routing_data_get_stub(const nis_routing_data_key_t UNUSED(*key), nis_routing_data_t **data) {
	static uint16_t d;
	*data = (nis_routing_data_t*) & d;
	return nis_routing_data_get_stub_ret;
}

#define CHECK_HDR_RES do { \
		CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(inner_src_ip)); \
		CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(inner_dst_ip)); \
		CU_ASSERT_EQUAL(entry.dst_ip , rte_cpu_to_be_32(GET_IPV4_ADDRESS(192, 168, 0, 1))); \
		CU_ASSERT_EQUAL(entry.src_ip, rte_cpu_to_be_32(GET_IPV4_ADDRESS(192, 168, 0, 0))); \
		CU_ASSERT_EQUAL(entry.dst_ip_port, rte_cpu_to_be_16(2152)); \
		CU_ASSERT_EQUAL(entry.src_ip_port, rte_cpu_to_be_16(2152)); \
		CU_ASSERT_EQUAL(tuple.outer_ip_dst, rte_cpu_to_be_32(GET_IPV4_ADDRESS(192, 168, 0, 1))); \
		CU_ASSERT_EQUAL(tuple.outer_ip_src, rte_cpu_to_be_32(GET_IPV4_ADDRESS(192, 168, 0, 0))); \
		CU_ASSERT_EQUAL(tuple.inner_ip_src, rte_cpu_to_be_32(inner_src_ip)); \
		CU_ASSERT_EQUAL(tuple.inner_ip_dst, rte_cpu_to_be_32(inner_dst_ip)); \
	} while (0)

static void
nts_edit_hdr_parse_gtp_test(void) {
	MOCK_SET(mocked_nis_routing_data_get, nis_routing_data_get_stub);
	struct rte_mbuf *gtpu_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t inner_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t inner_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);
	nts_enc_subentry_t entry;
	nts_acl_tuple_t tuple;
	struct ipv4_hdr *ip_hdr;

	init_gtpu_pkt(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0), GET_IPV4_ADDRESS(192, 168, 0, 1),
		inner_src_ip, inner_dst_ip, 0, 0, 0);

	nts_edit_hdr_parse_gtp(gtpu_pkt, &entry, &tuple, &ip_hdr, NES_UPSTREAM);
	CHECK_HDR_RES;

	init_gtpu_pkt(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0), GET_IPV4_ADDRESS(192, 168, 0, 1),
		inner_src_ip, inner_dst_ip, 0, 0, 1);

	nts_edit_hdr_parse_gtp(gtpu_pkt, &entry, &tuple, &ip_hdr, NES_UPSTREAM);
	CHECK_HDR_RES;

	init_gtpu_pkt_with_ext(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1), inner_src_ip, inner_dst_ip, 0, 0, 1);

	nts_edit_hdr_parse_gtp(gtpu_pkt, &entry, &tuple, &ip_hdr, NES_DOWNSTREAM);
	CHECK_HDR_RES;

	init_gtpu_pkt_with_ext(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1), inner_src_ip, inner_dst_ip, 0, 0, 0);

	nts_edit_hdr_parse_gtp(gtpu_pkt, &entry, &tuple, &ip_hdr, NES_DOWNSTREAM);
	CHECK_HDR_RES;

	nis_routing_data_get_stub_ret = NES_SUCCESS;
	nts_edit_hdr_parse_gtp(gtpu_pkt, &entry, &tuple, &ip_hdr, NES_DOWNSTREAM);
	CHECK_HDR_RES;

	rte_pktmbuf_free(gtpu_pkt);
}

static void
nts_edit_hdr_parse_ip_test(void) {
	MOCK_SET(mocked_nis_routing_data_get, nis_routing_data_get_stub);
	struct rte_mbuf *ip_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);
	nts_enc_subentry_t entry;
	nts_acl_tuple_t tuple;
	struct ipv4_hdr *ip_hdr;

	init_ip_pkt(ip_pkt, src_ip, dst_ip, 80, 80, 0);

	nts_edit_hdr_parse_ip(ip_pkt, &entry, &tuple, &ip_hdr);

	CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(src_ip));

	CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(dst_ip));

	CU_ASSERT_EQUAL(entry.dst_ip, rte_cpu_to_be_32(dst_ip));
	CU_ASSERT_EQUAL(entry.src_ip, rte_cpu_to_be_32(src_ip));
	CU_ASSERT_EQUAL(entry.dst_ip_port, rte_cpu_to_be_16(80));
	CU_ASSERT_EQUAL(entry.src_ip_port, rte_cpu_to_be_16(80));
	CU_ASSERT_EQUAL(tuple.inner_ip_src, rte_cpu_to_be_32(src_ip));
	CU_ASSERT_EQUAL(tuple.inner_ip_dst, rte_cpu_to_be_32(dst_ip));


	init_ip_pkt(ip_pkt, src_ip, dst_ip, 80, 80, 1);

	nts_edit_hdr_parse_ip(ip_pkt, &entry, &tuple, &ip_hdr);

	CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(src_ip));

	CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(dst_ip));

	CU_ASSERT_EQUAL(entry.dst_ip, rte_cpu_to_be_32(dst_ip));
	CU_ASSERT_EQUAL(entry.src_ip, rte_cpu_to_be_32(src_ip));
	CU_ASSERT_EQUAL(entry.dst_ip_port, rte_cpu_to_be_16(80));
	CU_ASSERT_EQUAL(entry.src_ip_port, rte_cpu_to_be_16(80));
	CU_ASSERT_EQUAL(tuple.inner_ip_src, rte_cpu_to_be_32(src_ip));
	CU_ASSERT_EQUAL(tuple.inner_ip_dst, rte_cpu_to_be_32(dst_ip));

	rte_pktmbuf_free(ip_pkt);
}

static void
nts_edit_hdr_vm_parse_test(void) {
	struct rte_mbuf *gtpu_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t inner_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t inner_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);

	struct nis_acl_tuple_tt {
		uint8_t proto;
		uint32_t inner_ip_src;
		uint32_t inner_ip_dst;
		uint16_t inner_port_src;
		uint16_t inner_port_dst;
		uint8_t tos;
		uint8_t _padding1;
		uint16_t _padding2; // multiples of 32bits for performance rte_acl reasons
	} __attribute__((packed));

	struct nis_acl_tuple_tt tuple;
	struct ipv4_hdr *ip_hdr;

	init_gtpu_pkt(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0), GET_IPV4_ADDRESS(192, 168, 0, 1),
		inner_src_ip, inner_dst_ip, 0, 0, 0);
	ip_hdr = nts_edit_get_inner_ipv4_hdr(gtpu_pkt);
	nts_edit_hdr_vm_parse(ip_hdr, (nis_acl_tuple_t*) & tuple);
	CU_ASSERT_EQUAL(tuple.inner_ip_src, rte_cpu_to_be_32(inner_src_ip));
	CU_ASSERT_EQUAL(tuple.inner_ip_dst, rte_cpu_to_be_32(inner_dst_ip));
	rte_pktmbuf_free(gtpu_pkt);
}

static int
edit_stub_fail(struct nts_route_entry_s UNUSED(*a), struct rte_mbuf UNUSED(*b), int UNUSED(g),
	void UNUSED(*c))
{
	return NES_FAIL;
}

static int
edit_stub_success(struct nts_route_entry_s UNUSED(*a),
	struct rte_mbuf UNUSED(*b),
	int UNUSED(g),
	void UNUSED(*c)) {
	return NES_SUCCESS;
}

static int nes_ring_find_stub_ret = NES_FAIL;

static int
nes_ring_find_stub(nes_ring_t UNUSED(**ring), const char UNUSED(*name)) {
	static int returned_fail = 0;
	if (!returned_fail) {
		returned_fail = 1;
		return nes_ring_find_stub_ret;
	}
	return NES_SUCCESS;
}

static void
nts_packet_edit_enq_test(void) {
	MOCK_SET(mocked_nes_ring_find, nes_ring_find_stub);
	nes_sq_t entries;
	nes_sq_ctor(&entries);
	int fake;
	size_t i;
	nts_route_entry_t entries_data[] = {
		{
			.ring_name = NULL,
			.dst_ring = NULL,
			.edit = NULL
		},
		{
			.ring_name = "test",
			.dst_ring = NULL,
			.edit = NULL
		},
		{
			.ring_name = "test",
			.dst_ring = NULL,
			.edit = NULL
		},
		{
			.ring_name = "test",
			.dst_ring = (nes_ring_t *) & fake,
			.edit = edit_stub_fail,
		},
		{
			.ring_name = "test",
			.dst_ring = (nes_ring_t *) & fake,
			.edit = edit_stub_success,
		},
	};

	for (i = 0; i < (sizeof (entries_data) / sizeof (nts_route_entry_t)); i++)
		nes_sq_enq(&entries, &entries_data[i]);

	CU_ASSERT_EQUAL(nts_packet_edit_enq(&entries, NULL, NULL, 0), NES_SUCCESS);
	nes_sq_dtor(&entries);
}

nes_sq_t *stub_entries;

static inline void
nes_acl_lookup_stub(nes_acl_ctx_t UNUSED(*ctx), const uint8_t UNUSED(**data), uint32_t data_cnt,
	void **entries) {
	uint32_t i;
	for (i = 0; i < data_cnt; i++) {
		if (i % 2)
			entries[i] = stub_entries;
		else
			entries[i] = NULL;
	}
}

static int
enq_success(struct nes_ring_s UNUSED(*a), void UNUSED(*b)) {
	return NES_SUCCESS;
}

static int
enq_fail(struct nes_ring_s UNUSED(*a), void UNUSED(*b)) {
	return NES_FAIL;
}

static void
nts_packet_flow_encap_gtpu_test(void) {
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
	ip_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	init_ipv4_hdr(ip_hdr, ip_src, ip_dst, 32);

	nts_enc_subentry_t encap_data = {
		.dst_mac_addrs = mac_dst,
		.src_mac_addrs = mac_src,
		.ue_ip = ip_src,
		.dst_ip = ip_dst,
		.src_ip = ip_src,
		.dst_ip_port = 2152,
		.src_ip_port = 2152,
		.teid = 0,
		.encap_flag = 0
	};

	gtpu_head_t *gtpu_pkt_header = nts_packet_flow_encap_gtpu(pkt, &encap_data, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(gtpu_pkt_header);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.gtpu_hdr.teid, 0);
	CU_ASSERT_EQUAL(memcmp(&gtpu_pkt_header->gtpu_no_vlan.outer_ether_hdr.d_addr,
		&mac_dst, sizeof (mac_dst)), 0);
	CU_ASSERT_EQUAL(memcmp(&gtpu_pkt_header->gtpu_no_vlan.outer_ether_hdr.s_addr,
		&mac_src, sizeof (mac_src)), 0);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_ipv4_hdr.dst_addr, ip_dst);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_ipv4_hdr.src_addr, ip_src);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_udp_hdr.dst_port, 2152);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_udp_hdr.src_port, 2152);

	nis_param_rab_t teid_data;
	teid_data.teid = 10;

	gtpu_pkt_header = nts_packet_flow_encap_gtpu(pkt, &encap_data, &teid_data);
	CU_ASSERT_PTR_NOT_NULL_FATAL(gtpu_pkt_header);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.gtpu_hdr.teid, teid_data.teid);
	CU_ASSERT_EQUAL(memcmp(&gtpu_pkt_header->gtpu_no_vlan.outer_ether_hdr.d_addr,
		&mac_dst, sizeof (mac_dst)), 0);
	CU_ASSERT_EQUAL(memcmp(&gtpu_pkt_header->gtpu_no_vlan.outer_ether_hdr.s_addr,
		&mac_src, sizeof (mac_src)), 0);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_ipv4_hdr.dst_addr, ip_dst);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_ipv4_hdr.src_addr, ip_src);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_udp_hdr.dst_port, 2152);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_no_vlan.outer_udp_hdr.src_port, 2152);

	nts_enc_subentry_t encap_vlan_data = {
		.dst_mac_addrs = mac_dst,
		.src_mac_addrs = mac_src,
		.ue_ip = ip_src,
		.dst_ip = ip_dst,
		.src_ip = ip_src,
		.dst_ip_port = 2152,
		.src_ip_port = 2152,
		.teid = 0,
		.encap_flag = NTS_ENCAP_VLAN_FLAG,
		.vlan_tci = 35
	};

	gtpu_pkt_header = nts_packet_flow_encap_gtpu(pkt, &encap_vlan_data, NULL);
	CU_ASSERT_PTR_NOT_NULL(gtpu_pkt_header);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_vlan.gtpu_hdr.teid, 0);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_vlan.outer_vlan_hdr.vlan_tci, 35);
	CU_ASSERT_EQUAL(memcmp(&gtpu_pkt_header->gtpu_vlan.outer_ether_hdr.d_addr,
		&mac_dst, sizeof (mac_dst)), 0);
	CU_ASSERT_EQUAL(memcmp(&gtpu_pkt_header->gtpu_vlan.outer_ether_hdr.s_addr,
		&mac_src, sizeof (mac_src)), 0);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_vlan.outer_ipv4_hdr.dst_addr, ip_dst);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_vlan.outer_ipv4_hdr.src_addr, ip_src);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_vlan.outer_udp_hdr.dst_port, 2152);
	CU_ASSERT_EQUAL(gtpu_pkt_header->gtpu_vlan.outer_udp_hdr.src_port, 2152);

	rte_pktmbuf_free(pkt);
}

static void
nts_packet_flow_encap_ip_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 1);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 0, 2);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	uint16_t pkt_len;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
	ip_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	pkt_len = init_ipv4_hdr(ip_hdr, ip_src, ip_dst, 32);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
	init_udp_hdr(udp_hdr, 8080, 8080, pkt_len);

	nts_enc_subentry_t encap_data = {
		.dst_mac_addrs = mac_dst,
		.src_mac_addrs = mac_src,
		.ue_ip = ip_src,
		.dst_ip = ip_dst,
		.src_ip = ip_src,
		.dst_ip_port = 8080,
		.src_ip_port = 8080,
		.teid = 0
	};

	ip_head_t *ip_pkt_header = nts_packet_flow_encap_ip(pkt, &encap_data);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ip_pkt_header);
	CU_ASSERT_EQUAL(memcmp(&ip_pkt_header->ip_no_vlan.ether_hdr.d_addr,
		&mac_dst, sizeof (mac_dst)), 0);
	CU_ASSERT_EQUAL(memcmp(&ip_pkt_header->ip_no_vlan.ether_hdr.s_addr,
		&mac_src, sizeof (mac_src)), 0);
	CU_ASSERT_EQUAL(ip_pkt_header->ip_no_vlan.ipv4_hdr.dst_addr, rte_cpu_to_be_32(ip_dst));
	CU_ASSERT_EQUAL(ip_pkt_header->ip_no_vlan.ipv4_hdr.src_addr, rte_cpu_to_be_32(ip_src));
	CU_ASSERT_EQUAL(ip_pkt_header->ip_no_vlan.udp_hdr.dst_port, rte_cpu_to_be_16(8080));
	CU_ASSERT_EQUAL(ip_pkt_header->ip_no_vlan.udp_hdr.src_port, rte_cpu_to_be_16(8080));

	nts_enc_subentry_t encap_vlan_data = {
		.dst_mac_addrs = mac_dst,
		.src_mac_addrs = mac_src,
		.ue_ip = ip_src,
		.dst_ip = ip_dst,
		.src_ip = ip_src,
		.dst_ip_port = 8080,
		.src_ip_port = 8080,
		.teid = 0,
		.encap_flag = NTS_ENCAP_VLAN_FLAG,
		.vlan_tci = 35
	};

	ip_pkt_header = nts_packet_flow_encap_ip(pkt, &encap_vlan_data);
	CU_ASSERT_PTR_NOT_NULL(ip_pkt_header);
	CU_ASSERT_EQUAL(ip_pkt_header->ip_vlan.vlan_hdr.vlan_tci, 35);
	CU_ASSERT_EQUAL(memcmp(&ip_pkt_header->ip_vlan.ether_hdr.d_addr,
		&mac_dst, sizeof (mac_dst)), 0);
	CU_ASSERT_EQUAL(memcmp(&ip_pkt_header->ip_vlan.ether_hdr.s_addr,
		&mac_src, sizeof (mac_src)), 0);
	CU_ASSERT_EQUAL(ip_pkt_header->ip_vlan.ipv4_hdr.dst_addr, rte_cpu_to_be_32(ip_dst));
	CU_ASSERT_EQUAL(ip_pkt_header->ip_vlan.ipv4_hdr.src_addr, rte_cpu_to_be_32(ip_src));
	CU_ASSERT_EQUAL(ip_pkt_header->ip_vlan.udp_hdr.dst_port, rte_cpu_to_be_16(8080));
	CU_ASSERT_EQUAL(ip_pkt_header->ip_vlan.udp_hdr.src_port, rte_cpu_to_be_16(8080));

	rte_pktmbuf_free(pkt);
}

static int nes_lookup_bulk_get_stub_ret = NES_FAIL;
static int
nes_lookup_bulk_get_stub(nes_lookup_table_t UNUSED(*lookup), const void UNUSED(**keys),
	int UNUSED(number), void UNUSED(**pentries)) {
	return nes_lookup_bulk_get_stub_ret;
}

static void
nts_flow_vm_test(void) {
	MOCK_SET(mocked_nes_lookup_bulk_get, nes_lookup_bulk_get_stub);
	nes_ring_t ring;
	nes_ctrl_ring_t ring_stats;
	nts_lookup_tables_t table;
	ring.routing_tables = &table;
	ring.ring_stats = &ring_stats;
	struct rte_mbuf *gtpu_pkt_0 = rte_pktmbuf_alloc(pkt_pktmbuf_pool),
		*gtpu_pkt_1 = rte_pktmbuf_alloc(pkt_pktmbuf_pool);

	struct rte_mbuf * packets[] = {gtpu_pkt_0, gtpu_pkt_1};
	uint32_t outer_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t outer_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);
	init_gtpu_pkt(gtpu_pkt_0, outer_src_ip, outer_dst_ip, GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1), 0, 0, 0);
	init_gtpu_pkt(gtpu_pkt_1, outer_src_ip, outer_dst_ip, GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1), 0, 0, 0);


	static nes_sq_t entries;
	int fake;
	nes_sq_ctor(&entries);
	nts_route_entry_t entries_data[] = {
		{
			.ring_name = NULL,
			.dst_ring = NULL,
			.edit = NULL
		},
		{
			.ring_name = "test",
			.dst_ring = (nes_ring_t *) & fake,
			.edit = edit_stub_fail,
		},
	};
	nes_sq_enq(&entries, &entries_data[0]);
	nes_sq_enq(&entries, &entries_data[1]);

	stub_entries = &entries;
	CU_ASSERT_EQUAL(nts_flow_vm(&ring, NULL, 0), NES_FAIL);
	nes_lookup_bulk_get_stub_ret = NES_SUCCESS;
	CU_ASSERT_EQUAL(nts_flow_vm(&ring, (void**)packets, 2), NES_SUCCESS);
	nes_sq_dtor(&entries);
}

static void
nts_edit_decap_test(void) {
	struct rte_mbuf *gtpu_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t inner_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t inner_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);
	init_gtpu_pkt(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0), GET_IPV4_ADDRESS(192, 168, 0, 1),
		inner_src_ip, inner_dst_ip, 0, 0, 0);
	nts_route_entry_t fake;
	nes_ring_t dst_ring;
	dst_ring.enq = enq_success;
	fake.dst_ring = &dst_ring;

	struct routing_params {
		struct ipv4_hdr *inner_ipv4_hdr;
	};
	struct routing_params routing_param;
	routing_param.inner_ipv4_hdr = nts_edit_get_inner_ipv4_hdr(gtpu_pkt);
	CU_ASSERT_EQUAL(nts_edit_decap(&fake, gtpu_pkt, 0, &routing_param), NES_SUCCESS);
	dst_ring.enq = enq_fail;
	CU_ASSERT_EQUAL(nts_edit_decap(&fake, gtpu_pkt, 0, &routing_param), NES_FAIL);
	rte_pktmbuf_free(gtpu_pkt);
}

static void
nts_edit_nodecap_test(void) {
	struct rte_mbuf *gtpu_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t inner_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t inner_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);
	init_gtpu_pkt(gtpu_pkt, GET_IPV4_ADDRESS(192, 168, 0, 0), GET_IPV4_ADDRESS(192, 168, 0, 1),
		inner_src_ip, inner_dst_ip, 0, 0, 0);
	nts_route_entry_t fake;
	nes_ring_t dst_ring;
	dst_ring.enq = enq_success;
	fake.dst_ring = &dst_ring;

	struct routing_params {
		struct ipv4_hdr *inner_ipv4_hdr;
	};
	struct routing_params routing_param;
	routing_param.inner_ipv4_hdr = nts_edit_get_inner_ipv4_hdr(gtpu_pkt);
	CU_ASSERT_EQUAL(nts_edit_nodecap(&fake, gtpu_pkt, 0, &routing_param), NES_SUCCESS);
	dst_ring.enq = enq_fail;
	CU_ASSERT_EQUAL(nts_edit_nodecap(&fake, gtpu_pkt, 0, &routing_param), NES_FAIL);
	rte_pktmbuf_free(gtpu_pkt);
}

static void
nts_edit_ring_flow_set_test(void) {
	struct rte_ring ring;
	nes_ring_t ring_nts = {
		.ring = &ring,
	};
	strcpy(ring.name, "NTS_DWSTR_GTPU2");
	ring_nts.flow = NULL;
	CU_ASSERT_EQUAL(nts_edit_ring_flow_set(&ring_nts), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(ring_nts.flow);

	strcpy(ring.name, "NTS_UPSTR_IP2");
	ring_nts.flow = NULL;
	CU_ASSERT_EQUAL(nts_edit_ring_flow_set(&ring_nts), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(ring_nts.flow);

	strcpy(ring.name, "NTS_LBP");
	ring_nts.flow = NULL;
	CU_ASSERT_EQUAL(nts_edit_ring_flow_set(&ring_nts), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(ring_nts.flow);

	strcpy(ring.name, "NTS_VM");
	ring_nts.flow = NULL;
	CU_ASSERT_EQUAL(nts_edit_ring_flow_set(&ring_nts), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(ring_nts.flow);

	strcpy(ring.name, "NTS_ERR");
	ring_nts.flow = NULL;
	CU_ASSERT_EQUAL(nts_edit_ring_flow_set(&ring_nts), NES_FAIL);
	CU_ASSERT_PTR_NULL(ring_nts.flow);
}

static void
nts_edit_init_test(void) {
	CU_ASSERT_EQUAL(nts_edit_init(), NES_SUCCESS);
	CU_ASSERT_EQUAL(nts_edit_init(), NES_FAIL);
}

static void
nts_route_entry_edit_set_test(void) {
	nts_route_entry_t entry;
	CU_ASSERT_EQUAL(nts_route_entry_edit_set(&entry, NTS_EDIT_NULL_CALLBACK), NES_SUCCESS);
	CU_ASSERT_PTR_NULL(entry.edit);
	entry.edit = NULL;

	CU_ASSERT_EQUAL(nts_route_entry_edit_set(&entry, NTS_EDIT_DECAP_ONLY), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(entry.edit);
	entry.edit = NULL;

	CU_ASSERT_EQUAL(nts_route_entry_edit_set(&entry, 999), NES_FAIL);
	CU_ASSERT_PTR_NULL(entry.edit);
}

static void
nts_route_entry_edit_get_test(void) {
	nts_route_entry_t entry;
	entry.edit = NULL;
	CU_ASSERT_EQUAL(nts_route_entry_edit_get(&entry), -1);

	CU_ASSERT_EQUAL(nts_route_entry_edit_set(&entry, NTS_EDIT_DECAP_ONLY), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(entry.edit);
	CU_ASSERT_EQUAL(nts_route_entry_edit_get(&entry), NTS_EDIT_DECAP_ONLY);
}

void add_nts_edit_suite_to_registry(void) {
	CU_pSuite nts_edit_suite = CU_add_suite("nts_edit", init_suite_nts_edit, cleanup_suite_nts_edit);

	CU_add_test(nts_edit_suite, "nts_edit_init_test", nts_edit_init_test);
	CU_add_test(nts_edit_suite, "nts_edit_get_outer_ipv4_hdr_test", nts_edit_get_outer_ipv4_hdr_test);
	CU_add_test(nts_edit_suite, "nts_edit_get_inner_ipv4_hdr_test", nts_edit_get_inner_ipv4_hdr_test);
	CU_add_test(nts_edit_suite, "nts_edit_hdr_parse_gtp_test", nts_edit_hdr_parse_gtp_test);
	CU_add_test(nts_edit_suite, "nts_edit_hdr_parse_ip_test", nts_edit_hdr_parse_ip_test);
	CU_add_test(nts_edit_suite, "nts_edit_hdr_vm_parse_test", nts_edit_hdr_vm_parse_test);
	CU_add_test(nts_edit_suite, "nts_packet_edit_enq_test", nts_packet_edit_enq_test);
	CU_add_test(nts_edit_suite, "nts_packet_flow_encap_gtpu_test", nts_packet_flow_encap_gtpu_test);
	CU_add_test(nts_edit_suite, "nts_packet_flow_encap_ip_test", nts_packet_flow_encap_ip_test);
	CU_add_test(nts_edit_suite, "nts_flow_vm_test", nts_flow_vm_test);
	CU_add_test(nts_edit_suite, "nts_edit_decap_test", nts_edit_decap_test);
	CU_add_test(nts_edit_suite, "nts_edit_nodecap_test", nts_edit_nodecap_test);
	CU_add_test(nts_edit_suite, "nts_edit_ring_flow_set_test", nts_edit_ring_flow_set_test);
	CU_add_test(nts_edit_suite, "nts_route_entry_edit_set_test", nts_route_entry_edit_set_test);
	CU_add_test(nts_edit_suite, "nts_route_entry_edit_get_test", nts_route_entry_edit_get_test);
}

