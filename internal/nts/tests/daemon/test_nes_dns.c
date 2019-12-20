/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include "test_nes_dns.h"
#include "pkt_generator.h"
#include "nts/nts_route.h"
#include "dns/nes_dns.h"
#include "ctrl/nes_ctrl.h"
#include "nes_dns_decl.h"
#include "libnes_cfgfile.h"
#include "io/nes_dev_addons.h"
#include "nes_ring_lookup.h"
#include "nes_ring_lookup_decl.h"
#include "libnes_cfgfile_def.h"

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define PKTMBUF_POOL_NAME "nes_dns_pktmbuf_pool"

extern nes_lookup_table_t nes_ring_lookup_table;
static struct rte_mempool *pkt_pktmbuf_pool;
MOCK_INIT(mocked_nes_lookup_entry_find);
MOCK_INIT(mocked_rte_pktmbuf_free);
MOCK_INIT(mocked_nts_acl_cfg_lookup_prepare);
MOCK_INIT(mocked_nts_acl_cfg_overlaps);
MOCK_INIT(mocked_nes_acl_find_rule_id);
MOCK_INIT(mocked_nes_acl_add_entries);
MOCK_INIT(mocked_nes_sq_enq);
MOCK_INIT(mocked_rte_mempool_create);

int
init_suite_nes_dns(void) {
	MOCK_RESET(mocked_nes_lookup_entry_find);
	MOCK_RESET(mocked_rte_pktmbuf_free);
	MOCK_RESET(mocked_nts_acl_cfg_lookup_prepare);
	MOCK_RESET(mocked_nts_acl_cfg_overlaps);
	MOCK_RESET(mocked_nes_acl_find_rule_id);
	MOCK_RESET(mocked_nes_acl_add_entries);
	MOCK_RESET(mocked_nes_sq_enq);
	MOCK_RESET(mocked_rte_mempool_create);

	pkt_pktmbuf_pool = rte_mempool_create(
		PKTMBUF_POOL_NAME,
		1,
		MBUF_SIZE,
		0,
		sizeof (struct rte_pktmbuf_pool_private),
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
cleanup_suite_nes_dns(void) {
	MOCK_RESET(mocked_nes_lookup_entry_find);
	MOCK_RESET(mocked_rte_pktmbuf_free);
	MOCK_RESET(mocked_nts_acl_cfg_lookup_prepare);
	MOCK_RESET(mocked_nts_acl_cfg_overlaps);
	MOCK_RESET(mocked_nes_acl_find_rule_id);
	MOCK_RESET(mocked_nes_acl_add_entries);
	MOCK_RESET(mocked_nes_sq_enq);
	MOCK_RESET(mocked_rte_mempool_create);

	return CUE_SUCCESS;
}

static void
nes_dns_agent_decap_test(void) {
	struct rte_mbuf *gtpu_pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	uint32_t inner_src_ip = GET_IPV4_ADDRESS(192, 168, 0, 2);
	uint32_t inner_dst_ip = GET_IPV4_ADDRESS(192, 168, 0, 3);
	init_gtpu_pkt(gtpu_pkt,
		GET_IPV4_ADDRESS(192, 168, 0, 0),
		GET_IPV4_ADDRESS(192, 168, 0, 1),
		inner_src_ip,
		inner_dst_ip,
		0,
		0,
		0);
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;

	eth_hdr = rte_pktmbuf_mtod(gtpu_pkt, struct ether_hdr *);
	uint8_t inner_ip_offset = sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr) +
		sizeof (struct udp_hdr) + sizeof (gtpu_hdr);
	nes_dns_agent_decap(gtpu_pkt, (struct ipv4_hdr*) ((uint8_t*) eth_hdr + inner_ip_offset));
	eth_hdr = rte_pktmbuf_mtod(gtpu_pkt, struct ether_hdr *);
	ip_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	CU_ASSERT_EQUAL(ip_hdr->src_addr, rte_cpu_to_be_32(inner_src_ip));
	CU_ASSERT_EQUAL(ip_hdr->dst_addr, rte_cpu_to_be_32(inner_dst_ip));
	rte_pktmbuf_free(gtpu_pkt);
}

static int nes_lookup_entry_find_stub_ret = NES_FAIL;
nts_enc_entry_t *nes_lookup_entry_find_entry = NULL;

static int
nes_lookup_entry_find_stub(nes_lookup_table_t *lookup_table, const void *key, void **pentry) {
	(void) lookup_table;
	(void) key;
	*pentry = nes_lookup_entry_find_entry;
	return nes_lookup_entry_find_stub_ret;
}
extern nts_lookup_tables_t *routing_table;

static void
nes_dns_agent_encap_test(void) {
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 0);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 0, 0);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	struct rte_mbuf *pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
	ip_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	init_ipv4_hdr(ip_hdr, ip_src, ip_dst, 32);

	MOCK_SET(mocked_nes_lookup_entry_find, nes_lookup_entry_find_stub);
	routing_table = NULL;

	static nts_enc_entry_t encap_entry;
	CU_ASSERT_EQUAL(nes_dns_agent_encap(pkt, NULL), NES_FAIL);
	nes_lookup_entry_find_stub_ret = NES_SUCCESS;
//    CU_ASSERT_EQUAL(nes_dns_agent_encap(pkt, &encap_entry), NES_FAIL);
	static nts_enc_entry_t entry;
	nes_lookup_entry_find_entry = &entry;
	CU_ASSERT_EQUAL(nes_dns_agent_encap(pkt, &encap_entry), NES_SUCCESS);
	rte_pktmbuf_free(pkt);
}

extern uint8_t forward_unresolved_queries;
extern int tap_dev_fd;
uint32_t static_dns_entries_cnt;

// static int
// enq_stub(struct nes_ring_s __attribute__((unused)) * ring, void __attribute__((unused)) * el) {
// 	return 1;
// }

// static void
// rte_pktmbuf_free_stub(struct rte_mbuf __attribute__((unused)) * m) {
// }

static int *nts_acl_cfg_lookup_prepare_stub_ret = NULL;
static int nts_acl_cfg_lookup_prepare_stub_ret_id = 0;

static int
nts_acl_cfg_lookup_prepare_stub(struct nts_acl_lookup_field __attribute__((unused)) * lookup,
	struct nts_acl_lookup_field __attribute__((unused)) * reverse_lookup,
	const char __attribute__((unused)) * lookup_str)
{
	if (nts_acl_cfg_lookup_prepare_stub_ret)
		return nts_acl_cfg_lookup_prepare_stub_ret[nts_acl_cfg_lookup_prepare_stub_ret_id++];

	return NES_FAIL;
}

static int *nts_acl_cfg_overlaps_stub_ret = NULL;
static int nts_acl_cfg_overlaps_stub_ret_id = 0;

static int
nts_acl_cfg_overlaps_stub(nes_acl_ctx_t __attribute__((unused)) * lookup_ctx,
	struct nts_acl_lookup_field __attribute__((unused)) * lookup)
{
	if (nts_acl_cfg_overlaps_stub_ret)
		return nts_acl_cfg_overlaps_stub_ret[nts_acl_cfg_overlaps_stub_ret_id++];

	return NTS_ACL_LOOKUPS_MATCH;
}

static int **rte_malloc_stub_ret;
static int rte_malloc_stub_ret_id;

static void*
rte_malloc_stub(const char __attribute__((unused)) * type,
	size_t __attribute__((unused)) size,
	unsigned __attribute__((unused)) align)
{
	return rte_malloc_stub_ret[rte_malloc_stub_ret_id++];
}

static void
rte_free_stub(void __attribute__((unused)) * ptr) {
}

static int *nes_acl_find_rule_id_stub_ret;
static int nes_acl_find_rule_id_stub_ret_id;

static int
nes_acl_find_rule_id_stub(nes_acl_ctx_t __attribute__((unused)) * ctx,
	struct rte_acl_rule __attribute__((unused)) * rule)
{
	if (nes_acl_find_rule_id_stub_ret)
		return nes_acl_find_rule_id_stub_ret[nes_acl_find_rule_id_stub_ret_id++];

	return -1;
}

static int nes_acl_add_entries_stub_ret = -1;

static int
nes_acl_add_entries_stub(nes_acl_ctx_t __attribute__((unused)) * ctx,
	void __attribute__((unused))**entries,
	struct rte_acl_rule __attribute__((unused))**rules,
	uint32_t __attribute__((unused))count)
{
	return nes_acl_add_entries_stub_ret;
}

static int nes_sq_enq_stub_ret = NES_FAIL;

static int
nes_sq_enq_stub(nes_sq_t __attribute__((unused)) * queue, void __attribute__((unused)) * data)
{
	return nes_sq_enq_stub_ret;
}

#define RESET__ADD_RET_IDS() do { \
		nts_acl_cfg_lookup_prepare_stub_ret_id = 0; \
		nts_acl_cfg_overlaps_stub_ret_id = 0; \
		rte_malloc_stub_ret_id = 0; \
		nes_acl_find_rule_id_stub_ret_id = 0; \
	} while(0)

static void
nes_dns_agent_add_routings_test(void)
{
	MOCK_SET(mocked_nts_acl_cfg_lookup_prepare, nts_acl_cfg_lookup_prepare_stub);
	MOCK_SET(mocked_nts_acl_cfg_overlaps, nts_acl_cfg_overlaps_stub);
	MOCK_SET(mocked_rte_malloc, rte_malloc_stub);
	MOCK_SET(mocked_rte_free, rte_free_stub);
	MOCK_SET(mocked_nes_acl_find_rule_id, nes_acl_find_rule_id_stub);
	MOCK_SET(mocked_nes_acl_add_entries, nes_acl_add_entries_stub);
	MOCK_SET(mocked_nes_sq_enq, nes_sq_enq_stub);

	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(NULL), NES_FAIL);
	forward_unresolved_queries = 1;
	int ret[] = {NES_SUCCESS, NES_FAIL};
	nts_acl_cfg_lookup_prepare_stub_ret = ret;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(NULL), NES_FAIL);
	RESET__ADD_RET_IDS();

	int *malloc_ret[] = {NULL};
	rte_malloc_stub_ret = malloc_ret;
	static int ret_prepare[] = {NES_SUCCESS, NES_SUCCESS};
	nts_acl_cfg_lookup_prepare_stub_ret = ret_prepare;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(NULL), NES_FAIL);
	RESET__ADD_RET_IDS();

	int ret_overlaps[] = {NTS_ACL_LOOKUPS_DIFFER, NTS_ACL_LOOKUPS_MATCH};
	nts_acl_cfg_overlaps_stub_ret = ret_overlaps;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(NULL), NES_FAIL);
	RESET__ADD_RET_IDS();

	static int ret_overlaps1[] = {NTS_ACL_LOOKUPS_DIFFER, NTS_ACL_LOOKUPS_DIFFER};
	nts_acl_cfg_overlaps_stub_ret = ret_overlaps1;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(NULL), NES_FAIL);
	RESET__ADD_RET_IDS();

	nts_route_entry_t upstream_route, downstream_route;
	nts_route_entry_t * malloc_ret1[] = {&upstream_route, NULL, &upstream_route, NULL};
	rte_malloc_stub_ret = (int**) malloc_ret1;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(NULL), NES_FAIL);
	RESET__ADD_RET_IDS();

	static nes_acl_ctx_t acl_ctx;
	nts_route_entry_t * malloc_ret2[] = {&upstream_route, &downstream_route, NULL};
	rte_malloc_stub_ret = (int**) malloc_ret2;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(&acl_ctx), NES_FAIL);
	RESET__ADD_RET_IDS();

	nes_sq_t q;
	struct rte_acl_rule rule;
	rule.data.userdata = 1;
	struct rte_acl_rule * rules[] = {&rule};
	acl_ctx.rules = rules;
	int *entries[] = {NULL};
	acl_ctx.entries = (void**) entries;
	static int find_ret[] = {0, 0, 0, 0};
	nes_acl_find_rule_id_stub_ret = find_ret;

	int *malloc_ret3[] = {(int*) &upstream_route, (int*) &downstream_route, (int*) &q, NULL};
	rte_malloc_stub_ret = (int**) malloc_ret3;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(&acl_ctx), NES_FAIL);
	RESET__ADD_RET_IDS();

	int *malloc_ret4[] =
		{(int*) &upstream_route, (int*) &downstream_route, (int*) &q, (int*) &q,
		 (int*) &upstream_route, (int*) &downstream_route, (int*) &q, (int*) &q};
	rte_malloc_stub_ret = malloc_ret4;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(&acl_ctx), NES_FAIL);
	RESET__ADD_RET_IDS();

	nes_sq_enq_stub_ret = NES_SUCCESS;
	CU_ASSERT_EQUAL(nes_dns_agent_add_routings(&acl_ctx), NES_SUCCESS);
	RESET__ADD_RET_IDS();
	forward_unresolved_queries = 0;

	MOCK_RESET(mocked_nts_acl_cfg_lookup_prepare);
	MOCK_RESET(mocked_nts_acl_cfg_overlaps);
	MOCK_RESET(mocked_rte_malloc);
	MOCK_RESET(mocked_rte_free);
	MOCK_RESET(mocked_nes_acl_find_rule_id);
	MOCK_RESET(mocked_nes_acl_add_entries);
	MOCK_RESET(mocked_nes_sq_enq);
}

static struct rte_mempool *rte_mempool_create_stub_ret;

static struct rte_mempool *
rte_mempool_create_stub(const char UNUSED(*name), unsigned UNUSED(n), unsigned UNUSED(elt_size),
	unsigned UNUSED(cache_size), unsigned UNUSED(private_data_size),
	rte_mempool_ctor_t UNUSED(*mp_init), void UNUSED(*mp_init_arg),
	rte_mempool_obj_ctor_t UNUSED(*obj_init), void UNUSED(*obj_init_arg),
	int UNUSED(socket_id), unsigned UNUSED(flags))
{
	return rte_mempool_create_stub_ret;
}

extern struct rte_cfgfile *nes_cfgfile;
extern nes_acl_ctx_t nes_ctrl_acl_ctx;
static void
nes_dns_agent_setup_test(void)
{
	MOCK_SET(mocked_rte_mempool_create, rte_mempool_create_stub);
	struct rte_cfgfile *old_cfg, *cfg = malloc(sizeof (*cfg));

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 0;
	cfg->sections = NULL;
	old_cfg = nes_cfgfile;
	nes_cfgfile = cfg;
	CU_ASSERT_EQUAL(nes_dns_agent_setup(NULL), NES_FAIL);

	struct rte_cfgfile_entry  entries_stub[4];
	memset(entries_stub, 0, sizeof(entries_stub));
	struct rte_cfgfile_entry  entries0[] = {
		{
			.name = "local-mac",
			.value = "AA:BB:CC:DD:EE:FF"
		}
	};

	struct rte_cfgfile_section sections[] = {
		{ .name = "DNS"},

	};
	cfg->num_sections = 1;
	sections[0].entries = entries_stub;
	sections[0].entries[0] = entries0[0];
	cfg->sections = sections;
	cfg->sections[0].num_entries = 1;

	CU_ASSERT_EQUAL(nes_dns_agent_setup(NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nes_dns_agent_setup("test"), NES_FAIL);
	int a;
	rte_mempool_create_stub_ret = (struct rte_mempool *) &a; // mempool is not used
	CU_ASSERT_EQUAL(nes_dns_agent_setup("test"), NES_FAIL);

	struct rte_cfgfile_entry  entries1[] = {
		{
			.name = "local-mac",
			.value = "AA:BB:CC:DD:EE:FF"
		},
		{
			.name = "local-ip",
			.value = "192.168.1.1"
		}
	};
	cfg->sections[0].entries[0] = entries1[0];
	cfg->sections[0].entries[1] = entries1[1];
	cfg->sections[0].num_entries = 2;

	CU_ASSERT_EQUAL(nes_dns_agent_setup("test"), NES_SUCCESS);

	struct rte_cfgfile_entry  entries2[] = {
		{
			.name = "local-mac",
			.value = "AA:BB:CC:DD:EE:FF"
		},
		{
			.name = "local-ip",
			.value = "192.168.1.1"
		},
		{
			.name = "external-ip",
			.value = "192.168.1.1"
		}
	};
	cfg->sections[0].entries[0] = entries2[0];
	cfg->sections[0].entries[1] = entries2[1];
	cfg->sections[0].entries[2] = entries2[2];
	cfg->sections[0].num_entries = 3;
	CU_ASSERT_EQUAL(nes_dns_agent_setup("test"), NES_FAIL);
	RESET__ADD_RET_IDS();

	struct rte_cfgfile_entry  entries3[] = {
		{
			.name = "local-mac",
			.value = "AA:BB:CC:DD:EE:FF"
		},
		{
			.name = "local-ip",
			.value = "192.168.1.1"
		},
		{
			.name = "external-ip",
			.value = "192.168.1.1"
		},
		{
			.name = "forward-unresolved",
			.value = "no"
		},
		{
			.name = "forward-unresolved",
			.value = "yes"
		}
	};
	cfg->sections[0].entries[0] = entries3[0];
	cfg->sections[0].entries[1] = entries3[1];
	cfg->sections[0].entries[2] = entries3[2];
	cfg->sections[0].entries[3] = entries3[3];
	cfg->sections[0].num_entries = 4;
	nts_route_entry_t upstream_route, downstream_route;
	nes_sq_t q;
	int *malloc_ret4[] = {
		(int*) &upstream_route, (int*) &downstream_route, (int*) &q, (int*) &q
	};
	rte_malloc_stub_ret = malloc_ret4;

	static nes_acl_ctx_t acl_ctx;
	struct rte_acl_rule rule;
	rule.data.userdata = 1;
	struct rte_acl_rule * rules[] = {&rule};
	acl_ctx.rules = rules;
	int *entries[] = {NULL};
	acl_ctx.entries = (void**) entries;
	nes_acl_ctx_t orig_nes_ctrl_acl_ctx = nes_ctrl_acl_ctx;
	nes_ctrl_acl_ctx = acl_ctx;
	CU_ASSERT_EQUAL(nes_dns_agent_setup("test1"), NES_FAIL);
	cfg->sections[0].entries[3] = entries3[4];
	CU_ASSERT_EQUAL(nes_dns_agent_setup("test1"), NES_FAIL);
	nes_cfgfile = old_cfg;
	nes_ctrl_acl_ctx = orig_nes_ctrl_acl_ctx;

	free(cfg);
}

void add_nes_dns_suite_to_registry(void) {
	CU_pSuite nes_dns_suite = CU_add_suite("nes_dns", init_suite_nes_dns, cleanup_suite_nes_dns);

	CU_add_test(nes_dns_suite, "nes_dns_agent_decap_test", nes_dns_agent_decap_test);
	CU_add_test(nes_dns_suite, "nes_dns_agent_encap_test", nes_dns_agent_encap_test);
	CU_add_test(nes_dns_suite, "nes_dns_agent_add_routings_test", nes_dns_agent_add_routings_test);
	CU_add_test(nes_dns_suite, "nes_dns_agent_setup_test", nes_dns_agent_setup_test);
}

