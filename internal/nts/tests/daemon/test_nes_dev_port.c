/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdlib.h>
#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <CUnit/CUnit.h>
#include "nes_common.h"
#include "test_nes_dev_port.h"
#include "io/nes_dev.h"
#include "libnes_cfgfile.h"
#include "libnes_queue.h"
#include "nts/nts_edit.h"
#include "nes_dev_port_decl.h"
#include "nes_dev_eth_decl.h"
#include "pkt_generator.h"
#include "io/nes_io.h"
#include "libnes_queue.h"
#include "nes_ring_lookup.h"
#include "nes_ring_lookup_decl.h"
#include "test_nes_ring_lookup.h"
#include "io/nes_dev_addons.h"
#include "libnes_cfgfile_def.h"

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define PKTMBUF_POOL_NAME "PORT_test_pool"
#define INVALID_PORT    (rte_eth_dev_count_avail() + 1)
#define INVALID_QUEUE   99
#define VALID_PORT      0
#define VALID_QUEUE     0

MOCK_INIT(mocked_nts_get_dst_ring);

static struct rte_mempool *pkt_pktmbuf_pool;
struct rte_cfgfile *cfg_bak;
extern struct rte_cfgfile *nes_cfgfile;
extern nes_acl_ctx_t nis_param_acl_ctx;
extern nes_lookup_table_t nes_ring_lookup_table;
static nes_queue_t * nes_io_devices;

#define CFG_ALLOC_SECTION_BATCH 4
#define CFG_ALLOC_ENTRIES_BATCH 8

static struct rte_cfgfile_entry  entries1[] = {
	{ .name = "name", .value = "ENB", },
	{ .name = "traffic-direction", .value = "both", },
	{ .name = "traffic-type", .value = "mixed", },
	{ .name = "egress-port", .value = "1", },
	{ .name = "mac", .value = "00:00:00:00:00:00", },
	{ .name = "pci-address", .value = "0000:00:00.0", },
};

static struct rte_cfgfile_entry  entries2[] = {
	{ .name = "name", .value = "EPC", },
	{ .name = "traffic-direction", .value = "both", },
	{ .name = "traffic-type", .value = "mixed", },
	{ .name = "egress-port", .value = "0", },
	{ .name = "mac", .value = "00:00:00:00:00:00", },
	{ .name = "pci-address", .value = "0000:00:00.0", },
};

static struct rte_cfgfile_entry  entries3[] = {
	{ .name = "name", .value = "LBP", },
	{ .name = "traffic-direction", .value = "lbp", },
	{ .name = "traffic-type", .value = "IP", },
	{ .name = "mac", .value = "00:00:00:00:00:00", },
	{ .name = "pci-address", .value = "0000:00:00.0", },
};

static nes_ring_t *
nts_get_dst_ring_stub(struct rte_mbuf __attribute__((unused)) *m, uint8_t __attribute__((unused)) is_gtp)  {
	return NULL;
}

int init_suite_nes_dev_port(void)
{
	MOCK_SET(mocked_nts_get_dst_ring, nts_get_dst_ring_stub);
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
	if (NULL == pkt_pktmbuf_pool)
		return -1;
	nes_io_dev_queue_get(&nes_io_devices);

	cfg_bak = nes_cfgfile;

	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile);

	nes_cfgfile->sections = malloc(
		sizeof(struct rte_cfgfile_section) * CFG_ALLOC_SECTION_BATCH);

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile->sections);

	strncpy(nes_cfgfile->sections[0].name, "PORT0", sizeof(nes_cfgfile->sections[0].name));
	nes_cfgfile->sections[0].num_entries = sizeof(entries1)/sizeof(entries1[0]);
	nes_cfgfile->sections[0].entries = entries1;

	strncpy(nes_cfgfile->sections[1].name, "PORT1", sizeof(nes_cfgfile->sections[1].name));
	nes_cfgfile->sections[1].num_entries = sizeof(entries2)/sizeof(entries2[0]);
	nes_cfgfile->sections[1].entries = entries2;

	strncpy(nes_cfgfile->sections[2].name, "PORT2", sizeof(nes_cfgfile->sections[2].name));
	nes_cfgfile->sections[2].num_entries = sizeof(entries3)/sizeof(entries3[0]);
	nes_cfgfile->sections[2].entries = entries3;

	nes_cfgfile->num_sections = 2;
	return CUE_SUCCESS;
}

int cleanup_suite_nes_dev_port(void)
{
	MOCK_RESET(mocked_nts_get_dst_ring);
	free(nes_cfgfile->sections);
	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;
	return CUE_SUCCESS;
}

static int change_key_in_cfg(const char *section, const char *key, char *new_key)
{
	int i;

	for (i = 0; i < nes_cfgfile->num_sections; i++) {
		if (0 == strncmp(nes_cfgfile->sections[i].name, section,
				sizeof(((struct rte_cfgfile_section*)0)->name) - 1)) {
			int j;
			for (j = 0; j < nes_cfgfile->sections[i].num_entries; j++) {
				if (0 == strncmp(nes_cfgfile->sections[i].entries[j].name, key,
						sizeof(((struct rte_cfgfile_entry *)0)->name) - 1)) {
					strncpy(nes_cfgfile->sections[i].entries[j].name, new_key,
						sizeof(((struct rte_cfgfile_entry *)0)->name) - 1);
					return NES_SUCCESS;
				}
			}
		}
	}
	return NES_FAIL;
}

static int change_entry_in_cfg(const char *section, const char *entry, char *new_value)
{
	const char *buffer;
	char *dst;
	if (NES_SUCCESS == nes_cfgfile_entry(section, entry, &buffer)) {
		dst = (char*)(uintptr_t)buffer;
		strncpy(dst, new_value, sizeof(((struct rte_cfgfile_entry *)0)->value) - 1);
		return NES_SUCCESS;
	}
	return NES_FAIL;
}

void test_nes_dev_port_new_device(void)
{
	char buf[256];
	struct ether_addr mac_addr;
	struct rte_pci_addr pci_addr;

	nes_dev_port_dtor();
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
	/* read MAC addresses from physical cards */
	CU_ASSERT_EQUAL(nes_dev_eth_mac_addr_get(0, &mac_addr), NES_SUCCESS);
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
		mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
	change_entry_in_cfg("PORT0", "mac", buf);
	nes_dev_eth_mac_addr_get(1, &mac_addr);
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
		mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
	change_entry_in_cfg("PORT1", "mac", buf);
	/* read PCI addresses from physical cards */
	nes_dev_eth_pci_addr_get(0, &pci_addr);
	sprintf(buf, "%04x:%02x:%02x.%d",
		pci_addr.domain, pci_addr.bus, pci_addr.devid, pci_addr.function);
	change_entry_in_cfg("PORT0", "pci-address", buf);
	nes_dev_eth_pci_addr_get(1, &pci_addr);
	sprintf(buf, "%04x:%02x:%02x.%d",
		pci_addr.domain, pci_addr.bus, pci_addr.devid, pci_addr.function);
	change_entry_in_cfg("PORT1", "pci-address", buf);

	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
	nes_dev_port_dtor();

	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"upstream");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"mixed");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"downstream");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"mixed");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
	nes_dev_port_dtor();

	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"upstream");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"LTE");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"downstream");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"IP");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
	nes_dev_port_dtor();

	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"downstream");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"LTE");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"upstream");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"IP");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
	nes_dev_port_dtor();

	change_key_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"traffic-ty");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
	nes_dev_port_dtor();
	change_key_in_cfg("PORT0", "traffic-ty", (char*)(uintptr_t)"traffic-type");

	change_key_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"traffic-dir");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
	nes_dev_port_dtor();
	change_key_in_cfg("PORT0", "traffic-dir", (char*)(uintptr_t)"traffic-direction");

	change_key_in_cfg("PORT0", "egress-port", (char*)(uintptr_t)"egress-p");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
	nes_dev_port_dtor();
	change_key_in_cfg("PORT0", "egress-p", (char*)(uintptr_t)"egress-port");

	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"downstream");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"LTE");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"upstream");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"IP");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
	nes_dev_port_dtor();

	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"LTE");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"IP");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
	nes_dev_port_dtor();

	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"ERROR");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"LTE");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"IP");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
	nes_dev_port_dtor();

	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"upstream");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"ERROR");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
	nes_dev_port_dtor();

	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
	nes_dev_port_dtor();
	change_entry_in_cfg("PORT0", "name", (char*)(uintptr_t)"");
	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"mixed");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"mixed");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);

	change_entry_in_cfg("PORT0", "name", (char*)(uintptr_t)"ENB");
	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"mixed");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"lbp");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"IP");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
	nes_dev_port_dtor();

	nes_ring_t *ring_bak;
	if (NES_SUCCESS == nes_ring_find(&ring_bak, "NTS_DWSTR_IP")) {
		nes_ring_del("NTS_DWSTR_IP");
		CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_FAIL);
		nes_ring_add("NTS_DWSTR_IP", ring_bak);
	}
	nes_dev_port_dtor();

	change_entry_in_cfg("PORT0", "name", (char*)(uintptr_t)"ENB");
	change_entry_in_cfg("PORT0", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT1", "traffic-direction", (char*)(uintptr_t)"both");
	change_entry_in_cfg("PORT0", "traffic-type", (char*)(uintptr_t)"mixed");
	change_entry_in_cfg("PORT1", "traffic-type", (char*)(uintptr_t)"mixed");
	CU_ASSERT_EQUAL(nes_dev_port_new_device(), NES_SUCCESS);
}

static struct nes_rings_bak_s upstr_rings_tab[] = {
	{ "NIS_UPSTR_RNIS", NULL },
	{ "NIS_UPSTR_SCTP", NULL },
	{ "NIS_UPSTR_GTPUC", NULL },
	{ "NIS_UPSTR_GTPC", NULL },
	{ "NTS_UPSTR_GTPU", NULL },
};
static struct nes_rings_bak_s dwstr_rings_tab[] = {
	{ "NIS_DWSTR_RNIS", NULL },
	{ "NIS_DWSTR_SCTP", NULL },
	{ "NIS_DWSTR_GTPUC", NULL },
	{ "NIS_DWSTR_GTPC", NULL },
	{ "NTS_DWSTR_GTPU", NULL },
};

void test_get_port_rings(void)
{
	nes_ring_t *ring_bak;
	nes_dev_t device;
	memset(&device, 0, sizeof(nes_dev_t));

	device.traffic_type  = TT_IP;
	device.egres_port = 1;
	device.name = (char*)(uintptr_t)"TEST";

	if (NES_SUCCESS == nes_ring_find(&ring_bak, "NTS_UPSTR_IP")) {
		nes_ring_del("NTS_UPSTR_IP");
		device.traffic_dir = TD_UPSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_BOTH;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		nes_ring_add("NTS_UPSTR_IP", ring_bak);
	}

	if (NES_SUCCESS == nes_ring_find(&ring_bak, "PORT_0_IO_ANY")) {
		nes_ring_del("PORT_0_IO_ANY");
		device.traffic_dir = TD_UPSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_DOWNSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_BOTH;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		nes_ring_add("PORT_0_IO_ANY", ring_bak);
	}

	if (NES_SUCCESS == nes_ring_find(&ring_bak, "PORT_1_IO_ANY")) {
		nes_ring_del("PORT_1_IO_ANY");
		device.traffic_dir = TD_UPSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_DOWNSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_BOTH;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		nes_ring_add("PORT_1_IO_ANY", ring_bak);
	}

	if (NES_SUCCESS == nes_ring_find(&ring_bak, "NTS_DWSTR_IP")) {
		nes_ring_del("NTS_DWSTR_IP");
		device.traffic_dir = TD_DOWNSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_BOTH;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		nes_ring_add("NTS_DWSTR_IP", ring_bak);
	}

	device.traffic_type  = TT_MIXED;

	if (NES_SUCCESS == nes_ring_find(&ring_bak, "PORT_0_IO_ANY")) {
		nes_ring_del("PORT_0_IO_ANY");
		device.traffic_dir = TD_UPSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_DOWNSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_BOTH;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		nes_ring_add("PORT_0_IO_ANY", ring_bak);
	}

	if (NES_SUCCESS == nes_ring_find(&ring_bak, "PORT_1_IO_ANY")) {
		nes_ring_del("PORT_1_IO_ANY");
		device.traffic_dir = TD_UPSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_DOWNSTREAM;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		device.traffic_dir = TD_BOTH;
		CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
		nes_ring_add("PORT_1_IO_ANY", ring_bak);
	}

	size_t i;
	for (i = 0; i < sizeof(upstr_rings_tab)/sizeof(upstr_rings_tab[0]); i++) {
		if (NES_SUCCESS == nes_ring_find(&upstr_rings_tab[i].ring,
				upstr_rings_tab[i].name)) {
			nes_ring_del(upstr_rings_tab[i].name);
			device.traffic_dir = TD_UPSTREAM;
			CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
			device.traffic_dir = TD_BOTH;
			CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
			nes_ring_add(upstr_rings_tab[i].name, upstr_rings_tab[i].ring);
		}
	}

	for (i = 0; i < sizeof(dwstr_rings_tab)/sizeof(dwstr_rings_tab[0]); i++) {
		if (NES_SUCCESS == nes_ring_find(&dwstr_rings_tab[i].ring,
				dwstr_rings_tab[i].name)) {
			nes_ring_del(dwstr_rings_tab[i].name);
			device.traffic_dir = TD_DOWNSTREAM;
			CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
			device.traffic_dir = TD_BOTH;
			CU_ASSERT_EQUAL(get_port_rings(&device), NES_FAIL);
			nes_ring_add(dwstr_rings_tab[i].name, dwstr_rings_tab[i].ring);
		}
	}
}

static struct rte_mbuf *pkt;

void test_scatter_port(void)
{
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	static uint32_t ip_src = GET_IPV4_ADDRESS(192, 168, 0, 1);
	static uint32_t ip_dst = GET_IPV4_ADDRESS(192, 168, 1, 1);
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	uint8_t ip_len;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 1, 10);
	init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
	ip_len = ipv4_hdr->version_ihl & 0xf;

	nes_queue_node_t *node;
	nes_dev_t *device = NULL;
	NES_QUEUE_FOREACH(node, nes_io_devices) {
		nes_queue_node_unlock(node);
		if (((nes_dev_t *)node->data)->dev_type == ETH) {
			device = node->data;
			break;
		}
	}

	if (NULL != device) {
		device->rx_cnt = 1;
		device->rx_pkts[0] = pkt;

		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 1, 10);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		ipv4_hdr = (struct ipv4_hdr *)((uint8_t*)ipv4_hdr + sizeof(struct vlan_hdr));
		init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
		ip_len = ipv4_hdr->version_ihl & 0xf;
		udp_hdr = (struct udp_hdr*)((uint32_t *)ipv4_hdr + ip_len);
		udp_hdr->dst_port = rte_cpu_to_be_16(UDP_GTPU_PORT);
		udp_hdr->src_port = rte_cpu_to_be_16(UDP_GTPU_PORT);
		((gtpuHdr_t*)(udp_hdr + 1))->msg_type = GTPU_MSG_GPDU;
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);

		/* UDP_GTPU_PORT */
		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
		ip_len = ipv4_hdr->version_ihl & 0xf;
		udp_hdr = (struct udp_hdr*)((uint32_t *)ipv4_hdr + ip_len);
		udp_hdr->dst_port = rte_cpu_to_be_16(UDP_GTPU_PORT);
		udp_hdr->src_port = rte_cpu_to_be_16(UDP_GTPU_PORT);
		((gtpuHdr_t*)(udp_hdr + 1))->msg_type = GTPU_MSG_GPDU;
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);

		/* UDP_GTPC_PORT */
		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
		ip_len = ipv4_hdr->version_ihl & 0xf;
		udp_hdr = (struct udp_hdr*)((uint32_t *)ipv4_hdr + ip_len);
		udp_hdr->dst_port = rte_cpu_to_be_16(UDP_GTPC_PORT);
		udp_hdr->src_port = rte_cpu_to_be_16(UDP_GTPC_PORT);
		((gtpuHdr_t*)(udp_hdr + 1))->msg_type = GTPU_MSG_GPDU;
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);

		/* udp_port !=  */
		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
		ip_len = ipv4_hdr->version_ihl & 0xf;
		udp_hdr = (struct udp_hdr*)((uint32_t *)ipv4_hdr + ip_len);
		udp_hdr->dst_port = rte_cpu_to_be_16(80);
		udp_hdr->src_port = rte_cpu_to_be_16(80);
		((gtpuHdr_t*)(udp_hdr + 1))->msg_type = GTPU_MSG_GPDU;
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);

		/* ipv4_hdr->next_proto_id = IP_PROTO_SCTP */
		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
		ipv4_hdr->next_proto_id = IP_PROTO_SCTP;
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);

		/* ipv4_hdr->next_proto_id != IP_PROTO_UDP */
		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
		ipv4_hdr->next_proto_id = IP_PROTO_ICMP;
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);

		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv6, 0, 0);
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);

		/* fragmented  packets */
		init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);
		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		init_ipv4_hdr(ipv4_hdr, ip_src, ip_dst, 200);
		ipv4_hdr->next_proto_id = IP_PROTO_ICMP;
		ipv4_hdr->fragment_offset = rte_cpu_to_be_16(IPV4_HDR_OFFSET_MASK);
		CU_ASSERT_EQUAL(scatter_eth_both_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_mixed(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_LTE(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_both_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_upstr_IP(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(scatter_eth_dwstr_IP(device, NULL), NES_SUCCESS);
	}
}

static int enq_fake(struct nes_ring_s *self, void **buffer, int count) {
	(void)self;
	(void)buffer;
	(void)count;
	return 0;
}

#define NTS_LBP_ANY 12
void test_scatter_eth_lbp(void)
{
	nes_ring_t *ring;
	nes_queue_node_t *node;
	nes_dev_t *device = NULL;
	NES_QUEUE_FOREACH(node, nes_io_devices) {
		nes_queue_node_unlock(node);
		if (((nes_dev_t *)node->data)->dev_type == ETH) {
			device = node->data;
			break;
		}
	}
	if (NULL != device) {
		int (*enq_bak)(struct nes_ring_s *, void **, int);
		ring = device->rx_rings[NTS_LBP_ANY];
		nes_ring_find(&device->rx_rings[NTS_LBP_ANY], "NTS_DWSTR_IP");
		device->rx_cnt = 0;
		CU_ASSERT_EQUAL(scatter_eth_lbp(device, NULL), NES_SUCCESS);
		device->rx_cnt = 1;
		device->rx_pkts[0] = pkt;
		CU_ASSERT_EQUAL(scatter_eth_lbp(device, NULL), NES_SUCCESS);
		enq_bak = device->rx_rings[NTS_LBP_ANY]->enq_burst;
		device->rx_rings[NTS_LBP_ANY]->enq_burst = enq_fake;
		CU_ASSERT_EQUAL(scatter_eth_lbp(device, NULL), NES_FAIL);
		device->rx_rings[NTS_LBP_ANY]->enq_burst = enq_bak;
		device->rx_rings[NTS_LBP_ANY] = ring;
	}
}

void test_ctor_eth_port(void)
{
	nes_dev_t dev;
	nes_dev_id_t data;
	CU_ASSERT_EQUAL(ctor_eth_port(&dev, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(ctor_eth_port(NULL, &data), NES_FAIL);
	dev.dev_type = ETH;
	dev.dev.eth.port_id = 255;
	CU_ASSERT_EQUAL(nes_dev_add_device(&dev), NES_FAIL);
}

void test_add_ring_to_ntsqueue(void)
{
#define PORT_RX_RINGS_CNT 14
	nes_ring_t *rx_rings[PORT_RX_RINGS_CNT];
	nes_ring_t ring;
	memset(rx_rings, 0, sizeof(rx_rings));
	ring.ring = NULL;
	rx_rings[0] = &ring;
	CU_ASSERT_EQUAL(add_ring_to_ntsqueue(NULL, (nes_ring_t **)&rx_rings), NES_SUCCESS);
}

void test_dtor_port(void)
{
	nes_queue_node_t *node;
	nes_dev_t *device = NULL;
	NES_QUEUE_FOREACH(node, nes_io_devices) {
		nes_queue_node_unlock(node);
		if (((nes_dev_t *)node->data)->dev_type == ETH) {
			device = node->data;
			break;
		}
	}
	if (NULL != device) {
		CU_ASSERT_EQUAL(device->dtor(device, NULL), NES_SUCCESS);
		CU_ASSERT_EQUAL(device->dtor(device, NULL), NES_SUCCESS);
	}
}

void add_nes_dev_port_suite_to_registry(void) {
	// CU_pSuite nes_dev_port_suite = CU_add_suite("nes_dev_port", init_suite_nes_dev_port, cleanup_suite_nes_dev_port);

	// CU_add_test(nes_dev_port_suite, "nes_dev_port_new_device", test_nes_dev_port_new_device);
	// CU_add_test(nes_dev_port_suite, "get_port_rings", test_get_port_rings);
	// CU_add_test(nes_dev_port_suite, "scatter_port", test_scatter_port);
	// CU_add_test(nes_dev_port_suite, "scatter_eth_lbp", test_scatter_eth_lbp);
	// CU_add_test(nes_dev_port_suite, "ctor_eth_port", test_ctor_eth_port);
	// CU_add_test(nes_dev_port_suite, "add_ring_to_ntsqueue", test_add_ring_to_ntsqueue);
	// CU_add_test(nes_dev_port_suite, "dtor_port", test_dtor_port);
}

