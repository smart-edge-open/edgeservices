/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdlib.h>
#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_vhost.h>
#include <rte_mbuf.h>
#include <CUnit/CUnit.h>
#include "nes_common.h"
#include "nes_ring_lookup.h"
#include "io/nes_dev.h"
#include "test_nes_dev_vhost.h"
#include "nes_dev_vhost_decl.h"
#include "libnes_cfgfile.h"
#include "libnes_queue.h"
#include "io/nes_io.h"
#include "nts/nts_io.h"
#include "pkt_generator.h"
#include "io/nes_mac_lookup.h"
#include "nts/nts_acl_cfg.h"
#include "libnes_cfgfile_def.h"

extern struct rte_cfgfile *nes_cfgfile;
static nes_queue_t *nes_io_devices;
static nes_queue_t *nts_io_rings;
extern struct rte_mempool *nes_dev_vhost_pktmbuf_pool;
extern nts_lookup_tables_t nts_io_lookup_tables;

MOCK_INIT(mocked_rte_vhost_enable_guest_notification);
MOCK_INIT(mocked_rte_vhost_dequeue_burst);

int init_suite_nes_dev_vhost(void)
{
	nes_io_dev_queue_get(&nes_io_devices);
	nts_io_ring_queue_get(&nts_io_rings);
	MOCK_RESET(mocked_rte_vhost_enable_guest_notification);
	MOCK_RESET(mocked_rte_vhost_dequeue_burst);
	nes_mac_lookup_init();
	return CUE_SUCCESS;
}

int cleanup_suite_nes_dev_vhost(void)
{
	MOCK_RESET(mocked_rte_vhost_enable_guest_notification);
	MOCK_RESET(mocked_rte_vhost_dequeue_burst);
	nes_dev_t *device;
	nes_queue_node_t *node;

	/* remove all VHOST devices */
	while (nes_io_devices->cnt) {
		NES_QUEUE_FOREACH_RETRY(node, nes_io_devices) {
			device = node->data;
			if (device->dev_type == VHOST) {
				nes_queue_node_unlock(node);
				nes_queue_remove(nes_io_devices, node);
			}
		}
	}
	return CUE_SUCCESS;
}

static void test_nes_dev_vhost_mempool_init(void)
{
	CU_ASSERT_EQUAL(NES_SUCCESS, nes_dev_vhost_mempool_init());
}

static void test_create_vm_rings(void)
{
	nes_dev_t *vhost_dev;
	vhost_dev = rte_zmalloc("vhost device", sizeof (*vhost_dev), RTE_CACHE_LINE_SIZE);
	vhost_dev->dev.vhost.vm_id = 0;

	CU_ASSERT_EQUAL(NES_SUCCESS, nts_lookup_init(&nts_io_lookup_tables));
	CU_ASSERT_EQUAL(NES_SUCCESS, create_vm_rings(vhost_dev));
}

static int rte_vhost_enable_guest_notification_stub_ret = 0;

int
rte_vhost_enable_guest_notification_stub(int __attribute__((unused)) vdev,
	uint16_t __attribute__((unused)) queue_id, int __attribute__((unused)) enable) {
	return rte_vhost_enable_guest_notification_stub_ret;
}

pthread_t destroy_thread;

void *destroy_thread_start(void *arg) {
	(void)arg;
	for (NES_FOREVER_LOOP) {
		nes_dev_t *device;
		nes_queue_node_t *node, *removed_node;
		/* Receive, scatter and send*/
		NES_QUEUE_FOREACH(node, nes_io_devices) {
			device = node->data;
			if (unlikely(device->remove)) {
				nes_queue_node_unlock(node);
				if ((removed_node = nes_queue_remove(nes_io_devices,
						node)) != NULL)
					rte_free(removed_node);

				break;
			}
		} /* end for all devices nodes */

		NES_QUEUE_FOREACH(node, nts_io_rings) {
			nes_ring_t *in_ring = node->data;
			if (unlikely(in_ring->remove)) {
				nes_queue_node_unlock(node);
				if ((removed_node = nes_queue_remove(nts_io_rings, node)) != NULL) {
					in_ring->remove = 0;
					rte_free(removed_node);
				}
				break;
			}
		} /* end for all ring nodes */
	} /* end for(;;) */
	return NULL;
}

#define CFG_ALLOC_SECTION_BATCH 8
static void test_mac_authorized(void)
{
	struct nes_dev_s dev;
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;
	static struct rte_mbuf *pkt;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	pkt = rte_pktmbuf_alloc(nes_dev_vhost_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);


	/* AUTH entry */
	static uint8_t mac_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	struct ether_addr ether_address;

	struct rte_cfgfile *cfg;
	struct rte_cfgfile* global_cfg_file;
	int num_sections = 1; // Vm common

	cfg = malloc(sizeof (*cfg));

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = num_sections;

	global_cfg_file = nes_cfgfile;
	nes_cfgfile = cfg;

	memcpy(ether_address.addr_bytes, mac_data, ETHER_ADDR_LEN);

	static struct rte_cfgfile_section section1 = {
		.name = "VM common",
	};

	static struct rte_cfgfile_entry  entries0[] = {
		{ .name = "max", .value = "32"},
	};
	section1.entries = entries0;
	cfg->sections = &section1;
	cfg->sections[0].num_entries = 1;
	struct mac_entry data;
	memset(&data, 0, sizeof(struct mac_entry));
	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_entry_add(&ether_address, &data));
	nts_acl_cfg_init_vm_rings_names();
	CU_ASSERT_EQUAL(NES_SUCCESS, mac_authorized(&dev, &pkt,1));
	free(cfg);
	nes_cfgfile = global_cfg_file;
}

static void test_send_vhost_unauthorized(void)
{
	CU_ASSERT_EQUAL(NES_SUCCESS,  send_vhost_unauthorized(NULL, NULL));
}

void add_nes_dev_vhost_suite_to_registry(void) {
	CU_pSuite nes_dev_vhost_suite = CU_add_suite("nes_dev_vhost", init_suite_nes_dev_vhost, cleanup_suite_nes_dev_vhost);

	CU_add_test(nes_dev_vhost_suite, "test_nes_dev_vhost_mempool_init", test_nes_dev_vhost_mempool_init);
	CU_add_test(nes_dev_vhost_suite, "test_create_vm_rings", test_create_vm_rings);
	CU_add_test(nes_dev_vhost_suite, "test_mac_authorized", test_mac_authorized);
	CU_add_test(nes_dev_vhost_suite, "test_send_vhost_unauthorized", test_send_vhost_unauthorized);
}

