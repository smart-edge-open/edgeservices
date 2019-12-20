/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_nes_io.h"
#include "nes_common.h"
#include "io/nes_io.h"
#include "libnes_cfgfile.h"
#include "io/nes_dev.h"
#include "nes_dev_vhost_decl.h"
#include "nts_io_decl.h"
#include "nes_ring_lookup.h"
#include "nes_ring_lookup_decl.h"
#include "test_nes_ring_lookup.h"
#include "io/nes_mac_lookup.h"
#include "pkt_generator.h"
#include "libnes_cfgfile_def.h"

static uint16_t rte_vhost_dequeue_burst_stub(int UNUSED(vid), uint16_t UNUSED(queue_id),
	struct rte_mempool *mbuf_pool, struct rte_mbuf **pkts, uint16_t UNUSED(count)) {

	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	pkts[0] = rte_pktmbuf_alloc(mbuf_pool);
	eth_hdr = rte_pktmbuf_mtod(pkts[0], struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);

	return 1;
}
int init_suite_nes_io(void) {
	rte_atomic32_clear(&threads_started);
	MOCK_SET(mocked_rte_vhost_dequeue_burst,rte_vhost_dequeue_burst_stub);

	static uint8_t mac_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	struct ether_addr ether_address;

	memcpy(ether_address.addr_bytes, mac_data, ETHER_ADDR_LEN);
	struct mac_entry data;
	memset(&data, 0, sizeof(struct mac_entry));
	nes_mac_lookup_entry_add(&ether_address, &data);

	return CUE_SUCCESS;
}

int cleanup_suite_nes_io(void) {
	nes_thread_terminate = 0;
	rte_atomic32_clear(&threads_started);
	MOCK_RESET(mocked_rte_vhost_dequeue_burst);
	return CUE_SUCCESS;
}

#define CFG_ALLOC_SECTION_BATCH 4
#define CFG_ALLOC_ENTRIES_BATCH 8
extern struct rte_cfgfile *nes_cfgfile;
pthread_t nes_io_main_thread;
static nes_queue_t * nes_io_devices;

static struct rte_cfgfile_entry  entries1[] = {
	{ .name = "name", .value = "ENB", },
	{ .name = "traffic-direction", .value = "both", },
	{ .name = "traffic-type", .value = "mixed", },
	{ .name = "egress-port", .value = "1", },
};

static struct rte_cfgfile_entry  entries2[] = {
	{ .name = "max", .value = "2"},
};

static struct rte_cfgfile_entry  entries3[] = {
	{ .name = "invalid", .value = "on"},
};

static void *nes_io_main_thread_start(void *arg) {
	(void)arg;
	nes_io_main(NULL);
	return NULL;
}

static void nes_io_main_test(void) {
	nes_thread_terminate = 1;
	void *res;
	struct rte_cfgfile *cfg_bak = nes_cfgfile;

	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile);

	nes_cfgfile->sections =
		malloc(sizeof(struct rte_cfgfile_section) * CFG_ALLOC_ENTRIES_BATCH);

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile->sections);

	strncpy(nes_cfgfile->sections[0].name, "PORT0", sizeof(nes_cfgfile->sections[0].name));
	nes_cfgfile->sections[0].num_entries = sizeof(entries1)/sizeof(entries1[0]);
	nes_cfgfile->sections[0].entries = entries1;


	strncpy(nes_cfgfile->sections[1].name, "VM common", sizeof(nes_cfgfile->sections[1].name));
	nes_cfgfile->sections[1].num_entries = sizeof(entries3)/sizeof(entries3[0]);
	nes_cfgfile->sections[1].entries = entries3;

	nes_cfgfile->num_sections = 2;

	CU_ASSERT_EQUAL(nes_io_main(NULL), NES_FAIL);

	rte_atomic32_set(&threads_started, THREADS_MASK);

	nes_cfgfile->sections[1].num_entries = sizeof(entries2)/sizeof(entries2[0]);
	nes_cfgfile->sections[1].entries = entries2;

	nes_thread_terminate = 1;
	CU_ASSERT_EQUAL(nes_io_main(NULL), NES_SUCCESS);

	nes_thread_terminate = 0;
	rte_atomic32_clear(&threads_started);

	nes_dev_t *device = NULL;
	nes_queue_node_t *node;
	nes_io_dev_queue_get(&nes_io_devices);
	pthread_create(&nes_io_main_thread, NULL, nes_io_main_thread_start, NULL);
	usleep(10);
	rte_atomic32_set(&threads_started, THREADS_MASK);
	usleep(10);
	NES_QUEUE_FOREACH_RETRY(node, nes_io_devices) {
		device = node->data;
		if (ETH == device->dev_type) {
			device->recv = NULL;
			device->scatter = NULL;
			device->send = NULL;
		}
	}
	usleep(100);
	nes_thread_terminate = 1;
	pthread_cancel(nes_io_main_thread);
	pthread_join(nes_io_main_thread, &res);
	nes_thread_terminate = 1;

	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;
}

void add_nes_io_suite_to_registry(void) {
	CU_pSuite nes_io_suite = CU_add_suite("nes_io", init_suite_nes_io, cleanup_suite_nes_io);

	CU_add_test(nes_io_suite, "nes_io_main", nes_io_main_test);
}

