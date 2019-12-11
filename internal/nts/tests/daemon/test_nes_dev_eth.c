/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdlib.h>
#include <stdint.h>
#include <rte_ethdev.h>
#include <CUnit/CUnit.h>
#include "nes_common.h"
#include "test_nes_dev_eth.h"
#include "io/nes_dev.h"
#include "libnes_cfgfile.h"
#include "nes_dev_eth_decl.h"
#include "pkt_generator.h"
#include "nts/nts_edit.h"
#include "io/nes_io.h"
#include "libnes_queue.h"
#include "nes_ring_lookup.h"
#include "nes_ring_lookup_decl.h"

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define PKTMBUF_POOL_NAME "ETH_test_pool"
#define INVALID_PORT    (rte_eth_dev_count_avail() + 1)
#define INVALID_QUEUE   99
#define VALID_PORT      1
#define VALID_QUEUE     0

static struct rte_mempool *pkt_pktmbuf_pool;
static struct rte_mbuf *pkt;
static nes_dev_t *device = NULL;
static nes_queue_t * nes_io_devices;
extern nes_lookup_table_t nes_ring_lookup_table;

int init_suite_nes_dev_eth(void)
{
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

	nes_queue_node_t *node;
	nes_io_dev_queue_get(&nes_io_devices);
	NES_QUEUE_FOREACH(node, nes_io_devices) {
		nes_queue_node_unlock(node);
		if (((nes_dev_t *)node->data)->dev_type == ETH) {
			device = node->data;
			break;
		}
	}
	if (NULL == device)
		return -1;

	return CUE_SUCCESS;
}

int cleanup_suite_nes_dev_eth(void)
{
	return CUE_SUCCESS;
}

void test_nes_dev_eth_pci_addr_get(void)
{
	struct rte_pci_addr pci_add;

	int port_id = device->dev.eth.port_id;

	/* 1. Pass */
	CU_ASSERT_EQUAL(NES_SUCCESS, nes_dev_eth_pci_addr_get(port_id, &pci_add));

	/* 2. Invalid port number */
	port_id = INVALID_PORT;
	CU_ASSERT_EQUAL(NES_FAIL, nes_dev_eth_pci_addr_get(port_id, &pci_add));

	/* 3. Invalid pci_addr pointer */
	CU_ASSERT_EQUAL(NES_FAIL, nes_dev_eth_pci_addr_get(port_id, NULL));

}

void test_nes_dev_eth_mac_addr_get(void)
{
	struct ether_addr eth_add;
	int port_id = device->dev.eth.port_id;

	CU_ASSERT_EQUAL(NES_SUCCESS, nes_dev_eth_mac_addr_get(port_id, &eth_add));

	/* Invalid port number */
	port_id = INVALID_PORT;
	CU_ASSERT_EQUAL(NES_FAIL, nes_dev_eth_mac_addr_get(port_id, &eth_add));

	/* Invalid eth_addr pointer */
	CU_ASSERT_EQUAL(NES_FAIL, nes_dev_eth_mac_addr_get(port_id, NULL));

}

void test_check_eth_port_link_status(void)
{
	int portid = VALID_PORT;

	/* UP by default */
	check_eth_port_link_status(portid);

	/* Link down*/
	rte_eth_dev_set_link_down (portid);
	check_eth_port_link_status(portid);
	rte_eth_dev_set_link_up (portid);

	/* Invalid port */
	portid = INVALID_PORT;
	check_eth_port_link_status(portid);
}

void test_init_eth_port(void)
{
	int port_num = INVALID_PORT;
	int queue_num = VALID_QUEUE;

	/* Invalid port number */
	CU_ASSERT_NOT_EQUAL(NES_SUCCESS, init_eth_port(port_num, queue_num));

	/* Port already started */
	port_num = VALID_PORT;
	CU_ASSERT_NOT_EQUAL(NES_SUCCESS, init_eth_port(port_num, queue_num));

	/* Invalid queue num */
	queue_num = INVALID_QUEUE;
	rte_eth_dev_stop(port_num);
	CU_ASSERT_NOT_EQUAL(NES_SUCCESS, init_eth_port(port_num, queue_num));

	/* Success */
	queue_num = VALID_QUEUE;
	rte_eth_dev_stop(port_num);
	CU_ASSERT_EQUAL(NES_SUCCESS, init_eth_port(port_num, queue_num));

}

void test_send_eth(void)
{
	static uint8_t mac_src_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	static uint8_t mac_dst_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 2};
	struct ether_addr mac_src, mac_dst;
	struct ether_hdr *eth_hdr;

	memcpy(mac_src.addr_bytes, mac_src_data, ETHER_ADDR_LEN);
	memcpy(mac_dst.addr_bytes, mac_dst_data, ETHER_ADDR_LEN);

	pkt = rte_pktmbuf_alloc(pkt_pktmbuf_pool);
	CU_ASSERT_PTR_NOT_NULL(pkt);
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	init_eth_hdr(eth_hdr, &mac_src, &mac_dst, ETHER_TYPE_IPv4, 0, 0);

	CU_ASSERT_EQUAL(NES_SUCCESS, device->send(device, NULL));

	/* self->tx_buffer_cnt > 0 */
	device->tx_buffer_cnt = 1;
	device->tx_buffer[0] = pkt;
	CU_ASSERT_EQUAL(NES_SUCCESS, device->send(device, NULL));

	/* tx_cnt > 0*/
	CU_ASSERT_EQUAL(1, device->tx_ring->enq_burst(device->tx_ring, (void **) &pkt, 1));
	CU_ASSERT_EQUAL(NES_SUCCESS, device->send(device, NULL));
}

void test_recv_eth(void)
{
	CU_ASSERT_EQUAL(NES_SUCCESS, device->recv(device, NULL));
}

void add_nes_dev_eth_suite_to_registry(void) {
	// CU_pSuite nes_dev_eth_suite = CU_add_suite("nes_dev_eth", init_suite_nes_dev_eth, cleanup_suite_nes_dev_eth);

	// CU_add_test(nes_dev_eth_suite, "test_nes_dev_eth_mac_addr_get", test_nes_dev_eth_mac_addr_get);
	// CU_add_test(nes_dev_eth_suite, "test_nes_dev_eth_pci_addr_get", test_nes_dev_eth_pci_addr_get);
	// CU_add_test(nes_dev_eth_suite, "test_check_eth_port_link_status", test_check_eth_port_link_status);
	// CU_add_test(nes_dev_eth_suite, "test_init_eth_port", test_init_eth_port);
	// CU_add_test(nes_dev_eth_suite, "test_send_eth", test_send_eth);
	// CU_add_test(nes_dev_eth_suite, "test_recv_eth", test_recv_eth);
}

