/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dev.h
 * @brief Header file for nes device. Includes declarations for nes_dev_eth and nes_dev_vhost
 */

#ifndef _NES_DEV_H_
#define _NES_DEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/param.h>

#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ip_frag.h>
#include <rte_atomic.h>
#include <rte_kni.h>


#include "nes_common.h"
#include "nes_ring.h"

#define ENB_RX_RINGS_CNT 5
#define EPC_RX_RINGS_CNT 5

#define RESEND_TIMEOUT_US 500

#define MAX_TROUGHPUT (1E10 / 8) // B/s for 10Gb NIC
#define MAX_BYTES_ETH_STATS 0xFFFFFFFFF // There is 36 bit a register in tested NICs for bytes stats
#define STATS_REFRESH_TIME \
	((uint64_t)(MAX_BYTES_ETH_STATS / MAX_TROUGHPUT) - 2) // 2 is to prevent stats overflow
#define MAX_PORTS UINT8_MAX
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */

#define PORT_SECTION_NAME   "PORT"
#define NAME_ENTRY          "name"

#define TRAFFIC_TYPE        "traffic-type"
#define TRAFFIC_TYPE_IP     "IP"
#define TRAFFIC_TYPE_LTE    "LTE"
#define TRAFFIC_TYPE_MIX    "mixed"

#define TRAFFIC_DIRECTION       "traffic-direction"
#define TRAFFIC_DIRECTION_UP    "upstream"
#define TRAFFIC_DIRECTION_DOWN  "downstream"
#define TRAFFIC_DIRECTION_BOTH  "both"
#define TRAFFIC_DIRECTION_LBP   "lbp"
#define TRAFFIC_DIRECTION_AVP   "avp"

#define MTU_ENTRY               "MTU"

#define EGRESS_PORT             "egress-port"
#define MAC_ENTRY               "mac"
#define PCI_ADDRESS             "pci-address"
#define PORT_TX_QUEUE_NAME_TEMPLATE "PORT_%d_IO_ANY"

#define PORT_NAME_SIZE 64

#define LBP_RX_RING_NAME "NTS_LBP_ANY"
#define AVP_RX_RING_NAME "NTS_AVP_ANY"
#define AVP_TX_RING_NAME "AVP_IO_ANY"

#define TX_BUFFER_SIZE (2 * MAX(MAX_BURST_SIZE, RTE_LIBRTE_IP_FRAG_MAX_FRAG))

extern struct rte_mempool *nes_main_pktmbuf_pool;
extern struct rte_mempool *nes_main_indir_pktmbuf_pool;
struct nes_ctrl_dev_s;

/**
* Ethernet type device distinctive parameters
*/
typedef struct nes_dev_id_eth_s {
	int port_id;
	int queue_id;
} nes_dev_id_eth_t;

/**
* VHOST device state
*/
typedef enum {
	VHOST_NOT_READY,
	VHOST_READY
} nes_dev_vhost_status;

/**
* VHOST type device distinctive parameters
*/
typedef struct nes_dev_id_vhost_s {
	int vm_id;
	volatile nes_dev_vhost_status status;
} __rte_cache_aligned nes_dev_id_vhost_t;

typedef struct nes_dev_id_kni_s {
	char *dev_id_name;
	uint16_t port_id;
	struct rte_kni *kni_dev;
	rte_atomic16_t stop;
} __rte_cache_aligned nes_dev_id_kni_t;

/**
* NES device type
*/
typedef union nes_dev_id_s {
	nes_dev_id_eth_t  eth;
	nes_dev_id_vhost_t vhost;
	nes_dev_id_kni_t kni;
} nes_dev_id_t;

typedef enum {
	ETH = 0,
	VHOST,
	KNI
} nes_dev_id_type;


typedef enum {
	TT_IP = 0,
	TT_LTE,
	TT_MIXED,
} nes_dev_traffic_type;

typedef enum {
	TD_UPSTREAM = 0,
	TD_DOWNSTREAM,
	TD_BOTH,
	TD_LBP,
	TD_AVP
} nes_dev_traffic_dir;

/**
* NES Device class
* Instance can be of Ethernet or VHOST type
*/
typedef struct nes_dev_s {
	nes_dev_id_t dev;
	nes_dev_id_type dev_type;

	nes_ring_t **rx_rings;
	int rx_ring_cnt;

	nes_ring_t *rx_default_ring;
	nes_ring_t *tx_ring;

	struct rte_mbuf *rx_pkts[MAX_BURST_SIZE];
	int rx_cnt;

	struct rte_mbuf *tx_buffer[TX_BUFFER_SIZE];
	int tx_buffer_cnt;
	uint64_t retry_send_start;
	uint64_t retry_timeout_cycles;

	struct ether_addr mac_address;

	nes_dev_traffic_type traffic_type;
	nes_dev_traffic_dir traffic_dir;
	int egres_port;
	char *name;
	uint8_t nes_port_id;
	uint8_t remove;
	struct rte_ip_frag_tbl *frag_tbl;
	struct rte_ip_frag_death_row death_row;
	uint16_t MTU;

	struct nes_ctrl_dev_s *dev_stats;
	int (*ctor)(struct nes_dev_s *self, void *data);
	int (*dtor)(struct nes_dev_s *self, void *data);
	int (*recv)(struct nes_dev_s *self, void *data);
	int (*send)(struct nes_dev_s *self, void *data);
	int (*scatter)(struct nes_dev_s *self, void *data);

} nes_dev_t;

/**
* Early initialization for vhost
* Mempool initialization, CUSE driver registration and starting session
*
* @return
*   NES_SUCCESS on success or NES_FAIL on error
*/
int nes_dev_vhost_early_init(void);

int nes_dev_eth_mac_addr_get(uint8_t port_id, struct ether_addr *addr);

int nes_dev_eth_pci_addr_get(uint8_t port_id, struct rte_pci_addr *addr);

void nes_dev_eth_start_stats_timer(void);

int count_port_devices(void);

int is_lbp_enabled(void);

int is_avp_enabled(void);

int nes_dev_port_new_device(void);

void nes_dev_port_dtor(void);

int init_eth_port(uint8_t port_num, uint8_t queue_num);

int recv_eth(struct nes_dev_s *self, __attribute__((unused)) void *data);

int send_eth(struct nes_dev_s *self, __attribute__((unused)) void *data);

int send_eth_mtu(struct nes_dev_s *self, __attribute__((unused)) void *data);

void check_eth_port_link_status(uint8_t portid);

int nes_dev_eth_find_port_id_by_pci(struct rte_pci_addr *pci_addr, uint8_t *port_id);

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* _NES_DEV_H_ */
