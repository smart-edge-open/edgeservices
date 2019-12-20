/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dev_eth.c
 * @brief Implementation of ethernet nes device
 */

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_udp.h>
#include <rte_alarm.h>

#include "nes_common.h"
#include "io/nes_dev.h"
#include "ctrl/nes_ctrl.h"
#include "nes_ring.h"
#include "nes_ring_lookup.h"
#include "nts/nts_edit.h"
#include "ctrl/nes_ctrl.h"
#include "nes_latency.h"
#include "nes_dev_addons.h"

#ifdef UNIT_TESTS
	#include "nes_dev_eth_decl.h"
#endif

NES_LATENCY_VARS;
#define MAX_TROUGHPUT (1E10 / 8) // B/s for 10Gb NIC
#define MAX_BYTES_ETH_STATS 0xFFFFFFFFF // There is 36 bit a register in tested NICs for bytes stats
#define STATS_REFRESH_TIME \
	((uint64_t)(MAX_BYTES_ETH_STATS / MAX_TROUGHPUT) - 2) // 2 is to prevent stats overflow
#define MAX_PORTS UINT8_MAX
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */

static uint8_t dpdk_ports_cnt;
static uint8_t dpdk_ports[MAX_PORTS];

static void
refresh_internal_ports_stats(__attribute__((unused)) void *param)
{
	struct rte_eth_stats stats;
	int i;
	for (i = 0; i < dpdk_ports_cnt; i++)
		rte_eth_stats_get(dpdk_ports[i], &stats);

	rte_eal_alarm_set(STATS_REFRESH_TIME * US_PER_S, refresh_internal_ports_stats, NULL);
}

void
nes_dev_eth_start_stats_timer(void)
{
	rte_eal_alarm_set(STATS_REFRESH_TIME * US_PER_S, refresh_internal_ports_stats, NULL);
}

void check_eth_port_link_status(uint8_t portid)
{
	uint8_t count, port_up = 0;
	struct rte_eth_link link;

	NES_LOG(INFO, "\nChecking link status for %d port\n", portid);
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(portid, &link);

		if (port_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			if (link.link_status)
				NES_LOG(INFO, "Port %d Link Up - speed %u "
					"Mbps - %s\n", portid,
					(unsigned)link.link_speed,
					(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
			else
				NES_LOG(INFO, "Port %d Link Down\n",
					(uint8_t)portid);
			break;
		}
		/* clear port_up flag if link down */
		if (link.link_status == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		} else
			port_up = 1;
	}
	NES_LOG(INFO, "done\n");
}

int
nes_dev_eth_mac_addr_get(uint8_t port_id, struct ether_addr *addr)
{
	if (port_id < rte_eth_dev_count_avail() && NULL != addr) {
		rte_eth_macaddr_get(port_id, addr);
		return NES_SUCCESS;
	}
	return NES_FAIL;

}

int
nes_dev_eth_pci_addr_get(uint8_t port_id, struct rte_pci_addr *addr)
{
	char addr_str[RTE_ETH_NAME_MAX_LEN] = { 0 };
	if (port_id < rte_eth_dev_count_avail() && NULL != addr) {
		if (!rte_eth_dev_get_name_by_port(port_id, addr_str) &&
				!rte_pci_addr_parse(addr_str, addr))
			return NES_SUCCESS;
	}
	return NES_FAIL;
}

int nes_dev_eth_find_port_id_by_pci(struct rte_pci_addr *pci_addr, uint8_t *port_id)
{
	struct rte_pci_addr eth_pci_addr;
	uint8_t i;

	for (i = 0; i < rte_eth_dev_count_avail(); i++) {

		if (NES_SUCCESS != nes_dev_eth_pci_addr_get(i, &eth_pci_addr))
			continue;

		if (0 == rte_eal_compare_pci_addr(pci_addr, &eth_pci_addr)) {
			*port_id = i;
			return NES_SUCCESS;
		}
	}
	return NES_FAIL;
}

int init_eth_port(uint8_t port_num, uint8_t queue_num)
{
	int rx_queues_cnt = 1, tx_queues_cnt = 1;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_rx_pkt_len = ETHER_MAX_LEN
		}
	};
	const uint16_t rx_ring_size = 512;
	const uint16_t tx_ring_size = 512;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int retval;

	rte_eth_dev_info_get(port_num, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MULTI_SEGS;

	if ((retval = rte_eth_dev_configure(port_num,
			rx_queues_cnt, tx_queues_cnt, &port_conf)) != 0) {
		NES_LOG(ERR, "rte_eth_dev_configure failed(return code: %d)", retval);
		return retval;
	}
	retval = rte_eth_rx_queue_setup(port_num, queue_num, rx_ring_size,
		rte_eth_dev_socket_id(port_num),
		NULL, nes_main_pktmbuf_pool);
	if (retval < 0) {
		NES_LOG(ERR, "rte_eth_rx_queue_setup failed(return code: %d)", retval);
		return retval;
	}

	txconf = &dev_info.default_txconf;
	txconf->offloads = port_conf.txmode.offloads;

	retval = rte_eth_tx_queue_setup(port_num, queue_num, tx_ring_size,
		rte_eth_dev_socket_id(port_num),
		txconf);
	if (retval < 0) {
		NES_LOG(ERR, "rte_eth_tx_queue_setup failed(return code: %d)", retval);
		return retval;
	}
	rte_eth_promiscuous_enable(port_num);
	retval  = rte_eth_dev_start(port_num);
	if (retval < 0) {
		NES_LOG(ERR, "rte_eth_dev_start failed(return code: %d)", retval);
		return retval;
	}

	if (dpdk_ports_cnt < (MAX_PORTS - 1))
		dpdk_ports[dpdk_ports_cnt++] = port_num;

	NES_LOG(INFO, "Port %d initialized and started\n", port_num);
	return NES_SUCCESS;
}

int recv_eth(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	NES_LATENCY_READ_TIMESTAMP(t_start);
	self->rx_cnt = rte_eth_rx_burst(self->dev.eth.port_id, self->dev.eth.queue_id,
		self->rx_pkts, MAX_BURST_SIZE);
	NES_LATENCY_INSERT_TIMESTAMPS(self->rx_pkts, self->rx_cnt, t_start);
	return NES_SUCCESS;
}

int send_eth(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	struct rte_mbuf *buf[MAX_BURST_SIZE];
	int tx_cnt, eth_tx_cnt, buf_id;
	nes_ring_t *tx_ring = self->tx_ring;

	if (unlikely(self->tx_buffer_cnt > 0)) {
		if (rte_get_timer_cycles() - self->retry_send_start > self->retry_timeout_cycles) {
			NES_STATS_DEV_UPDATE(self->tx_buffer_cnt, self->dev_stats->stats.drp_cnt_1);
			for (buf_id = 0; buf_id < self->tx_buffer_cnt; buf_id++) {
				NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(self->tx_buffer[buf_id]),
					self->dev_stats->stats.drp_bytes_1);
				rte_pktmbuf_free(self->tx_buffer[buf_id]);
			}
			self->tx_buffer_cnt = 0;
		} else {
			int i;
			tx_cnt = rte_eth_tx_burst(self->dev.eth.port_id,
				self->dev.eth.queue_id,
				self->tx_buffer,
				self->tx_buffer_cnt);
			if (tx_cnt > 0) {
				for (i = 0; i < self->tx_buffer_cnt - tx_cnt; i++)
					self->tx_buffer[i] = self->tx_buffer[i + tx_cnt];

				return NES_FAIL;
			}
		}
	}
	tx_cnt = tx_ring->deq_burst(tx_ring, (void**)buf, MAX_BURST_SIZE);
	NES_LATENCY_GET_TIMESTAMPS(buf, tx_cnt, pkt_timestamps);
	if (likely(tx_cnt > 0)) {
		eth_tx_cnt = rte_eth_tx_burst(self->dev.eth.port_id,
			self->dev.eth.queue_id, buf, tx_cnt);
		NES_LATENCY_READ_TIMESTAMP(t_end);
		NES_LATENCY_UPDATE(eth_tx_cnt, pkt_timestamps, t_end);
		if (unlikely(eth_tx_cnt < tx_cnt)) {
			for (buf_id = eth_tx_cnt; buf_id < tx_cnt; buf_id++)
				self->tx_buffer[self->tx_buffer_cnt++] = buf[buf_id];

			self->retry_send_start = rte_get_timer_cycles();
			return NES_FAIL;
		}
	}
	return NES_SUCCESS;
}

int send_eth_mtu(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	struct rte_mbuf *buf[MAX_BURST_SIZE];
	struct rte_mbuf *buf_to_send[TX_BUFFER_SIZE];
	int tx_cnt, eth_tx_cnt, buf_id;
	nes_ring_t *tx_ring = self->tx_ring;

	if (unlikely(self->tx_buffer_cnt > 0)) {
		if (rte_get_timer_cycles() - self->retry_send_start > self->retry_timeout_cycles) {
			NES_STATS_DEV_UPDATE(self->tx_buffer_cnt, self->dev_stats->stats.drp_cnt_1);
			for (buf_id = 0; buf_id < self->tx_buffer_cnt; buf_id++) {
				NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(self->tx_buffer[buf_id]),
					self->dev_stats->stats.drp_bytes_1);
				rte_pktmbuf_free(self->tx_buffer[buf_id]);
			}
			self->tx_buffer_cnt = 0;
		} else {
			int i;
			tx_cnt = rte_eth_tx_burst(self->dev.eth.port_id,
				self->dev.eth.queue_id,
				self->tx_buffer,
				self->tx_buffer_cnt);
			if (tx_cnt > 0) {
				for (i = 0; i < self->tx_buffer_cnt - tx_cnt; i++)
					self->tx_buffer[i] = self->tx_buffer[i + tx_cnt];

				return NES_FAIL;
			}
		}
	}


	tx_cnt = tx_ring->deq_burst(tx_ring, (void**)buf, MAX_BURST_SIZE);
	NES_LATENCY_GET_TIMESTAMPS(buf, tx_cnt, pkt_timestamps);
	if (likely(tx_cnt > 0)) {
		int                 pkt_cnt;
		int                 last_pkt;
		int                 i;
		struct ether_hdr    *eth_hdr;
		struct rte_mbuf     *pkt;
		uint16_t            mtu;

		last_pkt = 0;
		for (buf_id = 0; buf_id < tx_cnt; buf_id++) {
			pkt = buf[buf_id];

			eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			uint16_t l2_len = sizeof(struct ether_hdr);

			if (unlikely(eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN))) {
				eth_hdr = (struct ether_hdr *)
					((uint8_t*)eth_hdr + sizeof(struct vlan_hdr));
				l2_len += sizeof(struct vlan_hdr);
			}

			mtu = self->MTU - l2_len - sizeof(struct ipv4_hdr);
			mtu &= ~7U;
			mtu += sizeof(struct ipv4_hdr);

			if (likely(mtu >= (pkt->pkt_len - l2_len))) {
				buf_to_send[last_pkt] = pkt;
				pkt_cnt = 1;
			} else if (unlikely(
					eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
				buf_to_send[last_pkt] = pkt;
				pkt_cnt = 1;
			} else {
				struct ipv4_hdr     *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
				/* check DON'T FRAGMENT flag */
				if (unlikely(ipv4_hdr->fragment_offset &
						rte_cpu_to_be_16(IPV4_HDR_DF_FLAG))) {
					buf_to_send[last_pkt] = pkt;
					pkt_cnt = 1;
				} else {
					/* function rte_ipv4_fragment_packet needs mbuf started from L3 */
					/* also this function doesn't support segmented mbufs */
					rte_pktmbuf_adj(pkt, l2_len);

					pkt_cnt = rte_ipv4_fragment_packet(pkt,
						&buf_to_send[last_pkt],
						(uint16_t)(TX_BUFFER_SIZE - last_pkt),
						mtu, nes_main_pktmbuf_pool,
						nes_main_indir_pktmbuf_pool);

					/* check if error occurs */
					if (unlikely(pkt_cnt < 0)) {
						rte_pktmbuf_free(pkt);
						continue;
					}
					for (i = last_pkt; i < last_pkt + pkt_cnt; i++) {
						struct ether_hdr *new_eth_hdr = (struct ether_hdr *)
							rte_pktmbuf_prepend(buf_to_send[i], l2_len);
						if (NULL != new_eth_hdr) {
							rte_memcpy(new_eth_hdr,
								(uint8_t*)ipv4_hdr - l2_len,
								l2_len);
							buf_to_send[i]->l2_len = l2_len;
						} else
							NES_LOG(ERR, "No headroom in mbuf");
					}
					rte_pktmbuf_free(pkt);
				}
			}
			last_pkt += pkt_cnt;
		}

		if (likely(0 < last_pkt)) {
			eth_tx_cnt = (int)rte_eth_tx_burst(self->dev.eth.port_id,
				self->dev.eth.queue_id, buf_to_send, last_pkt);
			NES_LATENCY_READ_TIMESTAMP(t_end);
			NES_LATENCY_UPDATE(eth_tx_cnt, pkt_timestamps, t_end);
			if (unlikely(eth_tx_cnt < last_pkt)) {
				for (buf_id = eth_tx_cnt; buf_id < last_pkt; buf_id++) {
					self->tx_buffer[self->tx_buffer_cnt++] =
						buf_to_send[buf_id];
				}
				self->retry_send_start = rte_get_timer_cycles();
				return NES_FAIL;
			}
		}
	}
	return NES_SUCCESS;
}
