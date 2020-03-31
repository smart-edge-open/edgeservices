/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dev_kni.c
 * @brief Implementation of KNI nes device
 */

#include <rte_cycles.h>
#include <rte_malloc.h>
#include <unistd.h>
#include <string.h>
#include "io/nes_dev.h"
#include "nes_common.h"
#include "nes_ring.h"
#include "libnes_queue.h"
#include "io/nes_io.h"
#include "nts/nts_io.h"
#include "libnes_cfgfile.h"
#include "ctrl/nes_ctrl.h"
#include "io/nes_mac_lookup.h"
#include "io/nes_dev_addons.h"
#include "nes_ring_lookup.h"
#include "nes_common.h"
#include "io/nes_dev_kni.h"

#ifdef UNIT_TESTS
	#include "nes_dev_kni_decl.h"
#endif

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)

static uint32_t max_kni_ports;
static const char kni_name_format[RTE_KNI_NAMESIZE] = "vEth%u";

static char **nes_kni_dev_id_names;
NES_STATIC struct rte_mempool *nes_dev_kni_pktmbuf_pool;

static nes_queue_t *nes_io_devices;
static nes_queue_t *nts_io_rings;

static int kni_name_exists(const char* name)
{
	uint32_t i;
	if (NULL == name) {
		NES_LOG(ERR, "Invalid argument (name is NULL)\n");
		return NES_FAIL;
	}

	for (i = 0; i < max_kni_ports; i++) {
		if ((NULL != nes_kni_dev_id_names[i]) &&
			(0 == strcmp(name, nes_kni_dev_id_names[i])))
			return NES_SUCCESS;
	}
	return NES_FAIL;
}

static int get_new_kni_port_id(uint32_t *port_id)
{
	uint32_t i;
	for (i = 0; i < max_kni_ports; i++) {
		if (NULL == nes_kni_dev_id_names[i]) {
			*port_id = i;
			return NES_SUCCESS;
		}
	}

	return NES_FAIL;
}

NES_STATIC int
nes_dev_kni_mempool_init(void) {
	const unsigned num_mbufs = max_kni_ports * MBUFS_PER_RING;

	nes_dev_kni_pktmbuf_pool = rte_pktmbuf_pool_create(
		"kni_mbuf_pool",
		num_mbufs,
		MBUF_CACHE_SIZE,
		0,
		MBUF_SIZE,
		rte_socket_id());

	if (NULL != nes_dev_kni_pktmbuf_pool)
		return NES_SUCCESS;
	else {
		NES_LOG(ERR, "Initialization of mbufs failed.\n");
		return NES_FAIL;
	}
}

NES_STATIC struct rte_kni *
nes_dev_kni_alloc(uint16_t port_id, const char *if_id)
{
	struct rte_kni_conf conf;
	uint8_t mac_addr[ETHER_ADDR_LEN];
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, kni_name_format, port_id);

	// Use if_id as the MAC address if it is long enough and in hex format
	if (strnlen(if_id, ETHER_ADDR_LEN*2) == ETHER_ADDR_LEN*2) {
		if (sscanf(if_id, "%hhx%hhx%hhx%hhx%hhx%hhx",
				&mac_addr[0],
				&mac_addr[1],
				&mac_addr[2],
				&mac_addr[3],
				&mac_addr[4],
				&mac_addr[5]) == 6) {

			memcpy(conf.mac_addr, mac_addr, ETHER_ADDR_LEN);
			// Clear group address bit
			// https://tools.ietf.org/rfc/rfc1469.txt
			conf.mac_addr[0] &= 0xFE;
		}
	}
	conf.group_id = port_id;
	conf.mbuf_size = MBUF_DATA_SIZE;

	NES_LOG(INFO, "Allocating KNI port %d\n", port_id);
	return rte_kni_alloc(nes_dev_kni_pktmbuf_pool, &conf, NULL);
}

NES_STATIC int
create_kni_rings(nes_dev_t *self) {
	nts_io_ring_queue_get(&nts_io_rings);
	self->rx_rings = rte_zmalloc("kni_recv_ring", sizeof (nes_ring_t*), RTE_CACHE_LINE_SIZE);
	if (self->rx_rings == NULL) {
		NES_LOG(EMERG, "Unable to allocate rings");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_ring_per_kni_set(self->dev.kni.port_id,
			&self->rx_rings[0], &self->tx_ring)) {
		rte_free(self->rx_rings);
		NES_LOG(ERR, "Unable to set rings for KNI port %d", self->dev.kni.port_id);
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_queue_enqueue(nts_io_rings, self->rx_rings[0])) {
		rte_free(self->rx_rings);
		NES_LOG(ERR, "Unable to enqueue rings for KNI port %d", self->dev.kni.port_id);
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

NES_STATIC int
mac_authorization(struct nes_dev_s *self, struct rte_mbuf **m, int pkt_count) {
	struct ether_hdr *pkt_hdr;
	struct ether_addr ether_address;
	int i;
	struct mac_entry *mac_data;

	for (i = 0; i < pkt_count; i++) {
		pkt_hdr = rte_pktmbuf_mtod(m[i], struct ether_hdr *);

		ether_addr_copy(&pkt_hdr->s_addr, &ether_address);

		/* check if mac address exists in our lookup table */
		if (NES_SUCCESS == nes_mac_lookup_entry_find(&ether_address, &mac_data)) {
			mac_data->vm_id = self->dev.kni.port_id;
			mac_data->ring_name =
				nts_lookup_tx_kni_ring_name_get(self->dev.kni.port_id);
			if (NULL == mac_data->ring_name)
				return NES_FAIL;

			nes_ring_find(&mac_data->ring, mac_data->ring_name);
			memcpy(self->mac_address.addr_bytes,
				ether_address.addr_bytes, ETHER_ADDR_LEN);
			NES_LOG(INFO, "KNI device id: %d authorized with" \
				" MAC_ADDRESS %02x:%02x:%02x:%02x:%02x:%02x.\n",
				self->dev.kni.port_id,
				self->mac_address.addr_bytes[0], self->mac_address.addr_bytes[1],
				self->mac_address.addr_bytes[2], self->mac_address.addr_bytes[3],
				self->mac_address.addr_bytes[4], self->mac_address.addr_bytes[5]);
			return NES_SUCCESS;
		}
	}

	return NES_FAIL;
}

static int
recv_kni_authorized(struct nes_dev_s *self, __attribute__((unused)) void *data) {
	if (unlikely(rte_atomic16_read(&self->dev.kni.stop)))
		return NES_FAIL;

	self->rx_cnt = rte_kni_rx_burst(self->dev.kni.kni_dev, self->rx_pkts, MAX_BURST_SIZE);

	if (likely(self->rx_cnt > 0)) {
		int i;
		nes_ring_t *rx_ring = self->rx_rings[0];
		int ret_cnt = rx_ring->enq_burst(rx_ring, (void**) self->rx_pkts, self->rx_cnt);
		NES_STATS_DEV_UPDATE(self->rx_cnt, self->dev_stats->stats.rcv_cnt);
		for (i = 0; i < ret_cnt; i++) {
			NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(self->rx_pkts[i]),
				self->dev_stats->stats.rcv_bytes);
		}
		if (unlikely(ret_cnt < self->rx_cnt)) {
			NES_LOG(ERR, "Unable to enqueue all packets to ring.\n");
			for (i = ret_cnt; i < self->rx_cnt; i++)
				rte_pktmbuf_free(self->rx_pkts[i]);

			return NES_FAIL;
		}
	}
	return NES_SUCCESS;
}

static int
send_kni_authorized(struct nes_dev_s *self, __attribute__((unused)) void *data) {
	nes_ring_t *tx_ring = self->tx_ring;
	struct rte_mbuf * buf[MAX_BURST_SIZE];
	int tx_cnt, buf_id;

	if (unlikely(rte_atomic16_read(&self->dev.kni.stop)))
		return NES_FAIL;

	tx_cnt = tx_ring->deq_burst(tx_ring, (void**) buf, MAX_BURST_SIZE);
	if (likely(tx_cnt > 0)) {
		NES_STATS_DECL int sent_pkts = 0;
		NES_STATS_ASSGN(sent_pkts, rte_kni_tx_burst(self->dev.kni.kni_dev, buf, tx_cnt));
		NES_STATS_DEV_UPDATE(sent_pkts, self->dev_stats->stats.snd_cnt);
		NES_STATS_DEV_UPDATE((tx_cnt - sent_pkts), self->dev_stats->stats.drp_cnt_1);
		for (buf_id = 0; buf_id < sent_pkts; buf_id++) {
			NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(buf[buf_id]),
				self->dev_stats->stats.snd_bytes);
		}
		for (; buf_id < tx_cnt; buf_id++) {
			NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(buf[buf_id]),
				self->dev_stats->stats.drp_bytes_1);
			rte_pktmbuf_free(buf[buf_id]);
		}
	}
	rte_kni_handle_request(self->dev.kni.kni_dev);
	return NES_SUCCESS;
}

NES_STATIC int
send_kni_unauthorized(struct nes_dev_s *self, __attribute__((unused)) void *data) {
	if (unlikely(rte_atomic16_read(&self->dev.kni.stop)))
		return NES_FAIL;

	rte_kni_handle_request(self->dev.kni.kni_dev);
	return NES_SUCCESS;
}

static int
recv_kni_unauthorized(struct nes_dev_s *self, __attribute__((unused)) void *data) {
	if (unlikely(rte_atomic16_read(&self->dev.kni.stop)))
		return NES_FAIL;

	self->rx_cnt = rte_kni_rx_burst(self->dev.kni.kni_dev, self->rx_pkts, MAX_BURST_SIZE);

	if (likely(self->rx_cnt > 0)) {
		int i;
		NES_STATS_DEV_UPDATE(self->rx_cnt, self->dev_stats->stats.rcv_cnt);
		for (i = 0; i < self->rx_cnt; i++) {
			NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(self->rx_pkts[i]),
				self->dev_stats->stats.rcv_bytes);
		}
		if (NES_SUCCESS == mac_authorization(self, self->rx_pkts, self->rx_cnt)) {
			create_kni_rings(self);
			nes_ring_t *rx_ring = self->rx_rings[0];
			int ret_cnt = rx_ring->enq_burst(rx_ring,
				(void**) self->rx_pkts, self->rx_cnt);

			/* Replace recv and send callbacks */
			self->recv = recv_kni_authorized;
			self->send = send_kni_authorized;

			if (unlikely(ret_cnt < self->rx_cnt)) {
				NES_LOG(ERR, "Unable to enqueue all packets to ring.\n");
				for (i = ret_cnt; i < self->rx_cnt; i++)
					rte_pktmbuf_free(self->rx_pkts[i]);

				return NES_FAIL;
			}
		} else {
			for (i = 0; i < self->rx_cnt; i++)
				rte_pktmbuf_free(self->rx_pkts[i]);
		}
	}

	return NES_SUCCESS;
}

NES_STATIC void
nes_dev_kni_destroy(int port_id, char* deleted_if_name) {
	nes_queue_node_t *node;
	nes_dev_t *device;
	nes_ring_t *kni_ring = NULL;
	volatile uint8_t schedule_removal = 1;
	uint8_t found = 1;

	while (found || schedule_removal) {
		found = 0;
		NES_QUEUE_FOREACH_RETRY(node, nes_io_devices) {
			device = node->data;
			if (device->dev_type == KNI && device->dev.kni.port_id == port_id) {
				found = 1;
				if (schedule_removal) {
					rte_atomic16_set(&device->dev.kni.stop, 1);
					if (deleted_if_name) {
						strncpy(deleted_if_name,
							rte_kni_get_name(device->dev.kni.kni_dev),
							RTE_KNI_NAMESIZE);
					}
					free(nes_kni_dev_id_names[device->dev.kni.port_id]);
					rte_kni_release(device->dev.kni.kni_dev);
					nes_kni_dev_id_names[port_id] = NULL;
					device->remove = 1;
					nes_ctrl_del_device(device);
					kni_ring = (NULL == device->rx_rings) ?
						NULL : device->rx_rings[0];
					NES_LOG(INFO, "Removing KNI device %d\n",
						device->dev.kni.port_id);
					schedule_removal = 0;
				}
			}
		}
		if (!found && !schedule_removal) {
			NES_LOG(INFO, "KNI device %d removed\n", port_id);
			break;
		}
	}

	if (kni_ring != NULL) {
		schedule_removal = 1;
		for (;;) {
			found = 0;
			NES_QUEUE_FOREACH_RETRY(node, nts_io_rings) {
				if (kni_ring == (nes_ring_t *) node->data) {
					found = 1;
					if (schedule_removal) {
						kni_ring->remove = 1;
						NES_LOG(INFO, "Removing KNI ring %s \n",
							nes_ring_name(kni_ring));
						schedule_removal = 0;
					}
				}
			}
			if (!found && !schedule_removal)  {
				NES_LOG(INFO, "Removed ring for KNI device %d\n", port_id);
				break;
			}
		}
	}
}

NES_STATIC int
ctor_kni(nes_dev_t *self, __attribute__((unused)) void *data) {
	if (self == NULL) {
		NES_LOG(ERR, "Invalid ctor args\n");
		return NES_FAIL;
	}

	self->dev_type = KNI;
	self->tx_buffer_cnt = 0;
	self->retry_timeout_cycles = RESEND_TIMEOUT_US * rte_get_timer_hz() / 1E6;
	self->rx_rings = NULL;
	rte_atomic16_init(&self->dev.kni.stop);
	rte_atomic16_set(&self->dev.kni.stop, 0);

	const char *name = KNI_NAME_STRING;
	self->name = (char*) (uintptr_t) name;
	return NES_SUCCESS;
}

NES_STATIC int
dtor_kni(nes_dev_t *self, __attribute__((unused)) void *data) {

	nes_dev_kni_destroy(self->dev.kni.port_id, NULL);
	return NES_SUCCESS;
}

int
nes_dev_kni_create_port(const char* if_id, char* created_if_name)
{
	nes_dev_t *kni_dev;
	const char* buffer;
	uint32_t port_id = 0;

	if (NES_SUCCESS == kni_name_exists(if_id)) {
		NES_LOG(ERR, "KNI device with id: %s already exists\n", if_id);
		return NES_FAIL;
	}

	if (NES_SUCCESS != get_new_kni_port_id(&port_id)) {
		NES_LOG(ERR, "Couldn't find free kni dev\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_cfgfile_entry("KNI", "max", &buffer)) {
		NES_LOG(ERR, "Missing: section %s, entry %s, in config file.\n", "KNI", "number");
		return NES_FAIL;
	}
	if ((uint64_t)port_id > max_kni_ports) {
		NES_LOG(EMERG, "Fatal Error: Number of ports: %d," \
			" exceeds configured number of KNI instances: %d.\n",
			port_id, max_kni_ports);
		return NES_FAIL;
	}

	nes_io_dev_queue_get(&nes_io_devices);
	kni_dev = rte_zmalloc("kni device", sizeof (*kni_dev), RTE_CACHE_LINE_SIZE);
	if (kni_dev == NULL) {
		NES_LOG(ERR, "Couldn't allocate memory for kni dev %d\n", port_id);
		return NES_FAIL;
	}

	nes_kni_dev_id_names[port_id] = strndup(if_id, NES_MAX_KNI_ENTRY_LEN);
	kni_dev->dev.kni.dev_id_name = nes_kni_dev_id_names[port_id];
	if (NULL == kni_dev->dev.kni.dev_id_name) {
		NES_LOG(ERR, "Couldn't copy if_id for KNI device %d\n", port_id);
		nes_kni_dev_id_names[port_id] = NULL;
		rte_free(kni_dev);
		return NES_FAIL;
	}

	kni_dev->dev.kni.port_id = port_id;
	kni_dev->dev.kni.kni_dev = nes_dev_kni_alloc(port_id, if_id);
	kni_dev->remove = 0;
	kni_dev->ctor = ctor_kni;
	kni_dev->dtor = dtor_kni;
	kni_dev->scatter = NULL;
	kni_dev->ctor(kni_dev, NULL);
	kni_dev->recv = recv_kni_unauthorized;
	kni_dev->send = send_kni_unauthorized;

	NES_LOG(INFO, "New KNI device registered, waiting to be authorized.\n");

	if (NES_SUCCESS != nes_dev_add_device(kni_dev)) {
		rte_kni_release(kni_dev->dev.kni.kni_dev);
		free(nes_kni_dev_id_names[port_id]);
		nes_kni_dev_id_names[port_id] = NULL;
		rte_free(kni_dev);
		return NES_FAIL;
	}

	NES_LOG(INFO, "KNI inteface %s has been created for %s\n",
		rte_kni_get_name(kni_dev->dev.kni.kni_dev), kni_dev->dev.kni.dev_id_name);

	if (created_if_name) {
		strncpy(created_if_name, rte_kni_get_name(kni_dev->dev.kni.kni_dev),
			RTE_KNI_NAMESIZE);
	}
	return NES_SUCCESS;
}

int nes_dev_kni_init(void)
{
	const char* buffer;

	if (NES_SUCCESS != nes_cfgfile_entry("KNI", "max", &buffer)) {
		NES_LOG(ERR, "Missing: section %s, entry %s, in config file.\n", "KNI", "number");
		return NES_FAIL;
	}

	max_kni_ports = strtoul(buffer, NULL, 10);
	nes_kni_dev_id_names = rte_zmalloc("kni_dev_names", sizeof (char*) * max_kni_ports,
		RTE_CACHE_LINE_SIZE);
	rte_kni_init(max_kni_ports);
	return nes_dev_kni_mempool_init();
}

void nes_dev_kni_stop(void)
{
	uint32_t i;
	for (i = 0; i < max_kni_ports; i++) {
		if (NULL != nes_kni_dev_id_names[i])
			free(nes_kni_dev_id_names[i]);
	}
	rte_free(nes_kni_dev_id_names);
	rte_kni_close();
}

int nes_dev_kni_delete_port(const char* if_id, char* deleted_if_name)
{
	uint16_t i;
	for (i = 0; i < max_kni_ports; i++) {
		if (NULL != nes_kni_dev_id_names[i] &&
				(0 == strcmp(if_id, nes_kni_dev_id_names[i]))) {
			NES_LOG(INFO, "Removing KNI interface for %s\n", nes_kni_dev_id_names[i]);
			nes_dev_kni_destroy(i, deleted_if_name);
			return NES_SUCCESS;
		}
	}
	return NES_FAIL;
}
