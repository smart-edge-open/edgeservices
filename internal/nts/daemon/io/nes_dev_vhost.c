/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dev_vhost.c
 * @brief Implementation of vhost nes device
 */

#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_vhost.h>
#include <linux/virtio_net.h>
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

#ifdef UNIT_TESTS
	#include "nes_dev_vhost_decl.h"
#endif

#define MBUF_CACHE_SIZE 512
#define MBUF_OVERHEAD (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MBUF_DATA_SIZE 2048
#define MBUF_SIZE (MBUF_DATA_SIZE + MBUF_OVERHEAD)
#define VHOST_RINGS_CNT 32

static nes_queue_t * nes_io_devices;
static nes_queue_t * nts_io_rings;

#define VHOST_RXQ 0
#define VHOST_TXQ 1

NES_STATIC struct rte_mempool *nes_dev_vhost_pktmbuf_pool;

/**
 * Initializing mempool for VHOST
 */
NES_STATIC int
nes_dev_vhost_mempool_init(void) {
	const unsigned num_mbufs = VHOST_RINGS_CNT * MBUFS_PER_RING;

	nes_dev_vhost_pktmbuf_pool = rte_mempool_create(
		"VHOST_MBUF_POOL",
		num_mbufs,
		MBUF_SIZE,
		MBUF_CACHE_SIZE,
		sizeof (struct rte_pktmbuf_pool_private),
		rte_pktmbuf_pool_init,
		NULL,
		rte_pktmbuf_init,
		NULL,
		rte_socket_id(),
		0);
	if (NULL != nes_dev_vhost_pktmbuf_pool)
		return NES_SUCCESS;
	else {
		NES_LOG(ERR, "Initialization of mbufs failed.\n");
		return NES_FAIL;
	}
}

/**
 * Implementation of destroy_device
 */
NES_STATIC void
nes_dev_vhost_destroy_device(int vm_id) {
	nes_queue_node_t *node;
	nes_dev_t *device;
	nes_ring_t *vhost_ring = NULL;
	volatile uint8_t schedule_removal = 1;
	uint8_t found = 1;

	while (found || schedule_removal) {
		found = 0;
		NES_QUEUE_FOREACH_RETRY(node, nes_io_devices) {
			device = node->data;
			if (device->dev_type == VHOST && device->dev.vhost.vm_id == vm_id) {
				found = 1;
				if (schedule_removal) {
					device->dev.vhost.status = VHOST_NOT_READY;
					device->remove = 1;
					nes_ctrl_del_device(device);
					vhost_ring = (NULL == device->rx_rings) ?
						NULL : device->rx_rings[0];
					NES_LOG(INFO, "Removing VHOST device %d\n",
						device->dev.vhost.vm_id);
					schedule_removal = 0;
				}
			}
		}
		if (!found && !schedule_removal) {
			NES_LOG(INFO, "VHOST device %d removed\n", vm_id);
			break;
		}
	}

	if (vhost_ring != NULL) {
		schedule_removal = 1;
		for (;;) {
			found = 0;
			NES_QUEUE_FOREACH_RETRY(node, nts_io_rings) {
				if (vhost_ring == (nes_ring_t *) node->data) {
					found = 1;
					if (schedule_removal) {
						vhost_ring->remove = 1;
						NES_LOG(INFO, "Removing VHOST ring %s \n",
							nes_ring_name(vhost_ring));
						schedule_removal = 0;
					}
				}
			}
			if (!found && !schedule_removal)  {
				NES_LOG(INFO, "Removed VHOST ring for VM %d\n", vm_id);
				break;
			}
		}
	}

}

NES_STATIC int
create_vm_rings(nes_dev_t *self) {
	nts_io_ring_queue_get(&nts_io_rings);

	self->rx_rings = rte_zmalloc("vhost_recv_ring", sizeof (nes_ring_t*), RTE_CACHE_LINE_SIZE);
	if (self->rx_rings == NULL) {
		NES_LOG(EMERG, "Unable to allocate rings");
		return NES_FAIL;
	}
	/* Set vm rings, create them if do not exist */
	if (NES_SUCCESS != nes_ring_per_vm_set(self->dev.vhost.vm_id,
			&self->rx_rings[0], &self->tx_ring)) {
		rte_free(self->rx_rings);
		NES_LOG(ERR, "Unable to set rings for VM %d", self->dev.vhost.vm_id);
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_queue_enqueue(nts_io_rings, self->rx_rings[0])) {
		rte_free(self->rx_rings);
		NES_LOG(ERR, "Unable to enqueue rings for VM %d", self->dev.vhost.vm_id);
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

/**
 * VHOST device constructor
 */
NES_STATIC int
ctor_vhost(nes_dev_t *self, __attribute__((unused)) void *data) {
	if (self == NULL) {
		NES_LOG(ERR, "Invalid ctor args\n");
		return NES_FAIL;
	}

	self->dev_type = VHOST;
	self->tx_buffer_cnt = 0;
	self->retry_timeout_cycles = RESEND_TIMEOUT_US * rte_get_timer_hz() / 1E6;
	self->rx_rings = NULL;

	rte_vhost_enable_guest_notification(self->dev.vhost.vm_id, VHOST_RXQ, 0);
	rte_vhost_enable_guest_notification(self->dev.vhost.vm_id, VHOST_TXQ, 0);

	const char *name = VHOST_NAME_STRING;
	self->name = (char*) (uintptr_t) name;
	return NES_SUCCESS;
}

/**
 * VHOST device destructor
 */
NES_STATIC int
dtor_vhost(nes_dev_t *self, __attribute__((unused)) void *data) {

	nes_dev_vhost_destroy_device(self->dev.vhost.vm_id);
	return NES_SUCCESS;
}

NES_STATIC int
mac_authorized(struct nes_dev_s *self, struct rte_mbuf **m, int pkt_count) {
	struct ether_hdr *pkt_hdr;
	struct ether_addr ether_address;
	int i, j;
	struct mac_entry *mac_data;

	for (j = 0; j < pkt_count; j++) {
		pkt_hdr = rte_pktmbuf_mtod(m[j], struct ether_hdr *);

		for (i = 0; i < ETHER_ADDR_LEN; i++)
			ether_address.addr_bytes[i] = pkt_hdr->s_addr.addr_bytes[i];

		/* check if mac address exists in our lookup table */
		if (NES_SUCCESS == nes_mac_lookup_entry_find(&ether_address, &mac_data)) {
			mac_data->vm_id = self->dev.vhost.vm_id;
			mac_data->ring_name = nts_lookup_tx_vm_ring_name_get(self->dev.vhost.vm_id);
			if (NULL == mac_data->ring_name)
				return NES_FAIL;

			nes_ring_find(&mac_data->ring, mac_data->ring_name);
			memcpy(self->mac_address.addr_bytes,
				ether_address.addr_bytes, ETHER_ADDR_LEN);
			NES_LOG(INFO, "VM device id: %d" \
				" authorized with MAC_ADDRESS %02x:%02x:%02x:%02x:%02x:%02x.\n",
				self->dev.vhost.vm_id,
				self->mac_address.addr_bytes[0], self->mac_address.addr_bytes[1],
				self->mac_address.addr_bytes[2], self->mac_address.addr_bytes[3],
				self->mac_address.addr_bytes[4], self->mac_address.addr_bytes[5]);
			return NES_SUCCESS;
		}
	}

	return NES_FAIL;
}

/**
 * Authorized receiving from VHOST device
 */
static int
recv_vhost_authorized(struct nes_dev_s *self, __attribute__((unused)) void *data) {
	if (unlikely(self->dev.vhost.status != VHOST_READY))
		return NES_FAIL;

	self->rx_cnt = rte_vhost_dequeue_burst(self->dev.vhost.vm_id, VHOST_TXQ,
		nes_dev_vhost_pktmbuf_pool, self->rx_pkts, MAX_BURST_SIZE);

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

/**
 * Authorized sending to VHOST device
 */
static int
send_vhost_authorized(struct nes_dev_s *self, __attribute__((unused)) void *data) {
	nes_ring_t *tx_ring = self->tx_ring;
	struct rte_mbuf * buf[MAX_BURST_SIZE];
	int tx_cnt, buf_id;

	if (unlikely(self->dev.vhost.status != VHOST_READY))
		return NES_FAIL;

#if 0
	int ret_cnt;
	if (unlikely(self->tx_buffer_cnt > 0)) {
		if (rte_get_timer_cycles() - self->retry_send_start > self->retry_timeout_cycles) {


			for (buf_id = 0; buf_id < self->tx_buffer_cnt; buf_id++)
				rte_pktmbuf_free(self->tx_buffer[buf_id]);

			self->tx_buffer_cnt = 0;
		} else {
			self->tx_buffer_cnt -= rte_vhost_enqueue_burst(self->dev.vhost.vdev,
				VHOST_RXQ,
				self->tx_buffer,
				self->tx_buffer_cnt);
			if (self->tx_buffer_cnt > 0)
				return NES_FAIL;
		}
	}

	tx_cnt = tx_ring->deq_burst(tx_ring, (void**) buf, MAX_BURST_SIZE);

	if (likely(tx_cnt > 0)) {
		ret_cnt = rte_vhost_enqueue_burst(self->dev.vhost.vdev, VHOST_RXQ, buf, tx_cnt);
		buf_id = ret_cnt;
		while (likely(buf_id)) {
			buf_id--;
			rte_pktmbuf_free(buf[buf_id]);
		}
		if (unlikely(ret_cnt < tx_cnt)) {
			for (buf_id = ret_cnt; buf_id < tx_cnt; buf_id++)
				self->tx_buffer[self->tx_buffer_cnt++] = buf[buf_id];

			self->retry_send_start = rte_get_timer_cycles();
			return NES_FAIL;
		}
	}
#else
	tx_cnt = tx_ring->deq_burst(tx_ring, (void**) buf, MAX_BURST_SIZE);
	if (likely(tx_cnt > 0)) {
		NES_STATS_DECL int sent_pkts = 0;
		NES_STATS_ASSGN(sent_pkts, rte_vhost_enqueue_burst(self->dev.vhost.vm_id,
			VHOST_RXQ, buf, tx_cnt));
		NES_STATS_DEV_UPDATE(sent_pkts, self->dev_stats->stats.snd_cnt);
		NES_STATS_DEV_UPDATE((tx_cnt - sent_pkts), self->dev_stats->stats.drp_cnt_1);
		for (buf_id = 0; buf_id < sent_pkts; buf_id++) {
			NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(buf[buf_id]),
				self->dev_stats->stats.snd_bytes);
			rte_pktmbuf_free(buf[buf_id]);
		}
		for (; buf_id < tx_cnt; buf_id++) {
			NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(buf[buf_id]),
				self->dev_stats->stats.drp_bytes_1);
			rte_pktmbuf_free(buf[buf_id]);
		}
	}
#endif
	return NES_SUCCESS;
}

/**
 * Unauthorized sending to VHOST device
 */
NES_STATIC int
send_vhost_unauthorized(__attribute__((unused)) struct nes_dev_s *self,
	__attribute__((unused)) void *data) {
	return NES_SUCCESS;
}

/**
 * Unauthorized receiving from VHOST device
 */
static int
recv_vhost_unauthorized(struct nes_dev_s *self, __attribute__((unused)) void *data) {

	if (unlikely(self->dev.vhost.status != VHOST_READY))
		return NES_FAIL;

	self->rx_cnt = rte_vhost_dequeue_burst(self->dev.vhost.vm_id, VHOST_TXQ,
		nes_dev_vhost_pktmbuf_pool, self->rx_pkts, MAX_BURST_SIZE);

	if (likely(self->rx_cnt > 0)) {
		int i;
		NES_STATS_DEV_UPDATE(self->rx_cnt, self->dev_stats->stats.rcv_cnt);
		for (i = 0; i < self->rx_cnt; i++) {
			NES_STATS_DEV_UPDATE(rte_pktmbuf_pkt_len(self->rx_pkts[i]),
				self->dev_stats->stats.rcv_bytes);
		}
		if (NES_SUCCESS == mac_authorized(self, self->rx_pkts, self->rx_cnt)) {
			create_vm_rings(self);
			nes_ring_t *rx_ring = self->rx_rings[0];
			int ret_cnt = rx_ring->enq_burst(rx_ring, (void**) self->rx_pkts,
				self->rx_cnt);

			/* Replace recv and send callbacks */
			self->recv = recv_vhost_authorized;
			self->send = send_vhost_authorized;

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

/**
 * Implementation of new_device()
 */
NES_STATIC int
nes_dev_vhost_new_device(int vm_id) {
	nes_dev_t *vhost_dev;
	const char* buffer;
	uint64_t max_vms;

	if (NES_SUCCESS != nes_cfgfile_entry("VM common", "max", &buffer)) {
		NES_LOG(ERR, "Missing: section %s, entry %s, in config file.\n",
			"VM common", "number");
		return NES_FAIL;
	}
	max_vms = strtoul(buffer, NULL, 10);
	if ((uint64_t)vm_id > max_vms) {
		NES_LOG(EMERG, "Fatal Error: Number of ports: %d," \
			"exceeds configured number of VM instances: %ld.\n",
			vm_id, max_vms);
		return NES_FAIL;
	}

	nes_io_dev_queue_get(&nes_io_devices);
	vhost_dev = rte_zmalloc("vhost device", sizeof (*vhost_dev), RTE_CACHE_LINE_SIZE);
	if (vhost_dev == NULL) {
		NES_LOG(ERR, "(%d) couldn't allocate memory for vhost dev\n", vm_id);
		return NES_FAIL;
	}

	vhost_dev->dev.vhost.vm_id = vm_id;
	vhost_dev->dev.vhost.status = VHOST_NOT_READY;
	vhost_dev->remove = 0;


	vhost_dev->ctor = ctor_vhost;
	vhost_dev->dtor = dtor_vhost;
	vhost_dev->scatter = NULL;

	vhost_dev->ctor(vhost_dev, NULL);

	vhost_dev->recv = recv_vhost_unauthorized;
	vhost_dev->send = send_vhost_unauthorized;
	NES_LOG(INFO, "New VM device registered, waiting to be authorized.\n");
	if (NES_SUCCESS != nes_dev_add_device(vhost_dev))
		return NES_FAIL;
	vhost_dev->dev.vhost.status = VHOST_READY;

	NES_LOG(INFO, "VHOST device %d has been created\n", vm_id);

	return NES_SUCCESS;
}

static const struct vhost_device_ops virtio_ops = {
	.new_device = nes_dev_vhost_new_device,
	.destroy_device = nes_dev_vhost_destroy_device,
};

/**
 * Early init for VHOST
 */
int
nes_dev_vhost_early_init(void) {

	const char *dev_basename;
	/* Read vhost basename*/
	if (NES_SUCCESS != nes_cfgfile_entry("VM common", "vhost-dev", &dev_basename)) {
		NES_LOG(ERR, "Missing: section VM common, entry vhost-dev, in config file.\n");
		return NES_FAIL;
	}

	nes_dev_vhost_mempool_init();
	uint64_t flags = 0;
	if (0 != rte_vhost_driver_register(dev_basename, flags)) {
		NES_LOG(ERR, "VHOST driver setup failure.\n");
		rte_vhost_driver_unregister(dev_basename);
		return NES_FAIL;
	}

	rte_vhost_driver_callback_register(dev_basename, &virtio_ops);

	/* Start VHOST session. */
	rte_vhost_driver_start(dev_basename);

	return NES_SUCCESS;
}
