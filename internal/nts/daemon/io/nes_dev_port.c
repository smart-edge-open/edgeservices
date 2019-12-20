/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dev_port.c
 * @brief Implementation of logical port
 */

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_udp.h>
#include <rte_alarm.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>

#include "nes_common.h"
#include "io/nes_dev.h"
#include "io/nes_io.h"
#include "ctrl/nes_ctrl.h"
#include "nes_ring.h"
#include "nes_ring_lookup.h"
#include "nts/nts_edit.h"
#include "ctrl/nes_ctrl.h"
#include "nes_latency.h"
#include "libnes_cfgfile.h"
#include "nts/nts_io.h"
#include "nes_dev_addons.h"

#ifdef UNIT_TESTS
	#include "nes_dev_port_decl.h"
#endif

static nes_queue_t * nes_io_devices;

#define PREFETCH_OFFSET                 3
#define MAX_FLOW_NUM                    UINT16_MAX
#define MIN_FLOW_NUM                    1
#define DEF_FLOW_NUM                    0x1000
#define IP_FRAG_TBL_BUCKET_ENTRIES	16

static nes_queue_t *nts_io_rings;
static int no_of_ports = 0;

int count_port_devices(void)
{
	/* search for all logical ports */
	int i = 0;
	char port_name[PORT_NAME_SIZE];
#ifndef UNIT_TESTS
	if (no_of_ports)
		return no_of_ports;
#endif
	while (1) {
		snprintf(port_name, sizeof(port_name)/sizeof(port_name[0]),
			PORT_SECTION_NAME"%d", i);
		if (NES_SUCCESS != nes_cfgfile_has_section(port_name))
			break;
		i++;
	}
	no_of_ports = i;
	return i;
}

int is_lbp_enabled(void)
{
	int i = 0;
	char port_name[PORT_NAME_SIZE];
	const char      *buffer;
	while (1) {
		snprintf(port_name, sizeof(port_name)/sizeof(port_name[0]),
			PORT_SECTION_NAME"%d", i);
		if (NES_SUCCESS != nes_cfgfile_has_section(port_name))
			break;

		if (NES_SUCCESS == nes_cfgfile_entry(port_name, TRAFFIC_DIRECTION, &buffer)) {
			if (0 == strncmp(buffer, TRAFFIC_DIRECTION_LBP,
					sizeof(TRAFFIC_DIRECTION_LBP)))
				return NES_SUCCESS;
		}
		i++;
	}
	return NES_FAIL;
}

static int avp_enabled = -1;
int is_avp_enabled(void)
{
	int i = 0;
	char port_name[PORT_NAME_SIZE];
	const char      *buffer;

	/* if already checked - skip search process */
	if (-1 != avp_enabled)
		return avp_enabled;
	while (1) {
		snprintf(port_name, sizeof(port_name)/sizeof(port_name[0]),
			PORT_SECTION_NAME"%d", i);
		if (NES_SUCCESS != nes_cfgfile_has_section(port_name))
			break;

		if (NES_SUCCESS == nes_cfgfile_entry(port_name, TRAFFIC_DIRECTION, &buffer)) {
			if (0 == strncmp(buffer, TRAFFIC_DIRECTION_AVP,
					sizeof(TRAFFIC_DIRECTION_AVP))) {
				avp_enabled = NES_SUCCESS;
				return NES_SUCCESS;
			}
		}
		i++;
	}
	avp_enabled = NES_FAIL;
	return NES_FAIL;
}

enum port_rx_rings_id
{
	NIS_PORT_UPSTR_RNIS = 0,
	NIS_PORT_DWSTR_RNIS,
	NIS_PORT_UPSTR_SCTP,
	NIS_PORT_DWSTR_SCTP,
	NIS_PORT_UPSTR_GTPUC,
	NIS_PORT_DWSTR_GTPUC,
	NIS_PORT_UPSTR_GTPC,
	NIS_PORT_DWSTR_GTPC,
	NTS_PORT_UPSTR_GTPU,
	NTS_PORT_DWSTR_GTPU,
	NTS_PORT_UPSTR_IP,
	NTS_PORT_DWSTR_IP,
	NTS_LBP_ANY,
	NTS_AVP_ANY,
	PORT_RX_RINGS_CNT
};

enum scatter_flags
{
	SCATTER_FL_LTE = 1<<0,
	SCATTER_FL_IP = 1<<1,
	SCATTER_FL_MIXED = SCATTER_FL_LTE | SCATTER_FL_IP,
	SCATTER_FL_UPSTREAM = 1<<3,
	SCATTER_FL_DOWNSTREAM = 1<<4,
	SCATTER_FL_BOTH = 1<<5,
};


// For ports with BOTH direction upstream traffic rule has to be set to be able
// to determine traffic direction
static uint8_t is_upstream(struct rte_mbuf *m, uint8_t is_gtp) {
	nes_ring_t *dst_ring = nts_get_dst_ring(m, is_gtp);
	nes_dev_t *dev = nes_dev_get_device_by_tx_ring(dst_ring);
	if (NULL == dev)
		return 0;
	return 1;
}

/* ALL FLAGS SHOULD BE OPTIMIZED */
static FORCE_INLINE void scatter_eth_packets(struct nes_dev_s *self, int flags)
{
	uint16_t i, udp_port = 0;
	uint8_t is_upstream_dir;
	uint64_t   cur_tsc =  rte_rdtsc();

	for (i = 0; i < self->rx_cnt; i++) {
		struct ipv4_hdr *ipv4_hdr;
		struct ether_hdr *eth_hdr;
		struct udp_hdr *udp_hdr;
		uint8_t ip_len;
		uint16_t l2_off = 0;

		eth_hdr = rte_pktmbuf_mtod(self->rx_pkts[i], struct ether_hdr *);

		/* check if VLAN tag is present */
		if (eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
			eth_hdr = (struct ether_hdr *)((uint8_t*)eth_hdr + sizeof(struct vlan_hdr));
			l2_off = sizeof(struct vlan_hdr);
		}

		if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
#ifdef NES_DEBUG
			NES_LOG(DEBUG, "Detected unsupported ether type 0x%04x\n",
				rte_be_to_cpu_16(eth_hdr->ether_type));
			rte_pktmbuf_dump(stdout, self->rx_pkts[i], self->rx_pkts[i]->data_len);
#endif
			nes_ring_t *ring = self->rx_default_ring;
			ring->enq(ring, self->rx_pkts[i]);
			continue;
		}

		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

		if (rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr)) {
			struct rte_mbuf *mo;

			self->rx_pkts[i]->l2_len = l2_off + sizeof(*eth_hdr);
			self->rx_pkts[i]->l3_len = sizeof(*ipv4_hdr);
			/* process this fragment */
			mo = rte_ipv4_frag_reassemble_packet(self->frag_tbl,
				&self->death_row, self->rx_pkts[i], cur_tsc, ipv4_hdr);
			/* check if all packet are gathering */
			if (mo == NULL)
				continue;
			rte_pktmbuf_linearize(mo);
			/* packet reassembled */
			if (mo != self->rx_pkts[i]) {
				self->rx_pkts[i] = mo;
				eth_hdr = rte_pktmbuf_mtod(self->rx_pkts[i], struct ether_hdr *);

				ipv4_hdr = (struct ipv4_hdr *)((uint8_t*)(eth_hdr + 1) + l2_off);
			}
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

			NES_STATS_DEV_UPDATE(1, self->dev_stats->stats.ip_fragment);
		}

		if (flags & SCATTER_FL_LTE) {
			if (flags & SCATTER_FL_BOTH)
				is_upstream_dir = is_upstream(self->rx_pkts[i], 1);

			if (ipv4_hdr->next_proto_id == IP_PROTO_SCTP) {
				if (flags & SCATTER_FL_BOTH) {
					nes_ring_t *ring = is_upstream_dir ?
						self->rx_rings[NIS_PORT_UPSTR_SCTP] :
						self->rx_rings[NIS_PORT_DWSTR_SCTP];
					ring->enq(ring,self->rx_pkts[i]);       /* for Klockwork */
				} else if (flags & SCATTER_FL_UPSTREAM) {
					nes_ring_t *ring = self->rx_rings[NIS_PORT_UPSTR_SCTP];
					ring->enq(ring,self->rx_pkts[i]);       /* for Klockwork */
				} else if (flags & SCATTER_FL_DOWNSTREAM) {
					nes_ring_t *ring = self->rx_rings[NIS_PORT_DWSTR_SCTP];
					ring->enq(ring,self->rx_pkts[i]);       /* for Klockwork */
				}
				continue;
			}
			if (ipv4_hdr->next_proto_id != IP_PROTO_UDP) {
				if (flags & SCATTER_FL_IP) {
					if (flags & SCATTER_FL_BOTH) {
						nes_ring_t *ring = is_upstream(self->rx_pkts[i], 0) ?
							self->rx_rings[NTS_PORT_UPSTR_IP] :
							self->rx_rings[NTS_PORT_DWSTR_IP];
						ring->enq(ring,
							self->rx_pkts[i]);     /* for Klockwork */
					} else if (flags & SCATTER_FL_UPSTREAM) {
						nes_ring_t *ring =
							self->rx_rings[NTS_PORT_UPSTR_IP];
						ring->enq(ring,
							self->rx_pkts[i]);     /* for Klockwork */
					} else if (flags & SCATTER_FL_DOWNSTREAM) {
						nes_ring_t *ring =
							self->rx_rings[NTS_PORT_DWSTR_IP];
						ring->enq(ring,
							self->rx_pkts[i]);     /* for Klockwork */
					}
				} else {
					nes_ring_t *ring = self->rx_default_ring;
					ring->enq(ring, self->rx_pkts[i]);
				}
				continue;
			}

			ip_len = ipv4_hdr->version_ihl & 0xf;
			udp_hdr = (struct udp_hdr*)((uint32_t *)ipv4_hdr + ip_len);
			if (flags & SCATTER_FL_BOTH) {
				udp_port = is_upstream_dir ?
					udp_hdr->dst_port : udp_hdr->src_port;
			} else if (flags & SCATTER_FL_UPSTREAM)
				udp_port = udp_hdr->dst_port;
			else if (flags & SCATTER_FL_DOWNSTREAM)
				udp_port = udp_hdr->src_port;

			/* check if packet is GTP type of */
			if (udp_port == rte_cpu_to_be_16(UDP_GTPU_PORT) &&
				((gtpuHdr_t*)(udp_hdr + 1))->msg_type == GTPU_MSG_GPDU) {
				if (flags & SCATTER_FL_BOTH) {
					nes_ring_t *ring = is_upstream_dir ?
						self->rx_rings[NTS_PORT_UPSTR_GTPU] :
						self->rx_rings[NTS_PORT_DWSTR_GTPU];
					ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
				} else if (flags & SCATTER_FL_UPSTREAM) {
					nes_ring_t *ring = self->rx_rings[NTS_PORT_UPSTR_GTPU];
					ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
				} else if (flags & SCATTER_FL_DOWNSTREAM) {
					nes_ring_t *ring = self->rx_rings[NTS_PORT_DWSTR_GTPU];
					ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
				}
			} else if (udp_port == rte_cpu_to_be_16(UDP_GTPC_PORT)) {
				if (flags & SCATTER_FL_BOTH) {
					nes_ring_t *ring = is_upstream_dir ?
						self->rx_rings[NIS_PORT_UPSTR_GTPC] :
						self->rx_rings[NIS_PORT_DWSTR_GTPC];
					ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
				} else if (flags & SCATTER_FL_UPSTREAM) {
					nes_ring_t *ring = self->rx_rings[NIS_PORT_UPSTR_GTPC];
					ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
				} else if (flags & SCATTER_FL_DOWNSTREAM) {
					nes_ring_t *ring = self->rx_rings[NIS_PORT_DWSTR_GTPC];
					ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
				}
			} else {
				if (flags & SCATTER_FL_IP) {
					if (flags & SCATTER_FL_BOTH) {
						nes_ring_t *ring = is_upstream_dir ?
							self->rx_rings[NTS_PORT_UPSTR_IP] :
							self->rx_rings[NTS_PORT_DWSTR_IP];
						ring->enq(ring,
							self->rx_pkts[i]);     /* for Klockwork */
					} else if (flags & SCATTER_FL_UPSTREAM) {
						nes_ring_t *ring =
							self->rx_rings[NTS_PORT_UPSTR_IP];
						ring->enq(ring,
							self->rx_pkts[i]);     /* for Klockwork */
					} else if (flags & SCATTER_FL_DOWNSTREAM) {
						nes_ring_t *ring =
							self->rx_rings[NTS_PORT_DWSTR_IP];
						ring->enq(ring,
							self->rx_pkts[i]);     /* for Klockwork */
					}
				} else {
					nes_ring_t *ring = self->rx_default_ring;
					ring->enq(ring, self->rx_pkts[i]);
				}
			}
		} else if (flags & SCATTER_FL_IP) {
			if (flags & SCATTER_FL_BOTH) {
				nes_ring_t *ring = is_upstream(self->rx_pkts[i], 0) ?
					self->rx_rings[NTS_PORT_UPSTR_IP] :
					self->rx_rings[NTS_PORT_DWSTR_IP];
				ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
			} else if (flags & SCATTER_FL_UPSTREAM) {
				nes_ring_t *ring = self->rx_rings[NTS_PORT_UPSTR_IP];
				ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
			} else if (flags & SCATTER_FL_DOWNSTREAM) {
				nes_ring_t *ring = self->rx_rings[NTS_PORT_DWSTR_IP];
				ring->enq(ring, self->rx_pkts[i]);       /* for Klockwork */
			}
		}
	} /* for (i = 0; i < self->rx_cnt; i++) */
	rte_ip_frag_free_death_row(&self->death_row, PREFETCH_OFFSET);
}

NES_STATIC int scatter_eth_both_mixed(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_BOTH | SCATTER_FL_MIXED);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_upstr_mixed(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_UPSTREAM | SCATTER_FL_MIXED);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_dwstr_mixed(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_DOWNSTREAM | SCATTER_FL_MIXED);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_both_LTE(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_BOTH | SCATTER_FL_LTE);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_upstr_LTE(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_UPSTREAM | SCATTER_FL_LTE);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_dwstr_LTE(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_DOWNSTREAM | SCATTER_FL_LTE);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_both_IP(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_BOTH | SCATTER_FL_IP);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_upstr_IP(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_UPSTREAM | SCATTER_FL_IP);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_dwstr_IP(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	scatter_eth_packets(self, SCATTER_FL_DOWNSTREAM | SCATTER_FL_IP);
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_lbp(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	nes_ring_t *rx_ring = self->rx_rings[NTS_LBP_ANY];
	if (0 == self->rx_cnt)
		return NES_SUCCESS;

	int rx_cnt = rx_ring->enq_burst(rx_ring, (void **)self->rx_pkts, self->rx_cnt);
	if (rx_cnt < self->rx_cnt) {
		int i;
		NES_LOG(ERR,"Unable to enqueue %d packets to %s ring.\n",
			rx_cnt, nes_ring_name(rx_ring));
		for (i = rx_cnt; i < self->rx_cnt; i++)
			rte_pktmbuf_free(self->rx_pkts[i]);

		return NES_FAIL;
	}
	return NES_SUCCESS;
}

NES_STATIC int scatter_eth_avp(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	nes_ring_t *rx_ring = self->rx_rings[NTS_AVP_ANY];
	if (0 == self->rx_cnt)
		return NES_SUCCESS;

	int rx_cnt = rx_ring->enq_burst(rx_ring, (void **)self->rx_pkts, self->rx_cnt);
	if (rx_cnt < self->rx_cnt) {
		int i;
		NES_LOG(ERR,"Unable to enqueue %d packets to %s ring.\n",
			rx_cnt, nes_ring_name(rx_ring));
		for (i = rx_cnt; i < self->rx_cnt; i++)
			rte_pktmbuf_free(self->rx_pkts[i]);

		return NES_FAIL;
	}
	return NES_SUCCESS;
}

NES_STATIC int add_ring_to_ntsqueue(nes_queue_t *ntsqueue, nes_ring_t **rx_rings)
{
	static int rings_added[PORT_RX_RINGS_CNT] = { 0 };
	int i = 0;

	for (i = 0; i < PORT_RX_RINGS_CNT; i++) {
		if (NULL != rx_rings[i] && NULL != rx_rings[i]->ring) {
			/* check if this is NTS ring */
			if ((0 == rings_added[i]) &&
					(0 == strncmp(rx_rings[i]->ring->name,
					"NTS_", sizeof("NTS_") - 1))) {
				if (NES_SUCCESS != nes_queue_enqueue(ntsqueue, rx_rings[i]))
					return NES_FAIL;

				/* mark ring as added */
				rings_added[i] = 1;
			}
		}
	}

	return NES_SUCCESS;
}

NES_STATIC int get_port_rings(struct nes_dev_s *self)
{
	char tx_ring_name[PORT_NAME_SIZE];
	char rx_def_ring_name[PORT_NAME_SIZE];
	snprintf(tx_ring_name, sizeof(tx_ring_name)/sizeof(tx_ring_name[0]),
		PORT_TX_QUEUE_NAME_TEMPLATE, self->nes_port_id);
	snprintf(rx_def_ring_name, sizeof(rx_def_ring_name)/sizeof(rx_def_ring_name[0]),
		PORT_TX_QUEUE_NAME_TEMPLATE, self->egres_port);

	const int rx_rings_cnt = PORT_RX_RINGS_CNT;
	self->rx_rings = rte_zmalloc("rx rings", sizeof(nes_ring_t *) * rx_rings_cnt,
		RTE_CACHE_LINE_SIZE);
	if (NULL == self->rx_rings) {
		NES_LOG(ERR, "Couldn't allocate memory for rx rings for port\n");
		return NES_FAIL;
	}

	/* get all needed rings for IP */
	if (TT_IP == self->traffic_type || TT_MIXED == self->traffic_type) {
		switch (self->traffic_dir) {
		case TD_UPSTREAM:
			if (nes_ring_find(&self->rx_rings[NTS_PORT_UPSTR_IP], "NTS_UPSTR_IP") ||
					nes_ring_find(&self->tx_ring, tx_ring_name) ||
					nes_ring_find(&self->rx_default_ring, rx_def_ring_name)) {
				NES_LOG(ERR, "Unable to find all %s rings\n", self->name);
				return NES_FAIL;
			}
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue UPSTREAM ring pointer\n");
				return NES_FAIL;
			}
			break;
		case TD_DOWNSTREAM:
			if (nes_ring_find(&self->rx_rings[NTS_PORT_DWSTR_IP], "NTS_DWSTR_IP") ||
					nes_ring_find(&self->tx_ring, tx_ring_name) ||
					nes_ring_find(&self->rx_default_ring, rx_def_ring_name)) {
				NES_LOG(ERR, "Unable to find all %s rings\n", self->name);
				return NES_FAIL;
			}
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue DOWNSTREAM ring pointer\n");
				return NES_FAIL;
			}
			break;
		case TD_BOTH:
			if (nes_ring_find(&self->rx_rings[NTS_PORT_UPSTR_IP], "NTS_UPSTR_IP") ||
					nes_ring_find(&self->rx_rings[NTS_PORT_DWSTR_IP],
					"NTS_DWSTR_IP") ||
					nes_ring_find(&self->tx_ring, tx_ring_name) ||
					nes_ring_find(&self->rx_default_ring, rx_def_ring_name)) {
				NES_LOG(ERR, "Unable to find all %s rings\n", self->name);
				return NES_FAIL;
			}
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue UPSTR and DWSTR ring pointers\n");
				return NES_FAIL;
			}
			break;
		case TD_LBP:
			if (nes_ring_find(&self->rx_rings[NTS_LBP_ANY], LBP_RX_RING_NAME) ||
					nes_ring_find(&self->tx_ring, tx_ring_name)) {

				NES_LOG(ERR, "Unable to find all LBP rings\n");
				return NES_FAIL;
			}
			self->rx_default_ring = NULL;
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue LBP ring pointer\n");
				return NES_FAIL;
			}
			break;
		case TD_AVP:
			if (nes_ring_find(&self->rx_rings[NTS_AVP_ANY], AVP_RX_RING_NAME) ||
					nes_ring_find(&self->tx_ring, AVP_TX_RING_NAME)) {

				NES_LOG(ERR, "Unable to find all AVP rings\n");
				return NES_FAIL;
			}
			self->rx_default_ring = NULL;
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue AVP ring pointer\n");
				return NES_FAIL;
			}
			break;
		}
	}

	/* get all needed rings for LTE */
	if (TT_LTE == self->traffic_type || TT_MIXED == self->traffic_type) {
		switch (self->traffic_dir) {
		case TD_UPSTREAM:   /* ENB */
			if (nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_RNIS], "NIS_UPSTR_RNIS") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_SCTP],
						"NIS_UPSTR_SCTP") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_GTPUC],
						"NIS_UPSTR_GTPUC") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_GTPC],
						"NIS_UPSTR_GTPC") ||
					nes_ring_find(&self->rx_rings[NTS_PORT_UPSTR_GTPU],
						"NTS_UPSTR_GTPU") ||
					nes_ring_find(&self->tx_ring, tx_ring_name) ||
					nes_ring_find(&self->rx_default_ring, rx_def_ring_name)) {
				NES_LOG(ERR, "Unable to find all %s rings\n", self->name);
				return NES_FAIL;
			}
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue UPSTREAM ring pointer\n");
				return NES_FAIL;
			}
			break;
		case TD_DOWNSTREAM: /* EPC */
			if (nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_RNIS], "NIS_DWSTR_RNIS") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_SCTP],
						"NIS_DWSTR_SCTP") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_GTPUC],
						"NIS_DWSTR_GTPUC") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_GTPC],
						"NIS_DWSTR_GTPC") ||
					nes_ring_find(&self->rx_rings[NTS_PORT_DWSTR_GTPU],
						"NTS_DWSTR_GTPU") ||
					nes_ring_find(&self->tx_ring, tx_ring_name) ||
					nes_ring_find(&self->rx_default_ring, rx_def_ring_name)) {
				NES_LOG(ERR, "Unable to find all %s rings\n", self->name);
				return NES_FAIL;
			}
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue DOWNSTREAM ring pointer\n");
				return NES_FAIL;
			}
			break;
		case TD_BOTH:
			if (nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_RNIS], "NIS_UPSTR_RNIS") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_RNIS],
						"NIS_DWSTR_RNIS") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_SCTP],
						"NIS_UPSTR_SCTP") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_SCTP],
						"NIS_DWSTR_SCTP") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_GTPUC],
						"NIS_UPSTR_GTPUC") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_GTPUC],
						"NIS_DWSTR_GTPUC") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_UPSTR_GTPC],
						"NIS_UPSTR_GTPC") ||
					nes_ring_find(&self->rx_rings[NIS_PORT_DWSTR_GTPC],
						"NIS_DWSTR_GTPC") ||
					nes_ring_find(&self->rx_rings[NTS_PORT_UPSTR_GTPU],
						"NTS_UPSTR_GTPU") ||
					nes_ring_find(&self->rx_rings[NTS_PORT_DWSTR_GTPU],
						"NTS_DWSTR_GTPU") ||
					nes_ring_find(&self->tx_ring, tx_ring_name) ||
					nes_ring_find(&self->rx_default_ring, rx_def_ring_name)) {
				NES_LOG(ERR, "Unable to find all %s rings\n", self->name);
				return NES_FAIL;
			}
			if (NES_SUCCESS != add_ring_to_ntsqueue(nts_io_rings, self->rx_rings)) {
				NES_LOG(ERR, "Unable to enqueue BOTH ring pointer\n");
				return NES_FAIL;
			}
			break;
		default:
			break;
		}
	}
	return NES_SUCCESS;
}

NES_STATIC int ctor_eth_port(nes_dev_t *self, void* data)
{
	int retval;
	if (self == NULL || data == NULL) {
		NES_LOG(ERR, "Invalid ctor args\n");
		return NES_FAIL;
	}

	self->dev = *(nes_dev_id_t*)data;
	self->dev_type = ETH;
	self->tx_buffer_cnt = 0;
	self->retry_timeout_cycles = RESEND_TIMEOUT_US * rte_get_timer_hz() / 1E6;
	retval = init_eth_port(self->dev.eth.port_id, self->dev.eth.queue_id);
	check_eth_port_link_status(self->dev.eth.port_id);
	struct rte_pci_addr addr;
	struct ether_addr mac_addr;
	if (NES_SUCCESS == nes_dev_eth_pci_addr_get(self->dev.eth.port_id, &addr) &&
			NES_SUCCESS == nes_dev_eth_mac_addr_get(self->dev.eth.port_id, &mac_addr)) {
		memcpy(self->mac_address.addr_bytes, mac_addr.addr_bytes, ETHER_ADDR_LEN);
		NES_LOG(INFO, "DPDK port: %d PCI address: %04x:%02x:%02x.%d " \
			"MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", self->dev.eth.port_id,
			addr.domain, addr.bus, addr.devid, addr.function,
			mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
			mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
	}
	rte_eth_stats_reset(self->dev.eth.port_id);

	if (0 == retval)
		retval = get_port_rings(self);

	return retval;
}

static int dtor_port(struct nes_dev_s *self, __attribute__((unused)) void *data)
{
	rte_eth_dev_stop(self->dev.eth.port_id);
	if (NULL != self->rx_rings) {
		rte_free(self->rx_rings);
		self->rx_rings = NULL;
	}
	return NES_SUCCESS;
}

int nes_dev_port_new_device(void)
{
	nes_dev_t       *port_dev = NULL;
	nes_dev_id_t    known_dev;
	const char      *buffer;
	const char      *name;
	uint64_t        frag_cycles;


	/* search for all logical ports */
	int i = 0;
	uint8_t dpdk_port_id = 0;
	char port_name[PORT_NAME_SIZE];

	nes_io_dev_queue_get(&nes_io_devices);
	nts_io_ring_queue_get(&nts_io_rings);

	for (i = 0; i < count_port_devices(); i++) {
		snprintf(port_name, sizeof(port_name)/sizeof(port_name[0]),
			PORT_SECTION_NAME"%d", i);

		port_dev = rte_zmalloc("logical port device", sizeof(nes_dev_t),
			RTE_CACHE_LINE_SIZE);
		if (NULL == port_dev) {
			NES_LOG(ERR, "Couldn't allocate memory for port dev\n");
			break;
		}
		/* get port name */
		if (NES_SUCCESS != nes_cfgfile_entry(port_name, NAME_ENTRY, &name)) {
			NES_LOG(ERR, "Unable to find " NAME_ENTRY " entry for port %d\n", i);
			break;
		}
		if (0 < strlen(name)) {
			port_dev->name = rte_zmalloc("logical port name", strlen(name) + 1, 0);
			strncpy(port_dev->name, name, strlen(name));
		} else {
			NES_LOG(ERR, NAME_ENTRY" entry for port %d is NULL length\n", i);
			break;
		}
		/* get traffic direction */
		if (NES_SUCCESS != nes_cfgfile_entry(port_name, TRAFFIC_DIRECTION, &buffer)) {
			NES_LOG(ERR, "Unable to find "TRAFFIC_DIRECTION" entry for port %d\n", i);
			break;
		}
		if (0 == strncmp(buffer, TRAFFIC_DIRECTION_UP, sizeof(TRAFFIC_DIRECTION_UP)))
			port_dev->traffic_dir = TD_UPSTREAM;
		else if (0 == strncmp(buffer, TRAFFIC_DIRECTION_DOWN,
				sizeof(TRAFFIC_DIRECTION_DOWN)))
			port_dev->traffic_dir = TD_DOWNSTREAM;
		else if (0 == strncmp(buffer, TRAFFIC_DIRECTION_BOTH,
				sizeof(TRAFFIC_DIRECTION_BOTH)))
			port_dev->traffic_dir = TD_BOTH;
		else if (0 == strncmp(buffer, TRAFFIC_DIRECTION_LBP,
				sizeof(TRAFFIC_DIRECTION_LBP))) {
			port_dev->traffic_dir = TD_LBP;
			port_dev->traffic_type = TT_IP;
		} else if (0 == strncmp(buffer, TRAFFIC_DIRECTION_AVP,
				sizeof(TRAFFIC_DIRECTION_AVP))) {
			port_dev->traffic_dir = TD_AVP;
			port_dev->traffic_type = TT_IP;
		} else {
			NES_LOG(ERR, "Unrecognized "TRAFFIC_DIRECTION" entry for port %d\n", i);
			break;
		}

		port_dev->nes_port_id = (uint8_t)i;
		dpdk_port_id = (uint8_t)i;
		nes_ring_per_port_set(i, &port_dev->tx_ring);   /* tx ring for this port */

		/* get traffic type */
		if (TD_LBP != port_dev->traffic_dir &&
				TD_AVP != port_dev->traffic_dir) {
			if (NES_SUCCESS != nes_cfgfile_entry(port_name, TRAFFIC_TYPE, &buffer)) {
				NES_LOG(ERR,
					"Unable to find "TRAFFIC_TYPE" entry for port %d\n", i);
				break;
			}
			if (0 == strncmp(buffer, TRAFFIC_TYPE_IP, sizeof(TRAFFIC_TYPE_IP)))
				port_dev->traffic_type = TT_IP;
			else if (0 == strncmp(buffer, TRAFFIC_TYPE_LTE,
					sizeof(TRAFFIC_TYPE_LTE)))
				port_dev->traffic_type = TT_LTE;
			else if (0 == strncmp(buffer, TRAFFIC_TYPE_MIX,
					sizeof(TRAFFIC_TYPE_MIX)))
				port_dev->traffic_type = TT_MIXED;
			else {
				NES_LOG(ERR, "Unrecognized "TRAFFIC_TYPE" entry for port %d\n", i);
				break;
			}

			/* get egress port */
			if (NES_SUCCESS != nes_cfgfile_entry(port_name, EGRESS_PORT, &buffer)) {
				NES_LOG(ERR, "Unable to find "EGRESS_PORT" entry for port %d\n", i);
				break;
			}
			port_dev->egres_port = atoi(buffer);
			/* rx ring for egress port */
			nes_ring_per_port_set(port_dev->egres_port, &port_dev->rx_default_ring);
		}

		/* get pci address */
		if (NES_SUCCESS == nes_cfgfile_entry(port_name, PCI_ADDRESS, &buffer)) {
			struct rte_pci_addr pci_addr_cfg;
			if (0 != eal_parse_pci_DomBDF(buffer, &pci_addr_cfg)) {
				NES_LOG(ERR, "Unable to read " PCI_ADDRESS " from port %d\n", i);
				break;
			}

			if (NES_SUCCESS != nes_dev_eth_find_port_id_by_pci(&pci_addr_cfg,
					&dpdk_port_id)) {
				NES_LOG(ERR, "Unable to find port id for pci_addr=%s\n", buffer);
				break;
			}
		}

		/* get mac address if present */
		if (NES_SUCCESS == nes_cfgfile_entry(port_name, MAC_ENTRY, &buffer)) {
			struct ether_addr addr_from_cfg, addr_from_port;
			if (NES_SUCCESS != nes_acl_ether_aton(buffer, &addr_from_cfg) ||
				NES_SUCCESS != nes_dev_eth_mac_addr_get(dpdk_port_id,
					&addr_from_port)) {
				NES_LOG(ERR, "Invalid mac address %s for port %d\n", buffer, i);
				break;
			}
			if (0 != memcmp(&addr_from_cfg, &addr_from_port,
					sizeof(struct ether_addr))) {
				NES_LOG(ERR, "MAC address from config file" \
					" doesn't match the MAC address for port %d\n", i);
				break;
			}
		}

		/* get MTU parameter if present */
		if (NES_SUCCESS == nes_cfgfile_entry(port_name, MTU_ENTRY, &buffer))
			port_dev->MTU = atoi(buffer);
		else
			port_dev->MTU = 0;

		port_dev->ctor = &ctor_eth_port;
		port_dev->dtor = &dtor_port;
		port_dev->recv = &recv_eth;
		if (0 == port_dev->MTU)
			port_dev->send = &send_eth;
		else
			port_dev->send = &send_eth_mtu;

		/* assign scatter */
		switch (port_dev->traffic_dir) {
		case TD_UPSTREAM:
			switch (port_dev->traffic_type) {
			case TT_IP:
				port_dev->scatter = &scatter_eth_upstr_IP;
				break;
			case TT_LTE:
				port_dev->scatter = &scatter_eth_upstr_LTE;
				break;
			case TT_MIXED:
				port_dev->scatter = &scatter_eth_upstr_mixed;
				break;
			}
			break;
		case TD_DOWNSTREAM:
			switch (port_dev->traffic_type) {
			case TT_IP:
				port_dev->scatter = &scatter_eth_dwstr_IP;
				break;
			case TT_LTE:
				port_dev->scatter = &scatter_eth_dwstr_LTE;
				break;
			case TT_MIXED:
				port_dev->scatter = &scatter_eth_dwstr_mixed;
				break;
			}
			break;
		case TD_BOTH:
			switch (port_dev->traffic_type) {
			case TT_IP:
				port_dev->scatter = &scatter_eth_both_IP;
				break;
			case TT_LTE:
				port_dev->scatter = &scatter_eth_both_LTE;
				break;
			case TT_MIXED:
				port_dev->scatter = &scatter_eth_both_mixed;
				break;
			}
			break;
		case TD_LBP:
			port_dev->scatter = &scatter_eth_lbp;
			break;
		case TD_AVP:
			port_dev->scatter = &scatter_eth_avp;
			break;
		}

		known_dev.eth.port_id  = dpdk_port_id;
		known_dev.eth.queue_id = 0;

		if (NES_SUCCESS != port_dev->ctor(port_dev, &known_dev)) {
			rte_eth_dev_stop(dpdk_port_id);
			break;
		}

		/* create fragmentation table */
		frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * MAX_FLOW_NUM;
		if ((port_dev->frag_tbl = rte_ip_frag_table_create(MAX_FLOW_NUM,
				IP_FRAG_TBL_BUCKET_ENTRIES,
				MAX_FLOW_NUM,
				frag_cycles,
				rte_socket_id())) == NULL) {
			NES_LOG(ERR, "Unable to create IP fragmented table(%u)", MAX_FLOW_NUM);
			break;
		}

		if (NES_SUCCESS != nes_dev_add_device(port_dev))
			break;
	}

	/* check if there was an error */
	if (count_port_devices() != i) {
		nes_dev_port_dtor();
		if (NULL != port_dev) {
			rte_free(port_dev);
			port_dev = NULL;
		}
		return NES_FAIL;
	}

	return NES_SUCCESS;
}

void nes_dev_port_dtor(void)
{
	nes_io_dev_queue_get(&nes_io_devices);
	nes_queue_node_t *node;
	nes_dev_t *device;
	while (nes_io_devices->cnt) {
		NES_QUEUE_FOREACH_RETRY(node, nes_io_devices) {
			nes_queue_node_unlock(node);
			if ((node = nes_queue_remove(nes_io_devices, node)) != NULL) {
				device = ((nes_dev_t*)node->data);
				if (ETH == device->dev_type)
					rte_eth_dev_stop(device->dev.eth.port_id);

				if (NULL != device->frag_tbl)
					rte_ip_frag_table_destroy(device->frag_tbl);

				device->dtor(device, NULL);
				rte_free(node);
			}
			break;
		}
	}
}
