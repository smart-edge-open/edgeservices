/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_edit.c
 * @brief Implementation of nts packet editing
 */

#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_cycles.h>

#include "libnes_lookup.h"
#include "libnes_sq.h"
#include "io/nes_dev.h"
#include "nes_common.h"
#include "nts/nts_edit.h"
#include "nts/nts_lookup.h"
#include "nes_ring.h"
#include "nes_ring_lookup.h"
#include "nts/nts_acl.h"
#include "nis/nis_acl.h"
#include "nis/nis_routing_data.h"
#include "io/nes_dev_addons.h"
#include "io/nes_mac_lookup.h"

#ifdef UNIT_TESTS
	#include "nts_edit_decl.h"
#endif

typedef struct routing_params_s {
	struct ipv4_hdr *inner_ipv4_hdr;
	nes_ring_t      *egress_ring;
	// in future there will be more, for example for TEID based forwarding
} routing_params_t;

#define    NB_HDR_MBUF     8192
#define    HDR_MBUF_SIZE   (sizeof(struct rte_mbuf) + 2 * RTE_PKTMBUF_HEADROOM)

#define NB_CLONE_MBUF   (NB_HDR_MBUF * 2)
#define CLONE_MBUF_SIZE (sizeof(struct rte_mbuf))

#define HTONS rte_cpu_to_be_16

static struct rte_mempool *header_pool;
static struct rte_mempool *clone_pool;
extern nes_acl_ctx_t nes_ctrl_acl_ctx;
extern nes_acl_ctx_t nis_param_acl_ctx;

int
nts_edit_init(void) {
	header_pool = rte_mempool_create(
		"header_pool",
		NB_HDR_MBUF,
		HDR_MBUF_SIZE,
		32,
		0,
		NULL,
		NULL,
		rte_pktmbuf_init,
		NULL,
		rte_socket_id(),
		0);
	clone_pool = rte_mempool_create(
		"clone_pool",
		NB_CLONE_MBUF,
		CLONE_MBUF_SIZE,
		32,
		0,
		NULL,
		NULL,
		rte_pktmbuf_init,
		NULL,
		rte_socket_id(),
		0);
	if (NULL == header_pool ||
			NULL == clone_pool) {
		if (NULL != header_pool)
			rte_mempool_free(header_pool);

		NES_LOG(ERR, "Unable to create mbuffs pool for headers and cloning.\n");
		return NES_FAIL;
	}

	return NES_SUCCESS;
}

NES_STATIC inline struct ipv4_hdr*
nts_edit_get_outer_ipv4_hdr(struct rte_mbuf *pkt) {
	// add 1 to move pkt pointer to ipv4 header  pointer
	return (struct ipv4_hdr*) (rte_pktmbuf_mtod(pkt, struct ether_hdr *) + 1);
}

NES_STATIC inline struct ipv4_hdr*
nts_edit_get_inner_ipv4_hdr(struct rte_mbuf *pkt) {
	struct ipv4_hdr *ipv4_hdr;
	gtpuHdr_t *gtpuHdr;
	gtpuHdrOpt_t *gtpuHdrOpt;
	ipv4_hdr = nts_edit_get_outer_ipv4_hdr(pkt);
	gtpuHdr = (gtpuHdr_t *)
		((struct udp_hdr*)
		((uint32_t*) ipv4_hdr + (*(uint8_t*) ipv4_hdr & IPV4_HDR_IHL_MASK)) + 1);
	gtpuHdrOpt = (gtpuHdrOpt_t *) (gtpuHdr + 1);

	if ((*(uint8_t *) gtpuHdr & 0x4)) {
		uint8_t *ext_hdr = (uint8_t *) (gtpuHdrOpt + 1);
		// length is the first byte in extension header
		// next extension header field is the last byte
		while (*(ext_hdr + *ext_hdr - 1))
			ext_hdr += *ext_hdr;

		// move after the last extension header
		return (struct ipv4_hdr*) (ext_hdr + *ext_hdr);
	} else if ((*(uint8_t *) gtpuHdr & 0x3))
		return (struct ipv4_hdr*) (gtpuHdrOpt + 1);

	return (struct ipv4_hdr*) gtpuHdrOpt;
}

NES_STATIC inline void
nts_edit_hdr_parse_gtp(struct rte_mbuf *pkt, nts_enc_subentry_t *entry,
	nts_acl_tuple_t* tuple, struct ipv4_hdr **inner_ipv4_hdr, nes_direction_t direction) {
	struct ipv4_hdr *outer_ipv4_hdr;
	gtpuHdr_t *gtpuHdr;
	gtpuHdrOpt_t *gtpuHdrOpt;
	struct ether_hdr *eth;
	struct udp_hdr *outer_udp;
	uint16_t* inner_src_port;
	struct vlan_hdr *vlan;

	eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	outer_ipv4_hdr = nts_edit_get_outer_ipv4_hdr(pkt);

	/* check if VLAN tag is present */
	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
		vlan = (struct vlan_hdr *)(eth + 1);
		entry->encap_flag = NTS_ENCAP_GTPU_FLAG | NTS_ENCAP_VLAN_FLAG;
		entry->vlan_tci = vlan->vlan_tci;
		outer_ipv4_hdr = (struct ipv4_hdr*)
			((uint8_t*)outer_ipv4_hdr + sizeof(struct vlan_hdr));
	}
	outer_udp = (struct udp_hdr*)
		((uint32_t*)outer_ipv4_hdr + (*(uint8_t*)outer_ipv4_hdr & IPV4_HDR_IHL_MASK));
	gtpuHdr = (gtpuHdr_t *)(outer_udp + 1);
	gtpuHdrOpt = (gtpuHdrOpt_t *) (gtpuHdr + 1);

	if ((*(uint8_t *) gtpuHdr & 0x4)) {
		uint8_t *ext_hdr = (uint8_t *) (gtpuHdrOpt + 1);
		// length is the first byte in extension header
		// next extension header field is the last byte
		while (*(ext_hdr + *ext_hdr - 1))
			ext_hdr += *ext_hdr;

		// move after the last extension header
		*inner_ipv4_hdr = (struct ipv4_hdr*) (ext_hdr + *ext_hdr);
	} else if ((*(uint8_t *) gtpuHdr & 0x3))
		*inner_ipv4_hdr = (struct ipv4_hdr*) (gtpuHdrOpt + 1);
	else
		*inner_ipv4_hdr = (struct ipv4_hdr*) gtpuHdrOpt;

	inner_src_port = (uint16_t*)
		((uint32_t*)(*inner_ipv4_hdr) + (*(uint8_t*)(*inner_ipv4_hdr) & IPV4_HDR_IHL_MASK));

	ether_addr_copy(&eth->d_addr, &entry->dst_mac_addrs);
	ether_addr_copy(&eth->s_addr, &entry->src_mac_addrs);
	entry->dst_ip = outer_ipv4_hdr->dst_addr;
	entry->src_ip = outer_ipv4_hdr->src_addr;
	entry->dst_ip_port = outer_udp->dst_port;
	entry->src_ip_port = outer_udp->src_port;
	entry->teid = gtpuHdr->teid;
	entry->encap_flag = entry->encap_flag | NTS_ENCAP_GTPU_FLAG;

	tuple->encap_flag = entry->encap_flag;
	tuple->teid = gtpuHdr->teid;
	tuple->outer_ip_src = outer_ipv4_hdr->src_addr;
	tuple->outer_ip_dst = outer_ipv4_hdr->dst_addr;
	tuple->inner_ip_src = (*inner_ipv4_hdr)->src_addr;
	tuple->inner_ip_dst = (*inner_ipv4_hdr)->dst_addr;
	tuple->inner_port_src = *inner_src_port;
	tuple->inner_port_dst = *(inner_src_port + 1);

	nis_routing_data_t *data;
	nis_routing_data_key_t key = {
		.direction = direction,
		.enb_ip = (direction == NES_UPSTREAM) ? tuple->outer_ip_src : tuple->outer_ip_dst,
		.teid = tuple->teid
	};
	if (NES_SUCCESS == nis_routing_data_get(&key, &data)) {
		tuple->qci = data->qci;
		tuple->spid = data->spid;;
	}
}

NES_STATIC inline void
nts_edit_hdr_parse_ip(struct rte_mbuf *pkt, nts_enc_subentry_t *entry,
	nts_acl_tuple_t* tuple, struct ipv4_hdr **ipv4_header) {
	struct ipv4_hdr *outer_ipv4_hdr;
	struct ether_hdr *eth;
	struct udp_hdr *outer_udp;
	struct vlan_hdr *vlan;

	eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	outer_ipv4_hdr = nts_edit_get_outer_ipv4_hdr(pkt);

	/* check if VLAN tag is present */
	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
		vlan = (struct vlan_hdr *)(eth + 1);
		entry->encap_flag = NTS_ENCAP_VLAN_FLAG;
		entry->vlan_tci = vlan->vlan_tci;
		outer_ipv4_hdr = (struct ipv4_hdr*)
			((uint8_t*)outer_ipv4_hdr + sizeof(struct vlan_hdr));
	}
	*ipv4_header = outer_ipv4_hdr;
	outer_udp = (struct udp_hdr*)
		((uint32_t*)outer_ipv4_hdr + (*(uint8_t*)outer_ipv4_hdr & IPV4_HDR_IHL_MASK));

	ether_addr_copy(&eth->d_addr, &entry->dst_mac_addrs);
	ether_addr_copy(&eth->s_addr, &entry->src_mac_addrs);
	entry->dst_ip = outer_ipv4_hdr->dst_addr;
	entry->src_ip = outer_ipv4_hdr->src_addr;
	entry->dst_ip_port = outer_udp->dst_port;
	entry->src_ip_port = outer_udp->src_port;

	tuple->encap_flag = entry->encap_flag;
	tuple->inner_ip_src = (*ipv4_header)->src_addr;
	tuple->inner_ip_dst = (*ipv4_header)->dst_addr;
	tuple->inner_port_src = outer_udp->src_port;
	tuple->inner_port_dst = outer_udp->dst_port;
}

NES_STATIC inline void
nts_edit_hdr_vm_parse(struct ipv4_hdr *inner_ipv4_hdr, nis_acl_tuple_t* tuple) {
	assert(NULL != inner_ipv4_hdr);
	uint16_t* inner_src_port;

	inner_src_port = (uint16_t*)
		((uint32_t*)(inner_ipv4_hdr) + (*(uint8_t*)(inner_ipv4_hdr) & IPV4_HDR_IHL_MASK));

	tuple->proto = (inner_ipv4_hdr)->next_proto_id;
	tuple->inner_ip_src = (inner_ipv4_hdr)->src_addr;
	tuple->inner_ip_dst = (inner_ipv4_hdr)->dst_addr;
	tuple->tos = (inner_ipv4_hdr)->type_of_service;
	tuple->inner_port_src = *inner_src_port;
	tuple->inner_port_dst = *(inner_src_port + 1);
}

NES_STATIC inline int
nts_packet_edit_enq(nes_sq_t *entries, struct rte_mbuf *mbuf, routing_params_t *params,
	int is_upstream) {
	nes_sq_node_t *node;
	int retval = NES_FAIL;

	NES_SQ_FOREACH(node, entries) {
		nts_route_entry_t *entry = nes_sq_data(node);

		if (unlikely(NULL == entry->dst_ring)) {
			if (NULL != entry->ring_name) {
				if (NES_FAIL == nes_ring_find(&entry->dst_ring, entry->ring_name))
					continue;
			} else {
				struct ether_addr empty_mac;
				memset(&empty_mac, 0, sizeof(empty_mac));
				if (0 != memcmp(&entry->mac_addr, &empty_mac,
						sizeof(entry->mac_addr))) {
					struct mac_entry *data;
					if (NES_SUCCESS == nes_mac_lookup_entry_find(
							&entry->mac_addr, &data)) {
						entry->dst_ring = data->ring;
						entry->ring_name = data->ring_name;
					}
					if (NULL == entry->dst_ring)
						continue;
				}
			}
		}
		if (likely(NULL != entry->edit)) {
			if (unlikely(NES_FAIL == entry->edit(entry, mbuf, is_upstream,
					(void*) params)))
				continue;
		} else {
			if (unlikely(NULL == entry->dst_ring)) {
				NES_LOG(ERR, "Missing callback edit on routing entry %s.\n",
					(entry->ring_name != NULL) ? entry->ring_name : "NULL");
				continue;
			}
			entry->dst_ring->enq(entry->dst_ring, mbuf);
		}
		retval = NES_SUCCESS;
	}
	return retval;
}

NES_STATIC int
nts_flow_upstream_gtp(nes_ring_t *ingress_ring, void **buffer, int mbuf_num) {
	nts_enc_entry_t *entry;
	nts_enc_entry_t new_entry;
	nes_sq_t *route_entries[MAX_BURST_SIZE];
	struct ipv4_hdr *inner_ipv4_hdr;
	nts_acl_tuple_t tuples[MAX_BURST_SIZE];
	nts_acl_tuple_t * tuples_ptrs[MAX_BURST_SIZE];
	routing_params_t fwd_params[MAX_BURST_SIZE];
	int i;
	nts_lookup_tables_t *lookup = ingress_ring->routing_tables;
	struct rte_mbuf    **mbufs  = (struct rte_mbuf **)buffer;
	nes_ring_t *egress_ring = NULL;

	memset(&new_entry, 0, sizeof(new_entry));
	for (i = 0; i < mbuf_num; i++) {
		tuples_ptrs[i] = &tuples[i];
		nts_edit_hdr_parse_gtp(mbufs[i], &new_entry.upstream,
			&tuples[i], &inner_ipv4_hdr, NES_UPSTREAM);
		fwd_params[i].inner_ipv4_hdr = inner_ipv4_hdr;
		egress_ring = nes_dev_get_egressring_from_port_idx(mbufs[i]->port);

		fwd_params[i].egress_ring = egress_ring;
		new_entry.upstream.dst_ring = egress_ring;
		nes_lookup_entry_find(lookup->learning, &inner_ipv4_hdr->src_addr, (void**) &entry);
		if (NULL == entry) {
			nes_lookup_entry_add(lookup->learning,
				&inner_ipv4_hdr->src_addr, &new_entry);
		} else {
			rte_memcpy(&entry->upstream, &new_entry.upstream,
				sizeof (nts_enc_subentry_t));
		}
	}
	nes_acl_lookup(&nes_ctrl_acl_ctx, (const uint8_t**) tuples_ptrs,
		mbuf_num, (void**)route_entries);
	for (i = 0; i < mbuf_num; i++) {
		if (NULL != route_entries[i]) {
			if (NES_SUCCESS == nts_packet_edit_enq(route_entries[i],
					mbufs[i], &fwd_params[i], 1)) {
#ifdef MIRROR
				rte_pktmbuf_free(mbufs[i]);
#endif
				continue;
			}
		}
		egress_ring = fwd_params[i].egress_ring;
		if (NULL != egress_ring) {
			if (NES_SUCCESS != egress_ring->enq(egress_ring, mbufs[i]))
				rte_pktmbuf_free(mbufs[i]);
			continue;
		}
		rte_pktmbuf_free(mbufs[i]);
		NES_STATS_RING_UPDATE(1, ingress_ring->ring_stats->stats.drp_cnt_2);
	}

	return NES_SUCCESS;
}

NES_STATIC int
nts_flow_downstream_gtp(nes_ring_t *ingress_ring, void **buffer, int mbuf_num) {
	nts_enc_entry_t *entry;
	nts_enc_entry_t new_entry;
	nes_sq_t *route_entries[MAX_BURST_SIZE];
	struct ipv4_hdr *inner_ipv4_hdr;
	nts_acl_tuple_t tuples[MAX_BURST_SIZE];
	nts_acl_tuple_t * tuples_ptrs[MAX_BURST_SIZE];
	routing_params_t fwd_params[MAX_BURST_SIZE];
	int i;
	nts_lookup_tables_t *lookup = ingress_ring->routing_tables;
	struct rte_mbuf    **mbufs  = (struct rte_mbuf **)buffer;
	nes_ring_t *egress_ring = NULL;

	memset(&new_entry, 0, sizeof(new_entry));

	for (i = 0; i < mbuf_num; i++) {
		tuples_ptrs[i] = &tuples[i];
		nts_edit_hdr_parse_gtp(mbufs[i], &new_entry.downstream,
			&tuples[i], &inner_ipv4_hdr, NES_DOWNSTREAM);
		fwd_params[i].inner_ipv4_hdr = inner_ipv4_hdr;
		egress_ring = nes_dev_get_egressring_from_port_idx(mbufs[i]->port);
		fwd_params[i].egress_ring = egress_ring;
		new_entry.downstream.dst_ring = egress_ring;
		nes_lookup_entry_find(lookup->learning, &inner_ipv4_hdr->dst_addr, (void**) &entry);
		if (NULL == entry) {
			nes_lookup_entry_add(lookup->learning,
				&inner_ipv4_hdr->dst_addr, &new_entry);
		} else {
			rte_memcpy(&entry->downstream, &new_entry.downstream,
				sizeof (nts_enc_subentry_t));
		}
	}
	nes_acl_lookup(&nes_ctrl_acl_ctx, (const uint8_t**) tuples_ptrs,
		mbuf_num, (void**)route_entries);
	for (i = 0; i < mbuf_num; i++) {
		if (NULL != route_entries[i]) {
			if (NES_SUCCESS == nts_packet_edit_enq(route_entries[i],
					mbufs[i], &fwd_params[i], 0)) {
				rte_pktmbuf_free(mbufs[i]);
				continue;
			}
		}
		egress_ring = fwd_params[i].egress_ring;
		if (NULL != egress_ring) {
			if (NES_SUCCESS != egress_ring->enq(egress_ring, mbufs[i]))
				rte_pktmbuf_free(mbufs[i]);
			continue;
		}
		rte_pktmbuf_free(mbufs[i]);
		NES_STATS_RING_UPDATE(1, ingress_ring->ring_stats->stats.drp_cnt_2);
	}
	return NES_SUCCESS;
}

nes_ring_t *
nts_get_dst_ring(struct rte_mbuf *m, uint8_t is_gtp) {
	nts_acl_tuple_t tuple, *tuple_ptr = &tuple;
	struct ipv4_hdr *inner_ipv4_hdr;
	nes_sq_t *route_entry;
	nts_enc_entry_t ignored;

	if (is_gtp)
		nts_edit_hdr_parse_gtp(m, &ignored.upstream,
			&tuple, &inner_ipv4_hdr, NES_UPSTREAM);
	else
		nts_edit_hdr_parse_ip(m, &ignored.upstream, &tuple, &inner_ipv4_hdr);

	nes_acl_lookup(&nes_ctrl_acl_ctx, (const uint8_t **) &tuple_ptr,
		1, (void **)&route_entry);
	if (NULL == route_entry)
		return NULL;
	nts_route_entry_t *entry = nes_sq_data(nes_sq_head(route_entry));
	return entry->dst_ring;
}

NES_STATIC int
nts_flow_upstream_ip(nes_ring_t *ingress_ring, void **buffer, int mbuf_num) {
	nts_enc_entry_t *entry;
	nts_enc_entry_t new_entry;
	nes_sq_t *route_entries[MAX_BURST_SIZE];
	struct ipv4_hdr *inner_ipv4_hdr;
	nts_acl_tuple_t tuples[MAX_BURST_SIZE];
	nts_acl_tuple_t * tuples_ptrs[MAX_BURST_SIZE];
	routing_params_t fwd_params[MAX_BURST_SIZE];
	int i;
	nts_lookup_tables_t *lookup = ingress_ring->routing_tables;
	struct rte_mbuf    **mbufs  = (struct rte_mbuf **)buffer;
	nes_ring_t *egress_ring = NULL;

	memset(&new_entry, 0, sizeof(new_entry));
	for (i = 0; i < mbuf_num; i++) {
		tuples_ptrs[i] = &tuples[i];
		nts_edit_hdr_parse_ip(mbufs[i], &new_entry.upstream, &tuples[i], &inner_ipv4_hdr);
		fwd_params[i].inner_ipv4_hdr = inner_ipv4_hdr;
		egress_ring = nes_dev_get_egressring_from_port_idx(mbufs[i]->port);
		fwd_params[i].egress_ring = egress_ring;
		new_entry.upstream.dst_ring = egress_ring;
		nes_lookup_entry_find(lookup->learning, &inner_ipv4_hdr->src_addr, (void**) &entry);
		if (NULL == entry) {
			nes_lookup_entry_add(lookup->learning,
				&inner_ipv4_hdr->src_addr, &new_entry);
		} else {
			rte_memcpy(&entry->upstream, &new_entry.upstream,
				sizeof (nts_enc_subentry_t));
		}
	}
	nes_acl_lookup(&nes_ctrl_acl_ctx, (const uint8_t**) tuples_ptrs,
		mbuf_num, (void**)route_entries);
	for (i = 0; i < mbuf_num; i++) {
		if (NULL != route_entries[i]) {
			if (NES_SUCCESS == nts_packet_edit_enq(route_entries[i],
					mbufs[i], &fwd_params[i], 1)) {
#ifdef MIRROR
				rte_pktmbuf_free(mbufs[i]);
#endif
				continue;
			}
		}
		egress_ring = fwd_params[i].egress_ring;
		if (NULL != egress_ring) {
			if (NES_SUCCESS != egress_ring->enq(egress_ring, mbufs[i]))
				rte_pktmbuf_free(mbufs[i]);

			continue;
		}
		rte_pktmbuf_free(mbufs[i]);
		NES_STATS_RING_UPDATE(1, ingress_ring->ring_stats->stats.drp_cnt_2);
	}

	return NES_SUCCESS;
}

NES_STATIC int
nts_flow_downstream_ip(nes_ring_t *ingress_ring, void **buffer, int mbuf_num) {
	nts_enc_entry_t *entry;
	nts_enc_entry_t new_entry;
	nes_sq_t *route_entries[MAX_BURST_SIZE];
	struct ipv4_hdr *inner_ipv4_hdr;
	nts_acl_tuple_t tuples[MAX_BURST_SIZE];
	nts_acl_tuple_t * tuples_ptrs[MAX_BURST_SIZE];
	routing_params_t fwd_params[MAX_BURST_SIZE];
	int i;
	nts_lookup_tables_t *lookup = ingress_ring->routing_tables;
	struct rte_mbuf    **mbufs  = (struct rte_mbuf **)buffer;
	nes_ring_t *egress_ring = NULL;

	memset(&new_entry, 0, sizeof(new_entry));

	for (i = 0; i < mbuf_num; i++) {
		tuples_ptrs[i] = &tuples[i];
		nts_edit_hdr_parse_ip(mbufs[i], &new_entry.downstream, &tuples[i], &inner_ipv4_hdr);
		fwd_params[i].inner_ipv4_hdr = inner_ipv4_hdr;
		egress_ring = nes_dev_get_egressring_from_port_idx(mbufs[i]->port);

		fwd_params[i].egress_ring = egress_ring;
		new_entry.downstream.dst_ring = egress_ring;
		nes_lookup_entry_find(lookup->learning, &inner_ipv4_hdr->dst_addr, (void**) &entry);
		if (NULL == entry) {
			nes_lookup_entry_add(lookup->learning,
				&inner_ipv4_hdr->dst_addr, &new_entry);
		} else {
			rte_memcpy(&entry->downstream, &new_entry.downstream,
				sizeof (nts_enc_subentry_t));
		}
	}
	nes_acl_lookup(&nes_ctrl_acl_ctx, (const uint8_t**) tuples_ptrs,
		mbuf_num, (void**)route_entries);
	for (i = 0; i < mbuf_num; i++) {
		if (NULL != route_entries[i]) {
			if (NES_SUCCESS == nts_packet_edit_enq(route_entries[i],
					mbufs[i], &fwd_params[i], 0)) {
				rte_pktmbuf_free(mbufs[i]);
				continue;
			}
		}
		egress_ring = fwd_params[i].egress_ring;
		if (NULL != egress_ring) {
			if (NES_SUCCESS != egress_ring->enq(egress_ring, mbufs[i]))
				rte_pktmbuf_free(mbufs[i]);

			continue;
		}
		rte_pktmbuf_free(mbufs[i]);
		NES_STATS_RING_UPDATE(1, ingress_ring->ring_stats->stats.drp_cnt_2);
	}
	return NES_SUCCESS;
}


NES_STATIC inline
ip_head_t *nts_packet_flow_encap_ip(struct rte_mbuf *mbuf, const nts_enc_subentry_t *encap_data)
{
	ip_head_t *pkt_header;
	struct ether_hdr * eth_header;

	if (NTS_ENCAP_VLAN_FLAG & encap_data->encap_flag) {
		struct vlan_hdr * vlan_header;
		pkt_header = (ip_head_t *)rte_pktmbuf_prepend(mbuf, sizeof(struct vlan_hdr));
		if (NULL == pkt_header)
			return NULL;

		eth_header = &pkt_header->ip_vlan.ether_hdr;
		vlan_header = &pkt_header->ip_vlan.vlan_hdr;
		eth_header->ether_type = HTONS(ETHER_TYPE_VLAN);
		vlan_header->vlan_tci = encap_data->vlan_tci;
		vlan_header->eth_proto= HTONS(ETHER_TYPE_IPv4);
	} else {
		pkt_header = rte_pktmbuf_mtod(mbuf, ip_head_t *);
		if (NULL == pkt_header)
			return NULL;

		eth_header = &pkt_header->ip_no_vlan.ether_hdr;
		eth_header->ether_type = HTONS(ETHER_TYPE_IPv4);
	}
	ether_addr_copy(&encap_data->dst_mac_addrs, &eth_header->d_addr);
	ether_addr_copy(&encap_data->src_mac_addrs, &eth_header->s_addr);

	return pkt_header;
}

NES_STATIC inline
gtpu_head_t *nts_packet_flow_encap_gtpu(struct rte_mbuf *mbuf,
	const nts_enc_subentry_t *encap_data, const nis_param_rab_t *teid_entry)
{

	struct outer_ip_pkt_head {
		struct ipv4_hdr outer_ipv4_hdr;
		struct udp_hdr outer_udp_hdr;
		gtpuHdr_t gtpu_hdr;
	};

	gtpu_head_t *pkt_header;
	struct outer_ip_pkt_head * outer_ip_pkt_header;
	struct ether_hdr * eth_header;
	uint16_t pkt_len, vlan_len;
	const size_t gtpu_tunnel_len = sizeof (struct ipv4_hdr) +
		sizeof (struct udp_hdr) +
		sizeof (gtpuHdr_t);

	if (NTS_ENCAP_VLAN_FLAG & encap_data->encap_flag) {
		vlan_len = sizeof(struct vlan_hdr);
		pkt_header = (gtpu_head_t *)rte_pktmbuf_prepend(mbuf,
				vlan_len + gtpu_tunnel_len);
		if (NULL == pkt_header)
			return NULL;

		eth_header = &pkt_header->gtpu_vlan.outer_ether_hdr;
		eth_header->ether_type = HTONS(ETHER_TYPE_VLAN);
		pkt_header->gtpu_vlan.outer_vlan_hdr.vlan_tci = encap_data->vlan_tci;
		pkt_header->gtpu_vlan.outer_vlan_hdr.eth_proto= HTONS(ETHER_TYPE_IPv4);
		outer_ip_pkt_header = (struct outer_ip_pkt_head *)
			&pkt_header->gtpu_vlan.outer_ipv4_hdr;
	} else {
		vlan_len = 0;
		pkt_header = (gtpu_head_t *)rte_pktmbuf_prepend(mbuf, gtpu_tunnel_len);
		if (NULL == pkt_header)
			return NULL;

		eth_header = &pkt_header->gtpu_no_vlan.outer_ether_hdr;
		eth_header->ether_type = HTONS(ETHER_TYPE_IPv4);
		outer_ip_pkt_header = (struct outer_ip_pkt_head *)
			&pkt_header->gtpu_no_vlan.outer_ipv4_hdr;
	}

	// Increase l3_len to avoid any offload issues
	mbuf->l3_len += gtpu_tunnel_len;
	pkt_len = mbuf->pkt_len;

	ether_addr_copy(&encap_data->dst_mac_addrs, &eth_header->d_addr);
	ether_addr_copy(&encap_data->src_mac_addrs, &eth_header->s_addr);

	outer_ip_pkt_header->outer_ipv4_hdr.version_ihl     =
		(sizeof (struct ipv4_hdr) / IPV4_IHL_MULTIPLIER) | 0x40;
	outer_ip_pkt_header->outer_ipv4_hdr.packet_id       = 0x00;
	outer_ip_pkt_header->outer_ipv4_hdr.fragment_offset = 0;
	outer_ip_pkt_header->outer_ipv4_hdr.time_to_live    = 0xFF;
	outer_ip_pkt_header->outer_ipv4_hdr.next_proto_id   = IP_PROTO_UDP;
	outer_ip_pkt_header->outer_ipv4_hdr.hdr_checksum    = 0;
	outer_ip_pkt_header->outer_ipv4_hdr.total_length    =
		HTONS(pkt_len - sizeof (struct ether_hdr) - vlan_len);
	outer_ip_pkt_header->outer_ipv4_hdr.src_addr        = encap_data->src_ip;
	outer_ip_pkt_header->outer_ipv4_hdr.dst_addr        = encap_data->dst_ip;

	outer_ip_pkt_header->outer_udp_hdr.dgram_cksum = 0;
	outer_ip_pkt_header->outer_udp_hdr.src_port    = encap_data->src_ip_port;
	outer_ip_pkt_header->outer_udp_hdr.dst_port    = encap_data->dst_ip_port;
	outer_ip_pkt_header->outer_udp_hdr.dgram_len   = HTONS(pkt_len -
		sizeof (struct ether_hdr) -
		vlan_len -
		sizeof (struct ipv4_hdr));

	outer_ip_pkt_header->gtpu_hdr.npdu_flag   = 0;
	outer_ip_pkt_header->gtpu_hdr.seqnum_flag = 0;
	outer_ip_pkt_header->gtpu_hdr.exthdr_flag = 0;
	outer_ip_pkt_header->gtpu_hdr.reserved    = 0;
	outer_ip_pkt_header->gtpu_hdr.pt          = 1;
	outer_ip_pkt_header->gtpu_hdr.version     = 1;
	outer_ip_pkt_header->gtpu_hdr.msg_type    = GTPU_MSG_GPDU;
	outer_ip_pkt_header->gtpu_hdr.length      = HTONS(pkt_len -
		sizeof (struct ether_hdr) -
		vlan_len -
		sizeof (struct ipv4_hdr) -
		sizeof (struct udp_hdr) -
		sizeof (gtpuHdr_t));

	outer_ip_pkt_header->gtpu_hdr.teid = teid_entry != NULL ?
		teid_entry->teid : encap_data->teid;

	outer_ip_pkt_header->outer_ipv4_hdr.hdr_checksum =
		rte_ipv4_cksum(&outer_ip_pkt_header->outer_ipv4_hdr);

	return pkt_header;
}

NES_STATIC int
nts_flow_vm(nes_ring_t *ingress_ring, void **buffer, int mbuf_num) {
	struct ipv4_hdr *header;
	int i;
	nts_lookup_tables_t *lookup = ingress_ring->routing_tables;
	struct rte_mbuf    **mbufs  = (struct rte_mbuf **)buffer;

	assert(MAX_BURST_SIZE >= mbuf_num);

	nis_acl_tuple_t teid_keys[MAX_BURST_SIZE];
	nis_acl_tuple_t *teid_keys_ptrs[MAX_BURST_SIZE] = {NULL};
	nis_param_rab_t *teid_entries[MAX_BURST_SIZE] = {NULL};

	uint32_t * keys[2 * MAX_BURST_SIZE] = {NULL};
	nts_enc_entry_t * ueip_results[2 * MAX_BURST_SIZE] = {NULL};

	for (i = 0; i < mbuf_num; i++) {
		header = nts_edit_get_outer_ipv4_hdr(mbufs[i]);
		keys[2 * i] = &header->src_addr;
		keys[2 * i + 1] = &header->dst_addr;
		teid_keys_ptrs[i] = &teid_keys[i];
		nts_edit_hdr_vm_parse(header, teid_keys_ptrs[i]);
	}

	/*
	 * Even entries contain source IP addresses, i.e. if lookup is successful,
	 * UE IP is a source IP and packet must be tranmitted upstream
	 * Odd entries contain destination IP addresses, i.e. if lookup is successful,
	 * UE IP is a destination IP and packet must be transmitted downstream.
	 */
	if (NES_FAIL == nes_lookup_bulk_get(lookup->learning, conv_ptr_to_const(keys),
			2 * mbuf_num, (void **) ueip_results)) {
		NES_LOG(ERR, "Lookup in learning table failed.\n");
		goto exit_nts_flow_vm;
	}

	/* Try to get TEID from lookup. If fails - use cached entries */
	nes_acl_lookup(&nis_param_acl_ctx, (const uint8_t **) teid_keys_ptrs,
		mbuf_num, (void **) teid_entries);

	for (i = 0; i < 2 * mbuf_num; i += 2) {
		int idx = i / 2;
		nts_enc_subentry_t *encap_subentry;
		pkt_head_t    *pkt_header;
		nes_ring_t         *egress_ring;

		/* Both match - UE to UE? DROP */
		if (NULL != ueip_results[i] && NULL != ueip_results[i + 1]) {
			rte_pktmbuf_free(mbufs[idx]);
			continue;
		}

		if (NULL != ueip_results[i]) {
			/* Upstream */
			encap_subentry = &ueip_results[i]->upstream;
			egress_ring    = encap_subentry->dst_ring;
		}
		else if (NULL != ueip_results[i + 1]) {
			/* Downstream */
			encap_subentry = &ueip_results[i + 1]->downstream;
			egress_ring    = encap_subentry->dst_ring;
		} else {
			/* Drop - unable to determine direction */
			rte_pktmbuf_free(mbufs[idx]);
			NES_STATS_RING_UPDATE(1, ingress_ring->ring_stats->stats.drp_cnt_2);
			continue;
		}

		if (NTS_ENCAP_GTPU_FLAG & encap_subentry->encap_flag) {
			/* GTP-u traffic*/
			pkt_header = (pkt_head_t *)
				nts_packet_flow_encap_gtpu(mbufs[idx], encap_subentry,
					teid_entries[idx]);
		} else {
			/* IP traffic*/
			pkt_header = (pkt_head_t *)
				nts_packet_flow_encap_ip(mbufs[idx], encap_subentry);
		}
		if (NULL == pkt_header || NULL == egress_ring) {
			rte_pktmbuf_free(mbufs[idx]);
			NES_STATS_RING_UPDATE(1, ingress_ring->ring_stats->stats.drp_cnt_2);
			continue;
		}

		if (NES_SUCCESS != egress_ring->enq(egress_ring, mbufs[idx]))
			rte_pktmbuf_free(mbufs[idx]);
	}
	return NES_SUCCESS;

exit_nts_flow_vm:
	for (i = 0; i < mbuf_num; i++) {
		rte_pktmbuf_free(mbufs[i]);
		NES_STATS_RING_UPDATE(mbuf_num, ingress_ring->ring_stats->stats.drp_cnt_2);
	}
	return NES_FAIL;
}

#define NTS_UPSTR_GTP   "NTS_UPSTR_GTPU"
#define NTS_DWSTR_GTP   "NTS_DWSTR_GTPU"
#define NTS_UPSTR_IP    "NTS_UPSTR_IP"
#define NTS_DWSTR_IP    "NTS_DWSTR_IP"
#define NTS_LBP_PREFIX  "NTS_LBP"
#define NTS_VM_PREFIX   "NTS_VM"
#define NTS_KNI_PREFIX  "NTS_KNI"
#define NTS_AVP_PREFIX  "NTS_AVP"

int
nts_edit_ring_flow_set(nes_ring_t *ring) {
	char *ring_name = nes_ring_name(ring);

	if (0 == strncmp(ring_name, NTS_DWSTR_GTP, sizeof(NTS_DWSTR_GTP) - 1))
		ring->flow = nts_flow_downstream_gtp;
	else if (0 == strncmp(ring_name, NTS_UPSTR_GTP, sizeof(NTS_UPSTR_GTP) - 1))
		ring->flow = nts_flow_upstream_gtp;
	else if (0 == strncmp(ring_name, NTS_DWSTR_IP, sizeof(NTS_DWSTR_IP) - 1))
		ring->flow = nts_flow_downstream_ip;
	else if (0 == strncmp(ring_name, NTS_UPSTR_IP, sizeof(NTS_UPSTR_IP) - 1))
		ring->flow = nts_flow_upstream_ip;
	else if (0 == strncmp(ring_name, NTS_LBP_PREFIX, sizeof(NTS_LBP_PREFIX) - 1) ||
			0 == strncmp(ring_name, NTS_VM_PREFIX,  sizeof(NTS_VM_PREFIX) - 1) ||
			0 == strncmp(ring_name, NTS_KNI_PREFIX, sizeof(NTS_KNI_PREFIX) - 1) ||
			0 == strncmp(ring_name, NTS_AVP_PREFIX, sizeof(NTS_AVP_PREFIX) - 1))
		ring->flow = nts_flow_vm;

	return NULL == ring->flow ? NES_FAIL : NES_SUCCESS;
}

#define TCP_HDR_DATA_OFF_MASK   ((uint8_t)0xf)
#define TCP_DATA_OFF_MULTIPLIER (32/8)

NES_STATIC int
nts_edit_nodecap(nts_route_entry_t *self, struct rte_mbuf *src_mbuf,
	__attribute__((unused)) int is_upstream, __attribute__((unused)) void *ptr) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(src_mbuf, struct ether_hdr *);

	if (unlikely(NULL == eth_hdr))
		return NES_FAIL;

	ether_addr_copy(&self->mac_addr,&eth_hdr->d_addr);
	return self->dst_ring->enq(self->dst_ring, src_mbuf);
}

NES_STATIC int
nts_edit_decap(nts_route_entry_t *self, struct rte_mbuf *src_mbuf,
	__attribute__((unused)) int is_upstream, void *ptr) {
#ifndef MIRROR
	routing_params_t *params = ptr;
	struct ipv4_hdr *ip_hdr;
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(src_mbuf, struct ether_hdr *);
	uint16_t adj_len = (uint16_t)((uint8_t *)params->inner_ipv4_hdr - (uint8_t *)(eth_hdr + 1));
	rte_memcpy((uint8_t *)params->inner_ipv4_hdr - sizeof(struct ether_hdr),
		(uint8_t *)(eth_hdr), sizeof(struct ether_hdr));
	eth_hdr = (struct ether_hdr *)rte_pktmbuf_adj(src_mbuf, adj_len);
	if (unlikely(NULL == eth_hdr))
		return NES_FAIL;

	ether_addr_copy(&self->mac_addr,&eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	if (unlikely(src_mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
		ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		ip_hdr->hdr_checksum = 0;
	}

	return self->dst_ring->enq(self->dst_ring, src_mbuf);
#else
	routing_params_t *params = ptr;
	struct ether_hdr *new_ethhdr, *ethhdr;
	struct ipv4_hdr *new_iphdr, *iphdr;
	struct tcp_hdr *tcphdr;
	struct rte_mbuf *hdr;
	struct rte_mbuf *mbuf;
	uintptr_t l3_hdr_len, l4_hdr_len, adj_len, l4_hdr;

	/* Original Ethernet header */
	ethhdr = rte_pktmbuf_mtod(src_mbuf, struct ether_hdr *);
	/* Original inner ipv4 header*/
	iphdr = params->inner_ipv4_hdr;
	l3_hdr_len = (iphdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
	/* Original inner Layer 4 header */
	l4_hdr = (uintptr_t) iphdr + l3_hdr_len;

	/* Calculate L4 header length in bytes */
	switch (iphdr->next_proto_id) {
	case IP_PROTO_ICMP:
	case IP_PROTO_UDP:
		l4_hdr_len = 8;
		break;
	case IP_PROTO_TCP:
		tcphdr = (struct tcp_hdr *) l4_hdr;
		l4_hdr_len = (tcphdr->data_off & TCP_HDR_DATA_OFF_MASK);
		/* Ensure: 5 <= l4_hdr_len <= 15 */
		l4_hdr_len = (l4_hdr_len < 5 ? 5 : l4_hdr_len);
		/* Now convert it from words to bytes */
		l4_hdr_len *= TCP_DATA_OFF_MULTIPLIER;
		break;
	default:
		NES_LOG(ERR, "Unsupported protocol %d.\n", iphdr->next_proto_id);
		return NES_FAIL;
	}

	hdr = rte_pktmbuf_alloc(header_pool);
	if (unlikely(NULL == hdr)) {
		NES_LOG(ERR, "No free mbufs in headers pool.\n");
		return NES_FAIL;
	}
	mbuf = rte_pktmbuf_clone(src_mbuf, clone_pool);
	if (unlikely(NULL == mbuf)) {
		NES_LOG(ERR, "No free mbufs in clones pools.\n");
		rte_pktmbuf_free(hdr);
		return NES_FAIL;
	}

	/* Create new header - make room for it in header mbuf */
	new_ethhdr = (struct ether_hdr *) rte_pktmbuf_prepend(hdr,
			(uint16_t)sizeof (*new_ethhdr) +
			(uint16_t) l3_hdr_len +
			(uint16_t) l4_hdr_len);

	if (unlikely(NULL == new_ethhdr)) {
		rte_pktmbuf_free(hdr);
		return NES_FAIL;
	}
	/* First create new Ethernet header */
	ether_addr_copy(&self->mac_addr, &new_ethhdr->d_addr);
	ether_addr_copy(&ethhdr->s_addr, &new_ethhdr->s_addr);
	new_ethhdr->ether_type = ethhdr->ether_type;
	/* Then new IP/(ICMP|UDP|TCP) header */
	new_iphdr = (struct ipv4_hdr *) (new_ethhdr + 1);
	rte_memcpy(new_iphdr, iphdr, l3_hdr_len + l4_hdr_len);

	/*
	 *  DECAPSULATE cloned IP packet
	 */
	/* First find offset to inner IP header */
	adj_len = (uintptr_t) iphdr - (uintptr_t) ethhdr;
	/* Next add IP/IP/(ICMP|UDP|TCP) header length */
	adj_len += l3_hdr_len;
	adj_len += l4_hdr_len;
	/* Now adjust */
	ethhdr = (struct ether_hdr *) rte_pktmbuf_adj(mbuf, (uint16_t) adj_len);
	/* A cloned mbuf contains only payload (L5 and up) */

	/*
	 * Here all the data for new mbuf chain are edited, while src_mbuf stays untouched.
	 * Time to create the chain hdr->mbuf
	 */
	hdr->next = mbuf;
	hdr->pkt_len = (uint16_t) (hdr->data_len + mbuf->pkt_len);
	hdr->nb_segs = (uint8_t) (mbuf->nb_segs + 1);
	/* Copy metadata from source packet */
	hdr->port = mbuf->port;
	hdr->vlan_tci = mbuf->vlan_tci;
	hdr->tx_offload = mbuf->tx_offload;
	hdr->hash = mbuf->hash;
	hdr->ol_flags = mbuf->ol_flags;

	__rte_mbuf_sanity_check(hdr, 1);

	if (unlikely(NES_FAIL == self->dst_ring->enq(self->dst_ring, hdr))) {
		rte_pktmbuf_free(hdr);
		return NES_FAIL;
	}
	return NES_SUCCESS;
#endif
}

#ifdef MIRROR
static int
nts_edit_mirror_last(__attribute__((unused))nts_route_entry_t *self, struct rte_mbuf *mbuf,
	int is_upstream, __attribute__((unused))void *ptr) {
	nes_ring_t *dst_ring = is_upstream ? nes_io_epc_ring : nes_io_enb_ring;
	rte_mbuf_refcnt_update(mbuf, 1);

#ifdef MIRROR_DECAP
	if (NES_SUCCESS != nts_edit_decap(self, mbuf, is_upstream, ptr)) {
		rte_pktmbuf_free(mbuf);
		return NES_FAIL;
	}
#else
	rte_mbuf_refcnt_update(mbuf, 1);
	if (unlikely(NES_FAIL == self->dst_ring->enq(self->dst_ring, mbuf)))
		rte_pktmbuf_free(mbuf);

#endif // MIRROR_DECAP

	if (unlikely(NES_FAIL == dst_ring->enq(dst_ring, mbuf))) {
		rte_pktmbuf_free(mbuf);
		return NES_FAIL;
	}
	return NES_SUCCESS;
}
#endif // MIRROR

#ifdef MIRROR
static int
nts_edit_mirror(__attribute__((unused))nts_route_entry_t *self, struct rte_mbuf *mbuf,
	int is_upstream, __attribute__((unused))void *ptr) {

#ifdef MIRROR_DECAP
	if (NES_SUCCESS != nts_edit_decap(self, mbuf, is_upstream, ptr)) {
		rte_pktmbuf_free(mbuf);
		return NES_FAIL;
	}
#else
	(void)is_upstream;
	rte_mbuf_refcnt_update(mbuf, 1);
	if (unlikely(NES_FAIL == self->dst_ring->enq(self->dst_ring, mbuf)))
		rte_pktmbuf_free(mbuf);

#endif // MIRROR_DECAP
	return NES_SUCCESS;
}
#endif // MIRROR

int
nts_route_entry_edit_get(nts_route_entry_t *entry)
{
	if (nts_edit_decap == entry->edit)
		return NTS_EDIT_DECAP_ONLY;

#ifdef MIRROR
	if (nts_edit_mirror == entry->edit)
		return NTS_EDIT_MIRROR;
	if (nts_edit_mirror_last == entry->edit)
		return NTS_EDIT_MIRROR_LAST;
#endif // MIRROR
	return -1;
}

int
nts_route_entry_edit_set(nts_route_entry_t *entry, nts_edit_modes_t mode) {
	switch (mode) {
	case NTS_EDIT_NULL_CALLBACK:
		entry->edit = NULL;
		break;
	case NTS_EDIT_DECAP_ONLY:
		entry->edit = nts_edit_decap;
		break;
	case NTS_EDIT_NODECAP:
		entry->edit = nts_edit_nodecap;
		break;
#ifdef MIRROR
	case NTS_EDIT_MIRROR:
		entry->edit = nts_edit_mirror;
		break;
	case NTS_EDIT_MIRROR_LAST:
		entry->edit = nts_edit_mirror_last;
		break;
#endif // MIRROR
	default:
		NES_LOG(ERR, "trying to set unknown edit callback.\n");
		return NES_FAIL;
	}
	return NES_SUCCESS;
}
