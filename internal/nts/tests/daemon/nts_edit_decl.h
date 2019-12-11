/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NTS_EDIT_DECL_H
#define	NTS_EDIT_DECL_H

#ifndef FILE_NAME
	#define FILE_NAME nts_edit
#endif
#include "mock.h"

struct routing_params_s;
typedef struct routing_params_s routing_params_t;

struct nis_acl_tuple_s;
typedef struct nis_acl_tuple_s nis_acl_tuple_t;

struct nis_param_rab_s;
typedef struct nis_param_rab_s nis_param_rab_t;

inline struct ipv4_hdr* nts_edit_get_outer_ipv4_hdr(struct rte_mbuf *pkt);
inline struct ipv4_hdr* nts_edit_get_inner_ipv4_hdr(struct rte_mbuf *pkt);
inline void nts_edit_hdr_parse_ip(struct rte_mbuf *pkt, nts_enc_subentry_t *entry,
	nts_acl_tuple_t* tuple, struct ipv4_hdr **inner_ipv4_hdr);
inline void nts_edit_hdr_parse_gtp(struct rte_mbuf *pkt, nts_enc_subentry_t *entry,
	nts_acl_tuple_t* tuple, struct ipv4_hdr **inner_ipv4_hdr, nes_direction_t direction);
inline void nts_edit_hdr_vm_parse(struct ipv4_hdr *inner_ipv4_hdr, nis_acl_tuple_t* tuple);
inline int nts_packet_edit_enq(nes_sq_t *entries, struct rte_mbuf *mbuf,
	routing_params_t *params, int is_upstream);
int nts_flow_upstream_ip(nes_ring_t *ingress_ring, void **buffer, int mbuf_num);
int nts_flow_upstream_gtp(nes_ring_t *ingress_ring, void **buffer, int mbuf_num);
int nts_flow_downstream_ip(nes_ring_t *ingress_ring, void **buffer, int mbuf_num);
int nts_flow_downstream_gtp(nes_ring_t *ingress_ring, void **buffer, int mbuf_num);
inline ip_head_t *nts_packet_flow_encap_ip(struct rte_mbuf *mbuf,
	const nts_enc_subentry_t *encap_data);
inline gtpu_head_t *nts_packet_flow_encap_gtpu(struct rte_mbuf *mbuf,
	const nts_enc_subentry_t *encap_data, const nis_param_rab_t *teid_entry);
int nts_flow_vm(nes_ring_t *ingress_ring, void **buffer, int mbuf_num);
int nts_edit_decap(nts_route_entry_t *self, struct rte_mbuf *src_mbuf,
	__attribute__((unused)) int is_upstream, void *ptr);
int nts_edit_nodecap(nts_route_entry_t *self, struct rte_mbuf *src_mbuf,
	__attribute__((unused)) int is_upstream, __attribute__((unused)) void *ptr);
//MOCK_DECL(rte_mempool_create);
//#define rte_mempool_create MOCK_NAME(mocked_rte_mempool_create)

MOCK_DECL(nis_routing_data_get);
#define nis_routing_data_get MOCK_NAME(mocked_nis_routing_data_get)

MOCK_DECL(nes_ring_find);
#define nes_ring_find MOCK_NAME(mocked_nes_ring_find)

MOCK_DECL(nes_lookup_entry_find);
#define nes_lookup_entry_find MOCK_NAME(mocked_nes_lookup_entry_find)

MOCK_DECL(nes_lookup_entry_add);
#define nes_lookup_entry_add MOCK_NAME(mocked_nes_lookup_entry_add)

MOCK_DECL(nes_acl_lookup);
#define nes_acl_lookup MOCK_NAME(mocked_nes_acl_lookup)

MOCK_DECL(nes_lookup_bulk_get);
#define nes_lookup_bulk_get MOCK_NAME(mocked_nes_lookup_bulk_get)

#endif	/* NTS_EDIT_DECL_H */
