/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_edit.h
 * @brief Header file for nts_edit
 */

#ifndef _NTS_EDIT_H_
#define _NTS_EDIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_udp.h>

#include "io/nes_dev.h"
#include "nts/nts_lookup.h"
#include "nes_ring.h"
#include "nts/nts_route.h"

typedef enum {
	GTPU_MSG_ECHO_REQUEST     = 1,
	GTPU_MSG_ECHO_RESPONSE    = 2,
	GTPU_MSG_ERROR_INDICATION = 26,
	/* Should be Supported Extension Header Notification */
	GTPU_MSG_SEH_NOTIFICATION = 31,
	GTPU_MSG_END_MARKER       = 254,
	GTPU_MSG_GPDU             = 255,
} gtpu_msgtype_t;

typedef struct gtpuHdr_s {
	uint8_t npdu_flag     : 1;
	uint8_t seqnum_flag   : 1;
	uint8_t exthdr_flag   : 1;
	uint8_t reserved      : 1;
	uint8_t pt            : 1;
	uint8_t version       : 3;
	uint8_t  msg_type; /* Must be uint8 - enum is mapped to int */
	uint16_t length;
	uint32_t teid;
} __attribute__ ((__packed__)) gtpuHdr_t;

typedef struct gtpuHdrOpt_s {
	/* Optional GTP-U header fields */
	uint16_t seq_num;
	uint8_t  npdu;
	uint8_t  next;
} __attribute__ ((__packed__)) gtpuHdrOpt_t;

typedef struct gtpu_pkt_head_s
{
	struct ether_hdr outer_ether_hdr;
	struct ipv4_hdr outer_ipv4_hdr;
	struct udp_hdr outer_udp_hdr;
	gtpuHdr_t gtpu_hdr;
} __attribute__ ((__packed__)) gtpu_pkt_head_t;

typedef struct gtpu_pkt_head_vlan_s
{
	struct ether_hdr outer_ether_hdr;
	struct vlan_hdr outer_vlan_hdr;
	struct ipv4_hdr outer_ipv4_hdr;
	struct udp_hdr outer_udp_hdr;
	gtpuHdr_t gtpu_hdr;
} __attribute__ ((__packed__)) gtpu_pkt_head_vlan_t;

typedef union gtpu_head_s
{
	gtpu_pkt_head_t gtpu_no_vlan;
	gtpu_pkt_head_vlan_t gtpu_vlan;
} gtpu_head_t;

typedef struct ip_pkt_head_s
{
	struct ether_hdr ether_hdr;
	struct ipv4_hdr ipv4_hdr;
	struct udp_hdr udp_hdr;

} __attribute__ ((__packed__)) ip_pkt_head_t;

typedef struct ip_pkt_head_vlan_s
{
	struct ether_hdr ether_hdr;
	struct vlan_hdr vlan_hdr;
	struct ipv4_hdr ipv4_hdr;
	struct udp_hdr udp_hdr;
} __attribute__ ((__packed__)) ip_pkt_head_vlan_t;

typedef union ip_head_s
{
	ip_pkt_head_t ip_no_vlan;
	ip_pkt_head_vlan_t ip_vlan;
} ip_head_t;

typedef union pkt_head_s
{
	ip_head_t ip_head;
	gtpu_head_t gtpu_head;
} pkt_head_t;

#include "nts/nts_acl_cfg.h"

int nts_edit_ring_flow_set(nes_ring_t *ring);

int nts_edit_init(void);

int nts_route_entry_edit_set(nts_route_entry_t *, nts_edit_modes_t);

int nts_route_entry_edit_get(nts_route_entry_t *entry);

nes_ring_t *nts_get_dst_ring(struct rte_mbuf *m, uint8_t is_gtp);

#ifdef __cplusplus
}
#endif

#endif /* _NTS_EDIT_H_ */
