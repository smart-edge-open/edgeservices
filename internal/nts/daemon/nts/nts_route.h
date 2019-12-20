/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_route.h
 * @brief Routing related definitions
 */

#ifndef _NTS_ROUTE_H_
#define _NTS_ROUTE_H_

#ifdef __cpluplus
extern "C" {
#endif

#include <rte_mbuf.h>
#include "nes_ring.h"

#define NTS_ENCAP_VLAN_FLAG (1<<0)
#define NTS_ENCAP_GTPU_FLAG (1<<1)

	typedef struct nts_route_entry_s {
		const char *ring_name;
		nes_ring_t *dst_ring;
		uint32_t    ip_addr;
		struct ether_addr mac_addr;
		int (*edit)(struct nts_route_entry_s *, struct rte_mbuf *, int, void *);
	} nts_route_entry_t;

	typedef struct nts_enc_subentry_s {
		struct ether_addr dst_mac_addrs;
		struct ether_addr src_mac_addrs;
		uint32_t           ue_ip;
		uint32_t           dst_ip;
		uint32_t           src_ip;
		uint16_t           dst_ip_port;
		uint16_t           src_ip_port;
		uint32_t           teid;
		uint8_t            encap_flag;
		uint16_t           vlan_tci;
		nes_ring_t         *dst_ring;
	} nts_enc_subentry_t;

	typedef struct nts_enc_entry_s {
		nts_enc_subentry_t upstream;
		nts_enc_subentry_t downstream;
	} nts_enc_entry_t;

#ifdef __cpluplus
}
#endif

#endif /* _NTS_ROUTE_H_ */
