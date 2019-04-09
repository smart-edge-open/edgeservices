/*******************************************************************************
* Copyright 2019 Intel Corporation. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

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
