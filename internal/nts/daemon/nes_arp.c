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
 * @file nes_arp.c
 * @brief implementation of nes_arp
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>

#include "nes_arp.h"
#include "nes_common.h"

int
nes_arp_response(struct rte_mbuf *m, struct ether_addr eth_addr) {
	assert(m);
	uint32_t tmp_ip;

	struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	arp_header_ipv4_t *arp_r = (arp_header_ipv4_t *) (eth + 1);
	if (rte_cpu_to_be_16(HTYPE_ETHER) != arp_r->htype ||
			rte_cpu_to_be_16(ETHER_TYPE_IPv4) != arp_r->ptype ||
			rte_cpu_to_be_16(ARP_REQUEST) != arp_r->oper)
		return NES_FAIL;

	// reuse original mbuf to create the response
	ether_addr_copy(&arp_r->sha, &eth->d_addr);
	ether_addr_copy(&eth_addr, &eth->s_addr);

	arp_r->oper = rte_cpu_to_be_16(ARP_REPLY);
	tmp_ip = arp_r->tpa;
	arp_r->tpa = arp_r->spa;
	ether_addr_copy(&arp_r->sha, &arp_r->tha);
	arp_r->spa = tmp_ip;
	ether_addr_copy(&eth_addr, &arp_r->sha);

	return NES_SUCCESS;
}
