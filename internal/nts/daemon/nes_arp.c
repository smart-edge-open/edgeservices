/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

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
