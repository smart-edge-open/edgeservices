/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_arp.h
 * @brief Header file for nes_arp
 */

#ifndef NES_ARP_H
#define	NES_ARP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <rte_ether.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define HTYPE_ETHER 1

typedef struct arp_header_ipv4_s {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper;
	struct ether_addr sha;
	uint32_t spa;
	struct ether_addr tha;
	uint32_t tpa;
} __attribute__((__packed__))arp_header_ipv4_t;

int nes_arp_response(struct rte_mbuf *m, struct ether_addr eth_addr);

#ifdef	__cplusplus
}
#endif

#endif	/* NES_ARP_H */
