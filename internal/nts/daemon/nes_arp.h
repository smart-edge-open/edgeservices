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
 * @file nes_arp.h
 * @brief Header file for nes_arp
 *
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
