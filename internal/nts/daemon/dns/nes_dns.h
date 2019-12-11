/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dns.h
 * @brief Header file for nes_dns
 */

#ifndef NES_DNS_AGENT_H
#define	NES_DNS_AGENT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "nts/nts_acl.h"

#define DNS_AGENT_LOCAL_DNS_IP "local-ip"
#define DNS_AGENT_LOCAL_DNS_MAC "local-mac"
#define DNS_AGENT_EXTERNAL_DNS_GW_MAC "external-dns-gw-mac"
#define DNS_AGENT_EXTERNAL_DNS_IP "external-ip"
#define DNS_AGENT_FORWARD_UNRESOLVED "forward-unresolved"

typedef struct dns_header_s {
	uint16_t id;

	// Little endian order
	uint8_t rd : 1;
	uint8_t tc : 1;
	uint8_t aa : 1;
	uint8_t opcode : 4;
	uint8_t qr : 1;

	uint8_t rcode : 4;
	uint8_t z : 3;
	uint8_t ra : 1;

	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t qrcount;
} __attribute__((__packed__)) dns_header_t;

/**
 * @brief dns agent main thread function
 *
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dns_agent_main(__attribute__((unused))void *);

int nes_dns_agent_add_routings(nes_acl_ctx_t* lookup_ctx);


#ifdef	__cplusplus
}
#endif

#endif	/* NES_DNS_AGENT_H */
