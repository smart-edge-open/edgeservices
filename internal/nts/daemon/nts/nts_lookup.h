/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_lookup.h
 * @brief Header file for nts_lookup
 */

#ifndef _NTS_LOOKUP_H_
#define _NTS_LOOKUP_H_

#ifdef __cpluplus
extern "C" {
#endif

#include <arpa/inet.h>
#include "libnes_lookup.h"

#define IPV4_BYTES 4
#define PORT_BYTES 2

typedef struct nts_lookup_tables_s {
	nes_lookup_table_t *learning;
} nts_lookup_tables_t;

int nts_lookup_init(nts_lookup_tables_t *);

char *nts_lookup_tx_vm_ring_name_get(int);
char *nts_lookup_tx_kni_ring_name_get(int);

static inline char *
nts_ip_ntoa(uint32_t ip_addr)
{
	struct in_addr s_ip_addr = {
		.s_addr = ip_addr
	};
	return inet_ntoa(s_ip_addr);
}

#ifdef __cpluplus
}
#endif

#endif /* _NTS_LOOKUP_H_ */
