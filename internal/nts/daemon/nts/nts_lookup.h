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
