/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_DNS_HOSTS_DECL_H_
#define NES_DNS_HOSTS_DECL_H_


#ifndef FILE_NAME
	#define FILE_NAME nes_dns
#endif

#include "mock.h"

char* nes_dns_ipv4_host(char* line, size_t line_len);


MOCK_DECL(fopen);
#define fopen MOCK_NAME(mocked_fopen)

MOCK_DECL(getline);
#define getline MOCK_NAME(mocked_getline)

MOCK_DECL(fclose);
#define fclose MOCK_NAME(mocked_fclose)

MOCK_DECL(rte_realloc);
#define rte_realloc MOCK_NAME(mocked_rte_realloc)

MOCK_DECL(rte_malloc);
#define rte_malloc MOCK_NAME(mocked_rte_malloc)

MOCK_DECL(rte_free);
#define rte_free MOCK_NAME(mocked_rte_free)

#endif
