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
