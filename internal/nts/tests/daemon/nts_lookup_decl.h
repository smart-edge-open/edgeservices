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

#ifndef NTS_LOOKUP_DECL_H
#define	NTS_LOOKUP_DECL_H

#ifndef FILE_NAME
	#define FILE_NAME nts_lookup
#endif
#include "mock.h"

char** nts_lookup_init_ring_names(int cnt, uint8_t is_kni);
int nts_lookup_init_tx_kni_rings_names(int kni_cnt);
int nts_lookup_init_tx_vm_rings_names(int vms_cnt);

MOCK_DECL(rte_malloc);
#define rte_malloc MOCK_NAME(mocked_rte_malloc)

MOCK_DECL(rte_free);
#define rte_free MOCK_NAME(mocked_rte_free)

#endif	/* NTS_LOOKUP_DECL_H */
