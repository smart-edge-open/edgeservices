/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

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
