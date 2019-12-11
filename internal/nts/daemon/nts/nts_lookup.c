/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_lookup.c
 * @brief Implementation of lookup functionality
 */

#include <stdlib.h>

#include <rte_malloc.h>

#include "nes_common.h"
#include "nes_capacity.h"
#include "libnes_cfgfile.h"
#include "libnes_lookup.h"
#include "libnes_sq.h"
#include "nts/nts_lookup.h"
#include "nts_edit.h"
#include "nes_ring_lookup.h"
#define NTS_LOOKUP_VM_MAX 90

#ifdef UNIT_TESTS
	#include "nts_lookup_decl.h"
#endif
NES_STATIC int    nts_lookup_vm_max;
NES_STATIC int    nts_lookup_kni_max;
NES_STATIC char **nts_lookup_tx_ring_names;
NES_STATIC char **nts_lookup_kni_ring_names;

char *nts_lookup_tx_vm_ring_name_get(int vm_num)
{
	if ((0 > vm_num) || (vm_num >= nts_lookup_vm_max))
		return NULL;

	if (NULL == nts_lookup_tx_ring_names)
		return NULL;

	return nts_lookup_tx_ring_names[vm_num];
}

char *nts_lookup_tx_kni_ring_name_get(int kni_num)
{
	if ((0 > kni_num) || (kni_num >= nts_lookup_kni_max))
		return NULL;

	if (NULL == nts_lookup_kni_ring_names)
		return NULL;

	return nts_lookup_kni_ring_names[kni_num];
}

NES_STATIC char** nts_lookup_init_ring_names(int cnt, uint8_t is_kni)
{
	int i, j;
	char** ret = rte_malloc(
		"Ring names table",
		cnt * sizeof(char*),
		0);

	if (NULL == ret) {
		NES_LOG(ERR, "Could not allocate table for %s ring names.\n",
			is_kni ? "KNI" : "VHOST");
		return NULL;
	}
	for (i = 0; i < cnt; i++) {
		ret[i] = rte_malloc(
			"Ring name",
			NES_RING_NAME_LEN,
			0);
		if (NULL == ret[i]) {
			NES_LOG(ERR, "Ring name allocation failed");
			break;
		}
	}
	if (i < cnt) {
		for (j = 0; j < i; j++)
			rte_free(ret[j]);

		rte_free(ret);
		return NULL;
	}

	for (i = 0; i < cnt; i++) {
		if (is_kni) {
			snprintf(
				ret[i],
				NES_RING_NAME_LEN,
				"IO_KNI%d_ANY",
				i);
		} else {
			snprintf(
				ret[i],
				NES_RING_NAME_LEN,
				"IO_VM%d_ANY",
				i);
		}
	}
	return ret;
}

NES_STATIC int nts_lookup_init_tx_vm_rings_names(int vms_cnt)
{
	nts_lookup_tx_ring_names = nts_lookup_init_ring_names(vms_cnt, 0);
	if (NULL == nts_lookup_tx_ring_names)
		return NES_FAIL;

	return NES_SUCCESS;
}

NES_STATIC int nts_lookup_init_tx_kni_rings_names(int kni_cnt)
{
	nts_lookup_kni_ring_names = nts_lookup_init_ring_names(kni_cnt, 1);
	if (NULL == nts_lookup_kni_ring_names)
		return NES_FAIL;

	return NES_SUCCESS;
}

int nts_lookup_init(nts_lookup_tables_t * lookup_tables)
{
	const char* buffer;
	struct nes_lookup_params_s lookup_table_params = {
		.name = "nts_io_learning_lookup_table",
		/* Learning table size - make it 4 times the exact size to avoid hash conflicts */
		.number_of_entries = 4 * NES_MAX_UE,
		.key_len = IPV4_BYTES,
		.entry_len = sizeof(nts_enc_entry_t)
	};

	lookup_tables->learning = rte_malloc("Learning lookup table",
		sizeof(nes_lookup_table_t), 0);
	VERIFY_PTR_OR_RET(lookup_tables->learning, NES_FAIL);
	if (NES_SUCCESS != nes_lookup_ctor(lookup_tables->learning, &lookup_table_params))  {
		NES_LOG(ERR, "Failed to create learning lookup table\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != is_avp_enabled()) {
		if (NES_SUCCESS == nes_cfgfile_has_section("KNI")) {
			if (NES_SUCCESS != nes_cfgfile_entry("KNI", "max", &buffer)) {
				NES_LOG(ERR, "Missing: section %s, entry %s, in config file.\n",
					"KNI", "max");
				return NES_FAIL;
			}
			nts_lookup_kni_max = atoi(buffer);
			if (NES_SUCCESS != nts_lookup_init_tx_kni_rings_names(nts_lookup_kni_max)) {
				NES_LOG(ERR,"Failed to initialize KNI rings");
				return NES_FAIL;
			}
		}

		if (NES_SUCCESS != nes_cfgfile_entry("VM common","max",&buffer)) {
			NES_LOG(ERR, "Missing: section %s, entry %s, in config file.\n",
				"VM common", "max");
			return NES_FAIL;
		}
		nts_lookup_vm_max = atoi(buffer);

		return nts_lookup_init_tx_vm_rings_names(nts_lookup_vm_max);
	} else
		return NES_SUCCESS;
}
