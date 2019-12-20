/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <string.h>
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "nes_ring.h"
#include "nes_ring_lookup.h"
#ifdef UNIT_TESTS
	#include "nes_ring_lookup_decl.h"
#endif

NES_STATIC nes_lookup_table_t nes_ring_lookup_table;

int nes_ring_lookup_init(void)
{
	const char *buffer;
	int max_vm, retval;
	nes_lookup_params_t nes_ring_lookup_params = {
		.name = "Lookup table for NES rings",
		.key_len = RTE_RING_NAMESIZE,
		.entry_len = sizeof(nes_ring_t)
	};
	if (NES_SUCCESS == nes_cfgfile_entry("VM common", "max", &buffer))
		max_vm = atoi(buffer);
	else {
		NES_LOG(ERR,"Bad or missing max entry in [VM] section in config file.\n");
		return NES_FAIL;
	}

	/* Let it be twice as large as predictable number of rings to avoid conflicts */
	nes_ring_lookup_params.number_of_entries = 2*(nes_ring_norings()+2*max_vm);

	retval = nes_lookup_ctor(&nes_ring_lookup_table, &nes_ring_lookup_params);
	if (NES_FAIL == retval)
		NES_LOG(ERR,"Could not initialize %s.\n",nes_ring_lookup_params.name);

	return retval;
}

NES_STATIC void nes_ring_name_align(char *dst, const char *src)
{
	memset(dst, 0, RTE_RING_NAMESIZE);
	strncpy(dst, src, RTE_RING_NAMESIZE);
}

int nes_ring_find(nes_ring_t **ring, const char *name)
{
	char lookup_name[RTE_RING_NAMESIZE];
	nes_ring_name_align(lookup_name, name);
	return nes_lookup_entry_find(&nes_ring_lookup_table, lookup_name, (void **)ring);
}

int nes_ring_lookup_entry_get(const char * name,  nes_ring_t **ring)
{
	char lookup_name[RTE_RING_NAMESIZE];
	nes_ring_name_align(lookup_name, name);
	return nes_lookup_entry_get(&nes_ring_lookup_table, lookup_name, (void**)ring);
}
