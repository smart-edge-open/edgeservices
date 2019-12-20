/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_nts_io.h"
#include "nes_common.h"
#include "nts/nts_lookup.h"
#include "nts/nts_io.h"
#include "nis/nis_io.h"
#include "io/nes_io.h"
#include "libnes_cfgfile.h"
#include "nts_io_decl.h"
#include "nes_ring_lookup.h"
#include "nes_ring_lookup_decl.h"
#include "test_nes_ring_lookup.h"
#include "libnes_cfgfile_def.h"

static struct rte_cfgfile_section VM_common_section = {
	.name = "VM common"
};

static struct rte_cfgfile_entry  VM_common_entry = {
	.name = "max", .value = "5"
};

struct rte_cfgfile *cfg_bak;
pthread_t nis_io_main_thread;

extern struct rte_cfgfile *nes_cfgfile;
extern nes_lookup_table_t nes_ring_lookup_table;

#define CFG_ALLOC_SECTION_BATCH 8

int init_suite_nts_io(void) {
	cfg_bak = nes_cfgfile;
	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	if (!nes_cfgfile) {
		return CUE_NOMEMORY;
	}

	nes_cfgfile->num_sections = 1;

	VM_common_section.entries = &VM_common_entry;
	nes_cfgfile->sections = &VM_common_section;
	nes_cfgfile->sections[0].num_entries = 1;

	rte_atomic32_clear(&threads_started);
	return CUE_SUCCESS;
}

int cleanup_suite_nts_io(void) {
	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;
	nes_thread_terminate = 0;
	rte_atomic32_clear(&threads_started);
	return CUE_SUCCESS;
}

void nts_io_init_test(void) {
	nes_ring_t *entry;
	if (NES_SUCCESS == nes_ring_find(&entry, "NTS_UPSTR_GTPU")) {
		nes_ring_del("NTS_UPSTR_GTPU");
		nes_cfgfile->num_sections = 1;
		CU_ASSERT_EQUAL(nts_io_init(), NES_FAIL);
		nes_ring_add("NTS_UPSTR_GTPU", entry);
	}
}

void nts_io_main_test(void) {
	nes_thread_terminate = 1;
	nes_ring_t *entry;
	if (NES_SUCCESS == nes_ring_find(&entry, "NTS_UPSTR_GTPU")) {
		nes_ring_del("NTS_UPSTR_GTPU");
		CU_ASSERT_EQUAL(nts_io_main(NULL), NES_FAIL);
		nes_ring_add("NTS_UPSTR_GTPU", entry);
	}
}

void add_nts_io_suite_to_registry(void) {
	// CU_pSuite nts_io_suite = CU_add_suite("nts_io", init_suite_nts_io, cleanup_suite_nts_io);

	// CU_add_test(nts_io_suite, "nts_io_init", nts_io_init_test);
	// CU_add_test(nts_io_suite, "nts_io_main", nts_io_main_test);
}

