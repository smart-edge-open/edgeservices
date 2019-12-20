/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_nes_ring_lookup.h"
#include "nes_ring_lookup.h"
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "nes_ring_lookup_decl.h"
#include "libnes_cfgfile_def.h"

extern nes_lookup_table_t nes_ring_lookup_table;

int
init_suite_nes_ring_lookup(void) {
	return CUE_SUCCESS;
}

int
cleanup_suite_nes_ring_lookup(void) {
	return CUE_SUCCESS;
}

void nes_ring_add(const char *name, nes_ring_t *entry) {
	char lookup_name[RTE_RING_NAMESIZE];
	nes_ring_name_align(lookup_name, name);
	int32_t index = rte_hash_add_key(nes_ring_lookup_table.hash, lookup_name);
	if (0 > index)
		return;

	nes_ring_lookup_table.entries[index] = entry;
}

void nes_ring_del(const char *name) {
	char lookup_name[RTE_RING_NAMESIZE];
	nes_ring_name_align(lookup_name, name);

	rte_hash_del_key(nes_ring_lookup_table.hash, lookup_name);
}

static void
nes_ring_name_align_test(void) {
	const char test_str[] = "test";
	char res_str[RTE_RING_NAMESIZE] = {1};
	nes_ring_name_align(res_str, test_str);
	CU_ASSERT_EQUAL(strlen(test_str), strlen(test_str));
	CU_ASSERT_EQUAL(res_str[RTE_RING_NAMESIZE - 1], 0);
}

struct rte_cfgfile *cfg_bak;
extern struct rte_cfgfile *nes_cfgfile;
#define CFG_ALLOC_SECTION_BATCH 4
#define CFG_ALLOC_ENTRIES_BATCH 8

static struct rte_cfgfile_entry  entries0[] = {
	{
		.name = "test",
		.value = "1"
	}
};
static  struct rte_cfgfile_entry  entries1[] = {
	{
		.name = "max",
		.value = "1"
	}
};
static struct rte_cfgfile_entry  entries2[] = {
	{
		.name = "max",
		.value = "1073741816" // to exceed rte_hash entries limit
	}
};

static void nes_ring_lookup_init_test(void)
{
	cfg_bak = nes_cfgfile;
	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile);

	nes_cfgfile->sections =
		malloc(sizeof(struct rte_cfgfile_section) * CFG_ALLOC_SECTION_BATCH);

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile->sections);

	strncpy(nes_cfgfile->sections[0].name, "VM common", sizeof(nes_cfgfile->sections[0].name));
	nes_cfgfile->sections[0].num_entries = 1;
	nes_cfgfile->sections[0].entries = entries0;
	nes_cfgfile->num_sections = 1;
	CU_ASSERT_EQUAL(nes_ring_lookup_init(), NES_FAIL);
	int max_value = ((0xFFFFFFFF/2) - nes_ring_norings())/2;
	sprintf(entries2[0].value, "%d", max_value);
	nes_cfgfile->sections[0].entries = entries2;
	CU_ASSERT_EQUAL(nes_ring_lookup_init(), NES_FAIL);
	nes_cfgfile->sections[0].entries = entries1;
	CU_ASSERT_EQUAL(nes_ring_lookup_init(), NES_SUCCESS);
	free(nes_cfgfile->sections);
	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;
}

static void nes_ring_find_test(void) {
	nes_ring_t *ring = NULL;
	CU_ASSERT_EQUAL(nes_ring_find(&ring, "test"), NES_FAIL);
	CU_ASSERT_PTR_NULL(ring);
}

static void nes_ring_lookup_entry_get_test(void) {
	nes_ring_t *ring = NULL;
	CU_ASSERT_EQUAL(nes_ring_lookup_entry_get("test", &ring), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(ring);
}

void add_nes_ring_lookup_suite_to_registry(void) {
	CU_pSuite nes_ring_lookup_suite = CU_add_suite("nes_ring_lookup", init_suite_nes_ring_lookup, cleanup_suite_nes_ring_lookup);

	CU_add_test(nes_ring_lookup_suite, "nes_ring_name_align_test", nes_ring_name_align_test);
	CU_add_test(nes_ring_lookup_suite, "nes_ring_lookup_init_test", nes_ring_lookup_init_test);
	CU_add_test(nes_ring_lookup_suite, "nes_ring_find_test", nes_ring_find_test);
	CU_add_test(nes_ring_lookup_suite, "nes_ring_lookup_entry_get_test", nes_ring_lookup_entry_get_test);
}

