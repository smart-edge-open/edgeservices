/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <rte_malloc.h>

#include "test_nts_lookup.h"
#include "nts/nts_lookup.h"
#include "pkt_generator.h"
#include "nes_common.h"
#include "nts_lookup_decl.h"
#include "libnes_cfgfile.h"
#include "libnes_cfgfile_def.h"

MOCK_INIT(mocked_rte_malloc);
MOCK_INIT(mocked_rte_free);

int
init_suite_nts_lookup(void) {
	MOCK_RESET(mocked_rte_malloc);
	MOCK_RESET(mocked_rte_free);
	return CUE_SUCCESS;
}

static int **rte_malloc_stub_ret;
static int rte_malloc_stub_ret_id = 0;

static void*
rte_malloc_stub(const char __attribute__((unused)) * type,
	size_t __attribute__((unused)) size,
	unsigned __attribute__((unused)) align)
{
	return rte_malloc_stub_ret[rte_malloc_stub_ret_id++];
}

static void
rte_free_stub(void __attribute__((unused)) * ptr) {
}

int
cleanup_suite_nts_lookup(void) {
	MOCK_RESET(mocked_rte_malloc);
	MOCK_RESET(mocked_rte_free);
	return CUE_SUCCESS;
}
extern struct rte_cfgfile *nes_cfgfile;
extern nts_lookup_tables_t nts_io_lookup_tables;
static void nts_lookup_init_test(void) {
	MOCK_RESET(mocked_rte_malloc);
	MOCK_RESET(mocked_rte_free);
	struct rte_cfgfile *old_cfg, *cfg = malloc(sizeof (*cfg) + sizeof (cfg->sections[0]) * 1);

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 1;

	struct rte_cfgfile_entry  entries[] = {
		{
			.name = "max",
			.value = "6"
		}
	};

	struct rte_cfgfile_section sections[] = {
		{ .name = "VM common"},

	};

	sections[0].entries = entries;
	cfg->sections = sections;
	cfg->sections[0].num_entries = 1;
	old_cfg = nes_cfgfile;
	nes_cfgfile = cfg;

	CU_ASSERT_EQUAL(nts_lookup_init(&nts_io_lookup_tables), NES_SUCCESS);
	nes_cfgfile = old_cfg;

	free(cfg);
}
extern char **nts_lookup_tx_ring_names;
extern int nts_lookup_vm_max;

static void nts_lookup_tx_vm_ring_name_get_test(void) {
	CU_ASSERT_PTR_NULL(nts_lookup_tx_vm_ring_name_get(-1));
	nts_lookup_vm_max = 0;
	CU_ASSERT_PTR_NULL(nts_lookup_tx_vm_ring_name_get(1));
	nts_lookup_vm_max = 2;
	char **old_names = nts_lookup_tx_ring_names;
	nts_lookup_tx_ring_names = NULL;
	CU_ASSERT_PTR_NULL(nts_lookup_tx_vm_ring_name_get(1));

	char *name = (char*) (uintptr_t) "a";
	nts_lookup_tx_ring_names = &name;
	CU_ASSERT_STRING_EQUAL(nts_lookup_tx_vm_ring_name_get(0), name);
	nts_lookup_tx_ring_names = old_names;
}

static void nts_ip_ntoa_test(void) {
	uint32_t ip = rte_cpu_to_be_32(IPv4(192, 168, 0, 1));
	CU_ASSERT_STRING_EQUAL(nts_ip_ntoa(ip), "192.168.0.1");
}

static void nts_lookup_init_tx_vm_rings_names_test(void) {
	MOCK_SET(mocked_rte_malloc, rte_malloc_stub);
	MOCK_SET(mocked_rte_free, rte_free_stub);

	int fake;
	int *malloc_ret_0 = NULL;
	rte_malloc_stub_ret = (int**) &malloc_ret_0;
	CU_ASSERT_EQUAL(nts_lookup_init_tx_vm_rings_names(1), NES_FAIL);
	rte_malloc_stub_ret_id = 0;

	int *malloc_ret_1[] = {&fake, NULL};
	rte_malloc_stub_ret = (int**) &malloc_ret_1;
	CU_ASSERT_EQUAL(nts_lookup_init_tx_vm_rings_names(1), NES_FAIL);

	rte_malloc_stub_ret_id = 0;
	int *ptr_0 = malloc(sizeof (char*));
	int *ptr_1 = malloc(sizeof (char) * 32); //RTE_RING_NAMESIZE
	int *malloc_ret_2[] = {ptr_0, ptr_1};
	rte_malloc_stub_ret = (int**) &malloc_ret_2;
	CU_ASSERT_EQUAL(nts_lookup_init_tx_vm_rings_names(1), NES_SUCCESS);
	free(ptr_0);
	free(ptr_1);
	rte_malloc_stub_ret_id = 0;
}

void add_nts_lookup_suite_to_registry(void) {
	CU_pSuite nts_lookup_suite = CU_add_suite("nts_lookup", init_suite_nts_lookup, cleanup_suite_nts_lookup);

	CU_add_test(nts_lookup_suite, "nts_lookup_tx_vm_ring_name_get_test", nts_lookup_tx_vm_ring_name_get_test);
	CU_add_test(nts_lookup_suite, "nts_ip_ntoa_test", nts_ip_ntoa_test);
	CU_add_test(nts_lookup_suite, "nts_lookup_init_tx_vm_rings_names_test", nts_lookup_init_tx_vm_rings_names_test);
	CU_add_test(nts_lookup_suite, "nts_lookup_init_test", nts_lookup_init_test);
}

