/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include "test_nes_ring.h"
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "nes_ring_decl.h"
#include "io/nes_dev.h"
#include "ctrl/nes_ctrl.h"
#include "libnes_cfgfile_def.h"

static size_t NES_RINGS_CNT = 0;
static struct rte_ring *test_rte_ring = NULL;
extern struct rte_cfgfile *nes_cfgfile;

int
init_suite_nes_ring(void) {
	NES_RINGS_CNT = 0;
	while (NULL != nes_ring_params_table_get()[NES_RINGS_CNT].name)
		NES_RINGS_CNT++;

	return CUE_SUCCESS;
}

int
cleanup_suite_nes_ring(void) {
	return CUE_SUCCESS;
}

static void
nes_ring_params_table_get_test(void) {
	CU_ASSERT_PTR_NOT_NULL(nes_ring_params_table_get());
	CU_ASSERT_PTR_NULL(nes_ring_params_table_get()[NES_RINGS_CNT].name);
}

static void
nes_ring_name_test(void) {
	nes_ring_t nes_ring = {0};
	test_rte_ring = rte_ring_create("NTS_UPSTR_GTPU_TEST", 2, SOCKET_ID_ANY, 0);
	nes_ring.ring = test_rte_ring;

	CU_ASSERT_PTR_NOT_NULL(nes_ring.ring);
	CU_ASSERT_STRING_EQUAL(nes_ring_name(&nes_ring), "NTS_UPSTR_GTPU_TEST");

}

static void
nes_ring_norings_test(void) {
	CU_ASSERT_EQUAL(nes_ring_norings(), NES_RINGS_CNT + count_port_devices());
}

static void
nes_ring_set_flow_test(void) {
	nes_ring_t nes_ring = {0};
	// NULL flow
	nes_ring.ring = rte_ring_create("TTT", 2, SOCKET_ID_ANY, 0);
	CU_ASSERT_PTR_NOT_NULL(nes_ring.ring);
	CU_ASSERT_EQUAL(nes_ring_set_flow(&nes_ring), NES_SUCCESS);
	CU_ASSERT_PTR_NULL(nes_ring.flow);

	// not NULL flow
	nes_ring.ring = test_rte_ring;
	CU_ASSERT_PTR_NOT_NULL(nes_ring.ring);
	CU_ASSERT_EQUAL(nes_ring_set_flow(&nes_ring), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(nes_ring.flow);
}

static void
nes_ring_ctor_test(void) {
	nes_ring_t nes_ring = {0};
	nes_ring_params_t nes_ring_params = {0};
	nes_ring_params.multiproducer = 0;
	nes_ring_params.count = 3;
	CU_ASSERT_EQUAL(nes_ring_ctor(&nes_ring, &nes_ring_params), NES_FAIL);

	nes_ring_params.multiproducer = 1;
	nes_ring_params.count = 2;
	const char* nes_ring_name = "NTS_UPSTR_GTPU_TESTB";
	nes_ring_params.name = nes_ring_name;
	CU_ASSERT_EQUAL(nes_ring_ctor(&nes_ring, &nes_ring_params), NES_SUCCESS);
	CU_ASSERT_PTR_NOT_NULL(nes_ring.flow);
}

static void
nes_ring_dtor_test(void) {
	CU_ASSERT_EQUAL(nes_ring_dtor(NULL, NULL), NES_SUCCESS);
}

static void
nes_ring_enq_sp_test(void) {
	nes_ring_t nes_ring = {0};
	nes_ring.ring = test_rte_ring;
	nes_ctrl_ring_t ring_stats;
	nes_ring.ring_stats = &ring_stats;

	// The real usable ring size is count-1
	// instead of count to differentiate a free ring from an empty ring.
	CU_ASSERT_EQUAL(nes_ring_enq_sp(&nes_ring, NULL), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ring_enq_sp(&nes_ring, NULL), NES_FAIL);
}

static void
nes_ring_enq_burst_sp_test(void) {
	nes_ring_t nes_ring = {0};
	nes_ctrl_ring_t ring_stats;
	nes_ring.ring_stats = &ring_stats;
#define nes_ring_burst_size_sp 64
	nes_ring.ring = rte_ring_create("nes_ring_enq_burst_sp_test",
		nes_ring_burst_size_sp, SOCKET_ID_ANY, 0);
	CU_ASSERT_PTR_NOT_NULL(nes_ring.ring);
	int *data[nes_ring_burst_size_sp] = {NULL};
	CU_ASSERT_EQUAL(nes_ring_enq_burst_sp(&nes_ring, (void**) data,
		sizeof (data) / sizeof (data[0]) - 1), sizeof (data) / sizeof (data[0]) - 1);
	CU_ASSERT_EQUAL(nes_ring_enq_burst_sp(&nes_ring, (void**) data, 1), 0);
}

static void
nes_ring_deq_sp_test(void) {
	nes_ring_t nes_ring = {0};
	nes_ctrl_ring_t ring_stats;
	nes_ring.ring_stats = &ring_stats;
	nes_ring.ring = test_rte_ring;
	int *data = NULL;
	// The real usable ring size is count-1
	// instead of count to differentiate a free ring from an empty ring.
	// Entries were added in nes_ring_enq_sp_test
	CU_ASSERT_EQUAL(nes_ring_deq_sc(&nes_ring, (void**) &data), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ring_deq_sc(&nes_ring, (void**) &data), NES_FAIL);
}

static void
nes_ring_deq_burst_sc_test(void) {
	nes_ring_t nes_ring = {0};
	nes_ctrl_ring_t ring_stats;
	nes_ring.ring_stats = &ring_stats;
	nes_ring.ring = rte_ring_lookup("nes_ring_enq_burst_sp_test");
	// The real usable ring size is count-1
	// instead of count to differentiate a free ring from an empty ring.
	// Entries were added in nes_ring_enq_sp_test
	int *data[nes_ring_burst_size_sp] = {NULL};
	CU_ASSERT_EQUAL(nes_ring_deq_burst_sc(&nes_ring, (void**) data, nes_ring_burst_size_sp - 1),
		nes_ring_burst_size_sp - 1);
	CU_ASSERT_EQUAL(nes_ring_deq_burst_sc(&nes_ring, (void**) data, 1), 0);
}

static void
nes_ring_enq_mp_test(void) {
	nes_ring_t nes_ring = {0};
	nes_ctrl_ring_t ring_stats;
	nes_ring.ring_stats = &ring_stats;
	nes_ring.ring = rte_ring_create("nes_ring_enq_mp_test", 2, SOCKET_ID_ANY, 0);
	CU_ASSERT_PTR_NOT_NULL(nes_ring.ring);
	CU_ASSERT_EQUAL(nes_ring_enq_mp(&nes_ring, NULL), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ring_enq_mp(&nes_ring, NULL), NES_FAIL);
}

static void
nes_ring_enq_burst_mp_test(void) {
	nes_ring_t nes_ring = {0};
	nes_ctrl_ring_t ring_stats;
	nes_ring.ring_stats = &ring_stats;
#define nes_ring_burst_size_mp 64
	nes_ring.ring = rte_ring_create("nes_ring_enq_burst_mp_test",
		nes_ring_burst_size_mp, SOCKET_ID_ANY, 0);
	CU_ASSERT_PTR_NOT_NULL(nes_ring.ring);
	int *data[nes_ring_burst_size_mp] = {NULL};
	CU_ASSERT_EQUAL(nes_ring_enq_burst_mp(&nes_ring, (void**) data,
		sizeof (data) / sizeof (data[0]) - 1),
		sizeof (data) / sizeof (data[0]) - 1);
	CU_ASSERT_EQUAL(nes_ring_enq_burst_mp(&nes_ring, (void**) data, 1), 0);
}

static void
nes_ring_init_test(void) {
	struct rte_cfgfile *old_cfg, *cfg = malloc(sizeof (*cfg) + sizeof (cfg->sections[0]) * 1);

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 1;
	struct rte_cfgfile_entry  entries0[] = {
		{
			.name = "test",
			.value = "1"
		}
	};
	struct rte_cfgfile_section sections[] = {
		{ .name = "VM common"},

	};
	sections[0].entries = entries0;
	cfg->sections = sections;
	cfg->sections[0].num_entries = 1;
	old_cfg = nes_cfgfile;
	nes_cfgfile = cfg;
	CU_ASSERT_EQUAL(nes_ring_init(), NES_FAIL);
	// TODO: test other branches

	nes_cfgfile = old_cfg;
	free(cfg);
}

void add_nes_ring_suite_to_registry(void) {
	CU_pSuite nes_ring_suite = CU_add_suite("nes_ring", init_suite_nes_ring, cleanup_suite_nes_ring);

	CU_add_test(nes_ring_suite, "nes_ring_params_table_get_test", nes_ring_params_table_get_test);
	CU_add_test(nes_ring_suite, "nes_ring_name_test", nes_ring_name_test);
	CU_add_test(nes_ring_suite, "nes_ring_norings_test", nes_ring_norings_test);
	CU_add_test(nes_ring_suite, "nes_ring_set_flow_test", nes_ring_set_flow_test);
	CU_add_test(nes_ring_suite, "nes_ring_ctor_test", nes_ring_ctor_test);
	CU_add_test(nes_ring_suite, "nes_ring_dtor_test", nes_ring_dtor_test);
	CU_add_test(nes_ring_suite, "nes_ring_enq_sp_test", nes_ring_enq_sp_test);
	CU_add_test(nes_ring_suite, "nes_ring_enq_burst_sp_test", nes_ring_enq_burst_sp_test);
	CU_add_test(nes_ring_suite, "nes_ring_enq_mp_test", nes_ring_enq_mp_test);
	CU_add_test(nes_ring_suite, "nes_ring_enq_burst_mp_test", nes_ring_enq_burst_mp_test);
	CU_add_test(nes_ring_suite, "nes_ring_deq_sp_test", nes_ring_deq_sp_test);
	CU_add_test(nes_ring_suite, "nes_ring_deq_burst_sc_test", nes_ring_deq_burst_sc_test);
	CU_add_test(nes_ring_suite, "nes_ring_init_test", nes_ring_init_test);
}

