/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_nis_acl.h"
#include "nes_common.h"
#include "nis/nis_acl.h"
#include "nis_acl_decl.h"

MOCK_INIT(mocked_nes_acl_ctor);
MOCK_INIT(mocked_nes_acl_add_entries);

int init_suite_nis_acl(void) {
	MOCK_RESET(mocked_nes_acl_ctor);
	MOCK_RESET(mocked_nes_acl_add_entries);
	return CUE_SUCCESS;
}

int cleanup_suite_nis_acl(void) {
	MOCK_RESET(mocked_nes_acl_ctor);
	MOCK_RESET(mocked_nes_acl_add_entries);
	return CUE_SUCCESS;
}

static void nis_acl_rule_prepare_test(void) {
	struct nis_acl_lookup_field lookup;
	nis_param_pkt_flow_t  tft_param;
	memset(&lookup, 0, sizeof (struct nis_acl_lookup_field));
	memset(&tft_param, 0, sizeof (nis_param_pkt_flow_t));
	CU_ASSERT_EQUAL(nis_acl_rule_prepare(NULL, &tft_param), NES_FAIL);
	CU_ASSERT_EQUAL(nis_acl_rule_prepare(&lookup, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_acl_rule_prepare(&lookup, &tft_param), NES_SUCCESS);
}

static int
nes_acl_ctor_fake(nes_acl_ctx_t *ctx, const char *context_name, uint32_t entry_size,
	uint32_t max_entries_cnt, struct rte_acl_field_def* acl_fields_def, uint32_t acl_fields_cnt)
{
	(void)ctx;
	(void)context_name;
	(void)entry_size;
	(void)max_entries_cnt;
	(void)acl_fields_def;
	(void)acl_fields_cnt;
	return NES_FAIL;
}

static void nis_acl_lookup_init_test(void) {
	nes_acl_ctx_t lookup_ctx;
	MOCK_SET(mocked_nes_acl_ctor, nes_acl_ctor_fake);
	CU_ASSERT_EQUAL(nis_acl_lookup_init(&lookup_ctx), NES_FAIL);
	MOCK_RESET(mocked_nes_acl_ctor);
	CU_ASSERT_EQUAL(nis_acl_lookup_init(&lookup_ctx), NES_SUCCESS);
	nis_acl_lookup_dtor(&lookup_ctx);
}

static int
nes_acl_add_entries_fake_fail(nes_acl_ctx_t *ctx, void **entries, struct rte_acl_rule **rules,
	uint32_t count)
{
	(void)ctx;
	(void)entries;
	(void)rules;
	(void)count;
	return NES_FAIL;
}

static void nis_acl_lookup_add_test(void) {
	nes_acl_ctx_t lookup_ctx;
	nis_param_pkt_flow_t flow;
	nis_param_rab_t rab_params;

	CU_ASSERT_EQUAL(nis_acl_lookup_init(&lookup_ctx), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_add(&lookup_ctx, NULL, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_acl_lookup_add(&lookup_ctx, &flow, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_acl_lookup_add(&lookup_ctx, NULL, &rab_params), NES_FAIL);
	MOCK_SET(mocked_nes_acl_add_entries, nes_acl_add_entries_fake_fail);
	CU_ASSERT_EQUAL(nis_acl_lookup_add(&lookup_ctx, &flow, &rab_params), NES_FAIL);
	MOCK_RESET(mocked_nes_acl_add_entries);
	CU_ASSERT_EQUAL(nis_acl_lookup_add(&lookup_ctx, &flow, &rab_params), NES_SUCCESS);
	nis_acl_lookup_dtor(&lookup_ctx);
}

static void nis_acl_lookup_find_test(void) {
	nes_acl_ctx_t lookup_ctx;
	nis_param_pkt_flow_t flow;
	nis_param_rab_t rab_params;
	nis_param_rab_t *entry;
	CU_ASSERT_EQUAL(nis_acl_lookup_init(&lookup_ctx), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_add(&lookup_ctx, &flow, &rab_params), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_find(&lookup_ctx, &flow, &entry), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_find(&lookup_ctx, NULL, &entry), NES_FAIL);
	CU_ASSERT_EQUAL(nis_acl_lookup_del(&lookup_ctx, &flow), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_find(&lookup_ctx, &flow, &entry), NES_FAIL);
	nis_acl_lookup_dtor(&lookup_ctx);
}

static void nis_acl_lookup_del_test(void) {
	nes_acl_ctx_t lookup_ctx;
	nis_param_pkt_flow_t flow;
	nis_param_rab_t rab_params;
	CU_ASSERT_EQUAL(nis_acl_lookup_init(&lookup_ctx), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_add(&lookup_ctx, &flow, &rab_params), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_del(&lookup_ctx, &flow), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_acl_lookup_del(&lookup_ctx, NULL), NES_FAIL);
	nis_acl_lookup_dtor(&lookup_ctx);
}

static void nis_acl_lookup_dtor_test(void) {
	nes_acl_ctx_t lookup_ctx;
	CU_ASSERT_EQUAL(nis_acl_lookup_init(&lookup_ctx), NES_SUCCESS);
	nis_acl_lookup_dtor(&lookup_ctx);
}

void add_nis_acl_suite_to_registry(void) {
	CU_pSuite nis_acl_suite = CU_add_suite("nis_acl", init_suite_nis_acl, cleanup_suite_nis_acl);

	CU_add_test(nis_acl_suite, "nis_acl_rule_prepare", nis_acl_rule_prepare_test);
	CU_add_test(nis_acl_suite, "nis_acl_lookup_init", nis_acl_lookup_init_test);
	CU_add_test(nis_acl_suite, "nis_acl_lookup_add", nis_acl_lookup_add_test);
	CU_add_test(nis_acl_suite, "nis_acl_lookup_find", nis_acl_lookup_find_test);
	CU_add_test(nis_acl_suite, "nis_acl_lookup_del", nis_acl_lookup_del_test);
	CU_add_test(nis_acl_suite, "nis_acl_lookup_dtor", nis_acl_lookup_dtor_test);
}

