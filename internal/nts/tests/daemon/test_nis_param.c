/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_nis_param.h"
#include "nes_common.h"
#include "nis/nis_param.h"

int init_suite_nis_param(void) {
	return CUE_SUCCESS;
}

int cleanup_suite_nis_param(void) {
	return CUE_SUCCESS;
}

static void nis_param_init_test(void) {
	nes_acl_ctx_t lookup_ctx;
	CU_ASSERT_EQUAL(nis_param_init(&lookup_ctx), NES_SUCCESS);
	nis_param_ctx_dtor(&lookup_ctx);
}

static void nis_param_ctx_dtor_test(void) {
	nes_acl_ctx_t lookup_ctx;
	CU_ASSERT_EQUAL(nis_param_init(&lookup_ctx), NES_SUCCESS);
	nis_param_ctx_dtor(&lookup_ctx);
}

static void nis_param_rab_set_test(void) {
	nes_acl_ctx_t lookup_ctx;
	nis_param_pkt_flow_t flow;
	nis_param_rab_t rab_params;

	CU_ASSERT_EQUAL(nis_param_init(&lookup_ctx), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_set(&lookup_ctx, NULL, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_param_rab_set(&lookup_ctx, &flow, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_param_rab_set(&lookup_ctx, NULL, &rab_params), NES_FAIL);
	CU_ASSERT_EQUAL(nis_param_rab_set(&lookup_ctx, &flow, &rab_params), NES_SUCCESS);
	nis_param_ctx_dtor(&lookup_ctx);
}

static void nis_param_rab_get_test(void) {
	nes_acl_ctx_t lookup_ctx;
	nis_param_pkt_flow_t flow;
	nis_param_rab_t rab_params;
	nis_param_rab_t *entry;
	CU_ASSERT_EQUAL(nis_param_init(&lookup_ctx), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_set(&lookup_ctx, &flow, &rab_params), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_get(&lookup_ctx, &flow, &entry), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_get(&lookup_ctx, NULL, &entry), NES_FAIL);
	CU_ASSERT_EQUAL(nis_param_rab_del(&lookup_ctx, &flow), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_get(&lookup_ctx, &flow, &entry), NES_FAIL);
	nis_param_ctx_dtor(&lookup_ctx);
}

static void nis_param_rab_del_test(void) {
	nes_acl_ctx_t lookup_ctx;
	nis_param_pkt_flow_t flow;
	nis_param_rab_t rab_params;
	CU_ASSERT_EQUAL(nis_param_init(&lookup_ctx), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_set(&lookup_ctx, &flow, &rab_params), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_del(&lookup_ctx, &flow), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_param_rab_del(&lookup_ctx, NULL), NES_FAIL);
	nis_param_ctx_dtor(&lookup_ctx);
}

void add_nis_param_suite_to_registry(void) {
	CU_pSuite nis_param_suite = CU_add_suite("nis_param", init_suite_nis_param, cleanup_suite_nis_param);

	CU_add_test(nis_param_suite, "nis_param_init", nis_param_init_test);
	CU_add_test(nis_param_suite, "nis_param_ctx_dtor", nis_param_ctx_dtor_test);
	CU_add_test(nis_param_suite, "nis_param_rab_set", nis_param_rab_set_test);
	CU_add_test(nis_param_suite, "nis_param_rab_get", nis_param_rab_get_test);
	CU_add_test(nis_param_suite, "nis_param_rab_del", nis_param_rab_del_test);
}

