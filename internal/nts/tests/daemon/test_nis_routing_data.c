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

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_nis_routing_data.h"
#include "nes_common.h"
#include "nis/nis_routing_data.h"
#include "nis_acl_decl.h"

int init_suite_nis_routing_data(void) {
	return CUE_SUCCESS;
}

int cleanup_suite_nis_routing_data(void) {
	return CUE_SUCCESS;
}

extern nes_lookup_table_t *nis_routing_data_table;

static void nis_routing_data_get_test(void) {
	nis_routing_data_key_t key;
	nis_routing_data_t data1, *data2;
	if (nis_routing_data_table)
		nis_routing_data_dtor();
	CU_ASSERT_EQUAL(nis_routing_data_init(), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_routing_data_get(&key, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_routing_data_get(NULL, &data2), NES_FAIL);
	CU_ASSERT_EQUAL(nis_routing_data_add(&key, &data1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_routing_data_get(&key, &data2), NES_SUCCESS);
	if (nis_routing_data_table)
		nis_routing_data_dtor();
}

static void nis_routing_data_init_test(void) {
	if (nis_routing_data_table)
		nis_routing_data_dtor();
	CU_ASSERT_EQUAL(nis_routing_data_init(), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_routing_data_init(), NES_FAIL);
	if (nis_routing_data_table)
		nis_routing_data_dtor();
}

static void nis_routing_data_dtor_test(void) {
	if (nis_routing_data_table)
		nis_routing_data_dtor();
	CU_ASSERT_EQUAL(nis_routing_data_init(), NES_SUCCESS);
	if (nis_routing_data_table)
		nis_routing_data_dtor();
}

static void nis_routing_data_add_test(void) {
	nis_routing_data_key_t key;
	nis_routing_data_t data;
	if (nis_routing_data_table)
		nis_routing_data_dtor();
	CU_ASSERT_EQUAL(nis_routing_data_init(), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_routing_data_add(NULL, &data), NES_FAIL);
	CU_ASSERT_EQUAL(nis_routing_data_add(&key, NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_routing_data_add(&key, &data), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_routing_data_del(&key), NES_SUCCESS);
	if (nis_routing_data_table)
		nis_routing_data_dtor();
}

static void nis_routing_data_del_test(void) {
	nis_routing_data_key_t key;
	nis_routing_data_t data;
	if (nis_routing_data_table)
		nis_routing_data_dtor();
	CU_ASSERT_EQUAL(nis_routing_data_init(), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_routing_data_del(NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nis_routing_data_del(&key), NES_FAIL);
	CU_ASSERT_EQUAL(nis_routing_data_add(&key, &data), NES_SUCCESS);
	CU_ASSERT_EQUAL(nis_routing_data_del(&key), NES_SUCCESS);
	if (nis_routing_data_table)
		nis_routing_data_dtor();
}

void add_nis_routing_data_suite_to_registry(void) {
	CU_pSuite nis_routing_data_suite = CU_add_suite("nis_routing_data", init_suite_nis_routing_data, cleanup_suite_nis_routing_data);

	CU_add_test(nis_routing_data_suite, "nis_routing_data_get", nis_routing_data_get_test);
	CU_add_test(nis_routing_data_suite, "nis_routing_data_init", nis_routing_data_init_test);
	CU_add_test(nis_routing_data_suite, "nis_routing_data_dtor", nis_routing_data_dtor_test);
	CU_add_test(nis_routing_data_suite, "nis_routing_data_add", nis_routing_data_add_test);
	CU_add_test(nis_routing_data_suite, "nis_routing_data_del", nis_routing_data_del_test);
}

