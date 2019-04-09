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

#include "test_nes_common.h"
#include "nes_common.h"

int
init_suite_nes_common(void) {
	return CUE_SUCCESS;
}

int
cleanup_suite_nes_common(void) {
	return CUE_SUCCESS;
}

static void
conv_ptr_to_const_test(void) {
	uint32_t *a = NULL;
	CU_ASSERT_PTR_NULL(conv_ptr_to_const(NULL));
	CU_ASSERT_PTR_NOT_NULL(conv_ptr_to_const(&a));
}

CU_TestInfo tests_suite_nes_common[] = {
	{ "conv_ptr_to_const_test", conv_ptr_to_const_test},
	CU_TEST_INFO_NULL,
};
