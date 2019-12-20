/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NTS_ACL_H_
#define TEST_NTS_ACL_H_

#include <CUnit/CUnit.h>

int init_suite_nts_acl(void);
int cleanup_suite_nts_acl(void);

void add_nts_acl_suite_to_registry(void);

#endif /* TEST_NTS_ACL_H_ */
