/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NIS_ACL_DECL_H_
#define NIS_ACL_DECL_H_

#define FILE_NAME nis_acl
#include "mock.h"

MOCK_DECL(nes_acl_ctor);
#define nes_acl_ctor MOCK_NAME(mocked_nes_acl_ctor)

MOCK_DECL(nes_acl_add_entries);
#define nes_acl_add_entries MOCK_NAME(mocked_nes_acl_add_entries)

#endif
