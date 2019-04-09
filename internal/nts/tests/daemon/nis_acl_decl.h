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

#ifndef NIS_ACL_DECL_H_
#define NIS_ACL_DECL_H_

#define FILE_NAME nis_acl
#include "mock.h"

MOCK_DECL(nes_acl_ctor);
#define nes_acl_ctor MOCK_NAME(mocked_nes_acl_ctor)

MOCK_DECL(nes_acl_add_entries);
#define nes_acl_add_entries MOCK_NAME(mocked_nes_acl_add_entries)

#endif
