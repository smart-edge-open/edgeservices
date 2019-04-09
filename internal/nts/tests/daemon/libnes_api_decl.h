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

#ifndef LIBNES_API_DECL_H_
#define LIBNES_API_DECL_H_

//#undef FILE_NAME
#define FILE_NAME nes_ctrl
#include "mock.h"

MOCK_DECL(nes_cfgfile_load);
#define nes_cfgfile_load MOCK_NAME(mocked_nes_cfgfile_load)

MOCK_DECL(nes_cfgfile_close);
#define nes_cfgfile_close MOCK_NAME(mocked_nes_cfgfile_close)

#endif
