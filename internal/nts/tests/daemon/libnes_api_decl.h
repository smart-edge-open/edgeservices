/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

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
