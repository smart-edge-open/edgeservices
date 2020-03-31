/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef _NES_CLI_H_
#define _NES_CLI_H_
#ifdef __cplusplus
extern "C" {
#endif

#include "libnes_api_protocol.h"

int nes_cmdline_manager(void);

int nes_cmdline_file_manager(const char *path, const char *output_file);

#ifdef __cplusplus
}
#endif
#endif /* _NES_CLI_H_ */
