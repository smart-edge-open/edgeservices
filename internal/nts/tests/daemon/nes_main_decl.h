/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_MAIN_DECL_H_
#define NES_MAIN_DECL_H_

int nes_mempool_init(void);
int nes_init_interfaces(void);
void nes_handle_signals(int signal);


#endif
