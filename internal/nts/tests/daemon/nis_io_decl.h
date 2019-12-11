/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NIS_IO_DECL_H_
#define NIS_IO_DECL_H_

#define FILE_NAME nis_io
#include "mock.h"

int nis_io_init_traffic_rings(void);
int nis_io_init_flows(void);
int nis_io_init(void);

int nes_queue_enqueue(nes_queue_t *queue, void *data);

MOCK_DECL(nes_queue_enqueue);
#define nes_queue_enqueue MOCK_NAME(mocked_nes_queue_enqueue)

#endif
