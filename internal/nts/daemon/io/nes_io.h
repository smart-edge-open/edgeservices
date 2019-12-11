/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_io.h
 * @brief Header file for nes_io
 */

#ifndef _NES_IO_H_
#define _NES_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "libnes_queue.h"

#define THREAD_NTS_IO_ID (1<<0)
#define THREAD_NIS_IO_ID (1<<1)
#define THREAD_NES_CTRL_ID (1<<2)
#define THREAD_DNS_ID (1<<3)
#define THREADS_MASK (THREAD_NTS_IO_ID | THREAD_NIS_IO_ID | THREAD_NES_CTRL_ID | THREAD_DNS_ID)

extern rte_atomic32_t threads_started;

/**
 * Main function for nes i/o thread
 *
 * @return
 *   NES_SUCCESS on success or NES_FAIL on error
 */
int nes_io_main(__attribute__((unused))void *);
/**
 * Get queue for nes i/o device
 *
 * @param queue
 *   Pointer for nes io devices queueue
 */
void nes_io_dev_queue_get(nes_queue_t **queue);

#ifdef __cplusplus
}
#endif

#endif /* _NES_IO_H_ */
