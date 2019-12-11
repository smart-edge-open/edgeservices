/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_io.h
 * @brief Header file for nts_io
 */

#ifndef _NTS_IO_H_
#define _NTS_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "libnes_queue.h"
/**
 * Main function for nts thread
 *
 * @return
 *   NES_SUCCESS on success or NES_FAIL on error
 */
int nts_io_main(__attribute__((unused))void *);

/**
 * Getter for nts_io_ring queue
 *
 * @param queue
 *   queue pointer to set
 */
void nts_io_ring_queue_get(nes_queue_t **queue);

nts_lookup_tables_t *nts_io_routing_tables_get(void);

#ifdef __cplusplus
}
#endif

#endif /* _NTS_IO_H_ */
