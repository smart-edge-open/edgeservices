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
