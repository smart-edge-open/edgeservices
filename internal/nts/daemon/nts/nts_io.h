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
