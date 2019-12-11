/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nis_io.h
 * @brief Header file for nis_io
 */

#ifndef _NIS_IO_H_
#define _NIS_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
* Main function for nis i/o thread
*
* @return
* NES_SUCCESS on success or NES_FAIL on error
*/
int nis_io_main(__attribute__((unused))void *);

#ifdef __cplusplus
}
#endif

#endif /* _NIS_IO_H_ */
