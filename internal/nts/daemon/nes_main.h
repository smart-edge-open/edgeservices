/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_main.h
 * @brief Header file for nes_main
 */

#ifndef NES_MAIN_H_
#define NES_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LCORE_IO = 1,
	LCORE_NTS,
	LCORE_NIS,
	LCORE_CTRL,
	LCORE_DNS
} lcores;

enum NES_DAEMONIZE_ON
{
	NES_DAEM_ON = 2,
	NES_DAEM_OFF = 3
};

/**
* Check if NES daemonization is turned on.
*
*/
int nes_check_daemonize(void);

/**
* Initilization of mempool, eal, rings and interfaces.
*
*/
int nes_main(int argc, char** argv);

#ifdef UNIT_TESTS
	#include "nes_main_decl.h"
#endif

#ifdef __cplusplus
}
#endif
#endif /* NES_MAIN_H_ */
