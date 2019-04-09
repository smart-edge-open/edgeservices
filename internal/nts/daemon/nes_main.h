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
* @file nes_main.h
* @brief Header file for nes_main
*/
#ifndef NES_MAIN_H_
#define NES_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

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
