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
 * @file nes_client.c
 * @brief NES Server client
 */
#include <stdio.h>
#include <stdint.h>

#include "nes_cli.h"
#include "nes_client.h"

int main(int argc, char** argv)
{
	if (argc > 3) {
		printf("Usage: %s [commands_file] [commands_output_file]\n", argv[0]);
		return -1;
	}
	if (3 == argc || 2 == argc)
		return nes_cmdline_file_manager(argv[1], 2 == argc ? NULL : argv[2]);

	return nes_cmdline_manager();

}
