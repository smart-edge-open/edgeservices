/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_client.c
 * @brief NES Server client
 */

#include <stdio.h>
#include <stdint.h>

#include "nes_cli.h"
#include "nes_client.h"

int main(int argc, char **argv)
{
	if (argc > 3) {
		printf("Usage: %s [commands_file] [commands_output_file]\n", argv[0]);
		return -1;
	}
	if (3 == argc || 2 == argc)
		return nes_cmdline_file_manager(argv[1], 2 == argc ? NULL : argv[2]);

	return nes_cmdline_manager();

}
