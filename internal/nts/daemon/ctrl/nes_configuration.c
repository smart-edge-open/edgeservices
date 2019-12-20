/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_configuration.c
 * @brief nes server configuration
 */

#include <stdio.h>
#include <stdlib.h>
#include <rte_cfgfile.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_malloc.h>

#include "ctrl/nes_configuration.h"
#include "nes_common.h"
#include "libnes_cfgfile.h"

int nes_server_configure(configuration_t *conf)
{
	const char *ctrl_socket;
#ifdef EXT_CTRL_SOCKET
	const char *ctrl_ip;
	const char *ctrl_port;
	conf->server_ip = NULL;
	conf->server_port = 0;
#endif


	conf->server_socket = NULL;
	if (NES_FAIL == nes_cfgfile_entry("NES_SERVER", "ctrl_socket", &ctrl_socket)) {
#ifndef EXT_CTRL_SOCKET
		NES_LOG(ERR, "Error reading [NES_SERVER] ctrl_socket.\n");
		return NES_FAIL;
#else
		if (NES_FAIL == nes_cfgfile_entry("NES_SERVER", "ctrl_ip", &ctrl_ip)) {
			NES_LOG(ERR, "Reading server IP from config file failed.");
			return NES_FAIL;
		}

		if (NES_FAIL == nes_cfgfile_entry("NES_SERVER", "ctrl_port", &ctrl_port)) {
			NES_LOG(ERR, "Reading server port from config file failed.");
			return NES_FAIL;
		}
		conf->server_ip = ctrl_ip;
		conf->server_port = atoi(ctrl_port);
		conf->server_port = (uint16_t)conf->server_port;
#endif
	} else
		conf->server_socket = ctrl_socket;

	return NES_SUCCESS;
}
