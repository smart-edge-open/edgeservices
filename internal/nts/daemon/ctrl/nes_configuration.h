/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_configuration.h
 * @brief Header file for server configuration
 */

#ifndef _NES_CONFIGURATION_H_
#define _NES_CONFIGURATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SECTION_NAME "section"
#define CONF_FILE_PATH "config_file.cfg"

typedef struct configuration_s
{
#ifdef EXT_CTRL_SOCKET
	const char* server_ip;
	uint16_t    server_port;
#endif
	const char* server_socket;
} configuration_t;

int nes_server_configure(configuration_t *conf);

#ifdef __cplusplus
}
#endif
#endif /* _NES_CONFIGURATION_H_ */
