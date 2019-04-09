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
