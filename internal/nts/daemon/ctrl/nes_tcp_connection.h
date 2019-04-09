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
* @file nes_tcp_connection.h
* @brief Header file for tcp server connection
*/
#ifndef _NES_TCP_CONNECTION_H_
#define _NES_TCP_CONNECTION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <stdint.h>

typedef struct one_client_conn_s
{
	int client_id;
	int tcp_sock;
	struct cmdline *cmdline;
} one_client_conn_t;

typedef struct tcp_connection_s
{
	int listen_sock;
	socklen_t addr_len;
	int tcp_sock;

	struct sockaddr_in local_addr;
	struct sockaddr_un local_un_addr;
} tcp_connection_t;

#ifdef EXT_CTRL_SOCKET
int nes_connection_setup(const char *ip_addr, uint16_t port_nr, tcp_connection_t *conn);
#endif
int nes_connection_un_setup(const char *socket_path, tcp_connection_t *conn);

#ifdef __cplusplus
}
#endif
#endif /* _NES_TCP_CONNECTION_H_ */
