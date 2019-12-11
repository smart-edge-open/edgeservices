/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

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
