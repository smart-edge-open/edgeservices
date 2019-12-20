/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_tcp_connection.c
 * @brief tcp server connection
 */

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ctrl/nes_tcp_connection.h"
#include "nes_common.h"

#define MAX_IP_ADDR_LEN 16
#define MIN_IP_ADDR_LEN 7
#define PORTS_NUMBER    1024

#ifdef EXT_CTRL_SOCKET
int nes_connection_setup(const char *ip_addr, uint16_t port_nr, tcp_connection_t *conn)
{
	assert(NULL != conn);
	assert(NULL != ip_addr);
	assert(MAX_IP_ADDR_LEN >= strlen(ip_addr));
	assert(MIN_IP_ADDR_LEN <= strlen(ip_addr));
	assert(PORTS_NUMBER < port_nr);

	in_addr_t ip_addr_inet;
	int opt = 1;

	conn->addr_len = sizeof(struct sockaddr);
	ip_addr_inet = inet_addr(ip_addr);
	conn->listen_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (0 > conn->listen_sock) {
		NES_LOG(ERR, "Error creating listening socket.\n");
		return NES_FAIL;
	}

	if (setsockopt(conn->listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
			sizeof(opt)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	memset(&conn->local_addr, 0, sizeof(struct sockaddr_in));
	conn->local_addr.sin_family      = AF_INET;
	conn->local_addr.sin_addr.s_addr = htonl(ip_addr_inet);
	conn->local_addr.sin_port        = htons(port_nr);
	if (bind(conn->listen_sock, (struct sockaddr *)&conn->local_addr,
			sizeof(struct sockaddr_in))) {
		NES_LOG(ERR, "Error biding listening socket.\n");
		return NES_FAIL;
	}

	if (listen(conn->listen_sock, 5)) {
		NES_LOG(ERR, "Error listening on socket.\n");
		return NES_FAIL;
	}
	fprintf(stderr, "\n\nStarting to listen on port %d\n\n", port_nr);


	return NES_SUCCESS;
}
#endif

int nes_connection_un_setup(const char *socket_path, tcp_connection_t *conn)
{
	assert(NULL != conn);
	assert(NULL != socket_path);

	conn->addr_len = sizeof(struct sockaddr);
	conn->listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (0 > conn->listen_sock) {
		NES_LOG(ERR, "Error creating listening socket.\n");
		return NES_FAIL;
	}

	memset(&conn->local_un_addr, 0, sizeof(struct sockaddr_un));
	conn->local_un_addr.sun_family      = AF_UNIX;
	strncpy(conn->local_un_addr.sun_path, socket_path,
		sizeof(conn->local_un_addr.sun_path) - 1);
	conn->local_un_addr.sun_path[sizeof(conn->local_un_addr.sun_path) - 1] = 0;
	unlink(conn->local_un_addr.sun_path);
	if (bind(conn->listen_sock, (struct sockaddr *)&conn->local_un_addr,
			sizeof(struct sockaddr_un))) {
		NES_LOG(ERR, "Error biding listening socket.\n");
		return NES_FAIL;
	}

	if (listen(conn->listen_sock, 5)) {
		NES_LOG(ERR, "Error listening on socket.\n");
		return NES_FAIL;
	}
	fprintf(stderr, "\n\nStarting to listen on socket %s\n\n", conn->local_un_addr.sun_path);

	return NES_SUCCESS;
}
