/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include "test_nes_tcp_connection.h"
#include "nes_common.h"


int init_suite_nes_tcp_connection(void) {
	return CUE_SUCCESS;
}

int cleanup_suite_nes_tcp_connection(void) {
	return CUE_SUCCESS;
}

#ifdef EXT_CTRL_SOCKET
static void nes_connection_setup_test(void) {
	tcp_connection_t conn;

	CU_ASSERT_EQUAL(nes_connection_setup("0.0.0.0", 19999, &conn), NES_SUCCESS);
	close(conn.listen_sock);
	CU_ASSERT_EQUAL(nes_connection_setup("8.8.8.8", 19999, &conn), NES_FAIL);

	struct rlimit rlim;
	size_t i;
	getrlimit(RLIMIT_NOFILE, &rlim);
	int *socks;
	socks = (int*)malloc(rlim.rlim_cur * sizeof(int));
	for (i = 0; i < rlim.rlim_cur; i++)
		socks[i] = socket(AF_INET, SOCK_STREAM, 0);
	CU_ASSERT_EQUAL(nes_connection_setup("0.0.0.0", 19999, &conn), NES_FAIL);
	close(conn.listen_sock);

	for (i = 0; i < rlim.rlim_cur; i++)
		close(socks[i]);
	free(socks);
	close(conn.listen_sock);
}
#endif

static void nes_connection_un_setup_test(void) {
	tcp_connection_t conn;
	CU_ASSERT_EQUAL(nes_connection_un_setup("/tmp/ut_test.socket", &conn), NES_SUCCESS);
	close(conn.listen_sock);
	CU_ASSERT_EQUAL(nes_connection_un_setup("/1234567890/1234567890/", &conn), NES_FAIL);

	struct rlimit rlim;
	size_t i;
	getrlimit(RLIMIT_NOFILE, &rlim);
	int *socks;
	socks = (int*)malloc(rlim.rlim_cur * sizeof(int));

	CU_ASSERT_PTR_NOT_NULL_FATAL(socks);

	for (i = 0; i < rlim.rlim_cur; i++)
		socks[i] = socket(AF_INET, SOCK_STREAM, 0);
	CU_ASSERT_EQUAL(nes_connection_un_setup("/tmp/ut_test.socket", &conn), NES_FAIL);

	for (i = 0; i < rlim.rlim_cur; i++)
		close(socks[i]);
	free(socks);
	close(conn.listen_sock);
}

void add_nes_tcp_connection_suite_to_registry(void) {
	CU_pSuite nes_tcp_connection_suite =
			  CU_add_suite("nes_tcp_connection", init_suite_nes_tcp_connection, cleanup_suite_nes_tcp_connection);

	CU_add_test(nes_tcp_connection_suite, "nes_connection_un_setup", nes_connection_un_setup_test);

	#ifdef EXT_CTRL_SOCKET
	CU_add_test(nes_tcp_connection_suite, "nes_connection_setup", nes_connection_setup_test);
	#endif
}

