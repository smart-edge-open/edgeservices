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

CU_TestInfo tests_suite_nes_tcp_connection[] = {
#ifdef EXT_CTRL_SOCKET
	{ "nes_connection_setup", nes_connection_setup_test},
#endif
	{ "nes_connection_un_setup", nes_connection_un_setup_test},
	CU_TEST_INFO_NULL,
};
