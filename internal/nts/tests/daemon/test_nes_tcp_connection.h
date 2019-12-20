/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_TCP_CONNECTION_H_
#define TEST_NES_TCP_CONNECTION_H_

#include <CUnit/CUnit.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "ctrl/nes_tcp_connection.h"

int init_suite_nes_tcp_connection(void);
int cleanup_suite_nes_tcp_connection(void);

void add_nes_tcp_connection_suite_to_registry(void);

#endif /* TEST_NES_TCP_CONNECTION_H_ */
