/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_DNS_CONFIG_DECL_H_
#define NES_DNS_CONFIG_DECL_H_

#include <sys/socket.h>

#ifndef FILE_NAME
	#define FILE_NAME nes_dns
#endif
#include "mock.h"

int nes_dns_ether_aton(const char *mac, struct ether_addr *ether_address);


int open(const char *pathname, int flags, ...);
int ioctl (int __fd, unsigned long int __request, ...) __THROW;
int close(int fd);
int fcntl(int fd, int cmd, ...);



MOCK_DECL(open);
#define open MOCK_NAME(mocked_open)

MOCK_DECL(ioctl);
#define ioctl MOCK_NAME(mocked_ioctl)

MOCK_DECL(close);
#define close MOCK_NAME(mocked_close)

MOCK_DECL(fcntl);
#define fcntl MOCK_NAME(mocked_fcntl)

MOCK_DECL(socket);
#define socket MOCK_NAME(mocked_socket)


#endif
