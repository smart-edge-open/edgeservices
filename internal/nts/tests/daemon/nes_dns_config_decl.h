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
