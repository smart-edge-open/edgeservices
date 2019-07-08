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

#ifndef TEST_NES_DEV_ETH_H_
#define TEST_NES_DEV_ETH_H_

#include <CUnit/CUnit.h>

int init_suite_nes_dev_eth(void);
int cleanup_suite_nes_dev_eth(void);

void test_nes_dev_eth_pci_addr_get(void);
void test_nes_dev_eth_mac_addr_get(void);
void test_check_eth_port_link_status(void);
void test_init_eth_port(void);
void test_send_eth(void);
void test_recv_eth(void);

void add_nes_dev_eth_suite_to_registry(void);

#endif /* TEST_NES_DEV_ETH_H_ */
