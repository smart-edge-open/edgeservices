/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef TEST_NES_CTRL_H_
#define TEST_NES_CTRL_H_

#include <CUnit/CUnit.h>
#include "ctrl/nes_ctrl.h"

int init_suite_nes_ctrl(void);
int cleanup_suite_nes_ctrl(void);

void nes_ctrl_init_test(void);
void nes_ctrl_ctor_list_test(void);
void nes_ctrl_add_del_device_test(void);
void nes_ctrl_route_add_del_test(void);
void nes_ctrl_show_list_test(void);
void nes_ctrl_show_dev_all_test(void);
void nes_handle_msg_test(void);
void nes_ctrl_stats_dev_test(void);
void nes_ctrl_show_stats_test(void);
void nes_ctrl_route_show_test(void);
void nes_ctrl_get_mac_addr_test(void);
void nes_ctrl_clear_routes_test(void);
void nes_ctrl_clear_stats_test(void);
void nes_ctrl_flow_add_test(void);
void nes_ctrl_flow_show_test(void);
void nes_ctrl_flow_del_test(void);
void nes_ctrl_routing_data_add_test(void);
void nes_ctrl_routing_data_del_test(void);
void nes_ctrl_routing_data_show_test(void);
void nes_ctrl_encap_show_test(void);
void nes_ctrl_main_test(void);
void nes_ctrl_add_ring_test(void);
void nes_ctrl_del_ring_test(void);
void nes_ctrl_stats_ring_test(void);
void nes_ctrl_show_ring_all_test(void);
void nes_ctrl_add_kni_test(void);
void nes_ctrl_del_kni_test(void);

void add_nes_ctrl_suite_to_registry(void);

#endif /* TEST_NES_CTRL_H_ */
