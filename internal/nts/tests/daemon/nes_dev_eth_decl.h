/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_DEV_ETH_DECL_H_
#define NES_DEV_ETH_DECL_H_

void check_eth_port_link_status(uint8_t portid);
int init_eth_port(uint8_t port_num, uint8_t queue_num);
int recv_eth(struct nes_dev_s *self, __attribute__((unused)) void *data);
int send_eth(struct nes_dev_s *self, __attribute__((unused)) void *data);

#endif
