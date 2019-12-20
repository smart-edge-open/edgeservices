/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_DEV_PORT_DECL_H_
#define NES_DEV_PORT_DECL_H_

#ifndef FILE_NAME
	#define FILE_NAME nes_dev_port
#endif
#include "mock.h"

MOCK_DECL(nts_get_dst_ring);
#define nts_get_dst_ring MOCK_NAME(mocked_nts_get_dst_ring)
void check_eth_port_link_status(uint8_t portid);
int ctor_eth_port(struct nes_dev_s *self, void *data);
int init_eth_port(uint8_t port_num, uint8_t queue_num);
int recv_eth(struct nes_dev_s *self, __attribute__((unused)) void *data);
int send_eth(struct nes_dev_s *self, __attribute__((unused)) void *data);
int get_port_rings(struct nes_dev_s *self);
int scatter_eth_both_mixed(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_upstr_mixed(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_dwstr_mixed(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_both_LTE(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_upstr_LTE(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_dwstr_LTE(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_both_IP(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_upstr_IP(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_dwstr_IP(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_lbp(struct nes_dev_s *self, __attribute__((unused)) void *data);
int scatter_eth_avp(struct nes_dev_s *self, __attribute__((unused)) void *data);
int add_ring_to_ntsqueue(nes_queue_t *ntsqueue, nes_ring_t **rx_rings);
#endif
