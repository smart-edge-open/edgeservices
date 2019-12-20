/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file test_main.c
 * @brief Main for nes tests
 */

#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <CUnit/CUnit.h>
#include <CUnit/Console.h>
#include <CUnit/Basic.h>
#include "nes_main.h"
#include "nes_common.h"

#include "test_libnes_api.h"
#include "test_nes_main.h"
#include "test_nes_tcp_connection.h"
#include "test_nes_arp.h"
#include "test_nes_common.h"
#include "test_nes_ring.h"
#include "test_nes_configuration.h"
#include "test_nes_dev_eth.h"
#include "test_nes_dev_vhost.h"
#include "test_nes_ring_lookup.h"
#include "test_nes_ctrl.h"
#include "test_nes_dns_tools.h"
#include "test_nes_dns_hosts.h"
#include "test_nes_dns_config.h"
#include "test_nes_dns.h"
#include "test_nts_edit.h"
#include "test_nes_mac_lookup.h"
#include "test_nts_lookup.h"
#include "test_nis_acl.h"
#include "test_nis_io.h"
#include "test_nis_routing_data.h"
#include "test_nis_param.h"
#include "test_nts_io.h"
#include "test_nes_dev_port.h"
#include "test_nts_acl.h"
#include "test_nes_io.h"

char *nes_local_cfg_file;
volatile int nes_thread_terminate = 0;

void add_suites_to_registry(void);

int NES_TEST_MAIN(int argc, char * argv[])
{
	/* DPDK init */
	rte_eal_init(argc, argv);

	/* Store cfg file path */
	nes_local_cfg_file = malloc(sizeof (char) * strlen(argv[1]) + 1);
	if (!nes_local_cfg_file)
		return -1;

	strncpy(nes_local_cfg_file, argv[1], strlen(argv[1]) + 1);

	CU_initialize_registry();
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	CU_basic_set_mode(CU_BRM_VERBOSE);
	assert(!CU_is_test_running());

	add_suites_to_registry();

	CU_basic_run_tests();
	CU_cleanup_registry();

	return CU_get_error();
}

void add_suites_to_registry(void){
	add_nes_main_suite_to_registry();
	add_nis_io_suite_to_registry();
	add_nis_acl_suite_to_registry();
	add_nts_acl_suite_to_registry();
	add_nts_lookup_suite_to_registry();
	add_nes_dev_vhost_suite_to_registry();
	add_nes_libnes_api_suite_to_registry();
	add_nes_tcp_connection_suite_to_registry();
	add_nes_arp_suite_to_registry();
	add_nes_common_suite_to_registry();
	add_nes_ring_suite_to_registry();
	add_nes_configuration_suite_to_registry();
	add_nes_dns_tools_suite_to_registry();
	add_nes_dns_hosts_suite_to_registry();
	add_nes_dns_config_suite_to_registry();
	add_nes_dns_suite_to_registry();
	add_nts_edit_suite_to_registry();
	add_nes_mac_lookup_suite_to_registry();
	add_nis_routing_data_suite_to_registry();
	add_nis_param_suite_to_registry();
	add_nes_io_suite_to_registry();
	add_nes_ring_lookup_suite_to_registry();
	add_nes_dev_eth_suite_to_registry();
	add_nes_dev_port_suite_to_registry();
	add_nes_ctrl_suite_to_registry();
	add_nts_io_suite_to_registry();
}
