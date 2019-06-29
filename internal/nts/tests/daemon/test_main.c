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

CU_SuiteInfo nes_suites[] = {
	{"nes_main", init_suite_nes_main, cleanup_suite_nes_main,
		tests_suite_nes_main},
	{ "nis_io", init_suite_nis_io, cleanup_suite_nis_io,
		tests_suite_nis_io},
	{ "nis_acl", init_suite_nis_acl, cleanup_suite_nis_acl,
		tests_suite_nis_acl},
	{ "nts_acl", init_suite_nts_acl, cleanup_suite_nts_acl,
		tests_suite_nts_acl},
	{ "nts_lookup", init_suite_nts_lookup, cleanup_suite_nts_lookup,
		tests_suite_nts_lookup},
	{ "nes_dev_vhost", init_suite_nes_dev_vhost, cleanup_suite_nes_dev_vhost,
		tests_suite_nes_dev_vhost},
	{ "nes_libnes_api", init_suite_libnes_api, cleanup_suite_libnes_api,
		tests_suite_libnes_api},
	{ "nes_tcp_connection", init_suite_nes_tcp_connection, cleanup_suite_nes_tcp_connection,
		tests_suite_nes_tcp_connection},
	{ "nes_arp", init_suite_nes_arp, cleanup_suite_nes_arp,
		tests_suite_nes_arp},
	{ "nes_common", init_suite_nes_common, cleanup_suite_nes_common,
		tests_suite_nes_common},
	{ "nes_ring", init_suite_nes_ring, cleanup_suite_nes_ring,
		tests_suite_nes_ring},
	{ "nes_configuration", init_suite_nes_configuration, cleanup_suite_nes_configuration,
		tests_suite_nes_configuration},
	{ "nes_dns_tools", init_suite_nes_dns_tools, cleanup_suite_nes_dns_tools,
		tests_suite_nes_dns_tools},
	{ "nes_dns_hosts", init_suite_nes_dns_hosts, cleanup_suite_nes_dns_hosts,
		tests_suite_nes_dns_hosts},
	{ "nes_dns_config", init_suite_nes_dns_config, cleanup_suite_nes_dns_config,
		tests_suite_nes_dns_config},
	{ "nes_dns", init_suite_nes_dns, cleanup_suite_nes_dns,
		tests_suite_nes_dns},
	{ "nts_edit", init_suite_nts_edit, cleanup_suite_nts_edit,
		tests_suite_nts_edit},
	{ "nes_mac_lookup", init_suite_nes_mac_lookup, cleanup_suite_nes_mac_lookup,
		tests_suite_nes_mac_lookup},
	{ "nis_routing_data", init_suite_nis_routing_data, cleanup_suite_nis_routing_data,
		tests_suite_nis_routing_data},
	{ "nis_param", init_suite_nis_param, cleanup_suite_nis_param,
		tests_suite_nis_param},
	{ "nes_io", init_suite_nes_io, cleanup_suite_nes_io,
		tests_suite_nes_io},
	{ "nes_ring_lookup", init_suite_nes_ring_lookup, cleanup_suite_nes_ring_lookup,
		tests_suite_nes_ring_lookup},
	CU_SUITE_INFO_NULL,
};

static int nes_test_suites(void)
{
	CU_register_suites(nes_suites);
	return 0;
}

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
	nes_test_suites();

	CU_basic_run_tests();
	CU_cleanup_registry();

	return CU_get_error();
}
