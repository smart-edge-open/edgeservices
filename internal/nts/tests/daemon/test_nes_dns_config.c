/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <rte_ether.h>

#include "dns/nes_dns_config.h"
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "test_nes_dns_config.h"
#include "nes_dns_config_decl.h"
#include "pkt_generator.h"
#include "libnes_cfgfile_def.h"

extern struct rte_cfgfile *nes_cfgfile;

MOCK_INIT(mocked_open);
MOCK_INIT(mocked_ioctl);
MOCK_INIT(mocked_close);
MOCK_INIT(mocked_fcntl);
MOCK_INIT(mocked_socket);

int
init_suite_nes_dns_config(void) {
	MOCK_RESET(mocked_open);
	MOCK_RESET(mocked_ioctl);
	MOCK_RESET(mocked_close);
	MOCK_RESET(mocked_fcntl);
	MOCK_RESET(mocked_socket);
	return CUE_SUCCESS;
}

int
cleanup_suite_nes_dns_config(void) {
	MOCK_RESET(mocked_open);
	MOCK_RESET(mocked_ioctl);
	MOCK_RESET(mocked_close);
	MOCK_RESET(mocked_fcntl);
	MOCK_RESET(mocked_socket);
	return CUE_SUCCESS;
}

static void
nes_dns_ether_aton_test(void) {
	CU_ASSERT_EQUAL(nes_dns_ether_aton("-1:AA:AA:AAXX:AA:AA", NULL), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("XX:XX", NULL), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("AA:AA:AA:AAXX:AA:AA", NULL), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("AA//", NULL), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("", NULL), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("AA", NULL), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("0xFFFFFFFFFFFFFFFFFF", NULL), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("AA:AA:AA:AA:AA:AA::", NULL), NES_FAIL);

	struct ether_addr eth_addr;
	CU_ASSERT_EQUAL(nes_dns_ether_aton("AA:AA:AA:AA:AA:AAFF", &eth_addr), NES_FAIL);

	CU_ASSERT_EQUAL(nes_dns_ether_aton("AA:AA:AA:AA:AA:AA", &eth_addr), NES_SUCCESS);
}

static void
nes_dns_mac_from_cfg_test(void) {
	struct rte_cfgfile *old_cfg, *cfg = malloc(sizeof (*cfg) + sizeof (cfg->sections[0]) * 1);

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 1;

	struct rte_cfgfile_entry  entries0[] = {
		{
			.name = "local-mac",
			.value = "AA:BB:CC:DD:EE:FF"
		}
	};

	struct rte_cfgfile_section sections[] = {
		{ .name = "DNS"},

	};

	sections[0].entries = entries0;
	cfg->sections = sections;
	cfg->sections[0].num_entries = 1;
	old_cfg = nes_cfgfile;
	nes_cfgfile = cfg;
	struct ether_addr mac, mac_act;

	CU_ASSERT_EQUAL(nes_dns_ether_aton(entries0[0].value, &mac_act), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_dns_mac_from_cfg("locak-mac", NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nes_dns_mac_from_cfg("local-mac", &mac), NES_SUCCESS);
	CU_ASSERT_EQUAL(memcmp(&mac, &mac_act, sizeof (mac)), 0);

	nes_cfgfile = old_cfg;

	free(cfg);
}

static void
nes_dns_ip_from_cfg_test(void) {
	struct rte_cfgfile *old_cfg, *cfg = malloc(sizeof (*cfg) + sizeof (cfg->sections[0]) * 1);

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 1;

	struct rte_cfgfile_entry  entries0[] = {
		{
			.name = "local-ip",
			.value = "192.168.1.0"
		}
	};

	struct rte_cfgfile_entry  entries1[] = {
		{
			.name = "local-ip",
			.value = "ASDFq"
		}
	};

	struct rte_cfgfile_section sections[] = {
		{ .name = "DNS"},

	};

	sections[0].entries = entries1;
	cfg->sections = sections;
	cfg->sections[0].num_entries = 1;
	old_cfg = nes_cfgfile;
	nes_cfgfile = cfg;
	uint32_t ip;

	CU_ASSERT_EQUAL(nes_dns_ip_from_cfg("locak-ip", NULL), NES_FAIL);
	CU_ASSERT_EQUAL(nes_dns_ip_from_cfg("local-ip", NULL), NES_FAIL);

	cfg->sections[0].entries[0] = entries0[0];
	CU_ASSERT_EQUAL(nes_dns_ip_from_cfg("local-ip", &ip), NES_SUCCESS);
	CU_ASSERT_EQUAL(ip, rte_cpu_to_be_32(IPv4(192, 168, 1, 0)));
	nes_cfgfile = old_cfg;

	free(cfg);
}

static void
nes_dns_check_forward_unresolved_test(void) {
	struct rte_cfgfile *old_cfg, *cfg = malloc(sizeof (*cfg) + sizeof (cfg->sections[0]) * 1);

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 1;

	struct rte_cfgfile_entry  entries0[] = {
		{
			.name = "forward-unresolved",
			.value = "yes"
		}
	};
	struct rte_cfgfile_entry  entries1[] = {
		{
			.name = "forward-unresolved",
			.value = "no"
		}
	};
	struct rte_cfgfile_section sections[] = {
		{ .name = "DNS"},

	};

	sections[0].entries = entries0;
	cfg->sections = sections;
	cfg->sections[0].num_entries = 1;
	old_cfg = nes_cfgfile;
	nes_cfgfile = cfg;
	uint8_t forward;
	CU_ASSERT_EQUAL(nes_dns_check_forward_unresolved("forward-unresolvedo", &forward),
		NES_FAIL);
	CU_ASSERT_EQUAL(forward, DNS_FORWARD_OFF);
	CU_ASSERT_EQUAL(nes_dns_check_forward_unresolved("forward-unresolved", &forward),
		NES_SUCCESS);
	CU_ASSERT_EQUAL(forward, DNS_FORWARD_ON);
	cfg->sections[0].entries[0] = entries1[0];
	CU_ASSERT_EQUAL(nes_dns_check_forward_unresolved("forward-unresolved", &forward),
		NES_SUCCESS);
	CU_ASSERT_EQUAL(forward, DNS_FORWARD_OFF);
	nes_cfgfile = old_cfg;

	free(cfg);
}

static int open_stub_ret = -1;

static int
open_stub(const char __attribute__((unused)) * pathname, int __attribute__((unused)) flags, ...) {
	return open_stub_ret;
}

static int
close_stub(int __attribute__((unused)) fd) {
	return 0;
}

static int ioctl_stub_ret = -1;
static int *ioctl_stub_arr_ret = NULL;
static int ioctl_stub_arr_id = 0;

static int
ioctl_stub(int __attribute__((unused)) d, unsigned long int __attribute__((unused)) request, ...) {
	if (ioctl_stub_arr_ret)
		return ioctl_stub_arr_ret[ioctl_stub_arr_id++];

	return ioctl_stub_ret;
}

static int fcntl_stub_ret = -1;
static int *fcntl_stub_arr_ret = NULL;
static int fcntl_stub_arr_id = 0;

static int
fcntl_stub(int __attribute__((unused)) fd, int __attribute__((unused)) cmd, ...) {
	if (fcntl_stub_arr_ret)
		return fcntl_stub_arr_ret[fcntl_stub_arr_id++];

	return fcntl_stub_ret;
}

static int socket_stub_ret = 0;
static int
socket_stub(int __attribute__((unused)) domain, int __attribute__((unused)) type,
	int __attribute__((unused)) protocol) {
	return socket_stub_ret;
}

static void
nes_dns_tap_create_test(void) {
	MOCK_SET(mocked_open, open_stub);
	MOCK_SET(mocked_close, close_stub);
	MOCK_SET(mocked_ioctl, ioctl_stub);
	MOCK_SET(mocked_fcntl, fcntl_stub);
	MOCK_SET(mocked_socket, socket_stub);
	const char* tap_name = "dns_agent_tap";
	struct ether_addr mac_addr;
	uint32_t ip_addr;

	CU_ASSERT_EQUAL(nes_dns_tap_create(NULL, NULL, NULL, 0), -1);
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, NULL, NULL, 0), open_stub_ret);
	open_stub_ret = 0;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, NULL, NULL, 0), ioctl_stub_ret);
	ioctl_stub_ret = 0;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, NULL, NULL, 0), fcntl_stub_ret);
	fcntl_stub_ret = 0;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, NULL, NULL, 0), open_stub_ret); // success

	int fcntl_stub_arr[] = {0, -1};
	fcntl_stub_arr_ret = fcntl_stub_arr;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, NULL, NULL, 1), fcntl_stub_arr[1]);

	fcntl_stub_arr_ret = NULL;
	fcntl_stub_ret = 0;
	fcntl_stub_arr_id = 0;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, NULL, NULL, 1), open_stub_ret);

	int ioctl_stub_arr[] = {0, -1};
	ioctl_stub_arr_ret = ioctl_stub_arr;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, &mac_addr, NULL, 1), ioctl_stub_arr[1]);
	ioctl_stub_arr_ret = NULL;
	ioctl_stub_ret = 0;
	ioctl_stub_arr_id = 0;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, &mac_addr, NULL, 1), open_stub_ret);

	int ioctl_stub_arr0[] = {0, 0, -1};
	ioctl_stub_arr_ret = ioctl_stub_arr0;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, &mac_addr, &ip_addr, 1), ioctl_stub_arr0[2]);
	ioctl_stub_arr_id = 0;

	int ioctl_stub_arr1[] = {0, 0, 0, -1};
	ioctl_stub_arr_ret = ioctl_stub_arr1;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, &mac_addr, &ip_addr, 1), ioctl_stub_arr1[3]);
	ioctl_stub_arr_id = 0;

	int ioctl_stub_arr2[] = {0, 0, 0, 0, 0, -1};
	ioctl_stub_arr_ret = ioctl_stub_arr2;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, &mac_addr, &ip_addr, 1), ioctl_stub_arr2[5]);
	ioctl_stub_arr_id = 0;

	ioctl_stub_arr_ret = NULL;
	ioctl_stub_ret = 0;
	ioctl_stub_arr_id = 0;
	socket_stub_ret = -1;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, &mac_addr, &ip_addr, 1), socket_stub_ret);

	socket_stub_ret = 0;
	CU_ASSERT_EQUAL(nes_dns_tap_create(tap_name, &mac_addr, &ip_addr, 1), open_stub_ret);
}

void add_nes_dns_config_suite_to_registry(void) {
	CU_pSuite nes_dns_config_suite = CU_add_suite("nes_dns_config", init_suite_nes_dns_config, cleanup_suite_nes_dns_config);

	CU_add_test(nes_dns_config_suite, "nes_dns_ether_aton_test", nes_dns_ether_aton_test);
	CU_add_test(nes_dns_config_suite, "nes_dns_mac_from_cfg_test", nes_dns_mac_from_cfg_test);
	CU_add_test(nes_dns_config_suite, "nes_dns_ip_from_cfg_test", nes_dns_ip_from_cfg_test);
	CU_add_test(nes_dns_config_suite, "nes_dns_check_forward_unresolved_test", nes_dns_check_forward_unresolved_test);
	CU_add_test(nes_dns_config_suite, "nes_dns_tap_create_test", nes_dns_tap_create_test);
}

