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

#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <rte_ether.h>
#include "nes_ring.h"
#include "io/nes_mac_lookup.h"
#include "libnes_cfgfile.h"
#include "nes_api_common.h"
#include "test_nes_mac_lookup.h"
#include "libnes_cfgfile_def.h"

extern struct rte_cfgfile *nes_cfgfile;

int init_suite_nes_mac_lookup(void)
{
	return CUE_SUCCESS;
}

int cleanup_suite_nes_mac_lookup(void)
{
	return CUE_SUCCESS;
}

#define CFG_ALLOC_SECTION_BATCH 8
static void test_nes_mac_lookup_init(void)
{
	struct rte_cfgfile *cfg;
	struct rte_cfgfile* global_cfg_file;
	int num_sections = 1; // VM common
	cfg = malloc(sizeof (*cfg));

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = num_sections;

	global_cfg_file = nes_cfgfile;
	nes_cfgfile = cfg;

	static struct rte_cfgfile_section section1 = {
		.name = "VM common",
	};
	cfg->sections = &section1;

	static struct rte_cfgfile_entry  entries2[] = {
		{ .name = "max", .value = "32"},
	};
	cfg->sections[0].entries = entries2;
	cfg->sections[0].num_entries = 1;
	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_init());

	/* Bad or missing max entry */
	static struct rte_cfgfile_entry  entries3[] = {
		{ .name = "invalid", .value = "32"},
	};
	cfg->sections[0].entries[0] = entries3[0];
	cfg->sections[0].num_entries = 1;
	CU_ASSERT_EQUAL(NES_FAIL, nes_mac_lookup_init());

	free(cfg);
	nes_cfgfile = global_cfg_file;
}

static void test_nes_mac_lookup_entry_find(void)
{
	struct mac_entry *data_get;
	struct mac_entry data_add;
	static uint8_t mac_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	struct ether_addr ether_address;

	memcpy(ether_address.addr_bytes, mac_data, ETHER_ADDR_LEN);
	CU_ASSERT_EQUAL(NES_FAIL, nes_mac_lookup_entry_find(&ether_address, &data_get));

	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_entry_add(&ether_address, &data_add));

	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_entry_find(&ether_address, &data_get));
}

static void test_nes_mac_lookup_entry_add(void)
{
	struct mac_entry data_add;
	static uint8_t mac_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	struct ether_addr ether_address;

	struct rte_cfgfile *cfg;
	struct rte_cfgfile* global_cfg_file;
	int num_sections = 1; // Vm common

	cfg = malloc(sizeof (*cfg));

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = num_sections;

	global_cfg_file = nes_cfgfile;
	nes_cfgfile = cfg;

	memcpy(ether_address.addr_bytes, mac_data, ETHER_ADDR_LEN);

	static struct rte_cfgfile_section section1 = {
		.name = "VM common",

	};

	/* MAC authorization OFF */
	static struct rte_cfgfile_entry  entries0[] = {
		{ .name = "max", .value = "32"},
	};
	section1.entries = entries0;
	cfg->sections = &section1;
	cfg->sections[0].num_entries = 1;

	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_init());
	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_entry_add(&ether_address, &data_add));

	/* MAC authorization OFF */
	static struct rte_cfgfile_entry  entries1[] = {
		{ .name = "max", .value = "32"},
	};

	cfg->sections = &section1;
	section1.entries = entries1;
	cfg->sections[0].num_entries = 1;

	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_init());
	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_entry_add(&ether_address, &data_add));

	free(cfg);
	nes_cfgfile = global_cfg_file;
}

static void test_nes_mac_lookup_entry_del(void)
{
	struct mac_entry data_add;
	static uint8_t mac_data[] = {0x00, 0xAA, 0x55, 0xFF, 0xCC, 1};
	struct ether_addr ether_address;

	struct rte_cfgfile *cfg;
	struct rte_cfgfile* global_cfg_file;
	int num_sections = 1; // Vm common

	cfg = malloc(sizeof (*cfg));

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = num_sections;

	global_cfg_file = nes_cfgfile;
	nes_cfgfile = cfg;

	memcpy(ether_address.addr_bytes, mac_data, ETHER_ADDR_LEN);

	static struct rte_cfgfile_section section1 = {
		.name = "VM common",
	};

	/* MAC authorization OFF */
	static struct rte_cfgfile_entry  entries0[] = {
		{ .name = "max", .value = "32"},
	};

	section1.entries = entries0;
	cfg->sections = &section1;
	cfg->sections[0].num_entries = 1;

	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_init());
	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_entry_add(&ether_address, &data_add));

	CU_ASSERT_EQUAL(NES_SUCCESS, nes_mac_lookup_entry_del(&ether_address));

	free(cfg);
	nes_cfgfile = global_cfg_file;
}

CU_TestInfo tests_suite_nes_mac_lookup[] =
{
	{ "test_nes_mac_lookup_init", test_nes_mac_lookup_init},
	{ "test_nes_mac_lookup_entry_find", test_nes_mac_lookup_entry_find},
	{ "test_nes_mac_lookup_entry_add", test_nes_mac_lookup_entry_add},
	{ "test_nes_mac_lookup_entry_del", test_nes_mac_lookup_entry_del},
	CU_TEST_INFO_NULL,
};
