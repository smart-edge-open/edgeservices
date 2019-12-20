/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_nts_acl.h"
#include "nes_common.h"
#include "nts/nts_acl.h"
#include "nts_acl_decl.h"
#include "libnes_cfgfile.h"
#include "libnes_cfgfile_def.h"

MOCK_INIT(mocked_nes_acl_ctor);
MOCK_INIT(mocked_nes_acl_add_entries);
MOCK_INIT(mocked_nts_acl_cfg_init_vm_rings_names);

struct rte_cfgfile *cfg_bak;

extern struct rte_cfgfile *nes_cfgfile;
extern nes_lookup_table_t nes_ring_lookup_table;
static struct rte_cfgfile_section section1, section2;

#define CFG_ALLOC_SECTION_BATCH 4
#define CFG_ALLOC_ENTRIES_BATCH 8

static struct rte_cfgfile_entry  entries1[] = {
	{ .name = "mac", .value = "00:00:00:00:00:00", },
	{ .name = NTS_ACL_CFG_ENTRY_NAME, .value = "prio:99,encap_proto:gtpu,srv_ip:12.34.56.78", },
	{ .name = NTS_ACL_CFG_ENTRY_NAME, .value = "prio:9,encap_proto:noencap,srv_ip:12.34.78.56", },
};

static struct rte_cfgfile_section section_VM_common = {
	.name = "VM common"
};
static struct rte_cfgfile_entry  entry_max = {
	.name = "max", .value = "5"
};

static struct rte_cfgfile_entry  entries2[] = {
	{
		.name = "local-mac",
		.value = "AA:BB:CC:DD:EE:FF"
	},
	{
		.name = "local-ip",
		.value = "192.168.1.1"
	},
	{
		.name = "external-ip",
		.value = "192.168.1.1"
	}
};

int init_suite_nts_acl(void) {
	MOCK_RESET(mocked_nes_acl_ctor);
	MOCK_RESET(mocked_nes_acl_add_entries);
	MOCK_RESET(mocked_nts_acl_cfg_init_vm_rings_names);

	cfg_bak = nes_cfgfile;
	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	if (!nes_cfgfile)
		return CUE_NOMEMORY;

	nes_cfgfile->sections =
		malloc(sizeof(struct rte_cfgfile_section) * CFG_ALLOC_ENTRIES_BATCH);

	if (!nes_cfgfile->sections) {
		free(nes_cfgfile);
		return CUE_NOMEMORY;
	}

	strncpy(section1.name, "PORT0", sizeof(section1.name));

	section1.entries = entries1;
	nes_cfgfile->sections[0] = section1;
	nes_cfgfile->sections[0].num_entries = sizeof(entries1)/sizeof(entries1[0]);

	section_VM_common.entries = &entry_max;
	nes_cfgfile->sections[1] = section_VM_common;
	nes_cfgfile->sections[1].num_entries = 1;

	strncpy(section2.name, "DNS", sizeof(section2.name));
	section2.num_entries = sizeof(entries2)/sizeof(entries2[0]);
	section2.entries = entries2;
	nes_cfgfile->sections[2] = section2;

	nes_cfgfile->num_sections = 2;

	return CUE_SUCCESS;
}

int cleanup_suite_nts_acl(void) {
	free(nes_cfgfile->sections);
	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;
	MOCK_RESET(mocked_nes_acl_ctor);
	MOCK_RESET(mocked_nes_acl_add_entries);
	MOCK_RESET(mocked_nts_acl_cfg_init_vm_rings_names);
	return CUE_SUCCESS;
}

static int
nes_acl_ctor_fake(nes_acl_ctx_t *ctx, const char *context_name, uint32_t entry_size,
	uint32_t max_entries_cnt, struct rte_acl_field_def* acl_fields_def, uint32_t acl_fields_cnt)
{
	(void)ctx;
	(void)context_name;
	(void)entry_size;
	(void)max_entries_cnt;
	(void)acl_fields_def;
	(void)acl_fields_cnt;
	return NES_FAIL;
}

static int nts_acl_cfg_init_vm_rings_names_fake(void)
{
	return NES_FAIL;
}

static void nts_acl_lookup_init_test(void)
{
	nes_acl_ctx_t lookup_ctx;
	MOCK_SET(mocked_nes_acl_ctor, nes_acl_ctor_fake);
	CU_ASSERT_EQUAL(nts_acl_lookup_init(&lookup_ctx), NES_FAIL);
	MOCK_RESET(mocked_nes_acl_ctor);
	MOCK_SET(mocked_nts_acl_cfg_init_vm_rings_names, nts_acl_cfg_init_vm_rings_names_fake);
	CU_ASSERT_EQUAL(nts_acl_lookup_init(&lookup_ctx), NES_FAIL);
	MOCK_RESET(mocked_nts_acl_cfg_init_vm_rings_names);

	CU_ASSERT_EQUAL(nts_acl_lookup_init(&lookup_ctx), NES_SUCCESS);

	nts_acl_lookup_dtor(&lookup_ctx);
}

static void nts_acl_lookup_add_impl_test(void)
{
	nes_acl_ctx_t lookup_ctx;
	struct ether_addr mac;
	memset(&mac, 0, sizeof(mac));
	CU_ASSERT_EQUAL(nts_acl_lookup_init(&lookup_ctx), NES_SUCCESS);

	CU_ASSERT_EQUAL(nts_acl_lookup_add_impl(&lookup_ctx, NULL, "test", mac, NTS_EDIT_NODECAP),
		NES_FAIL);
	CU_ASSERT_EQUAL(nts_acl_lookup_add_impl(&lookup_ctx, (char*)(uintptr_t)"testlookup",
		"test2", mac, NTS_EDIT_NODECAP), NES_FAIL);

	nts_acl_lookup_dtor(&lookup_ctx);
}

static void nts_acl_flush_test(void)
{
	nes_acl_ctx_t lookup_ctx;
	char lookup_keys[256];
	struct ether_addr mac;
	memset(&mac, 0, sizeof(mac));
	CU_ASSERT_EQUAL(nts_acl_lookup_init(&lookup_ctx), NES_SUCCESS);
	strncpy(lookup_keys, "prio:99,encap_proto:gtpu,srv_ip:78.34.56.78", sizeof(lookup_keys));
	CU_ASSERT_EQUAL(nts_acl_lookup_add_impl(&lookup_ctx, lookup_keys, "test",
		mac, NTS_EDIT_NODECAP), NES_SUCCESS);
	strncpy(lookup_keys, "prio:99,encap_proto:gtpu,srv_ip:78.74.56.78", sizeof(lookup_keys));
	CU_ASSERT_EQUAL(nts_acl_lookup_add_impl(&lookup_ctx, lookup_keys, "test2",
		mac, NTS_EDIT_NODECAP), NES_SUCCESS);

	nts_acl_flush(&lookup_ctx);
	nts_acl_lookup_dtor(&lookup_ctx);
}

void add_nts_acl_suite_to_registry(void) {
	CU_pSuite nts_acl_suite = CU_add_suite("nts_acl", init_suite_nts_acl, cleanup_suite_nts_acl);

	CU_add_test(nts_acl_suite, "nts_acl_lookup_init", nts_acl_lookup_init_test);
	CU_add_test(nts_acl_suite, "nts_acl_lookup_add_impl", nts_acl_lookup_add_impl_test);
	CU_add_test(nts_acl_suite, "nts_acl_flush", nts_acl_flush_test);
}

