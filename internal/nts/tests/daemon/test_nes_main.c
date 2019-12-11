/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <CUnit/CUnit.h>
#include "nes_common.h"
#include "nes_main_decl.h"
#include "test_nes_main.h"
#include "libnes_cfgfile.h"
#include "nes_ring.h"
#include "io/nes_dev.h"
#include "libnes_cfgfile_def.h"

extern struct rte_cfgfile *nes_cfgfile;
extern char * nes_local_cfg_file;
#define NES_SERVER_CONF_DEFAULT_PATH "/opt/intel/nev_sdk/nes_root/scripts/nes.cfg"

int init_suite_nes_main(void)
{
	char   *nes_conf_path = NULL;

	/* check if environment variable NES_SERVER_CONF exists */
	nes_conf_path = getenv("NES_SERVER_CONF");
	if (NULL == nes_conf_path)
		nes_conf_path = (char*)(uintptr_t)NES_SERVER_CONF_DEFAULT_PATH;

	/* try to load config file from default localization or defined in environment variable */
	if (NES_FAIL == nes_cfgfile_load(nes_conf_path)) {
		NES_LOG(INFO, "Could not load config file %s.", nes_conf_path);
		if (NULL != nes_local_cfg_file) {
			if (NES_FAIL == nes_cfgfile_load(nes_local_cfg_file)) {
				NES_LOG(ERR, "Could not load config file %s.",
					nes_local_cfg_file);
				return -1;
			}
		}
	}

	return CUE_SUCCESS;
}

int cleanup_suite_nes_main(void)
{
	return CUE_SUCCESS;
}

static void test_nes_mempool_init(void)
{
	CU_ASSERT(NES_SUCCESS == nes_mempool_init());
}


static struct rte_cfgfile_section sections[4];

static void test_nes_init_interfaces(void)
{
	struct rte_cfgfile* global_cfg_file;
	int num_sections = 4; // ENB, EPC, LBP, VM common

	global_cfg_file = nes_cfgfile;
	nes_cfgfile = malloc(sizeof (struct rte_cfgfile));

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile);

	nes_cfgfile->sections = malloc(sizeof (struct rte_cfgfile_section) * num_sections);

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile->sections);

	nes_cfgfile->num_sections = num_sections;
	strncpy(sections[0].name, "PORT0", sizeof(sections[0].name));
	strncpy(sections[1].name, "PORT1", sizeof(sections[1].name));
	strncpy(sections[2].name, "PORT2", sizeof(sections[2].name));
	strncpy(sections[3].name, "VM common", sizeof(sections[3].name));

	static struct rte_cfgfile_entry  entries1[] = {
		{ .name = "name", .value = "ENB", },
		{ .name = "traffic-direction", .value = "upstream", },
		{ .name = "traffic-type", .value = "LTE", },
		{ .name = "egress-port", .value = "1", },
	};

	static struct rte_cfgfile_entry  entries2[] = {
		{ .name = "name", .value = "EPC", },
		{ .name = "traffic-direction", .value = "downstream", },
		{ .name = "traffic-type", .value = "LTE", },
		{ .name = "egress-port", .value = "0", },
	};

	static struct rte_cfgfile_entry  entries3[] = {
		{ .name = "name", .value = "LBP", },
		{ .name = "traffic-direction", .value = "lbp", },
		{ .name = "traffic-type", .value = "IP", },
	};

	static struct rte_cfgfile_entry  entries4[] = {
		{ .name = "max", .value = "2", },
	};


	static struct rte_cfgfile_entry  entries5 = {
		.name = "wrong_entry",
		.value = "3",
	};

	sections[0].entries = entries1;
	nes_cfgfile->sections[0] = sections[0];
	nes_cfgfile->sections[0].num_entries = sizeof(entries1)/sizeof(entries1[0]);

	sections[1].entries = entries2;
	nes_cfgfile->sections[1] = sections[1];
	nes_cfgfile->sections[1].num_entries = sizeof(entries2)/sizeof(entries2[0]);

	sections[2].entries = entries3;
	nes_cfgfile->sections[2] = sections[2];
	nes_cfgfile->sections[2].num_entries = sizeof(entries3)/sizeof(entries3[0]);
	sections[3].entries = entries4;
	nes_cfgfile->sections[3] = sections[3];
	nes_cfgfile->sections[3].num_entries = sizeof(entries4)/sizeof(entries4[0]);

	//ring initialization is required
	CU_ASSERT(NES_SUCCESS == nes_ring_init());

	nes_cfgfile->sections[0].entries[0] = entries5;

	free(nes_cfgfile);
	nes_cfgfile = global_cfg_file;
}

static void test_nes_handle_signals(void)
{
	int signal = SIGKILL;
	nes_handle_signals(signal);
	signal = SIGTERM;
	nes_handle_signals(signal);
}

void add_nes_main_suite_to_registry(void) {
	CU_pSuite nes_main_suite = CU_add_suite("nes_main", init_suite_nes_main, cleanup_suite_nes_main);

	CU_add_test(nes_main_suite, "test_nes_mempool_init", test_nes_mempool_init);
	CU_add_test(nes_main_suite, "test_nes_init_interfaces", test_nes_init_interfaces);
	CU_add_test(nes_main_suite, "test_nes_handle_signals", test_nes_handle_signals);
}

