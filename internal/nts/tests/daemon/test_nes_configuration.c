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

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "test_nes_configuration.h"
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "libnes_cfgfile_def.h"

extern struct rte_cfgfile *nes_cfgfile;

int init_suite_nes_configuration(void) {
	return CUE_SUCCESS;
}

int cleanup_suite_nes_configuration(void) {
	return CUE_SUCCESS;
}


#define CFG_ALLOC_SECTION_BATCH 8
#define CFG_ALLOC_ENTRY_BATCH 16

static void nes_server_configure_test(void) {

	struct rte_cfgfile *cfg, *cfg_bak;
	cfg = malloc(sizeof (*cfg) + sizeof (cfg->sections[0]) * CFG_ALLOC_SECTION_BATCH);

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 1;

	cfg_bak = nes_cfgfile;

	nes_cfgfile = cfg;

	static struct rte_cfgfile_entry  entries1 = {
		.name = "ctrl_socket", .value = "/tmp/test"
	};
	static struct rte_cfgfile_section sections = {
		.name = "NES_SERVER"

	};

	sections.entries = &entries1;
	cfg->sections = &sections;
	cfg->sections[0].num_entries = 1;

	configuration_t conf;
	CU_ASSERT_EQUAL(nes_server_configure(&conf), NES_SUCCESS);

	memset(cfg->sections[0].entries, 0, sizeof(cfg->sections[0].entries[0]));
	cfg->sections[0].num_entries = 0;

	CU_ASSERT_EQUAL(nes_server_configure(&conf), NES_FAIL);

#ifdef EXT_CTRL_SOCKET
	static struct rte_cfgfile_entry  entries2 = {
		.name = "ctrl_ip", .value = "127.0.0.1"
	};
	cfg->sections[0].entries[0] = entries2;
	cfg->sections[0].num_entries = 1;

	CU_ASSERT_EQUAL(nes_server_configure(&conf), NES_FAIL);

	static struct rte_cfgfile_entry  entries3[] = {
		{ .name = "ctrl_ip", .value = "127.0.0.1" },
		{ .name = "ctrl_port", .value = "19999" },
	};
	cfg->sections[0].entries[0] = entries3[0];
	cfg->sections[0].entries[1] = entries3[1];
	cfg->sections[0].num_entries = 2;

	CU_ASSERT_EQUAL(nes_server_configure(&conf), NES_SUCCESS);

#endif
	free(cfg);
	nes_cfgfile = cfg_bak;
}

CU_TestInfo tests_suite_nes_configuration[] = {
	{ "nes_server_configure", nes_server_configure_test},
	CU_TEST_INFO_NULL,
};
