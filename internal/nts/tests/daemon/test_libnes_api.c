/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include "test_libnes_api.h"
#include "libnes_api.h"
#include "libnes_cfgfile.h"
#include "ctrl/nes_ctrl.h"
#include "io/nes_io.h"
#include "nes_ctrl_decl.h"
#include "libnes_api_decl.h"
#include "libnes_cfgfile_def.h"

#define MAX_NEW_CTX 250
#define SERVICENAME_SIZE 64

char * service_names[MAX_NEW_CTX];
static nes_remote_t remote_NEV;

#define CFG_ALLOC_SECTION_BATCH 8
#define CFG_ALLOC_ENTRY_BATCH 16
extern struct rte_cfgfile *nes_cfgfile;
struct rte_cfgfile *cfg_bak;
int nts_ctrl_lcore = 4;

pthread_t nes_ctrl_main_thread;

MOCK_INIT(mocked_nes_cfgfile_load);
MOCK_INIT(mocked_nes_cfgfile_close);

static void *nes_ctrl_main_thread_start(void *arg) {
	(void)arg;
	nes_ctrl_main(NULL);
	return NULL;
}

int init_suite_libnes_api(void)
{
	int i;
	for (i = 0; i < MAX_NEW_CTX; i++) {
		service_names[i] = calloc(sizeof(char), SERVICENAME_SIZE);
		if (NULL == service_names[i]) {
			printf("Unable to allocate needed memory");
			break;
		}
		snprintf(service_names[i], SERVICENAME_SIZE - 1, "%d", i);
	}

	cfg_bak = nes_cfgfile;
	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	if (!nes_cfgfile)
		return CUE_NOMEMORY;

	nes_cfgfile->sections = malloc(
		sizeof(struct rte_cfgfile_section) * CFG_ALLOC_SECTION_BATCH);

	if (!nes_cfgfile->sections) {
		free(nes_cfgfile);
		return CUE_NOMEMORY;
	}

	nes_cfgfile->num_sections = 2;

	static struct rte_cfgfile_section section_NES_SERVER = {
		.name = "NES_SERVER"
	};
	static struct rte_cfgfile_entry  entry_ctrl_socket = {
		.name = "ctrl_socket", .value = "/tmp/test"
	};
	// memcpy(nes_cfgfile->sections[0], &section_NES_SERVER, sizeof(section_NES_SERVER));
	section_NES_SERVER.entries = &entry_ctrl_socket;
	nes_cfgfile->sections[0] = section_NES_SERVER;
	nes_cfgfile->sections[0].num_entries = 1;

	static struct rte_cfgfile_section section_VM_common = {
		.name = "VM common"
	};
	static struct rte_cfgfile_entry  entry_max = {
		.name = "max", .value = "5"
	};

	section_VM_common.entries = &entry_max;
	nes_cfgfile->sections[1] = section_VM_common;
	nes_cfgfile->sections[1].num_entries = 1;

	nes_ctrl_mock_init();

	MOCK_RESET(mocked_nes_cfgfile_load);
	MOCK_RESET(mocked_nes_cfgfile_close);

	nes_thread_terminate = 0;
	rte_atomic32_clear(&threads_started);
	/* start the main thread */
	pthread_create(&nes_ctrl_main_thread, NULL, nes_ctrl_main_thread_start, NULL);
	while (!(THREAD_NES_CTRL_ID & rte_atomic32_read(&threads_started)))
		usleep(1);

	return CUE_SUCCESS;
}

int cleanup_suite_libnes_api(void)
{
	int i;
	void *res;
	nes_thread_terminate = 1;
	nes_conn_init(&remote_NEV, NULL, 0);
	sleep(1);
	pthread_cancel(nes_ctrl_main_thread);
	pthread_join(nes_ctrl_main_thread, &res);

	close(remote_NEV.socket_fd);
	free(nes_cfgfile->sections);
	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;

	for (i = 0; i < MAX_NEW_CTX; i++) {
		if (service_names[i])
			free(service_names[i]);
	}

	MOCK_RESET(mocked_nes_cfgfile_load);
	MOCK_RESET(mocked_nes_cfgfile_close);
	nes_thread_terminate = 0;
	rte_atomic32_clear(&threads_started);
	return CUE_SUCCESS;
}

static int nes_cfgfile_load_fake_success(char *filename) {
	(void)filename;
	return NES_SUCCESS;
}

static void nes_cfgfile_close_fake(void) {

}

static void nes_conn_init_test(void)
{
	MOCK_SET(mocked_nes_cfgfile_load, nes_cfgfile_load_fake_success);
	MOCK_SET(mocked_nes_cfgfile_close, nes_cfgfile_close_fake);
	CU_ASSERT(NES_SUCCESS == nes_conn_init(&remote_NEV, (char*)(uintptr_t)"127.0.0.1", 6666));
	CU_ASSERT(NES_SUCCESS == nes_conn_close(&remote_NEV));
	CU_ASSERT(NES_SUCCESS == nes_conn_init(&remote_NEV, NULL, 0));
	CU_ASSERT(NES_SUCCESS == nes_conn_close(&remote_NEV));
}

static void nes_route_clear_all_test(void) {
	CU_ASSERT(NES_SUCCESS == nes_conn_init(&remote_NEV, NULL, 0));
	sleep(1);
	CU_ASSERT(NES_SUCCESS == nes_route_clear_all(&remote_NEV));
	nes_conn_close(&remote_NEV);
}

void add_nes_libnes_api_suite_to_registry(void) {
	CU_pSuite nes_libnes_api_suite = CU_add_suite("nes_libnes_api", init_suite_libnes_api, cleanup_suite_libnes_api);

	CU_add_test(nes_libnes_api_suite, "nes_conn_init", nes_conn_init_test);
	CU_add_test(nes_libnes_api_suite, "nes_route_clear_all", nes_route_clear_all_test);
}

