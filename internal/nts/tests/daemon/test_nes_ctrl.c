/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include "test_nes_ctrl.h"
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "nis/nis_acl.h"
#include "nis/nis_routing_data.h"
#include "io/nes_io.h"
#include "nes_ctrl_decl.h"
#include "libnes_api.h"
#include "libnes_api_decl.h"
#include "libnes_cfgfile_def.h"

#define LOOKUP_ENTRY "prio:99,srv_ip:12.34.56.78"

#define CFG_ALLOC_SECTION_BATCH 8
#define CFG_ALLOC_ENTRY_BATCH 16

MOCK_INIT(mocked_nis_param_rab_set);
MOCK_INIT(mocked_nis_param_rab_get);
MOCK_INIT(mocked_nis_param_rab_del);
MOCK_INIT(mocked_nes_lookup_ctor);
MOCK_INIT(mocked_nts_acl_lookup_init);
MOCK_INIT(mocked_nes_server_configure);
#ifdef EXT_CTRL_SOCKET
	MOCK_INIT(mocked_nes_connection_setup);
#endif
MOCK_INIT(mocked_nes_connection_un_setup);
MOCK_INIT(mocked_socket);
MOCK_INIT(mocked_nes_lookup_entry_get);
MOCK_INIT(mocked_nes_lookup_entry_add);
MOCK_INIT(mocked_nes_lookup_entry_del);
MOCK_INIT(mocked_nes_lookup_entry_find);
//MOCK_INIT(mocked_nes_sq_enq);

struct rte_cfgfile *cfg_bak;
extern struct rte_cfgfile *nes_cfgfile;
extern nes_acl_ctx_t nis_param_acl_ctx;

static struct rte_cfgfile_section section_VM_common = {
	.name = "VM common"
};
static struct rte_cfgfile_entry  entry_max = {
	.name = "max", .value = "5"
};

static struct rte_cfgfile_section section_NES_SERVER = {
	.name = "NES_SERVER"
};
static struct rte_cfgfile_entry  entry_ctrl_socket[] = {
	{ .name = "ctrl_socket", .value = "/tmp/test" },
	{ .name = "ctrl_ip", .value = "0.0.0.0" },
	{ .name = "ctrl_port", .value = "19999" },
};

struct add_route_data {
	struct ether_addr vm_mac_addr;
	char lookup[];
};

int init_suite_nes_ctrl(void) {
	nes_ctrl_mock_init();

	cfg_bak = nes_cfgfile;
	nes_cfgfile = malloc(sizeof (*nes_cfgfile));

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile);

	nes_cfgfile->sections = malloc(
		sizeof(struct rte_cfgfile_section) * CFG_ALLOC_SECTION_BATCH);

	CU_ASSERT_PTR_NOT_NULL_FATAL(nes_cfgfile->sections);

	nes_cfgfile->num_sections = 1;

	section_VM_common.entries = &entry_max;
	nes_cfgfile->sections[0] = section_VM_common;
	nes_cfgfile->sections[0].num_entries = 1;

	nes_cfgfile->num_sections = 2;
	section_NES_SERVER.entries = entry_ctrl_socket;
	nes_cfgfile->sections[1] = section_NES_SERVER;
	nes_cfgfile->sections[1].num_entries = 1;

	return CUE_SUCCESS;
}

int cleanup_suite_nes_ctrl(void) {
	nes_ctrl_mock_init();
	nis_param_ctx_dtor(&nis_param_acl_ctx);
	free(nes_cfgfile->sections);
	free(nes_cfgfile);
	nes_cfgfile = cfg_bak;
	MOCK_RESET(mocked_nes_lookup_entry_find);
	return CUE_SUCCESS;
}


static int nts_acl_lookup_init_fake_fail(nes_acl_ctx_t* lookup_ctx) {
	(void)lookup_ctx;
	return NES_FAIL;
}

static int nes_server_configure_fake_fail(configuration_t *conf) {
	(void)conf;
	return NES_FAIL;
}

#ifdef EXT_CTRL_SOCKET
static int
nes_connection_setup_fake_success(const char *ip_addr, uint16_t port_nr, tcp_connection_t *conn) {
	(void)ip_addr;
	(void)port_nr;
	(void)conn;
	return NES_SUCCESS;
}

static int
nes_connection_setup_fake_fail(const char *ip_addr, uint16_t port_nr, tcp_connection_t *conn) {
	(void)ip_addr;
	(void)port_nr;
	(void)conn;
	return NES_FAIL;
}
#endif

static int nes_connection_un_setup_fake_fail(const char *socket_path, tcp_connection_t *conn) {
	(void)socket_path;
	(void)conn;
	return NES_FAIL;
}

void nes_ctrl_init_test(void) {
	nes_cfgfile->num_sections = 1;  //only VM_common section

	MOCK_SET(mocked_nts_acl_lookup_init, nts_acl_lookup_init_fake_fail);
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_FAIL);
	MOCK_RESET(mocked_nts_acl_lookup_init);

	nis_param_ctx_dtor(&nis_param_acl_ctx);
	MOCK_SET(mocked_nes_server_configure, nes_server_configure_fake_fail);
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_FAIL);
	MOCK_RESET(mocked_nes_server_configure);
	nis_param_ctx_dtor(&nis_param_acl_ctx);

	nes_cfgfile->num_sections = 2;
	section_NES_SERVER.entries = entry_ctrl_socket;
	nes_cfgfile->sections[1] = section_NES_SERVER;
	nes_cfgfile->sections[1].num_entries = 1;

	MOCK_SET(mocked_nes_connection_un_setup, nes_connection_un_setup_fake_fail);
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_FAIL);
	MOCK_RESET(mocked_nes_connection_un_setup);
	nis_param_ctx_dtor(&nis_param_acl_ctx);

	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_FAIL);

	nis_param_ctx_dtor(&nis_param_acl_ctx);

#ifdef EXT_CTRL_SOCKET
	nes_cfgfile->sections[1] = section_NES_SERVER;
	nes_cfgfile->sections[1].entries[0] = entry_ctrl_socket[1];
	nes_cfgfile->sections[1].entries[1] = entry_ctrl_socket[2];
	nes_cfgfile->sections[1].num_entries = 2;

	MOCK_SET(mocked_nes_connection_setup, nes_connection_setup_fake_fail);
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_FAIL);
	nis_param_ctx_dtor(&nis_param_acl_ctx);

	MOCK_SET(mocked_nes_connection_setup, nes_connection_setup_fake_success);
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_SUCCESS);
	MOCK_RESET(mocked_nes_connection_setup);
	nis_param_ctx_dtor(&nis_param_acl_ctx);

	MOCK_SET(mocked_nes_connection_setup, nes_connection_setup_fake_success);
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_SUCCESS);
	MOCK_RESET(mocked_nes_connection_setup);
#endif
}

void nes_ctrl_ctor_list_test(void) {
	CU_ASSERT_EQUAL(nes_ctrl_ctor_dev_list(), NES_SUCCESS);
}

void nes_ctrl_add_del_device_test(void) {
	nes_dev_t dev1, dev2;//, dev3;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_FAIL);
}

static nes_api_msg_t *api_frame(uint16_t func_id, void *data, size_t length) {
	nes_api_msg_t *api_msg = NULL;
	api_msg = malloc(sizeof(nes_api_msg_t) + length);

	CU_ASSERT_PTR_NOT_NULL_FATAL(api_msg);

	api_msg->message_type = eRequest;
	api_msg->function_id = func_id;
	if (length)
		memcpy(api_msg->data, data, length);

	api_msg->data_size = length;
	return api_msg;
}

static void route_add_test(uint8_t is_mirror) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;

	const char *lookup_keys = LOOKUP_ENTRY;

	struct ether_addr vm_mac_addr;
	memset(&vm_mac_addr, 0, sizeof(vm_mac_addr));

	uint16_t keys_len = strlen(lookup_keys) + 1;
	uint16_t data_len = sizeof(struct add_route_data) + sizeof(char) * keys_len;

	struct add_route_data* data = malloc(sizeof(nes_api_msg_t) + data_len);

	CU_ASSERT_PTR_NOT_NULL_FATAL(data);

	data->vm_mac_addr = vm_mac_addr;

	strncpy(data->lookup, lookup_keys, keys_len);

	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	api_msg = api_frame(is_mirror ? eNesAddMirror : eNesAddRoute, data, data_len);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	free(data);

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

static void route_del_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;

	char *lookup_keys = (char*)(uintptr_t)LOOKUP_ENTRY;
	uint16_t data_len = sizeof(char) * strlen(lookup_keys) + 1;

	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	api_msg = api_frame(eNesDelRoute, lookup_keys, data_len);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

void nes_ctrl_route_add_del_test(void) {
	route_add_test(0);
	route_add_test(0);
	route_del_test();
	route_add_test(1);
	route_del_test();
}

void nes_ctrl_show_list_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	api_msg = api_frame(eNesStatsShowList, NULL, 0);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

void nes_ctrl_show_dev_all_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	api_msg = api_frame(eNesStatsDevAll, NULL, 0);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

void nes_handle_msg_test(void) {
	nes_api_msg_t msg;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	CU_ASSERT_EQUAL(nes_handle_msg(NULL, &api_response), -1);
	CU_ASSERT_EQUAL(nes_handle_msg(&msg, NULL), -1);
	api_msg = api_frame(5555, NULL, 0);
	CU_ASSERT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	api_msg->message_type = eResponse;
	CU_ASSERT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
}

void nes_ctrl_stats_dev_test(void) {
	uint16_t id = 0;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	api_msg = api_frame(eNesStatsDev, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	id = 5;
	api_msg = api_frame(eNesStatsDev, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	id = 1;
	api_msg = api_frame(eNesStatsDev, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

void nes_ctrl_show_stats_test(void) {
	nes_dev_t dev1, dev2;
	nes_dev_stats_t stats;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	uint16_t id = 0;
	int status = NES_SUCCESS;
	for (id = 0; id < 3; id++) {
		if (2 <= id)
			status = NES_FAIL;
		else
			status = NES_SUCCESS;
		CU_ASSERT(nes_ctrl_show_dev_stats(id, &stats) == status);
		CU_ASSERT(nes_ctrl_show_dev_stats(id, NULL) == status);
	}

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

void nes_ctrl_route_show_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;

	char *lookup_keys = (char*)(uintptr_t)LOOKUP_ENTRY;
	struct ether_addr vm_mac_addr;
	memset(&vm_mac_addr, 0, sizeof(vm_mac_addr));

	uint16_t data_len = sizeof(char) * strlen(lookup_keys) + 1;

	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);
	route_add_test(0);

	api_msg = api_frame(eNesShowRoute, lookup_keys, data_len);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	route_del_test();
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

void nes_ctrl_get_mac_addr_test(void) {
	uint16_t id = 0;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	api_msg = api_frame(eNesMacAddressGet, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	id = 5;
	api_msg = api_frame(eNesMacAddressGet, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	id = 1;
	api_msg = api_frame(eNesMacAddressGet, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

void nes_ctrl_clear_routes_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);

	struct rte_cfgfile *cfg, *cfg_bak;
	cfg = malloc(sizeof (*cfg) + sizeof (cfg->sections[0]) * CFG_ALLOC_SECTION_BATCH);

	CU_ASSERT_PTR_NOT_NULL_FATAL(cfg);

	cfg->num_sections = 0;

	cfg_bak = nes_cfgfile;

	nes_cfgfile = cfg;

	api_msg = api_frame(eNesRouteClearAll, NULL, 0);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	free(cfg);
	nes_cfgfile = cfg_bak;

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
}

void nes_ctrl_clear_stats_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nes_dev_t dev1, dev2;
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev1, "VM"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_device(&dev2, "ETH"), NES_SUCCESS);

	api_msg = api_frame(eNesStatsClearAll, NULL, 0);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);

	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_device(&dev2), NES_SUCCESS);
}

enum nes_flow_function_id {
	eNesAddFlow = 100,
	eNesShowFlow,
	eNesDelFlow,
	eNesAddRouteData,
	eNesDelRouteData,
	eNesShowRouteData,
	eNesShowEncap
};

static int
nis_param_rab_get_fake_success(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow,
	nis_param_rab_t ** param_rab) {
	(void)ctx;
	(void)flow;
	static nis_param_rab_t rab;
	*param_rab = &rab;
	return NES_SUCCESS;
}

static int
nis_param_rab_set_fake_fail(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow,
	nis_param_rab_t *rab_params) {
	(void)ctx;
	(void)flow;
	(void)rab_params;
	return NES_FAIL;
}

static int nis_param_rab_del_fake_success(nes_acl_ctx_t *ctx, nis_param_pkt_flow_t *flow) {
	(void)ctx;
	(void)flow;
	return NES_SUCCESS;
}

void nes_ctrl_flow_add_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	struct add_flow_data {
		nis_param_pkt_flow_t flow_params;
		nis_param_rab_t rab_params;
	} data;

	api_msg = api_frame(eNesAddFlow, &data, sizeof(struct add_flow_data));
	CU_ASSERT_EQUAL(nes_ctrl_init(), NES_SUCCESS);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	MOCK_SET(mocked_nis_param_rab_set, nis_param_rab_set_fake_fail);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	MOCK_RESET(mocked_nis_param_rab_set);
	free(api_msg);
}

void nes_ctrl_flow_show_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	struct show_flow_data {
		nis_param_pkt_flow_t flow_params;
	} data;

	api_msg = api_frame(eNesShowFlow, &data, sizeof(struct show_flow_data));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	MOCK_SET(mocked_nis_param_rab_get, nis_param_rab_get_fake_success);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	MOCK_RESET(mocked_nis_param_rab_get);
	free(api_msg);
}

void nes_ctrl_flow_del_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	struct del_flow_data {
		nis_param_pkt_flow_t flow_params;
	} data;

	api_msg = api_frame(eNesDelFlow, &data, sizeof(struct del_flow_data));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	MOCK_SET(mocked_nis_param_rab_del, nis_param_rab_del_fake_success);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	MOCK_RESET(mocked_nis_param_rab_del);
	free(api_msg);
}

void nes_ctrl_routing_data_add_test(void) {
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	nis_routing_data_key_t routing_key;
	struct routing_msg_s {
		nis_routing_data_key_t routing_key;
		nis_routing_data_t routing_data;
	} data;
	api_msg = api_frame(eNesAddRouteData, &data, sizeof(struct routing_msg_s));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesAddRouteData, &data, sizeof(struct routing_msg_s) - 1);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesDelRouteData, &routing_key, sizeof(nis_routing_data_key_t) - 1);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
}

void nes_ctrl_routing_data_del_test(void) {
	nis_routing_data_key_t routing_key;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	struct routing_msg_s {
		nis_routing_data_key_t routing_key;
		nis_routing_data_t routing_data;
	} data1;

	api_msg = api_frame(eNesDelRouteData, &routing_key, sizeof(nis_routing_data_key_t));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesAddRouteData, &data1, sizeof(struct routing_msg_s));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesDelRouteData, &routing_key, sizeof(nis_routing_data_key_t));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesDelRouteData, &routing_key, sizeof(nis_routing_data_key_t) - 1);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
}

void nes_ctrl_routing_data_show_test(void) {
	nis_routing_data_key_t routing_key;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	struct routing_msg_s {
		nis_routing_data_key_t routing_key;
		nis_routing_data_t routing_data;
	} data1;

	api_msg = api_frame(eNesShowRouteData, &routing_key, sizeof(nis_routing_data_key_t));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesAddRouteData, &data1, sizeof(struct routing_msg_s));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesShowRouteData, &routing_key, sizeof(nis_routing_data_key_t));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesShowRouteData, &routing_key, sizeof(nis_routing_data_key_t) - 1);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	api_msg = api_frame(eNesDelRouteData, &routing_key, sizeof(nis_routing_data_key_t) - 1);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
}

static int
nes_lookup_entry_find_fake_success(nes_lookup_table_t *lookup_table, const void *key, void **pentry)
{
	(void)lookup_table;
	(void)key;
	static nts_enc_entry_t tmp;
	*pentry = &tmp;
	return NES_SUCCESS;
}

static int
nes_lookup_entry_find_fake_fail(nes_lookup_table_t *lookup_table, const void *key, void **pentry) {
	(void)lookup_table;
	(void)key;
	*pentry = NULL;
	return NES_FAIL;
}

void nes_ctrl_encap_show_test(void) {
	uint32_t ip = 0;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	api_msg = api_frame(eNesShowEncap, &ip, sizeof(ip));
	MOCK_SET(mocked_nes_lookup_entry_find, nes_lookup_entry_find_fake_success);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);

	MOCK_SET(mocked_nes_lookup_entry_find, nes_lookup_entry_find_fake_fail);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	MOCK_RESET(mocked_nes_lookup_entry_find);
	free(api_msg);
}

pthread_t nes_ctrl_main_thread;

static void *nes_ctrl_main_thread_start(void *arg) {
	(void)arg;
	nes_ctrl_main(NULL);
	return NULL;
}

static void connect_to_nesctrl(nes_remote_t *remote)
{
	CU_ASSERT_EQUAL(nes_conn_init(remote, NULL, 0), NES_SUCCESS);
	if (-1 == fcntl(remote->socket_fd, F_SETFL,
			fcntl(remote->socket_fd, F_GETFL) | O_NONBLOCK))
		remote->socket_fd = -1;
}

static int nes_cfgfile_load_fake_success(char *filename) {
	(void)filename;
	return NES_SUCCESS;
}

static int
nes_lookup_ctor_fake_fail(nes_lookup_table_t *lookup_table,
	nes_lookup_params_t *lookup_table_params)
{
	(void)lookup_table;
	(void)lookup_table_params;
	return NES_FAIL;
}

static int
nes_lookup_entry_get_fake_fail(nes_lookup_table_t *lookup_table, const void *key, void **pentry)
{
	(void)lookup_table;
	(void)key;
	*pentry = NULL;
	return NES_FAIL;
}

static void nes_cfgfile_close_fake(void)
{
}

#define MAX_CONNECTIONS         64
#define TEST_PACKET_LENGTH      100
#define TEST_PACKET_PART_1      sizeof(LOOKUP_ENTRY)/2
#define MAX_RESPONSE_LENGTH     512
#define DEFAULT_RESPONSE_TOUT   100000

void nes_ctrl_main_test(void)
{
	nes_remote_t *remote_NEV;
	void *res;
	uint8_t *buffer;
	nes_api_msg_t *api_msg;
	nes_api_msg_t *response;

	MOCK_SET(mocked_nts_acl_lookup_init, nts_acl_lookup_init_fake_fail);
	CU_ASSERT_EQUAL(nes_ctrl_main(NULL), NES_FAIL);
	MOCK_RESET(mocked_nts_acl_lookup_init);
	nis_param_ctx_dtor(&nis_param_acl_ctx);

	MOCK_SET(mocked_nes_lookup_ctor, nes_lookup_ctor_fake_fail);
	CU_ASSERT_EQUAL(nes_ctrl_main(NULL), NES_FAIL);
	MOCK_RESET(mocked_nes_lookup_ctor);
	nis_param_ctx_dtor(&nis_param_acl_ctx);

	MOCK_SET(mocked_nes_cfgfile_load, nes_cfgfile_load_fake_success);
	MOCK_SET(mocked_nes_cfgfile_close, nes_cfgfile_close_fake);
	rte_atomic32_clear(&threads_started);
	pthread_create(&nes_ctrl_main_thread, NULL, nes_ctrl_main_thread_start, NULL);
	while (!(THREAD_NES_CTRL_ID & rte_atomic32_read(&threads_started)))
		usleep(1);

	remote_NEV = calloc(MAX_CONNECTIONS, sizeof(nes_remote_t));

	if (NULL == remote_NEV)
		return;

	connect_to_nesctrl(&remote_NEV[0]);

	buffer = malloc(sizeof(nes_api_msg_t) + TEST_PACKET_LENGTH);
	response = malloc(sizeof(nes_api_msg_t) + MAX_RESPONSE_LENGTH);
	if (NULL != buffer && NULL != response) {
		char *lookup_keys = (char*)(uintptr_t)LOOKUP_ENTRY;
		uint16_t keys_len = strlen(lookup_keys) + 1;
		uint16_t data_len = sizeof(struct add_route_data) + sizeof(char) * keys_len;
		struct ether_addr vm_mac_addr;
		memset(&vm_mac_addr, 0, sizeof(vm_mac_addr));

		api_msg = (nes_api_msg_t*)buffer;
		api_msg->message_type = eRequest;
		api_msg->function_id = eNesAddRoute;

		struct add_route_data* add_route_data = (struct add_route_data*)api_msg->data;
		add_route_data->vm_mac_addr = vm_mac_addr;
		strncpy(add_route_data->lookup, lookup_keys, keys_len);

		api_msg->data_size = TEST_PACKET_LENGTH - sizeof(nes_api_msg_t);
		send(remote_NEV[0].socket_fd, buffer, TEST_PACKET_PART_1, MSG_NOSIGNAL);
		usleep(DEFAULT_RESPONSE_TOUT);
		CU_ASSERT(0 >= recv(remote_NEV[0].socket_fd, response,
			MAX_RESPONSE_LENGTH, MSG_NOSIGNAL));

		connect_to_nesctrl(&remote_NEV[1]);

		send(remote_NEV[1].socket_fd, buffer, TEST_PACKET_LENGTH, MSG_NOSIGNAL);
		usleep(DEFAULT_RESPONSE_TOUT);
		CU_ASSERT(0 < recv(remote_NEV[1].socket_fd, response,
			MAX_RESPONSE_LENGTH, MSG_NOSIGNAL));

		send(remote_NEV[0].socket_fd, &buffer[TEST_PACKET_PART_1],
			TEST_PACKET_LENGTH - TEST_PACKET_PART_1, MSG_NOSIGNAL);
		usleep(DEFAULT_RESPONSE_TOUT);
		CU_ASSERT(0 < recv(remote_NEV[0].socket_fd, response,
			MAX_RESPONSE_LENGTH, MSG_NOSIGNAL));

		api_msg->function_id = 0xff;
		send(remote_NEV[1].socket_fd, buffer, TEST_PACKET_LENGTH, MSG_NOSIGNAL);
		usleep(DEFAULT_RESPONSE_TOUT);
		CU_ASSERT(0 >= recv(remote_NEV[0].socket_fd, response,
			MAX_RESPONSE_LENGTH, MSG_NOSIGNAL));

		/* 2 packets sent at once */
		int packet_length;
		api_msg->message_type = eRequest;
		api_msg->function_id = eNesAddRoute;
		api_msg->data_size = data_len;
		packet_length = api_msg->data_size + sizeof(nes_api_msg_t);

		api_msg = (nes_api_msg_t*)&buffer[packet_length];
		api_msg->message_type = eRequest;
		api_msg->function_id = eNesDelRoute;
		api_msg->data_size = sizeof(char) * strlen(lookup_keys) + 1;

		strncpy((char*)api_msg->data, lookup_keys, TEST_PACKET_LENGTH - packet_length);
		packet_length += api_msg->data_size + sizeof(nes_api_msg_t);
		send(remote_NEV[1].socket_fd, buffer, packet_length, MSG_NOSIGNAL);
		usleep(DEFAULT_RESPONSE_TOUT);
		CU_ASSERT(0 < recv(remote_NEV[1].socket_fd, response,
			MAX_RESPONSE_LENGTH, MSG_NOSIGNAL));

		MOCK_SET(mocked_nes_lookup_entry_find, nes_lookup_entry_find_fake_fail);
		send(remote_NEV[1].socket_fd, buffer, packet_length, MSG_NOSIGNAL);
		usleep(DEFAULT_RESPONSE_TOUT);
		CU_ASSERT(0 < recv(remote_NEV[1].socket_fd, response,
			MAX_RESPONSE_LENGTH, MSG_NOSIGNAL));

		MOCK_SET(mocked_nes_lookup_entry_get, nes_lookup_entry_get_fake_fail);
		send(remote_NEV[1].socket_fd, buffer, packet_length, MSG_NOSIGNAL);
		usleep(DEFAULT_RESPONSE_TOUT);
		CU_ASSERT(0 >= recv(remote_NEV[1].socket_fd, response,
			MAX_RESPONSE_LENGTH, MSG_NOSIGNAL));

		connect_to_nesctrl(&remote_NEV[2]);
		usleep(DEFAULT_RESPONSE_TOUT);

		MOCK_RESET(mocked_nes_lookup_entry_get);
		MOCK_RESET(mocked_nes_lookup_entry_find);

		nes_conn_close(&remote_NEV[0]);
		nes_conn_close(&remote_NEV[1]);
		nes_conn_close(&remote_NEV[2]);

		int i = 0;

		for (i = 0; i < MAX_CONNECTIONS; i++) {
			usleep(1000);
			connect_to_nesctrl(&remote_NEV[i]);
		}

		usleep(DEFAULT_RESPONSE_TOUT * 2);

		for (i = 0; i < MAX_CONNECTIONS; i++)
			nes_conn_close(&remote_NEV[i]);

		usleep(DEFAULT_RESPONSE_TOUT * 2);
	}

	if (NULL != buffer)
		free(buffer);
	
	if (NULL != response)
		free(response);

	nes_thread_terminate = 1;
	usleep(10);
	pthread_cancel(nes_ctrl_main_thread);
	pthread_join(nes_ctrl_main_thread, &res);
	MOCK_RESET(mocked_nes_cfgfile_load);
	MOCK_RESET(mocked_nes_cfgfile_close);

	if (NULL != remote_NEV)
		free(remote_NEV);
}

static nes_ring_t ring1;
static nes_ring_t ring2;
static nes_ring_t ring3;

void nes_ctrl_add_ring_test(void) {
	CU_ASSERT_EQUAL(nes_ctrl_add_ring(&ring1, "test1"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_ring(&ring2, "test2"), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_add_ring(&ring3, "test3"), NES_SUCCESS);
}

void nes_ctrl_del_ring_test(void) {
	CU_ASSERT_EQUAL(nes_ctrl_del_ring(&ring2), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_ring(&ring1), NES_SUCCESS);
	CU_ASSERT_EQUAL(nes_ctrl_del_ring(&ring3), NES_SUCCESS);
}

void nes_ctrl_stats_ring_test(void) {
	uint16_t id = 0;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	api_msg = api_frame(eNesStatsRing, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	rte_free(api_response);

	id = -1;
	api_msg = api_frame(eNesStatsRing, &id, sizeof(id));
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	rte_free(api_response);
}

void nes_ctrl_show_ring_all_test(void)
{
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	api_msg = api_frame(eNesStatsRingAll, NULL, 0);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	rte_free(api_response);
}

void nes_ctrl_add_kni_test(void)
{
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	api_msg = api_frame(eNesAddKni, NULL, 0);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	rte_free(api_response);
}

void nes_ctrl_del_kni_test(void)
{
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	api_msg = api_frame(eNesDelKni, NULL, 0);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	CU_ASSERT_NOT_EQUAL(nes_handle_msg(api_msg, &api_response), -1);
	free(api_msg);
	rte_free(api_response);
}

void add_nes_ctrl_suite_to_registry(void) {
	// CU_pSuite nes_ctrl_suite = CU_add_suite("nes_ctrl", init_suite_nes_ctrl, cleanup_suite_nes_ctrl);

	// CU_add_test(nes_ctrl_suite, "nes_ctrl_main", nes_ctrl_main_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_init", nes_ctrl_init_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_ctor_list", nes_ctrl_ctor_list_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_add_del_device", nes_ctrl_add_del_device_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_show_list", nes_ctrl_show_list_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_route_add_del", nes_ctrl_route_add_del_test);
	// CU_add_test(nes_ctrl_suite, "nes_handle_msg", nes_handle_msg_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_show_dev_all", nes_ctrl_show_dev_all_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_stats_dev", nes_ctrl_stats_dev_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_show_stats", nes_ctrl_show_stats_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_route_show", nes_ctrl_route_show_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_get_mac_addr", nes_ctrl_get_mac_addr_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_clear_routes", nes_ctrl_clear_routes_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_clear_stats", nes_ctrl_clear_stats_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_flow_add", nes_ctrl_flow_add_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_flow_show", nes_ctrl_flow_show_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_flow_del", nes_ctrl_flow_del_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_routing_data_add", nes_ctrl_routing_data_add_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_routing_data_del", nes_ctrl_routing_data_del_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_routing_data_show", nes_ctrl_routing_data_show_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_encap_show", nes_ctrl_encap_show_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_add_ring", nes_ctrl_add_ring_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_del_ring", nes_ctrl_del_ring_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_stats_ring", nes_ctrl_stats_ring_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_show_ring_all", nes_ctrl_show_ring_all_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_add_kni", nes_ctrl_add_kni_test);
	// CU_add_test(nes_ctrl_suite, "nes_ctrl_del_kni", nes_ctrl_del_kni_test);
}

// TEST COMPLETION
// void nes_ctrl_main_test(void);
// void nes_ctrl_init_test(void);                  //100%
// void nes_ctrl_ctor_list_test(void);             //90% rte_malloc
// void nes_ctrl_add_del_device_test(void);        //del 100%, add 90% end
// void nes_ctrl_show_list_test(void);             //100%
// void nes_ctrl_route_add_del_test(void);
// void nes_handle_msg_test(void);                 //
// void nes_ctrl_show_dev_all_test(void);          //100%
// void nes_ctrl_stats_dev_test(void);             //100%
// void nes_ctrl_show_stats_test(void);
// void nes_ctrl_route_show_test(void);
// void nes_ctrl_get_mac_addr_test(void);
// void nes_ctrl_clear_routes_test(void);          //100%
// void nes_ctrl_clear_stats_test(void);           //100%
// void nes_ctrl_flow_add_test(void);              //100%
// void nes_ctrl_flow_show_test(void);             //100%
// void nes_ctrl_flow_del_test(void);              //100%
// void nes_ctrl_routing_data_add_test(void);
// void nes_ctrl_routing_data_del_test(void);
// void nes_ctrl_routing_data_show_test(void);
// void nes_ctrl_encap_show_test(void);            //rte_zmalloc
// void nes_ctrl_add_ring_test(void);
// void nes_ctrl_del_ring_test(void);
// void nes_ctrl_stats_ring_test(void);
// void nes_ctrl_show_ring_all_test(void);
// void nes_ctrl_add_kni_test(void);
// void nes_ctrl_del_kni_test(void);

