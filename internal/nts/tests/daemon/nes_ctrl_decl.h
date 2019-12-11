/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_CTRL_DECL_H_
#define NES_CTRL_DECL_H_

#define FILE_NAME nes_ctrl
#include "mock.h"
#include "nis/nis_param.h"
#include "nts/nts_acl.h"
#include "ctrl/nes_configuration.h"
#include "ctrl/nes_tcp_connection.h"
#include <sys/stat.h>

int nes_handle_msg(nes_api_msg_t *api_msg, nes_api_msg_t **response);

MOCK_DECL(nes_lookup_entry_find);
#define nes_lookup_entry_find MOCK_NAME(mocked_nes_lookup_entry_find)

MOCK_DECL(nis_param_rab_set);
#define nis_param_rab_set MOCK_NAME(mocked_nis_param_rab_set)

MOCK_DECL(nis_param_rab_get);
#define nis_param_rab_get MOCK_NAME(mocked_nis_param_rab_get)

MOCK_DECL(nis_param_rab_del);
#define nis_param_rab_del MOCK_NAME(mocked_nis_param_rab_del)

//MOCK_DECL(nis_routing_data_get);
//#define nis_routing_data_get MOCK_NAME(mocked_nis_routing_data_get)

MOCK_DECL(nes_lookup_ctor);
#define nes_lookup_ctor MOCK_NAME(mocked_nes_lookup_ctor)
MOCK_DECL(nts_acl_lookup_init);
#define nts_acl_lookup_init MOCK_NAME(mocked_nts_acl_lookup_init)
MOCK_DECL(nes_server_configure);
#define nes_server_configure MOCK_NAME(mocked_nes_server_configure)
#ifdef EXT_CTRL_SOCKET
	MOCK_DECL(nes_connection_setup);
	#define nes_connection_setup MOCK_NAME(mocked_nes_connection_setup)
#endif
MOCK_DECL(nes_connection_un_setup);
#define nes_connection_un_setup MOCK_NAME(mocked_nes_connection_un_setup)
MOCK_DECL(socket);
#define socket MOCK_NAME(mocked_socket)
MOCK_DECL(nes_lookup_entry_get);
#define nes_lookup_entry_get MOCK_NAME(mocked_nes_lookup_entry_get)
MOCK_DECL(nes_lookup_entry_add);
#define nes_lookup_entry_add MOCK_NAME(mocked_nes_lookup_entry_add)
MOCK_DECL(nes_lookup_entry_del);
#define nes_lookup_entry_del MOCK_NAME(mocked_nes_lookup_entry_del)
nts_lookup_tables_t *nts_io_routing_tables_get(void);

//MOCK_DECL(nes_sq_enq);
//#define nes_sq_enq MOCK_NAME(mocked_nes_sq_enq)


static inline void nes_ctrl_mock_init(void) {
	MOCK_RESET(mocked_nes_lookup_entry_find);
	MOCK_RESET(mocked_nis_param_rab_set);
	MOCK_RESET(mocked_nis_param_rab_get);
	MOCK_RESET(mocked_nis_param_rab_del);
	MOCK_RESET(mocked_nes_lookup_ctor);
	MOCK_RESET(mocked_nts_acl_lookup_init);
	MOCK_RESET(mocked_nes_server_configure);
#ifdef EXT_CTRL_SOCKET
	MOCK_RESET(mocked_nes_connection_setup);
#endif
	MOCK_RESET(mocked_nes_connection_un_setup);
	MOCK_RESET(mocked_socket);
	MOCK_RESET(mocked_nes_lookup_entry_get);
	MOCK_RESET(mocked_nes_lookup_entry_add);
	MOCK_RESET(mocked_nes_lookup_entry_del);
//    MOCK_RESET(mocked_nes_sq_enq);
}

#endif
