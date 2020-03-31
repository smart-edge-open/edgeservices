/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nts_acl.h
 * @brief Header file for nts_acl
 */

#ifndef NTS_ACL_H
#define	NTS_ACL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <rte_acl.h>
#include <rte_spinlock.h>

#include "nes_common.h"
#include "nts/nts_acl_cfg.h"

int nts_acl_lookup_init(nes_acl_ctx_t *lookup_ctx);

void nts_acl_lookup_dtor(nes_acl_ctx_t *lookup_ctx);

int nts_acl_lookup_add_vm(nes_acl_ctx_t *lookup_ctx, char *lookup_str,
	struct ether_addr vm_mac_addr, nts_edit_modes_t edit_mode);

int nts_acl_lookup_remove(nes_acl_ctx_t *lookup_ctx, char *lookup_str);

int nts_acl_lookup_find(nes_acl_ctx_t *lookup_ctx, char *lookup_str,
	nes_sq_t **upstream_route, nes_sq_t **downstream_route);

int nts_acl_add_dataplane_entries(nes_acl_ctx_t *lookup_ctx);

void nts_acl_flush(nes_acl_ctx_t *lookup_ctx);

#ifdef	__cplusplus
}
#endif

#endif	/* NTS_ACL_H */
