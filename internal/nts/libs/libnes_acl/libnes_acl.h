/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_acl.h
 * @brief Header file for libnes_acl
 */

#ifndef _LIBNES_ACL_H
#define	_LIBNES_ACL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <rte_acl.h>
#include <rte_spinlock.h>
#include <assert.h>

#define USER_DATA_OFFSET 1
#define MAX_DATA_NUM 64
#define DEFAULT_CATEGORIES 1

typedef struct nes_acl_ctx_s {
	struct rte_acl_ctx *acl_ctx;
	rte_spinlock_t acl_lock;
	rte_spinlock_t data_lock;

	char names[2][RTE_ACL_NAMESIZE];
	uint8_t name_id;

	void **entries;
	uint32_t entry_size;
	uint32_t entries_cnt;
	uint32_t max_entries;

	struct rte_acl_rule **rules;
	struct rte_acl_field_def* acl_fields_def;
	uint32_t acl_fields_cnt;
} nes_acl_ctx_t;


int nes_acl_ctor(nes_acl_ctx_t *ctx, const char *context_name, uint32_t entry_size,
	uint32_t max_entries_cnt, struct rte_acl_field_def* acl_fields_def,
	uint32_t acl_fields_cnt);
void nes_acl_dtor(nes_acl_ctx_t *ctx);
int nes_acl_add_entries(nes_acl_ctx_t *ctx, void **entries, struct rte_acl_rule **rules,
	uint32_t count);
int nes_acl_del_entry(nes_acl_ctx_t *ctx, struct rte_acl_rule * rule);
int nes_acl_find_rule_id(nes_acl_ctx_t *ctx, struct rte_acl_rule * rule);

static inline void
nes_acl_lookup(nes_acl_ctx_t* ctx, const uint8_t **data, uint32_t data_cnt, void **entries) {
	assert(ctx);

	uint32_t results[MAX_DATA_NUM] = { 0 };
	uint32_t i;

	memset(entries, 0, data_cnt * sizeof(void*));
	if (unlikely(NULL == ctx->acl_ctx))
		return;

	rte_spinlock_lock(&ctx->acl_lock);
	if (likely(NULL != ctx->acl_ctx))
		rte_acl_classify(ctx->acl_ctx, data, results, data_cnt, DEFAULT_CATEGORIES);

	rte_spinlock_unlock(&ctx->acl_lock);
	for (i = 0; i < data_cnt; i++)
		if (results[i])
			entries[i] = ctx->entries[results[i] - USER_DATA_OFFSET];
}

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBNES_ACL_H */
