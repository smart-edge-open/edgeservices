/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_acl.c
 * @brief rte_acl wrapper for nes
 */

#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <rte_acl.h>

#include "libnes_acl.h"
#include "nes_common.h"

static int
nes_acl_build_ctx(nes_acl_ctx_t *ctx) {
	assert(ctx);

	int err;
	uint32_t i;
	struct rte_acl_config cfg = {0};
	struct rte_acl_ctx *new_context = NULL, *old_context = NULL;

	if (ctx->entries_cnt == 0) {
		if (ctx->acl_ctx) {
			old_context = ctx->acl_ctx;
			rte_spinlock_lock(&ctx->acl_lock);
			ctx->acl_ctx = NULL;
			rte_spinlock_unlock(&ctx->acl_lock);
			rte_acl_free(old_context);
			NES_LOG(INFO, "No more entries in %s\n", ctx->names[ctx->name_id]);
		}
		return NES_SUCCESS;
	}
	if (ctx->acl_ctx)
		ctx->name_id ^= 1;

	struct rte_acl_param acl_param = {
		.name = ctx->names[ctx->name_id],
		.socket_id = rte_socket_id(),
		.rule_size = RTE_ACL_RULE_SZ(ctx->acl_fields_cnt),
		.max_rule_num = ctx->max_entries
	};
	if (NULL == (new_context = rte_acl_create(&acl_param))) {
		NES_LOG(ERR, "Failed to create nes ACL context\n");
		return NES_FAIL;
	}

	rte_spinlock_lock(&ctx->data_lock);
	for (i = 0; i < ctx->max_entries; i++) {
		if (NULL == ctx->rules[i])
			continue;

		err = rte_acl_add_rules(new_context, ctx->rules[i], 1);
		if (err) {
			NES_LOG(ERR, "Failed to add a rule %d\n", err);
			rte_spinlock_unlock(&ctx->data_lock);
			return NES_FAIL;
		}
	}
	rte_spinlock_unlock(&ctx->data_lock);

	cfg.num_categories = DEFAULT_CATEGORIES;
	cfg.num_fields = ctx->acl_fields_cnt;
	memcpy(cfg.defs, ctx->acl_fields_def, RTE_ACL_RULE_SZ(ctx->acl_fields_cnt));

	err = rte_acl_build(new_context, &cfg);
	if (err) {
		NES_LOG(ERR, "Failed to rebuild runtime structures for nes ACL context %d\n", err);
		return NES_FAIL;
	}

	if (ctx->acl_ctx) {
		old_context = ctx->acl_ctx;
		rte_spinlock_lock(&ctx->acl_lock);
		ctx->acl_ctx = new_context;
		rte_spinlock_unlock(&ctx->acl_lock);
		rte_acl_free(old_context);
	} else
		ctx->acl_ctx = new_context;

	return NES_SUCCESS;
}

int
nes_acl_ctor(nes_acl_ctx_t *ctx, const char *context_name, uint32_t entry_size,
	uint32_t max_entries_cnt, struct rte_acl_field_def* acl_fields_def, uint32_t acl_fields_cnt)
{
	assert(ctx);

	ctx->name_id = 0;
	ctx->entries_cnt = 0;
	ctx->acl_ctx = NULL;
	ctx->entry_size = entry_size;
	ctx->acl_fields_cnt = acl_fields_cnt;
	ctx->acl_fields_def = acl_fields_def;
	ctx->max_entries = max_entries_cnt;

	rte_spinlock_init(&ctx->acl_lock);
	rte_spinlock_init(&ctx->data_lock);
	snprintf(ctx->names[0], RTE_ACL_NAMESIZE, "%s_0", context_name);
	snprintf(ctx->names[1], RTE_ACL_NAMESIZE, "%s_1", context_name);

	ctx->rules = rte_calloc(
		"nes acl rules",
		max_entries_cnt,
		sizeof (struct rte_acl_rule*),
		0);
	ctx->entries = rte_calloc(
		"nes acl entries",
		max_entries_cnt,
		sizeof (void*),
		0);

	if (NULL == ctx->rules || NULL == ctx->entries) {
		NES_LOG(ERR, "Failed to allocate rules or routes table for NES acl\n");
		return NES_FAIL;
	}

	return nes_acl_build_ctx(ctx);
}

void
nes_acl_dtor(nes_acl_ctx_t *ctx) {
	assert(ctx);

	uint32_t i;
	rte_spinlock_lock(&ctx->acl_lock);
	rte_spinlock_lock(&ctx->data_lock);
	for (i = 0; i < ctx->max_entries; i++) {
		if (NULL != ctx->entries[i])
			rte_free(ctx->entries[i]);

		if (NULL != ctx->rules[i])
			rte_free(ctx->rules[i]);
	}
	rte_free(ctx->entries);
	rte_free(ctx->rules);
	ctx->entries = NULL;
	ctx->rules = NULL;

	if (NULL != ctx->acl_ctx)
		rte_acl_free(ctx->acl_ctx);

	rte_spinlock_unlock(&ctx->data_lock);
	rte_spinlock_unlock(&ctx->acl_lock);
}

static void *
nes_acl_dup(void *src, size_t size) {
	void *dst;

	VERIFY_PTR_OR_RET(src, NULL);
	dst = rte_malloc("nes_acl_data", size, 0);
	VERIFY_PTR_OR_RET(dst, NULL);

	return memcpy(dst, src, size);
}

int
nes_acl_add_entries(nes_acl_ctx_t *ctx, void **entries, struct rte_acl_rule **rules, uint32_t count)
{
	assert(ctx);
	assert(entries);
	assert(rules);

	uint32_t i, j;
	void *new_entries[count];
	struct rte_acl_rule *new_rules[count];
	if (ctx->entries_cnt + count > ctx->max_entries) {
		NES_LOG(ERR, "Failed to add, nes acl is full\n");
		return NES_FAIL;
	}

	//-------------Copy input data-------------//
	for (i = 0; i < count; i++) {
		new_entries[i] = nes_acl_dup(entries[i], ctx->entry_size);
		new_rules[i] = nes_acl_dup(rules[i], RTE_ACL_RULE_SZ(ctx->acl_fields_cnt));
		if (NULL == new_entries[i] || NULL == new_rules[i]) {
			// free previously allocated entries and exit
			while (i--) {
				rte_free(new_entries[i]);
				rte_free(new_rules[i]);
			}
			return NES_FAIL;
		}
	}
	//-------------Copy input data-------------//

	rte_spinlock_lock(&ctx->data_lock);
	for (i = 0; i < count; i++) {
		for (j = 0; j < ctx->max_entries; j++) {
			if (NULL == ctx->entries[j] && NULL == ctx->rules[j]) {
				ctx->entries[j] = new_entries[i];
				ctx->rules[j] = new_rules[i];
				ctx->rules[j]->data.userdata = USER_DATA_OFFSET + j;
				ctx->entries_cnt++;
				break;
			}
		}
	}
	rte_spinlock_unlock(&ctx->data_lock);
	return nes_acl_build_ctx(ctx);
}

int
nes_acl_del_entry(nes_acl_ctx_t *ctx, struct rte_acl_rule *rule) {
	assert(ctx);

	int i, entry_id;
	rte_spinlock_lock(&ctx->data_lock);
	i = nes_acl_find_rule_id(ctx, rule);

	if (i < 0 ||
			(entry_id = ctx->rules[i]->data.userdata - USER_DATA_OFFSET) < 0 ||
			entry_id > (int) ctx->max_entries - 1) {
		rte_spinlock_unlock(&ctx->data_lock);
		return NES_FAIL;
	}
	rte_free(ctx->entries[entry_id]);
	rte_free(ctx->rules[i]);
	ctx->entries[entry_id] = NULL;
	ctx->rules[i] = NULL;
	ctx->entries_cnt--;
	rte_spinlock_unlock(&ctx->data_lock);
	return nes_acl_build_ctx(ctx);
}

int
nes_acl_find_rule_id(nes_acl_ctx_t *ctx, struct rte_acl_rule *rule) {
	assert(ctx);

	int i;
	if (NULL == rule || 0 == ctx->entries_cnt)
		return -1;

	for (i = 0; i < (int) ctx->max_entries; i++) {
		if ((NULL != ctx->rules[i]) && (0 == memcmp(ctx->rules[i]->field, rule->field,
				sizeof (struct rte_acl_field)*ctx->acl_fields_cnt)))
			return i;
	}
	return -1;
}
