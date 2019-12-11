/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_cmdline_parse_string.c
 * @brief Implementation of nes_acl_string for cmdline, it is longer than standard cmdline string
 */

#include <inttypes.h>
#include <string.h>

#include <stdio.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include "nes_cmdline_parse_string.h"

struct cmdline_token_ops nes_cmdline_token_acl_string_ops = {
	.parse = nes_cmdline_parse_acl_string,
	.complete_get_nb = NULL,
	.complete_get_elt = NULL,
	.get_help = NULL
};

struct cmdline_token_ops nes_cmdline_token_kni_string_ops = {
	.parse = nes_cmdline_parse_kni_string,
	.complete_get_nb = NULL,
	.complete_get_elt = NULL,
	.get_help = NULL
};

static int
nes_cmdline_parse_string(cmdline_parse_token_hdr_t *tk, const char *buf, void *res,
	unsigned int buf_len, unsigned int max_len) {
	uint16_t token_len = 0;

	if (NULL == res || NULL == tk || NULL == buf || 0 == *buf || buf_len < max_len)
		return -1;

	while (!cmdline_isendoftoken(buf[token_len]))
		token_len++;

	if (token_len > max_len - 1)
		return -1;

	snprintf(res, token_len + 1, "%s", buf);
	return token_len;
}

int nes_cmdline_parse_acl_string(cmdline_parse_token_hdr_t *tk, const char *buf, void *res,
	unsigned int buf_len) {
	return nes_cmdline_parse_string(tk, buf, res, buf_len, NES_MAX_LOOKUP_ENTRY_LEN);
}

int nes_cmdline_parse_kni_string(cmdline_parse_token_hdr_t *tk, const char *buf, void *res,
	unsigned int buf_len) {
	return nes_cmdline_parse_string(tk, buf, res, buf_len, NES_MAX_KNI_ENTRY_LEN);
}
