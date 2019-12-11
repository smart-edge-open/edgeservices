/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_cmdline_parse_string.h
 * @brief Header file for nes_cmdline_parse_string
 */

#ifndef nes_cmdline_parse_string_H
#define	nes_cmdline_parse_string_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "libnes_cfgfile.h"

typedef char nes_cmdline_acl_string_t[NES_MAX_LOOKUP_ENTRY_LEN];
typedef char nes_cmdline_kni_string_t[NES_MAX_KNI_ENTRY_LEN];
extern struct cmdline_token_ops nes_cmdline_token_acl_string_ops;
extern struct cmdline_token_ops nes_cmdline_token_kni_string_ops;

int nes_cmdline_parse_acl_string(cmdline_parse_token_hdr_t *tk, const char *srcbuf, void *res,
	unsigned int buf_len);
int nes_cmdline_parse_kni_string(cmdline_parse_token_hdr_t *tk, const char *srcbuf, void *res,
	unsigned int buf_len);

#define NES_TOKEN_ACL_STRING_INITIALIZER(structure, field, string)  \
	{                                                           \
		{                                                   \
			&nes_cmdline_token_acl_string_ops,          \
			offsetof(structure, field),                 \
		},                                                  \
		{                                                   \
			string,                                     \
		},                                                  \
	}

#define NES_TOKEN_KNI_STRING_INITIALIZER(structure, field, string)  \
	{                                                           \
		{                                                   \
			&nes_cmdline_token_kni_string_ops,          \
			offsetof(structure, field),                 \
		},                                                  \
		{                                                   \
			string,                                     \
		},                                                  \
	}



#ifdef	__cplusplus
}
#endif

#endif	/* nes_cmdline_parse_string_H */
