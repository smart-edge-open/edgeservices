/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_cfgfile.c
 * @brief Implementation of nes library for configuration from file
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "rte_cfgfile.h"

#include "nes_common.h"
#include "libnes_cfgfile.h"

NES_STATIC struct rte_cfgfile *nes_cfgfile;

static size_t strip(char *input, size_t orig_len) {
	size_t new_len = orig_len, i, idx = 1;

	if (!orig_len)
		return 0;

	if (isspace(input[orig_len - 1])) {
		while (new_len > 0 && isspace(input[new_len - 1]))
			input[--new_len] = 0;
	}

	if (isspace(input[0])) {
		while (isspace(input[idx]) && idx < new_len)
			idx++;
		new_len -= idx;
		for (i = 0; i < new_len; i++)
			input[i] = input[i + idx];
		input[i] = 0;
	}
	return new_len;
}

int nes_cfgfile_load(char *filename)
{
	int flags = 0; /* No flags */
	nes_cfgfile = rte_cfgfile_load(filename, flags);
	return NULL == nes_cfgfile ? NES_FAIL : NES_SUCCESS;
}

int nes_cfgfile_entry(const char *section, const char *entry, const char **value)
{
	assert(nes_cfgfile);
	*value = rte_cfgfile_get_entry(nes_cfgfile, section, entry);
	return NULL == *value ? NES_FAIL : NES_SUCCESS;
}

int nes_cfgfile_has_section(const char *section)
{
	assert(nes_cfgfile);
	return 0 == rte_cfgfile_has_section(nes_cfgfile,section) ? NES_FAIL : NES_SUCCESS;
}

int nes_cfgfile_get_entries(const char *sectionname, struct rte_cfgfile_entry  *entries,
	int max_entries)
{
	assert(nes_cfgfile);
	return rte_cfgfile_section_entries(nes_cfgfile, sectionname, entries, max_entries) > 0 ?
		NES_SUCCESS : NES_FAIL;
}

int nes_cfgfile_section_num_entries(const char *sectionname)
{
	assert(nes_cfgfile);
	return rte_cfgfile_section_num_entries(nes_cfgfile, sectionname);
}


void nes_cfgfile_close(void)
{
	rte_cfgfile_close(nes_cfgfile);
	nes_cfgfile = NULL;
}


int
nes_cfgfile_get_lookup_entries(const char *lookup_str, struct cfg_lookup_entry *entries,
	int max_entries) {
	assert(entries);
	char *name_value_pairs[MAX_LOOKUP_ENTRIES];
	uint8_t i, entries_cnt;
	char lookup_str_buf[NES_MAX_LOOKUP_ENTRY_LEN + 1];

	if (strlen(lookup_str) > NES_MAX_LOOKUP_ENTRY_LEN)
		return NES_FAIL;

	strncpy(lookup_str_buf, lookup_str, NES_MAX_LOOKUP_ENTRY_LEN);
	lookup_str_buf[NES_MAX_LOOKUP_ENTRY_LEN] = '\0';
	entries_cnt = rte_strsplit(lookup_str_buf, strlen(lookup_str_buf), name_value_pairs,
		MAX_LOOKUP_ENTRIES, ',');

	if (entries_cnt < 2) {
		NES_LOG(ERR, "Error splitting lookup entries %u\n%s\n", entries_cnt, lookup_str);
		return NES_FAIL;
	}
	if (entries_cnt > max_entries) {
		NES_LOG(WARNING, "Not all lookup entries are going to be read\n");
		entries_cnt = max_entries;
	}
	for (i = 0; i < entries_cnt; i++) {
		char *split[MAX_LOOKUP_ENTRIES];
		if (rte_strsplit(name_value_pairs[i], strlen(name_value_pairs[i]), split,
				MAX_LOOKUP_ENTRIES, ':') != 2) {
			NES_LOG(ERR, "Unable to parse %s\n", name_value_pairs[i]);
			return NES_FAIL;
		}
		snprintf(entries[i].name, sizeof(entries[i].name), "%s", split[0]);
		snprintf(entries[i].value, sizeof(entries[i].value), "%s", split[1]);
		strip(entries[i].name, strnlen(entries[i].name, sizeof (entries[i].name)));
		strip(entries[i].value, strnlen(entries[i].value, sizeof (entries[i].value)));
	}
	return NES_SUCCESS;
}

int
nes_cfgfile_num_lookup_entries(const char *lookup_str) {
	assert(lookup_str);
	char lookup_str_buf[NES_MAX_LOOKUP_ENTRY_LEN + 1];
	strncpy(lookup_str_buf, lookup_str, NES_MAX_LOOKUP_ENTRY_LEN);
	lookup_str_buf[NES_MAX_LOOKUP_ENTRY_LEN] = '\0';
	char *name_value_pairs[MAX_LOOKUP_ENTRIES];
	return rte_strsplit(lookup_str_buf, strlen(lookup_str_buf), name_value_pairs,
		MAX_LOOKUP_ENTRIES, ',');
}
