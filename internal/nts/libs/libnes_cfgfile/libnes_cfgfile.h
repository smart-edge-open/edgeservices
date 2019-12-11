/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_cfgfile.h
 * @brief Header file for libnes_cfgfile
 */

#ifndef _LIBNES_CFGFILE_H_
#define _LIBNES_CFGFILE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rte_cfgfile.h"
#include <rte_string_fns.h>

#define CFG_FILE_VALUE_LEN CFG_VALUE_LEN
#define CFG_FILE_NAME_LEN CFG_NAME_LEN
#define NES_MAX_LOOKUP_ENTRY_LEN 220
#define NES_MAX_KNI_ENTRY_LEN 64
#define MAX_LOOKUP_ENTRIES 10

struct cfg_lookup_entry {
	char name[CFG_FILE_NAME_LEN];
	char value[CFG_FILE_VALUE_LEN];
};

/**
 * @brief Load configuration file content
 *
 * @param[in] filename - configuration file path
 * @return NES_SUCCESS on success and NES_FAIL on fail
 */
int nes_cfgfile_load(char *filename);

/**
 * @brief Get configuration entry
 *
 * @param[in] section - configuration section
 * @param[in] entry - configuration field
 * @param[out] value - configuration field value
 * @return NES_SUCCESS on success and NES_FAIL on fail
 */
int nes_cfgfile_entry(const char *section, const char *entry, const char **value);

/**
 * @brief Check if configuration section exists
 *
 * @param[in] section - configuration section
 * @return NES_SUCCESS when configuration section exists and NES_FAIL when it does not
 */
int nes_cfgfile_has_section(const char *section);

/**
 * @brief Close previously opened configuration file
 *
 * @return NES_SUCCESS on success and NES_FAIL on fail
 */
void nes_cfgfile_close(void);

/**
 * @brief Get all configuration entries from specified section
 *
 * @param[in] sectionname - configuration section
 * @param[out] entries - configuration entries
 * @param[in] max_entries - max number of entries to get
 * @return NES_SUCCESS on success and NES_FAIL on fail
 */
int nes_cfgfile_get_entries(const char *sectionname, struct rte_cfgfile_entry  *entries,
	int max_entries);

/**
 * @brief Get lookup entries from specified lookup string
 *
 * @param[in] lookup_str - lookup string
 * @param[out] entries - lookup entries
 * @param[in] max_entries - max number of entries to get
 * @return NES_SUCCESS on success and NES_FAIL on fail
 */
int nes_cfgfile_get_lookup_entries(const char *lookup_str, struct cfg_lookup_entry *entries,
	int max_entries);

/**
 * @brief Get the number of lookup entries specified in lookup string
 *
 * @param[in] lookup_str - lookup string
 * @return number of lookup entries
 */
int nes_cfgfile_num_lookup_entries(const char *lookup_str);

/**
 * @brief Get the number of entries in configuration section
 *
 * @param[in] sectionname - configuration section
 * @return number of configuration entries
 */
int nes_cfgfile_section_num_entries(const char *sectionname);

#ifdef __cplusplus
}
#endif

#endif /* _LIBNES_CFGFILE_H_ */
