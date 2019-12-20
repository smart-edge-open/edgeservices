/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dns_hosts.c
 * @brief implementation of nes_dns_hosts
 */

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <rte_udp.h>
#include <rte_malloc.h>

#include "nes_common.h"
#include "nes_dns_hosts.h"

#ifdef UNIT_TESTS
	#include "nes_dns_hosts_decl.h"
#endif

static char **static_dns_entries;
NES_STATIC uint32_t static_dns_entries_cnt;

NES_STATIC char*
nes_dns_ipv4_host(char* line, size_t line_len) {
	if (NULL == line)
		return NULL;

	line_len = strnlen(line, line_len);
	uint16_t i = 0, ip_idx = 0;
	struct sockaddr_in sa;
	char ipv4_text[MAX_IPv4_STR_LEN];
	char *ret = NULL;

	// ignore preceding white spaces
	while (i < line_len && isspace(line[i])) ++i;

	//check for comment
	if (i < line_len && '#' == line[i])
		return ret;

	//read and validate the ipv4
	while (i < line_len && !isspace(line[i])) {
		if (ip_idx > (MAX_IPv4_STR_LEN - 1))
			return ret;
		ipv4_text[ip_idx++] = line[i++];
	}
	if (ip_idx >= (MIN_IPv4_STR_LEN - 1) && ip_idx < MAX_IPv4_STR_LEN) {
		ipv4_text[ip_idx] = '\0';
		if (inet_pton(AF_INET, ipv4_text, &sa.sin_addr) <= 0)
			return ret;
	} else
		return ret;

	// ignore white spaces
	while (i < line_len && isspace(line[i])) ++i;

	if (i < line_len && ('#' != line[i]))
		ret = &line[i];

	while (i < line_len && !isspace(line[i])) ++i;

	if (i < line_len)
		line[i] = '\0';
	else if (line[i] != '\0')
		ret = NULL;

	return ret;
}

int
nes_dns_load_static_hosts(void) {
	uint32_t i = 0;
	size_t line_len = 0;
	char *line = NULL;
	char *host = NULL;
	FILE* f = fopen(HOSTS_PATH, "r");
	if (NULL == f) {
		NES_LOG(ERR, "Failed to open %s, error %s\n", HOSTS_PATH, strerror(errno));
		return NES_FAIL;
	}

	while (getline(&line, &line_len, f) > 0) {
		if (NULL != (host = nes_dns_ipv4_host(line, line_len))) {
			if (NULL == (static_dns_entries = rte_realloc(static_dns_entries,
					++static_dns_entries_cnt * sizeof (char*), 0))) {
				NES_LOG(ERR, "Failed to reallocate static dns entries array\n");
				fclose(f);
				static_dns_entries_cnt = 0;
				return NES_FAIL;
			}

			if (NULL == (static_dns_entries[static_dns_entries_cnt - 1] =
					rte_malloc(NULL, (strlen(host) + 1), 0))) {
				NES_LOG(ERR, "Failed to allocate static dns entry\n");
				for (i = 0; i < (static_dns_entries_cnt - 1); i++)
					rte_free(static_dns_entries[i]);

				rte_free(static_dns_entries);
				fclose(f);
				static_dns_entries_cnt = 0;
				return NES_FAIL;
			}
			strncpy(static_dns_entries[static_dns_entries_cnt - 1],
				host, strlen(host) + 1);
		}
		free(line);
		line = NULL;
		line_len = 0;
	}
	free(line);
	fclose(f);

	NES_LOG(INFO, "%u static entries found in %s:\n", static_dns_entries_cnt, HOSTS_PATH);
	for (i = 0; i < static_dns_entries_cnt; ++i)
		NES_LOG(INFO, "\t%s\n", static_dns_entries[i]);

	return NES_SUCCESS;
}

int
nes_dns_in_static_hosts(char** hosts, uint8_t hosts_cnt) {
	uint32_t i, j;

	if (NULL == hosts)
		return NES_FAIL;

	for (j = 0; j < hosts_cnt; ++j) {
		uint8_t found = 0;
		for (i = 0; i < static_dns_entries_cnt; ++i) {
			if (0 == strncmp(hosts[j], static_dns_entries[i],
					strlen(static_dns_entries[i]))) {
				found = 1;
				break;
			}
		}
		if (1 != found)
			return NES_FAIL;
	}
	return NES_SUCCESS;
}
