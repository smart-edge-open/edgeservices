/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <rte_malloc.h>

#include "nes_common.h"
#include "test_nes_dns_hosts.h"
#include "dns/nes_dns_hosts.h"
#include "nes_dns_hosts_decl.h"

MOCK_INIT(mocked_fopen);
MOCK_INIT(mocked_fclose);
MOCK_INIT(mocked_getline);
MOCK_INIT(mocked_rte_realloc);
MOCK_INIT(mocked_rte_malloc);
MOCK_INIT(mocked_rte_free);

int
init_suite_nes_dns_hosts(void) {
	MOCK_RESET(mocked_fopen);
	MOCK_RESET(mocked_fclose);
	MOCK_RESET(mocked_getline);
	MOCK_RESET(mocked_rte_realloc);
	MOCK_RESET(mocked_rte_malloc);
	MOCK_RESET(mocked_rte_free);

	return CUE_SUCCESS;
}

int
cleanup_suite_nes_dns_hosts(void) {
	MOCK_RESET(mocked_fopen);
	MOCK_RESET(mocked_fclose);
	MOCK_RESET(mocked_getline);
	MOCK_RESET(mocked_rte_realloc);
	MOCK_RESET(mocked_rte_malloc);
	MOCK_RESET(mocked_rte_free);

	return CUE_SUCCESS;
}

static FILE* fopen_stub_ret;

static FILE*
fopen_stub(const char __attribute__((unused)) * filename, const char __attribute__((unused)) * mode)
{
	return fopen_stub_ret;
}

static int
fclose_stub(FILE __attribute__((unused)) * fp) {
	return 0;
}

static int *rte_realloc_stub_ret;

static void*
rte_realloc_stub(void __attribute__((unused)) * ptr,
	size_t __attribute__((unused)) size,
	unsigned __attribute__((unused)) align)
{
	return rte_realloc_stub_ret;
}

static int *rte_malloc_stub_ret;

static void*
rte_malloc_stub(const char __attribute__((unused)) * type,
	size_t __attribute__((unused)) size,
	unsigned __attribute__((unused)) align)
{
	return rte_malloc_stub_ret;
}

static void
rte_free_stub(void __attribute__((unused)) * ptr) {
}

static ssize_t getline_ret[] = {0, 1, 0};
static int getline_ret_idx;
char getline_line[32];
static size_t getline_line_len = 1;

static ssize_t
getline_stub(char __attribute__((unused))**lineptr,
	size_t __attribute__((unused)) * n, FILE __attribute__((unused)) * stream) {
	*lineptr = malloc(sizeof (getline_line));
	CU_ASSERT_PTR_NOT_NULL_FATAL(lineptr);
	strncpy(*lineptr, getline_line, sizeof (getline_line));
	*n = getline_line_len;
	return getline_ret[getline_ret_idx++ % (sizeof (getline_ret) / sizeof (ssize_t))];
}

static void
nes_dns_load_static_hosts_test(void) {
	MOCK_SET(mocked_fopen, fopen_stub);
	MOCK_SET(mocked_fclose, fclose_stub);
	MOCK_SET(mocked_getline, getline_stub);
	MOCK_SET(mocked_rte_realloc, rte_realloc_stub);
	MOCK_SET(mocked_rte_malloc, rte_malloc_stub);
	MOCK_SET(mocked_rte_free, rte_free_stub);

	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_FAIL);
	fopen_stub_ret = (FILE*) 0xABCD; // file in nes_dns_load_static_hosts is not used
	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_SUCCESS); // getline returned 0

	strncpy(getline_line, "#", sizeof ("#"));
	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_SUCCESS); // getline returned 1
	// nes_dns_ipv4_host returned null

	strncpy(getline_line, "127.0.0.1 example.com", sizeof ("127.0.0.1 example.com"));
	getline_line_len = sizeof ("127.0.0.1 example.com");
	getline_ret_idx = 1;
	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_FAIL); // getline returned 1
	// nes_dns_ipv4_host returned good pointer
	// rte_realloc returned NULL

	getline_ret_idx = 1;
	rte_realloc_stub_ret = malloc(sizeof (char*));
	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_FAIL); // getline returned 1
	// nes_dns_ipv4_host returned good pointer
	// rte_realloc returned allocated pointer
	// rte_malloc returned NULL

	getline_ret_idx = 1;
	rte_malloc_stub_ret = malloc(sizeof (char) * (sizeof ("example.com") + 1));
	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_SUCCESS); // getline returned 1
	// nes_dns_ipv4_host returned good pointer
	// rte_realloc returned allocated pointer
	// rte_malloc returned allocated pointer
	// function succeded with one host loaded

	getline_ret_idx = 1;
	int *rte_malloc_stub_ret_tmp = rte_malloc_stub_ret;
	rte_malloc_stub_ret = NULL;
	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_FAIL); // getline returned 1
	// nes_dns_ipv4_host returned good pointer
	// rte_realloc returned allocated pointer
	// rte_malloc returned NULL
	// function succeded with one host loaded

	rte_malloc_stub_ret = rte_malloc_stub_ret_tmp;
	getline_ret_idx = 1;
	CU_ASSERT_EQUAL(nes_dns_load_static_hosts(), NES_SUCCESS); // getline returned 1
	// nes_dns_ipv4_host returned good pointer
	// rte_realloc returned allocated pointer
	// rte_malloc returned allocated pointer
	// function succeded with one host loaded
}

static void
nes_dns_in_static_hosts_test(void) {
	CU_ASSERT_EQUAL(nes_dns_in_static_hosts(NULL, 0), NES_FAIL);
	char *host = malloc(sizeof (char) * 32);

	CU_ASSERT_PTR_NOT_NULL_FATAL(host);

	strncpy(host, "example.com", 32);
	CU_ASSERT_EQUAL(nes_dns_in_static_hosts(&host, 1), NES_SUCCESS);
	strncpy(host, "example", 32);
	CU_ASSERT_EQUAL(nes_dns_in_static_hosts(&host, 1), NES_FAIL);

	free(rte_realloc_stub_ret);
	free(rte_malloc_stub_ret);
	free(host);
}

static void
nes_dns_ipv4_host_test(void) {
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(NULL, 0));

	char line_comment[] = " #";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_comment, sizeof(line_comment)));

	char line_bad[] = "";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad, sizeof(line_bad)));

	char line_bad_ip[] = "1234.1234.1234.1234";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad_ip, sizeof(line_bad_ip)));

	char line_bad_ip0[] = "123.123.123.1234";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad_ip0, sizeof(line_bad_ip0)));

	char line_bad_ip1[] = "1 ";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad_ip1, sizeof(line_bad_ip1)));

	char line_bad_ip2[] = "-123.123.123.13";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad_ip2, sizeof(line_bad_ip2)));

	char line_bad_host[] = "123.123.123.123 #";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad_host, sizeof(line_bad_host)));

	char line_bad_host0[] = "123.123.123.123";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad_host0, sizeof(line_bad_host0)));

	char line_bad_host1[] = "123.123.123.123 example.com";
	CU_ASSERT_PTR_NULL(nes_dns_ipv4_host(line_bad_host1, sizeof(line_bad_host1) - 2));

	char line_good[] = "123.123.123.123 example.com";
	CU_ASSERT_PTR_NOT_NULL(nes_dns_ipv4_host(line_good, sizeof(line_good)));

	char line_good1[] = "123.123.123.123 example.com ";
	CU_ASSERT_PTR_NOT_NULL(nes_dns_ipv4_host(line_good1, sizeof(line_good1)));

	char line_good2[] = "123.123.123.123 example.com #";
	CU_ASSERT_PTR_NOT_NULL(nes_dns_ipv4_host(line_good2, sizeof(line_good2)));
}

void add_nes_dns_hosts_suite_to_registry(void) {
	CU_pSuite nes_dns_hosts_suite = CU_add_suite("nes_dns_hosts", init_suite_nes_dns_hosts, cleanup_suite_nes_dns_hosts);

	CU_add_test(nes_dns_hosts_suite, "nes_dns_load_static_hosts_test", nes_dns_load_static_hosts_test);
	CU_add_test(nes_dns_hosts_suite, "nes_dns_in_static_hosts_test", nes_dns_in_static_hosts_test);
	CU_add_test(nes_dns_hosts_suite, "nes_dns_ipv4_host_test", nes_dns_ipv4_host_test);
}

