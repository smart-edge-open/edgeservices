/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_unittest.h
 * @brief Header file for unit tests
 */

#ifndef _LIBNES_UNITTEST_H_
#define _LIBNES_UNITTEST_H_

#ifdef __cplusplus
extern "C" {
#endif

static size_t _subtests = 0, _tests = 0, _subtests_failed = 0, _tests_failed = 0;

#define START_TEST_CASE     int ret = 0
#define RUN_TEST(x, y) \
	{ \
		_tests++; \
		if (!x()) \
			printf("Test %s passed\n", y); \
		else { \
			printf("Test %s failed\n", y); _tests_failed++; \
		} \
	}
#define SHOULD_BE(x) \
	{ \
		_subtests++; \
		if (!(x)) { \
			_subtests_failed++; \
			ret++; \
			printf("Line %d fails\n", __LINE__); \
		} \
	}
#define END_TEST_CASE       return ret
#define RAPORT_OF_TESTS \
	{ \
		printf("Report:\n"); \
		printf("Main tests=%zu, failed=%zu(%.1f%%)\n", \
		       _tests, _tests_failed, ((float)_tests_failed*100)/(float)_tests); \
		printf("Subtests=%zu, failed=%zu(%.1f%%)\n", \
		       _subtests, _subtests_failed, \
		       ((float)_subtests_failed*100)/(float)_subtests); \
	}


#ifdef __cplusplus
}
#endif

#endif /* _LIBNES_UNITTEST_H_ */
