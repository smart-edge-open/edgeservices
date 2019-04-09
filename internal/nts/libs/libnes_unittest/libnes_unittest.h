/*******************************************************************************
* Copyright 2019 Intel Corporation. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

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
