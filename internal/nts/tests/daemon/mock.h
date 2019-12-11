/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef __MOCK_H__
#define __MOCK_H__


#ifndef FILE_NAME
	#error "You must define FILE_NAME before including this file"
#endif

#if 1

#define TOKENPASTE_(x,y) x ## y
#define TOKENPASTE(x,y) TOKENPASTE_(x,y)

#define MOCK_NAME(mocked_f) TOKENPASTE(mocked_f,FILE_NAME)


#define MOCK_DECL(f) extern __typeof(f) __attribute__((unused)) *TOKENPASTE(mocked_##f,FILE_NAME); \
	static __typeof(f) __attribute__((unused)) *TOKENPASTE(mocked_##f##_orig,FILE_NAME) = f


#define MOCK_INIT(mocked_f) \
	__typeof(TOKENPASTE(mocked_f##_orig,FILE_NAME))MOCK_NAME(mocked_f) = NULL
#define MOCK_SET(mocked_f,new_f) MOCK_NAME(mocked_f) = new_f
#define MOCK_RESET(mocked_f) MOCK_NAME(mocked_f) = TOKENPASTE(mocked_f##_orig,FILE_NAME)

#define UNUSED(var) __attribute__((unused))(var)

#else

#define MOCK_NAME(mocked_f) mocked_f


#define MOCK_DECL(f) extern __typeof(f) __attribute__((unused)) *mocked_##f; \
	static __typeof(f) __attribute__((unused)) *mocked_##f##_orig = f

#define MOCK_INIT(mocked_f) __typeof(mocked_f##_orig)mocked_f = NULL
#define MOCK_SET(mocked_f,new_f) mocked_f = new_f
#define MOCK_RESET(mocked_f) mocked_f = mocked_f##_orig

#define UNUSED(var) __attribute__((unused))(var)

#endif

#endif
