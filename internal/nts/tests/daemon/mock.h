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
