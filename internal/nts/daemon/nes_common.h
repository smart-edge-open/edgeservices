/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_common.h
 * @brief Header file for common declarations
 */

#ifndef _NES_COMMON_H_
#define _NES_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_log.h>
#include "nes_api_common.h"

#define LOOKUP_TABLE_ENTRIES 2048
#define MAX_LOOKUPS_PER_VM 10
#define MAX_VM_NUMBER 90
#define MAX_BURST_SIZE 32

#define RTE_LOGTYPE_NES RTE_LOGTYPE_USER1
#if defined (COVERAGE_ENABLED) || defined (LIBNES_API)
	#define NES_LOG(level,...) do { printf(__VA_ARGS__); } while(0)
#else
	#define NES_LOG(level,...) RTE_LOG(level, NES, "["#level"] "__VA_ARGS__)
#endif

#ifdef UNIT_TESTS
	#define NES_STATIC
	#define NES_TEST_MAIN main
	#define NES_MAIN __attribute__((unused)) nes_main
	#define NES_EXIT(status)
	extern volatile int nes_thread_terminate;
	#define NES_FOREVER_LOOP ;!nes_thread_terminate;
	#define FORCE_INLINE
#else
	#define NES_STATIC static
	#define NES_MAIN main
	#define NES_EXIT(status) exit(status)
	#define NES_FOREVER_LOOP ;;
	#define FORCE_INLINE __attribute__((always_inline)) inline
#endif

#define UDP_GTPU_PORT 2152
#define UDP_GTPC_PORT 2123
#define IP_PROTO_SCTP   132
#define IP_PROTO_UDP    17
#define IP_PROTO_TCP    6
#define IP_PROTO_ICMP   1

static inline const void** conv_ptr_to_const(uint32_t** ptr)
{
	return (const void **)(void*)ptr;
}

typedef enum {
	NES_UPSTREAM,
	NES_DOWNSTREAM,
} nes_direction_t;

#define rte_memcmp strcmp

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* _NES_COMMON_H_ */
