/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_ring.h
 * @brief Header file for nes_ring
 */

#ifndef NES_RING_H_
#define NES_RING_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_ring.h>
#include "nts/nts_lookup.h"

#define NES_RING_ELEMENTS_DEFAULT 1024
#define NES_RING_NAME_LEN RTE_RING_NAMESIZE

#define MBUFS_PER_RING NES_RING_ELEMENTS_DEFAULT
#define MBUFS_PER_PORT 1536

enum {
	YES,
	NO
};

/**
* Ring parameters
* Ring parameters for ring cosntructor
*/
typedef struct nes_ring_params_s {
	/**
	* Ring name
	*/
	const char *name;
	/**
	* Maximum number of ring elements.
	* If set to 0, NES_RING_ELEMENTS_DEFAULT is used.
	*/
	uint16_t count;
	/**
	* Specify single/multi producer ring access mode.
	* For multi producer set YES, otherwise set NO.
	* All rings are single consumer.
	*/
	uint8_t  multiproducer;
	/**
	* Force enqueue threshold in microseconds.
	* A bigger value may boost bandwidth at the cost of latency.
	* Smaller one may boost latency at the cost of bandwidth.
	* If unsure, test with 0;
	*/
	uint32_t threshold_us;
} nes_ring_params_t;

#define NES_RING_BURST_SIZE MAX_BURST_SIZE

/**
* Abstract ring object
*/
typedef struct nes_ring_s {
	struct rte_ring *ring;
	nts_lookup_tables_t *routing_tables;
	uint8_t remove;

	struct nes_ctrl_ring_s *ring_stats;
	int (*ctor)(struct nes_ring_s *, void *);
	int (*enq)(struct nes_ring_s *, void *);
	int (*enq_burst)(struct nes_ring_s *, void **, int);
	int (*flow)(struct nes_ring_s *, void **, int);
	int (*deq)(struct nes_ring_s *, void **);
	int (*deq_burst)(struct nes_ring_s *, void **, int);
	int (*dtor)(struct nes_ring_s *, void *);
} nes_ring_t;

static inline char *nes_ring_name(nes_ring_t *self)
{
	return self->ring->name;
}

int nes_ring_norings(void);
int nes_ring_init(void);
nes_ring_params_t *nes_ring_params_table_get(void);
int nes_ring_per_vm_set(int vm_id, nes_ring_t **rx_ring_ptr, nes_ring_t **tx_ring_ptr);
int nes_ring_per_kni_set(int port_id, nes_ring_t **rx_ring_ptr, nes_ring_t **tx_ring_ptr);
int nes_ring_per_port_set(int port_id, nes_ring_t **tx_ring_ptr);

#ifdef __cplusplus
}
#endif

#endif /* NES_RING_H_ */
