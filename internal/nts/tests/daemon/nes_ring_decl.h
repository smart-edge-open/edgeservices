/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_RING_DECL_H_
#define NES_RING_DECL_H_

int nes_ring_set_flow(nes_ring_t *self);
int nes_ring_ctor(nes_ring_t *self, void *arg);
int nes_ring_dtor(__attribute__((unused)) nes_ring_t *self,__attribute__((unused)) void *data);
int nes_ring_enq_sp(nes_ring_t *self, void *buffer);
int nes_ring_enq_burst_sp(nes_ring_t *self, void **buffer, int count);
int nes_ring_enq_mp(nes_ring_t *self, void *buffer);
int nes_ring_enq_burst_mp(nes_ring_t *self, void **buffer, int count);
int nes_ring_deq_burst_sc(nes_ring_t *self, void **buffer, int count);
int nes_ring_deq_sc(nes_ring_t *self, void **buffer);
int nes_ring_instantiate(nes_ring_t **newring, nes_ring_params_t *params);

#endif
