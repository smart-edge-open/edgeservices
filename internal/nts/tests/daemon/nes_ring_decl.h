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
