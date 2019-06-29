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

#ifndef NES_DEV_KNI_DECL_H
#define	NES_DEV_KNI_DECL_H

int nes_dev_kni_mempool_init(void);
int create_kni_rings(nes_dev_t *self);
int mac_authorization(struct nes_dev_s *self, struct rte_mbuf **m, int pkt_count);
int send_kni_unauthorized(struct nes_dev_s *self, __attribute__((unused)) void *data);
void nes_dev_kni_destroy(int port_id, char* deleted_if_name);
int ctor_kni(nes_dev_t *self, __attribute__((unused)) void *data);
int dtor_kni(nes_dev_t *self, __attribute__((unused)) void *data);

#endif	/* NES_DEV_KNI_DECL_H */
