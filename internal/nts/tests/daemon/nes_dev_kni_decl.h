/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

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
