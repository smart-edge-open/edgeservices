/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_capacity.h
 * @brief NES daemon capacity limitations
 */

#ifndef _NES_CAPACITY_H_
#define _NES_CAPACITY_H_

#ifdef __cplusplus
extern "C" {
#endif

#define NES_MAX_CELLS       (48)
#define NES_MAX_UE_PER_CELL (1000)
#define NES_MAX_UE          (NES_MAX_CELLS * NES_MAX_UE_PER_CELL)

#define NES_MAX_RB_PER_UE (4)
#define NES_MAX_RB        (NES_MAX_UE * NES_MAX_RB_PER_UE)

#define NES_MAX_MEC_APPS          (4)

#define NES_MAX_ROUTING_RULES_PER_MEC_APP (1024)
#define NES_MAX_ROUTING_RULES             (NES_MAX_MEC_APPS * NES_MAX_ROUTING_RULES_PER_MEC_APP)

#define NES_MAX_SERVICES_PER_MEC_APP (64)
#define NES_MAX_SERVICES             (NES_MAX_MEC_APPS * NES_MAX_SERVICES_PER_MEC_APP)

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* _NES_CAPACITY_H_ */
