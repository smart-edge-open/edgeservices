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
