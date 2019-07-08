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
* @file nes_dev_kni.h
* @brief Header file for nes KNI device.
*/
#ifndef _NES_DEV_KNI_H_
#define _NES_DEV_KNI_H_

#ifdef __cplusplus
extern "C" {
#endif

int nes_dev_kni_init(void);

void nes_dev_kni_stop(void);

NES_STATIC struct rte_kni * nes_dev_kni_alloc(uint16_t port_id, const char* if_id);

int nes_dev_kni_create_port(const char* if_id, char* created_if_name);

int nes_dev_kni_delete_port(const char* if_id, char* deleted_if_name);


#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* _NES_DEV_H_ */
