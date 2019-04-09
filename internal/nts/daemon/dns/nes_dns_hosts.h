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
 * @file nes_dns_hosts.h
 * @brief Header file for nes_dns_hosts
 */


#ifndef NES_DNS_HOSTS_H
#define	NES_DNS_HOSTS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define HOSTS_PATH "/etc/hosts"
#define MAX_IPv4_STR_LEN 16
#define MIN_IPv4_STR_LEN 7

/**
 * @brief Load hosts from HOSTS_PATH
 *
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dns_load_static_hosts(void);

/**
 * @brief Check if provided hosts are in static hosts entries loaded by nes_dns_load_static_hosts
 *
 * @param[in] hosts - hosts to check
 * @param[in] hosts_cnt - hosts count
 * @return NES_SUCCESS if all hosts found and NES_FAIL if not.
 */
int nes_dns_in_static_hosts(char** hosts, uint8_t hosts_cnt);

#ifdef	__cplusplus
}
#endif

#endif	/* NES_DNS_HOSTS_H */
