/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

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
