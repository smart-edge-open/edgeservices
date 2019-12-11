/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dns_config.h
 * @brief Header file for nes_dns_config
 */

#ifndef NES_DNS_CONFIG_H
#define	NES_DNS_CONFIG_H

#ifdef	__cplusplus
extern "C" {
#endif

#define DNS_AGENT_SECTION "DNS"
#define DNS_AGENT_TAP_DEV_NAME "dns_agent_tap"

enum {
	DNS_FORWARD_OFF,
	DNS_FORWARD_ON
};
/**
 * @brief Get local dns tap device mac address from config file
 *
 * @param[in] mac_entry - entry in config file, DNS_AGENT_SECTION section
 * @param[out] mac - mac address from config file
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dns_mac_from_cfg(const char *mac_entry, struct ether_addr *mac);

/**
 * @brief Get ip address from config file, DNS_AGENT_SECTION section
 *
 * @param[in] ip_entry - entry in config file DNS_AGENT_SECTION section
 * @param[out] ip - ip address from config file
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dns_ip_from_cfg(const char *ip_entry, uint32_t *ip) ;

/**
 * @brief Set up dns tap device
 *
 * @param[in] name - tap device name
 * @param[in] mac_addr - tap device mac address
 * @param[in] ip_addr - tap device ip address
 * @param[in] non_block - if set read from tap device is going to be non-blocking
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dns_tap_create(const char* name, struct ether_addr *mac_addr, uint32_t *ip_addr,
	uint8_t non_block);

/**
 * @brief Check if forwarding of unresolved queries is turned on in config file
 *
 * @param[in] forward_unresolved_entry - entry in config file DNS_AGENT_SECTION section
 * @param[out] forward - set to 1 if forwarding is on
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dns_check_forward_unresolved(const char *forward_unresolved_entry, uint8_t *forward);

#ifdef	__cplusplus
}
#endif

#endif	/* NES_DNS_CONFIG_H */
