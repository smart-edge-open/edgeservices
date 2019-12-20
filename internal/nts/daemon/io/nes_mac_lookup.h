/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_mac_lookup.h
 * @brief Prototypes for NES MAC lookup functions
 */

#ifndef _NES_MAC_LOOKUP_H_
#define _NES_MAC_LOOKUP_H_

#ifdef __cpluplus
extern "C" {
#endif

struct mac_entry {
	const char *ring_name;
	nes_ring_t *ring;
	int vm_id;
};

int nes_mac_lookup_init(void);
int nes_mac_lookup_entry_find(const struct ether_addr *, struct mac_entry **);
int nes_mac_lookup_entry_add(const struct ether_addr *, struct mac_entry *data);
int nes_mac_lookup_entry_del(const struct ether_addr *);

#ifdef __cpluplus
}
#endif
#endif /* _NES_MAC_LOOKUP_H_ */
