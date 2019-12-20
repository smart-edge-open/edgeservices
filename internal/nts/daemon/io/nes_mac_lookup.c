/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#include <string.h>
#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "nes_dev.h"
#include "nes_mac_lookup.h"

static nes_lookup_table_t nes_mac_lookup_table;
#define VM_NAME_LENGTH 20

int nes_mac_lookup_init(void)
{
	const char *buffer;
	int max_vm, retval;
	nes_lookup_params_t nes_mac_lookup_params = {
		.name = "nes_mac_lookup table",
		.key_len = sizeof(struct ether_addr),
		.entry_len = sizeof(struct mac_entry)
	};

	if (NES_SUCCESS == nes_cfgfile_entry("VM common", "max", &buffer))
		max_vm = atoi(buffer);
	else {
		NES_LOG(ERR,"Bad or missing max entry in [VM] section in config file.\n");
		return NES_FAIL;
	}

	nes_mac_lookup_params.number_of_entries = max_vm;

	retval = nes_lookup_ctor(&nes_mac_lookup_table, &nes_mac_lookup_params);
	if (NES_FAIL == retval) {
		NES_LOG(ERR,"Could not initialize %s.\n",nes_mac_lookup_params.name);
		return retval;
	}

	return retval;
}

rte_spinlock_t mac_lookup_lock = RTE_SPINLOCK_INITIALIZER;

int nes_mac_lookup_entry_find(const struct ether_addr *ether_address, struct mac_entry **data)
{
	int ret;
	rte_spinlock_lock(&mac_lookup_lock);
	ret = nes_lookup_entry_find(&nes_mac_lookup_table, ether_address, (void **)data);
	rte_spinlock_unlock(&mac_lookup_lock);
	return ret;
}

int nes_mac_lookup_entry_add(const struct ether_addr *ether_address, struct mac_entry *data)
{
	int ret;
	NES_LOG(INFO, "Adding authorization entry for MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ether_address->addr_bytes[0], ether_address->addr_bytes[1],
		ether_address->addr_bytes[2], ether_address->addr_bytes[3],
		ether_address->addr_bytes[4], ether_address->addr_bytes[5]);
	rte_spinlock_lock(&mac_lookup_lock);
	ret = nes_lookup_entry_add(&nes_mac_lookup_table, ether_address, data);
	rte_spinlock_unlock(&mac_lookup_lock);
	return ret;
}

int nes_mac_lookup_entry_del(const struct ether_addr *ether_address)
{
	int ret;
	if (0 == memcmp(ether_address, "\x00\x00\x00\x00\x00\x00", sizeof(struct ether_addr)))
		return NES_FAIL;
	NES_LOG(INFO, "Removing entry for MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ether_address->addr_bytes[0], ether_address->addr_bytes[1],
		ether_address->addr_bytes[2], ether_address->addr_bytes[3],
		ether_address->addr_bytes[4], ether_address->addr_bytes[5]);
	rte_spinlock_lock(&mac_lookup_lock);
	ret = nes_lookup_entry_del(&nes_mac_lookup_table, ether_address);
	rte_spinlock_unlock(&mac_lookup_lock);
	return ret;
}
