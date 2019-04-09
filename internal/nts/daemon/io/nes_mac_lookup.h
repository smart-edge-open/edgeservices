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
