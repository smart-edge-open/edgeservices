/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

#ifndef NES_DNS_DECL_H_
#define NES_DNS_DECL_H_

//#undef FILE_NAME
#ifndef FILE_NAME
	#define FILE_NAME nes_dns
#endif

#include "mock.h"
MOCK_DECL(nes_lookup_entry_find);
#define nes_lookup_entry_find MOCK_NAME(mocked_nes_lookup_entry_find)

MOCK_DECL(rte_pktmbuf_free);
#define rte_pktmbuf_free MOCK_NAME(mocked_rte_pktmbuf_free)

MOCK_DECL(nts_acl_cfg_lookup_prepare);
#define nts_acl_cfg_lookup_prepare MOCK_NAME(mocked_nts_acl_cfg_lookup_prepare)

MOCK_DECL(nts_acl_cfg_overlaps);
#define nts_acl_cfg_overlaps MOCK_NAME(mocked_nts_acl_cfg_overlaps)

MOCK_DECL(rte_malloc);
#define rte_malloc MOCK_NAME(mocked_rte_malloc)

MOCK_DECL(rte_free);
#define rte_free MOCK_NAME(mocked_rte_free)

MOCK_DECL(nes_acl_find_rule_id);
#define nes_acl_find_rule_id MOCK_NAME(mocked_nes_acl_find_rule_id)

MOCK_DECL(nes_acl_add_entries);
#define nes_acl_add_entries MOCK_NAME(mocked_nes_acl_add_entries)

MOCK_DECL(nes_sq_enq);
#define nes_sq_enq MOCK_NAME(mocked_nes_sq_enq)

MOCK_DECL(rte_mempool_create);
#define rte_mempool_create MOCK_NAME(mocked_rte_mempool_create)

int nes_dns_agent_decap(struct rte_mbuf *m, struct ipv4_hdr *inner_ipv4);
int nes_dns_agent_encap(struct rte_mbuf *m, nts_enc_entry_t *encap_entry);
int nes_dns_agent_flow(__attribute__((unused))nts_route_entry_t *self,struct rte_mbuf *src_mbuf,
	int is_upstream, void *ptr);
int nes_dns_agent_setup(const char *tap_name);
void nes_dns_tap_loop(void);

#endif
