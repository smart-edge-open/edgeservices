/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dns.c
 * @brief implementation of nes_dns
 */

#include <stdio.h>
#include <stdint.h>

#include <unistd.h>

#include <rte_udp.h>
#include "libnes_cfgfile.h"
#include "nes_ring_lookup.h"
#include "nts/nts_acl_cfg.h"
#include "nes_common.h"
#include "nts/nts_io.h"
#include "nts/nts_edit.h"
#include "nes_dns.h"
#include "nes_dns_hosts.h"
#include "nes_dns_config.h"
#include "nes_dns_tools.h"
#include "nes_arp.h"
#include "io/nes_io.h"
#include "io/nes_dev_addons.h"

#ifdef UNIT_TESTS
	#include "nes_dns_decl.h"
#endif

#define DNS_PORT 53
#define DNS_PRIO RTE_ACL_MAX_PRIORITY

#define MAX_HOST_LEN 255
#define MAX_PACKET_SZ 2048
#define MBUF_SZ \
	(MAX_PACKET_SZ + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF 8192
#define PKT_BURST_SZ 32
#define MEMPOOL_CACHE_SZ PKT_BURST_SZ

NES_STATIC int tap_dev_fd = -1;
static uint32_t local_dns_ip = 0;
static uint32_t external_dns_ip = 0;
static struct ether_addr local_dns_mac;
static struct ether_addr external_dns_gw_mac;

NES_STATIC uint8_t forward_unresolved_queries;
static struct rte_mempool *pktmbuf_pool = NULL;
extern nes_acl_ctx_t nes_ctrl_acl_ctx;
NES_STATIC nts_lookup_tables_t *routing_table;

NES_STATIC int
nes_dns_agent_decap(struct rte_mbuf *m, struct ipv4_hdr *inner_ipv4) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct ether_addr orig_src_mac;
	ether_addr_copy(&eth_hdr->s_addr, &orig_src_mac);
	/* check if VLAN tag is present */
	uint16_t adj_len = (uint16_t) ((uint8_t *) inner_ipv4 - (uint8_t *) (eth_hdr + 1));
	if (eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN))
		eth_hdr = (struct ether_hdr *)((uint8_t*)eth_hdr + sizeof(struct vlan_hdr));

	rte_memcpy((uint8_t *) inner_ipv4 - sizeof (struct ether_hdr),
		(uint8_t *) (eth_hdr), sizeof (struct ether_hdr));
	eth_hdr = (struct ether_hdr *) rte_pktmbuf_adj(m, adj_len);
	if (unlikely(NULL == eth_hdr))
		return NES_FAIL;

	ether_addr_copy(&orig_src_mac, &eth_hdr->s_addr);
	ether_addr_copy(&local_dns_mac, &eth_hdr->d_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	return NES_SUCCESS;
}

NES_STATIC int
nes_dns_agent_encap(struct rte_mbuf *mbuf, nts_enc_entry_t *encap_entry) {
	if (NULL == mbuf || NULL == encap_entry)
		return NES_FAIL;

	struct outer_ip_pkt_head {
		struct ipv4_hdr outer_ipv4_hdr;
		struct udp_hdr outer_udp_hdr;
		gtpuHdr_t gtpu_hdr;
	};

	gtpu_head_t *pkt_header;
	struct outer_ip_pkt_head * outer_ip_pkt_header;
	struct ether_hdr * eth_header;
	uint16_t pkt_len, vlan_len;
	nts_enc_subentry_t *encap_data = &encap_entry->downstream;
	if (NTS_ENCAP_VLAN_FLAG & encap_data->encap_flag) {
		vlan_len = sizeof(struct vlan_hdr);
		pkt_header = (gtpu_head_t *)rte_pktmbuf_prepend(mbuf,
				vlan_len +
				sizeof (struct ipv4_hdr) +
				sizeof (struct udp_hdr) +
				sizeof (gtpuHdr_t));
		if (NULL == pkt_header)
			return NES_FAIL;

		eth_header = &pkt_header->gtpu_vlan.outer_ether_hdr;
		eth_header->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);
		pkt_header->gtpu_vlan.outer_vlan_hdr.vlan_tci = encap_data->vlan_tci;
		pkt_header->gtpu_vlan.outer_vlan_hdr.eth_proto= rte_cpu_to_be_16(ETHER_TYPE_IPv4);
		outer_ip_pkt_header = (struct outer_ip_pkt_head *)
			&pkt_header->gtpu_vlan.outer_ipv4_hdr;
	} else {
		vlan_len = 0;
		pkt_header = (gtpu_head_t *)rte_pktmbuf_prepend(mbuf,
				sizeof (struct ipv4_hdr) +
				sizeof (struct udp_hdr) +
				sizeof (gtpuHdr_t));
		if (NULL == pkt_header)
			return NES_FAIL;

		eth_header = &pkt_header->gtpu_no_vlan.outer_ether_hdr;
		eth_header->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
		outer_ip_pkt_header = (struct outer_ip_pkt_head *)
			&pkt_header->gtpu_no_vlan.outer_ipv4_hdr;
	}

	pkt_len = mbuf->pkt_len;

	ether_addr_copy(&encap_data->dst_mac_addrs, &eth_header->d_addr);
	ether_addr_copy(&encap_data->src_mac_addrs, &eth_header->s_addr);

	outer_ip_pkt_header->outer_ipv4_hdr.version_ihl     =
		(sizeof (struct ipv4_hdr) / IPV4_IHL_MULTIPLIER) | 0x40;
	outer_ip_pkt_header->outer_ipv4_hdr.packet_id       = 0x00;
	outer_ip_pkt_header->outer_ipv4_hdr.fragment_offset = 0;
	outer_ip_pkt_header->outer_ipv4_hdr.time_to_live    = 0xFF;
	outer_ip_pkt_header->outer_ipv4_hdr.next_proto_id   = IP_PROTO_UDP;
	outer_ip_pkt_header->outer_ipv4_hdr.hdr_checksum    = 0;
	outer_ip_pkt_header->outer_ipv4_hdr.total_length    =
		rte_cpu_to_be_16(pkt_len - sizeof (struct ether_hdr) - vlan_len);
	outer_ip_pkt_header->outer_ipv4_hdr.src_addr        = encap_data->src_ip;
	outer_ip_pkt_header->outer_ipv4_hdr.dst_addr        = encap_data->dst_ip;

	outer_ip_pkt_header->outer_udp_hdr.dgram_cksum = 0;
	outer_ip_pkt_header->outer_udp_hdr.src_port    = encap_data->src_ip_port;
	outer_ip_pkt_header->outer_udp_hdr.dst_port    = encap_data->dst_ip_port;
	outer_ip_pkt_header->outer_udp_hdr.dgram_len   = rte_cpu_to_be_16(pkt_len -
			sizeof (struct ether_hdr) -
			vlan_len -
			sizeof (struct ipv4_hdr));

	outer_ip_pkt_header->gtpu_hdr.npdu_flag   = 0;
	outer_ip_pkt_header->gtpu_hdr.seqnum_flag = 0;
	outer_ip_pkt_header->gtpu_hdr.exthdr_flag = 0;
	outer_ip_pkt_header->gtpu_hdr.reserved    = 0;
	outer_ip_pkt_header->gtpu_hdr.pt          = 1;
	outer_ip_pkt_header->gtpu_hdr.version     = 1;
	outer_ip_pkt_header->gtpu_hdr.msg_type    = GTPU_MSG_GPDU;
	outer_ip_pkt_header->gtpu_hdr.length      = rte_cpu_to_be_16(pkt_len -
		sizeof (struct ether_hdr) -
		vlan_len -
		sizeof (struct ipv4_hdr) -
		sizeof (struct udp_hdr) -
		sizeof (gtpuHdr_t));

	outer_ip_pkt_header->gtpu_hdr.teid        = encap_data->teid;

	outer_ip_pkt_header->outer_ipv4_hdr.hdr_checksum =
		rte_ipv4_cksum(&outer_ip_pkt_header->outer_ipv4_hdr);
	return NES_SUCCESS;
}

NES_STATIC int
nes_dns_agent_flow(__attribute__((unused))nts_route_entry_t *self, struct rte_mbuf *src_mbuf,
	int is_upstream, void *ptr) {
	assert(ptr);
	assert(src_mbuf);
	struct ether_hdr *eth_hdr, *vlan_eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	typedef struct routing_params_s {
		struct ipv4_hdr *inner_ipv4_hdr;
		nes_ring_t  *egress_ring;
	} routing_params_t;

	routing_params_t *params = ptr;

	if (forward_unresolved_queries && is_upstream) {
		uint8_t found_in_static_hosts = 1;
		struct udp_hdr *udp_header =
			(struct udp_hdr*) ((uint32_t*) params->inner_ipv4_hdr +
				(*(uint8_t*) params->inner_ipv4_hdr & IPV4_HDR_IHL_MASK));
		dns_header_t *dns_hdr = (dns_header_t*)
			((uint8_t*) udp_header + sizeof (struct udp_hdr));

		if (0 == dns_hdr->qr &&
				0 == dns_hdr->opcode && rte_be_to_cpu_16(dns_hdr->qdcount) > 0) {
			char **hosts = rte_malloc(NULL,
				sizeof (char*) * rte_be_to_cpu_16(dns_hdr->qdcount), 0);
			VERIFY_PTR_OR_RET(hosts, NES_FAIL);
			uint8_t offset = 0;
			uint8_t hosts_cnt = 0, i = 0;
			char* query = ((char*) dns_hdr) + sizeof (dns_header_t);
			for (i = 0; i < rte_be_to_cpu_16(dns_hdr->qdcount); ++i) {
				hosts[hosts_cnt] = rte_malloc(NULL, MAX_HOST_LEN, 0);
				if (NULL == hosts[hosts_cnt]) {
					for (i = 0; i < hosts_cnt; ++i)
						rte_free(hosts[i]);

					rte_free(hosts);
					return NES_FAIL;
				}
				if (NES_SUCCESS != nes_dns_labels_to_domain(
						(const char*) (query + offset), hosts[hosts_cnt],
						MAX_HOST_LEN)) {
					for (i = 0; i < hosts_cnt + 1; ++i)
						rte_free(hosts[i]);

					rte_free(hosts);
					hosts = NULL;
					hosts_cnt = 0;
					break;
				}
				// append null char, QTYPE and QCLASS length (uint16_t)
				offset += strlen(query) + 1 + sizeof (uint16_t) * 2;
				hosts_cnt++;
			}
			if (NES_SUCCESS != nes_dns_in_static_hosts(hosts, hosts_cnt)) {
				found_in_static_hosts = 0;

				eth_hdr = rte_pktmbuf_mtod(src_mbuf, struct ether_hdr *);
				struct ipv4_hdr* outer_hdr = (struct ipv4_hdr*) (eth_hdr + 1);
				struct udp_hdr* udp_hdr = (struct udp_hdr*) (outer_hdr + 1);
				uint16_t udp_port = udp_hdr->dst_port;
				uint32_t old_inner_ip = params->inner_ipv4_hdr->dst_addr;
				const uint8_t msg_type = ((gtpuHdr_t*)(udp_hdr + 1))->msg_type;
				if (udp_port == rte_cpu_to_be_16(UDP_GTPU_PORT) &&
						msg_type == GTPU_MSG_GPDU) {
					uint16_t old_inner_udp_cksum =
						((struct udp_hdr*)
						(params->inner_ipv4_hdr + 1))->dgram_cksum;
					uint16_t old_inner_ip_cksum =
						params->inner_ipv4_hdr->hdr_checksum;

					nes_dns_recompute_inner_ipv4_checksums(
						params->inner_ipv4_hdr,
						params->inner_ipv4_hdr->dst_addr,
						external_dns_ip);
					udp_hdr->dgram_cksum =
						nes_dns_recompute_cksum16(udp_hdr->dgram_cksum,
							old_inner_udp_cksum,
							((struct udp_hdr*)
							(params->inner_ipv4_hdr + 1))->dgram_cksum);
					udp_hdr->dgram_cksum =
						nes_dns_recompute_cksum_new_ip(udp_hdr->dgram_cksum,
							old_inner_ip, external_dns_ip);
					set_new_ipv4_dst(params->inner_ipv4_hdr, &external_dns_ip);
					udp_hdr->dgram_cksum =
						nes_dns_recompute_cksum16(udp_hdr->dgram_cksum,
							old_inner_ip_cksum,
							params->inner_ipv4_hdr->hdr_checksum);
					params->egress_ring->enq(params->egress_ring, src_mbuf);
				} else {
					ether_addr_copy(&external_dns_gw_mac, &eth_hdr->d_addr);

					params->inner_ipv4_hdr->hdr_checksum = 0;
					params->inner_ipv4_hdr->dst_addr = external_dns_ip;
					nes_dns_recompute_inner_ipv4_checksums(
						params->inner_ipv4_hdr, old_inner_ip,
						external_dns_ip);

					nes_ring_t *egress_ring =
						nes_dev_get_egressring_from_port_idx(src_mbuf->port);
					if (NULL == egress_ring)
						rte_pktmbuf_free(src_mbuf);
					else
						egress_ring->enq(egress_ring, src_mbuf);
				}
			}

			for (i = 0; i < hosts_cnt; ++i)
				rte_free(hosts[i]);

			rte_free(hosts);

			if (!found_in_static_hosts)
				return NES_SUCCESS;
		}
	} else if (forward_unresolved_queries && !is_upstream) {
		nes_dns_recompute_inner_ipv4_checksums(params->inner_ipv4_hdr,
			params->inner_ipv4_hdr->src_addr, local_dns_ip);
		set_new_ipv4_src(params->inner_ipv4_hdr, &local_dns_ip);
		params->egress_ring->enq(params->egress_ring, src_mbuf);
		return NES_SUCCESS;
	}

	if (!is_upstream)
		return NES_FAIL;

	eth_hdr = rte_pktmbuf_mtod(src_mbuf, struct ether_hdr *);
	vlan_eth_hdr = NULL;
	ipv4_hdr = (struct ipv4_hdr*) (eth_hdr + 1);
	if (eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
		vlan_eth_hdr = eth_hdr;
		ipv4_hdr = (struct ipv4_hdr*) ((uint8_t*)ipv4_hdr + sizeof(struct vlan_hdr));
	}
	if (ipv4_hdr->next_proto_id == IP_PROTO_UDP) {
		struct udp_hdr* udp_hdr =
			(struct udp_hdr*)((uint32_t *)ipv4_hdr + (ipv4_hdr->version_ihl & 0xf));
		uint16_t udp_port = udp_hdr->dst_port;
		if (udp_port == rte_cpu_to_be_16(UDP_GTPU_PORT) &&
				((gtpuHdr_t*)(udp_hdr + 1))->msg_type == GTPU_MSG_GPDU) {
			if (NES_SUCCESS != nes_dns_agent_decap(src_mbuf, params->inner_ipv4_hdr)) {
				rte_pktmbuf_free(src_mbuf);
				return NES_FAIL;
			}
		} else {
			if (NULL != vlan_eth_hdr) {
				struct ether_addr orig_src_mac;
				ether_addr_copy(&eth_hdr->s_addr, &orig_src_mac);
				eth_hdr = (struct ether_hdr *)
					rte_pktmbuf_adj(src_mbuf, sizeof(struct vlan_hdr));
				if (unlikely(NULL == eth_hdr)) {
					rte_pktmbuf_free(src_mbuf);
					return NES_FAIL;
				}
				ether_addr_copy(&orig_src_mac, &eth_hdr->s_addr);
				eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
			}
			ether_addr_copy(&local_dns_mac, &eth_hdr->d_addr);
		}
	}

	if (write(tap_dev_fd, rte_pktmbuf_mtod(src_mbuf, void*),
			rte_pktmbuf_data_len(src_mbuf)) < rte_pktmbuf_data_len(src_mbuf)) {
		NES_LOG(ERR, "Failed writing to DNS tap device\n");
		rte_pktmbuf_free(src_mbuf);
		return NES_FAIL;
	}
	rte_pktmbuf_free(src_mbuf);

	return NES_SUCCESS;
}

#define ADD_ROUTING_GTPU_STRING "prio:%d,encap_proto:gtpu,srv_ip:%s,srv_port:%d"
#define ADD_ROUTING_IP_STRING   "prio:%d,encap_proto:noencap,srv_ip:%s,srv_port:%d"

static int
nes_dns_agent_add_routing_impl(nes_acl_ctx_t* lookup_ctx, int is_gtpu) {
	assert(lookup_ctx);

	char dns_lookup_key[NES_MAX_LOOKUP_ENTRY_LEN];
	struct in_addr ip_addr;
	struct nts_acl_lookup_field dns_upstream_rule, dns_downstream_rule, ignored_rule;
	struct nts_acl_lookup_field *rule_ptr;
	nts_route_entry_t *upstream_route = NULL, *downstream_route = NULL;
	nes_sq_t *upstream_entry = NULL, *downstream_entry = NULL;
	int rule_id;

	ip_addr.s_addr = local_dns_ip;
	if (is_gtpu) {
		snprintf(dns_lookup_key, NES_MAX_LOOKUP_ENTRY_LEN, ADD_ROUTING_GTPU_STRING,
			DNS_PRIO, inet_ntoa(ip_addr), DNS_PORT);
	} else {
		snprintf(dns_lookup_key, NES_MAX_LOOKUP_ENTRY_LEN, ADD_ROUTING_IP_STRING,
			DNS_PRIO, inet_ntoa(ip_addr), DNS_PORT);
	}
	if (NES_SUCCESS != nts_acl_cfg_lookup_prepare(&dns_upstream_rule,
			&ignored_rule, dns_lookup_key)) {
		NES_LOG(ERR, "Failed parsing: %s\n", dns_lookup_key);
		return NES_FAIL;
	}

	if (forward_unresolved_queries) {
		ip_addr.s_addr = external_dns_ip;
		if (is_gtpu) {
			snprintf(dns_lookup_key, NES_MAX_LOOKUP_ENTRY_LEN,
				ADD_ROUTING_GTPU_STRING, DNS_PRIO, inet_ntoa(ip_addr), DNS_PORT);
		} else {
			snprintf(dns_lookup_key, NES_MAX_LOOKUP_ENTRY_LEN,
				ADD_ROUTING_IP_STRING, DNS_PRIO, inet_ntoa(ip_addr), DNS_PORT);
		}
		// dns_downstream_rule will cover the traffic from external_dns_ip
		// with source port DNS_PORT
		if (NES_SUCCESS != nts_acl_cfg_lookup_prepare(&ignored_rule,
				&dns_downstream_rule, dns_lookup_key)) {
			NES_LOG(ERR, "Failed parsing: %s\n", dns_lookup_key);
			return NES_FAIL;
		}
	}

	if (NTS_ACL_LOOKUPS_DIFFER != nts_acl_cfg_overlaps(lookup_ctx, &dns_upstream_rule) ||
			(forward_unresolved_queries &&
			NTS_ACL_LOOKUPS_DIFFER != nts_acl_cfg_overlaps(lookup_ctx,
				&dns_downstream_rule)))
		NES_LOG(WARNING, "There is a rule overlapping with the DNS rule\n");

	if ((upstream_route = rte_malloc("dns route", sizeof (nts_route_entry_t), 0)) == NULL ||
			(forward_unresolved_queries && (downstream_route = rte_malloc("dns route",
				sizeof (nts_route_entry_t), 0)) == NULL)) {
		rte_free(upstream_route);
		NES_LOG(ERR, "Failed to allocate new dns routes\n");
		return NES_FAIL;
	}

	upstream_route->dst_ring = NULL;
	upstream_route->edit = nes_dns_agent_flow;
	upstream_route->ring_name = NULL;
	if (forward_unresolved_queries)
		memcpy(downstream_route, upstream_route, sizeof (*upstream_route));

	if (nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &dns_upstream_rule) >= 0 ||
			(forward_unresolved_queries && nes_acl_find_rule_id(lookup_ctx,
					(struct rte_acl_rule*) &dns_downstream_rule) >= 0)) {
		NES_LOG(ERR, "DNS agent rules already added\n");
		rte_free(upstream_route);
		rte_free(downstream_route);
	}

	if ((upstream_entry = rte_malloc("dns route entry", lookup_ctx->entry_size, 0)) == NULL) {
		NES_LOG(ERR, "Failed to allocate dns entry\n");
		return NES_FAIL;
	}
	nes_sq_ctor(upstream_entry);
	rule_ptr = &dns_upstream_rule;
	if (NES_SUCCESS != nes_acl_add_entries(lookup_ctx, (void**) &upstream_entry,
			(struct rte_acl_rule**) &rule_ptr, 1))
		NES_LOG(ERR, "Failed to add upstream entry\n");
	// entry is copied and not used anymore
	rte_free(upstream_entry);
	rule_id = nes_acl_find_rule_id(lookup_ctx, (struct rte_acl_rule*) &dns_upstream_rule);
	upstream_entry =
		lookup_ctx->entries[lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];

	if (forward_unresolved_queries) {
		if ((downstream_entry = rte_malloc("dns route entry",
				lookup_ctx->entry_size, 0)) == NULL) {
			NES_LOG(ERR, "Failed to allocate new entry\n");
			return NES_FAIL;
		}
		nes_sq_ctor(downstream_entry);
		rule_ptr = &dns_downstream_rule;
		if (NES_SUCCESS != nes_acl_add_entries(lookup_ctx, (void**) &downstream_entry,
				(struct rte_acl_rule**) &rule_ptr, 1))
			NES_LOG(ERR, "Failed to add upstream entry\n");
		// entry is copied and not used anymore
		rte_free(downstream_entry);
		rule_id = nes_acl_find_rule_id(lookup_ctx,
			(struct rte_acl_rule*) &dns_downstream_rule);
		downstream_entry = lookup_ctx->entries[
			lookup_ctx->rules[rule_id]->data.userdata - USER_DATA_OFFSET];
	}

	if (NES_SUCCESS != nes_sq_enq(upstream_entry, upstream_route) ||
			(forward_unresolved_queries &&
			NES_SUCCESS != nes_sq_enq(downstream_entry, downstream_route))) {
		NES_LOG(ERR, "Could not add routing entry");
		rte_free(upstream_route);
		rte_free(downstream_route);
		return NES_FAIL;
	}
	return NES_SUCCESS;
}

int
nes_dns_agent_add_routings(nes_acl_ctx_t* lookup_ctx) {
	assert(lookup_ctx);
	nes_ring_t *ring;

	if (NES_SUCCESS == nes_ring_find(&ring, "NTS_UPSTR_GTPU")) {
		if (NES_FAIL == nes_dns_agent_add_routing_impl(lookup_ctx, 1))
			return NES_FAIL;
	}
	if (NES_SUCCESS == nes_ring_find(&ring, "NTS_UPSTR_IP")) {
		if (NES_FAIL == nes_dns_agent_add_routing_impl(lookup_ctx, 0))
			return NES_FAIL;
	}
	return NES_SUCCESS;
}

NES_STATIC int
nes_dns_agent_setup(const char *tap_name) {

	if (NES_SUCCESS != nes_cfgfile_has_section(DNS_AGENT_SECTION)) {
		NES_LOG(INFO, "No \"%s\" in config file, DNS agent won't start\n",
			DNS_AGENT_SECTION);
		return NES_FAIL;
	}

	if (NULL == tap_name) {
		NES_LOG(ERR, "Empty tap device name\n");
		return NES_FAIL;
	}

	pktmbuf_pool = rte_mempool_create("mbuf_pool", NB_MBUF, MBUF_SZ,
		MEMPOOL_CACHE_SZ,
		sizeof (struct rte_pktmbuf_pool_private),
		rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
		rte_socket_id(), 0);
	if (pktmbuf_pool == NULL) {
		NES_LOG(ERR, "Could not initialise mbuf pool\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_dns_mac_from_cfg(DNS_AGENT_LOCAL_DNS_MAC, &local_dns_mac)) {
		NES_LOG(ERR, "Failed to read %s\n", DNS_AGENT_LOCAL_DNS_MAC);
		return NES_FAIL;
	}
	if (NES_SUCCESS != nes_dns_ip_from_cfg(DNS_AGENT_LOCAL_DNS_IP, &local_dns_ip)) {
		NES_LOG(ERR, "Could not read local DNS ip\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_dns_check_forward_unresolved(DNS_AGENT_FORWARD_UNRESOLVED,
			&forward_unresolved_queries)) {
		NES_LOG(WARNING, "%s isn't set in the config file," \
			" forwarding unresolved queries is turned off\n",
			DNS_AGENT_FORWARD_UNRESOLVED);
	}

	if (forward_unresolved_queries) {
		if (NES_SUCCESS != nes_dns_ip_from_cfg(DNS_AGENT_EXTERNAL_DNS_IP,
				&external_dns_ip)) {
			NES_LOG(ERR, "Could not read external DNS ip\n");
			return NES_FAIL;
		}
		if (NES_SUCCESS != nes_dns_mac_from_cfg(DNS_AGENT_EXTERNAL_DNS_GW_MAC,
				&external_dns_gw_mac)) {
			NES_LOG(ERR, "Failed to read %s\n", DNS_AGENT_EXTERNAL_DNS_GW_MAC);
			return NES_FAIL;
		}
	}

	if ((tap_dev_fd = nes_dns_tap_create(tap_name, &local_dns_mac, &local_dns_ip, 0)) < 0) {
		NES_LOG(ERR, "Failed to setup %s\n", tap_name);
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_dns_agent_add_routings(&nes_ctrl_acl_ctx)) {
		NES_LOG(ERR, "Failed to setup DNS routing\n");
		return NES_FAIL;
	}

	if (DNS_FORWARD_ON == forward_unresolved_queries) {
		if (NES_FAIL == nes_dns_load_static_hosts()) {
			NES_LOG(ERR, "Failed to read static DNS entries\n");
			return NES_FAIL;
		}
	}
	return NES_SUCCESS;
}

NES_STATIC void
nes_dns_tap_loop(void) {
	int ret;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	const uint16_t dns_port = rte_cpu_to_be_16(DNS_PORT);
	nts_enc_entry_t *encap_entry = NULL;
	routing_table = nts_io_routing_tables_get();
	char *buf_ptr;
	int buf_length;

	for (;;) {
		struct rte_mbuf *m = rte_pktmbuf_alloc(pktmbuf_pool);
		if (m == NULL)
			continue;
		ret = read(tap_dev_fd, rte_pktmbuf_mtod(m, void*), MAX_PACKET_SZ);
		if (ret < 0) {
			rte_pktmbuf_free(m);
			continue;
		}
		m->nb_segs = 1;
		m->pkt_len = (uint16_t) ret;
		m->data_len = (uint16_t) ret;
		m->next = NULL;

		if (NES_SUCCESS == nes_dns_is_arp(m)) {
			struct ether_addr addr;
			uint8_t addr_bytes[ETHER_ADDR_LEN] = {0x0, 0x1e, 0x67, 0xd1, 0x9e, 0xde};
			rte_memcpy(addr.addr_bytes, addr_bytes, ETHER_ADDR_LEN);

			if (NES_SUCCESS != nes_arp_response(m, addr)) {
				rte_pktmbuf_free(m);
				continue;
			}

			buf_ptr = rte_pktmbuf_mtod(m, char*);
			buf_length = rte_pktmbuf_data_len(m);

			while (buf_length) {
				ret = write(tap_dev_fd, buf_ptr, buf_length);
				if (-1 == ret) {
					NES_LOG(ERR, "Error writing to DNS TAP socket!\n");
					break;
				} else if (0 < ret) {
					buf_ptr += ret;
					buf_length -= ret;
				} else
					break;
			}
			rte_pktmbuf_free(m);
			continue;
		}

		if (NES_SUCCESS != nes_dns_is_ip(m) || (ip_hdr = (struct ipv4_hdr*)
				(rte_pktmbuf_mtod(m, struct ether_hdr *) + 1))->next_proto_id != IP_PROTO_UDP) {
			rte_pktmbuf_free(m);
			continue;
		}

		udp_hdr = (struct udp_hdr*)
			((uint32_t*) ip_hdr + (*(uint8_t*) ip_hdr & IPV4_HDR_IHL_MASK));
		if (udp_hdr->src_port != dns_port || ip_hdr->src_addr != local_dns_ip) {
			rte_pktmbuf_free(m);
			continue;
		}
		if (NES_FAIL == nes_lookup_entry_find(routing_table->learning, &ip_hdr->dst_addr,
				(void**) &encap_entry)) {
			rte_pktmbuf_free(m);
			continue;
		}
		if ((NTS_ENCAP_GTPU_FLAG & encap_entry->downstream.encap_flag)) {
			if (NES_SUCCESS != nes_dns_agent_encap(m, encap_entry)) {
				rte_pktmbuf_free(m);
				continue;
			}
		} else {
			ip_head_t *pkt_header;
			struct ether_hdr * eth_header;
			if (NTS_ENCAP_VLAN_FLAG & encap_entry->downstream.encap_flag) {
				struct vlan_hdr * vlan_header;
				pkt_header = (ip_head_t *)
					rte_pktmbuf_prepend(m, sizeof(struct vlan_hdr));
				if (NULL == pkt_header) {
					rte_pktmbuf_free(m);
					continue;
				}
				eth_header = &pkt_header->ip_vlan.ether_hdr;
				vlan_header = &pkt_header->ip_vlan.vlan_hdr;
				eth_header->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);
				vlan_header->vlan_tci = encap_entry->downstream.vlan_tci;
				vlan_header->eth_proto= rte_cpu_to_be_16(ETHER_TYPE_IPv4);
			} else {
				pkt_header = rte_pktmbuf_mtod(m, ip_head_t *);
				if (NULL == pkt_header) {
					rte_pktmbuf_free(m);
					continue;
				}
				eth_header = &pkt_header->ip_no_vlan.ether_hdr;
				eth_header->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
			}
			ether_addr_copy(&encap_entry->downstream.dst_mac_addrs,
				&eth_header->d_addr);
			ether_addr_copy(&encap_entry->downstream.src_mac_addrs,
				&eth_header->s_addr);
		}
		nes_ring_t *ring = encap_entry->downstream.dst_ring;
		if (NULL == ring)
			rte_pktmbuf_free(m);
		else
			ring->enq(ring, m);
	}
}

int
nes_dns_agent_main(__attribute__((unused))void *arg) {
	if (NES_SUCCESS != nes_dns_agent_setup(DNS_AGENT_TAP_DEV_NAME)) {
		rte_atomic32_add(&threads_started, THREAD_DNS_ID);
		NES_LOG(WARNING, "DNS agent not working\n");
		return 0;
	}
	NES_LOG(INFO, "DNS agent started\n");
	rte_atomic32_add(&threads_started, THREAD_DNS_ID);
	nes_dns_tap_loop();
	return 0;
}
