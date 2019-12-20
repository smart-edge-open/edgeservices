/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_api_common.h
 * @brief Common header file for NES daemon and external client
 *
 * Contains definitions shared between NES daemon and NES API user.
 * Should not be included directly, but it is not prohibited.
 */

#ifndef _NES_API_COMMON_H_
#define _NES_API_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __DOXYGEN__
#ifdef NES_DAEMON
#include <rte_ether.h>
#include <rte_ip.h>
#else
#include <netinet/ether.h>
#include <netinet/ip.h>
#endif /* NES_DAEMON */
#endif /*__DOXYGEN__*/

/** Size of ctrl device or ring name string */
#define CTRL_NAME_SIZE 15

/**
 * NES error return values
 */
enum NES_ERROR {
	/**
	 * on success
	 */
	NES_SUCCESS = 0,
	/**
	 * on failure
	 */
	NES_FAIL
};

/**
 * NTS editing modes.
 * Except NULL_CALLBACK all edit modes assume forwarding after packet is modified.
 */
typedef enum {
	/**
	 * Special purpose "do-not-touch" mode
	 */
	NTS_EDIT_NULL_CALLBACK,
	/**
	 * Actions: decapsulate and forward
	 */
	NTS_EDIT_DECAP_ONLY,
	/**
	 * Actions: do not decapsulate, forward
	 */
	NTS_EDIT_NODECAP,
	/**
	 * Actions: decapsulate, replace service IP with VM IP, forward
	 */
	NTS_EDIT_DECAP_IP_REPLACE,
	/**
	 * Actions: update reference counter and send the packet to the VM
	 */
	NTS_EDIT_MIRROR,
	/**
	 * Actions: update reference counter, send the packet to the VM
	 * and send it upstream or downstream.
	 */
	NTS_EDIT_MIRROR_LAST
} nts_edit_modes_t;


/**
 * Route entry contents.
 */
typedef struct nes_route_entry_data_s {
	/**
	 * VM MAC address (a placeholder).
	 */
	struct ether_addr macaddr;
	/**
	 * VM IP address (a placeholder).
	 */
	struct in_addr    ipaddr;
	/**
	 * VM identifier.
	 */
	int               vmid;
	/**
	 * Callback mode.
	 */
	nts_edit_modes_t  cbmode;
} nes_route_entry_data_t;

typedef struct nes_route_list_req_s {
	/**
	 * Number of existing routes to skip
	 */
	uint16_t entry_offset;
	/**
	 * Specifies the maximum number of entries to read
	 */
	uint16_t max_entry_cnt;
} __attribute__ ((__packed__)) nes_route_list_req_t;

#define ROUTES_LIST_MAX_CNT 1024

typedef struct nes_route_data_s {
	/**
	 * Priority of the route
	 */
	int prio;
	/**
	 * Encapsulation protocol
	 */
	uint8_t encap_proto;
	/**
	 * QCI range start
	 */
	uint8_t qci_min;
	/**
	 * QCI range end
	 */
	uint8_t qci_max;
	/**
	 * SPID range start
	 */
	uint8_t spid_min;
	/**
	 * SPID range end
	 */
	uint8_t spid_max;
	/**
	 * TEID range start
	 */
	uint32_t teid_min;
	/**
	 * TEID range end
	 */
	uint32_t teid_max;
	/**
	 * ENB IP
	 */
	uint32_t enb_ip;
	/**
	 * ENB IP mask
	 */
	uint32_t enb_ip_mask;
	/**
	 * EPC IP
	 */
	uint32_t epc_ip;
	/**
	 * EPC IP mask
	 */
	uint32_t epc_ip_mask;
	/**
	 * UE IP
	 */
	uint32_t ue_ip;
	/**
	 * UE IP mask
	 */
	uint32_t ue_ip_mask;
	/**
	 * Service IP
	 */
	uint32_t srv_ip;
	/**
	 * Service IP mask
	 */
	uint32_t srv_ip_mask;
	/**
	 * UE port range start
	 */
	uint16_t ue_port_min;
	/**
	 * UE port range end
	 */
	uint16_t ue_port_max;
	/**
	 * Service port range start
	 */
	uint16_t srv_port_min;
	/**
	 * Service port range end
	 */
	uint16_t srv_port_max;

	struct ether_addr dst_mac_addr;
} __attribute__ ((__packed__)) nes_route_data_t;
/**
 * Statistics for device structure
 */
typedef struct nes_dev_stats_s {
	/**
	 * Number of packets received
	 */
	uint64_t  rcv_cnt;
	/**
	 * Number of packets sent
	 */
	uint64_t  snd_cnt;
	/**
	 * Number of packets dropped (caused by a TX buffer overflow)
	 */
	uint64_t  drp_cnt_1;
	/**
	 * Number of packets dropped (read from physical card)
	 */
	uint64_t  drp_cnt_2;
	/**
	 * Number of bytes received
	 */
	uint64_t  rcv_bytes;
	/**
	 * Number of bytes sent
	 */
	uint64_t  snd_bytes;
	/**
	 * Number of bytes dropped (caused by a TX buffer overflow)
	 */
	uint64_t  drp_bytes_1;
	/**
	 * Number of IP fragmented packets
	 */
	uint64_t  ip_fragment;
} __attribute__ ((__packed__)) nes_dev_stats_t;

/**
 * Statistics for ring structure
 */
typedef struct nes_ring_stats_s {
	/**
	 * Number of packets received
	 */
	uint64_t  rcv_cnt;
	/**
	 * Number of packets sent
	 */
	uint64_t  snd_cnt;
	/**
	 * Ring Full dropped packets counter
	 */
	uint64_t  drp_cnt_1;
	/**
	 * No Route dropped packets counter
	 */
	uint64_t  drp_cnt_2;

} __attribute__ ((__packed__)) nes_ring_stats_t;

#define VERIFY_PTR_OR_RET(ptr, ret_val) do {    \
		if (NULL == (ptr))      \
			return (ret_val);   \
	} while(0)


#ifdef __cplusplus
}
#endif
#endif /* _NES_API_COMMON_H_ */
