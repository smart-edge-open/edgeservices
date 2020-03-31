/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_api.h
 * @brief NES API library header file
 *
 * The functions marked as INTERNAL are supported by command line interface
 * but not JSON based RESTful API. It can change in the future.
 * Functions marked as EXPERIMENTAL are newly defined and may still be under discussion,
 * i.e. their names, prototypes or semantics can be changed, but it is highly unlikely.
 * @todo   Enable the detailed diagnostics by providing more meaningful
 *         return values of NES API calls
 */

#ifndef _LIBNES_API_H_
#define _LIBNES_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __DOXYGEN__
#include "libnes_sq.h"
#include "nes_api_common.h"
#endif /*__DOXYGEN__*/
#define NES_MAX_LOOKUP_ENTRY_LEN 220
#define NES_MAX_KNI_ENTRY_LEN 64

typedef void (*nes_connection_closed_cb)(void);
typedef void (*nes_on_error_cb)(void);

typedef enum nes_remote_state
{
	eInvalid,
	eConnected,
	eDisconnected
} nes_remote_state_t;

typedef struct nes_remote_s
{
	int socket_fd;
	nes_remote_state_t state;
	char     *ip_address;
	uint16_t port_nr;

	nes_connection_closed_cb on_connection_closed;
	nes_on_error_cb          on_error;

} __attribute__ ((aligned (8))) nes_remote_t;

/**
 * NES_API device structure
 */
typedef struct nes_api_dev_s {
	/**
	 * Device name
	 */
	char      name[CTRL_NAME_SIZE];
	/**
	 * Device index
	 */
	uint16_t  index;
	/**
	 * MAC address
	 */
	struct ether_addr macaddr;
	/**
	 * Device statistics structure
	 */
	nes_dev_stats_t  stats;

} __attribute__ ((aligned (8))) nes_api_dev_t;

/**
 * NES_API ring structure
 */
typedef struct nes_api_ring_s {

	/**
	 * Ring name
	 */
	char      name[CTRL_NAME_SIZE];
	/**
	 * Ring index
	 */
	uint16_t  index;
	/**
	 * Ring statistics structure
	 */
	nes_ring_stats_t stats;

} __attribute__ ((__packed__)) nes_api_ring_t;

#ifndef LIB_NES_SHARED
/**
 * @brief Initialize connection with NES server.
 *
 * @param[in] self    - connection entity
 * @param[in] ip_addr - IP address of NES server [obsolete]
 * @param[in] port    - Port number of NES server [obsolete]
 * @return NES_SUCCESS on success and NES_FAIL on fail
 */
int nes_conn_init(nes_remote_t *self, char *ip_addr, uint16_t port);
#endif

/**
 * @brief Connect to NES server.
 *
 * @param[in] self - connection entity
 * @param[in] unix_sock_path - unix socket path, if NULL self->ip_address and self->port_nr are used
 * @return NES_SUCCESS on success and NES_FAIL on fail
 */
int nes_conn_start(nes_remote_t *self, const char *unix_sock_path);

/**
 * @brief Close the connection with NES server.
 *
 * @param[in] self - connection entity
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_conn_close(nes_remote_t *self);

/**
 * @brief Shows list of all devices with id number.
 *
 * @param[in] self - connection entity
 * @return Device  list on success and NULL on fail.
 */
nes_sq_t *nes_stats_show_list(nes_remote_t *self);

/**
 * @brief
 * Shows list of all devices with number of received,
 * sent and dropped packets.
 *
 * @param[in] self - connection entity
 * @return nes_sq_t *device_list
 */
nes_sq_t *nes_stats_all_dev(nes_remote_t *self);

/**
 * @brief
 * Shows list of all rings with number of received,
 * sent and dropped packets.
 *
 * @param[in] self - connection entity
 * @return nes_sq_t *device_list
 */
nes_sq_t *nes_stats_all_ring(nes_remote_t *self);

/**
 * @brief Shows statistics for specified device.<br>
 * The ID number from devices list need to be entered.
 *
 * @param[in] self
 *   connection entity
 * @param[in] id
 *   device identification number (from devices list)
 * @param[out] stats
 *   pointer to the device statistics structure.
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_stats_dev(nes_remote_t *self, uint16_t id, nes_dev_stats_t *stats);
/**
 * @brief Shows statistics for specified ring.<br>
 * The ID number from ring list need to be entered.
 *
 * @param[in] self
 *   connection entity
 * @param[in] id
 *   ring identification number (from ring list)
 * @param[out] stats
 *   pointer to the device statistics structure.
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_stats_ring(nes_remote_t *self, uint16_t id, nes_ring_stats_t *stats);
/**
 * @brief
 * Clear all devices and rings statistics.
 *
 * @param[in] self - connection entity
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_clear_all_stats(nes_remote_t *self);

/**
 * @brief Add route entry.
 *
 * @param[in] self - connection entity
 * @param[in] vm_mac_addr - VM MAC address
 * @anchor lookup_keys
 * @param[in] lookup_keys - values or ranges of keys for desired entry.
 *   - Input string format: prio:PRIO, coma separated lookup fields.
 *     -  Priority - weight to measure the priority of the rules (higher is better),
 *                   must be in the range of 0 to 536870911
 *     -  encap_proto  : Specify encapsulation protocol<br>
 *          Possible values are "gtpu" or "noencap". If unset GTP-U encapsulation is assumed
 *     -  ue_ip    : IP[/IP_MASK]
 *     -  srv_ip   : IP[/IP_MASK]
 *     -  enb_ip   : IP[/IP_MASK] (not used for IP support on SGI interface)
 *     -  epc_ip   : IP[/IP_MASK] (not used for IP support on SGI interface)<br>
 *          IP must be in the range of 0.0.0.0 to 255.255.255.255<br>
 *          IP_MASK must be in range of 0 to 32
 *     -  ue_port  : PORT_MIN[-PORT_MAX]
 *     -  srv_port : PORT_MIN[-PORT_MAX]<br>
 *          PORT_MIN/PORT_MAX must be in the range of 0 to 65535
 *     -  teid     : TEID_MIN[-TEID_MAX] (not used for IP support on SGI interface)<br>
 *          TEID_MIN/TEID_MAX must be in the range of 0 to 4294967295
 *     -  qci      : QCI_MIN[-QCI_MAX] (not used for IP support on SGI interface)
 *     -  spid     : SPID_MIN[-SPID_MAX] (not used for IP support on SGI interface)<br>
 *          QCI_MIN/QCI_MAX as well as SPID_MIN/SPID_MAX must be in the range of 0 to 255<br>
 *     The parameter should always contain a prio field and
 *     at least one of the other parameters described above
 *     (e.g.  "prio:99,srv_ip:192.168.10.00/24"),
 *     the values of not provided fields are set to "any"(the whole range) by default.
 *     If max value/mask is not provided min value is used as max
 *     (e.g. "prio:99,srv_ip:192.168.10.11,srv_port:80" is the same as
 *     "prio:99,srv_ip:192.168.10.11/32,srv_port:80-80")<br>
 *     For IP routing example:<br>
 *     "prio:99,encap_proto:noencap,srv_ip:192.168.10.11,srv_port:80"
 * @param[in] vmid - ID of VM [obsolete]
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_add(nes_remote_t *self, struct ether_addr vm_mac_addr, char *lookup_keys, int vmid);

/**
 * @brief Add KNI interface.
 *
 * @param[in] self - connection entity
 * @param[in] dev_id_name - KNI device identification string
 * @param[out] created_if_name - Created KNI interface name
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_kni_add(nes_remote_t *self, const char *dev_id_name, char *created_if_name);

/**
 * @brief Delete KNI interface.
 *
 * @param[in] self - connection entity
 * @param[in] dev_id_name - KNI device identification string
 * @param[out] deleted_if_name - Deleted KNI interface name
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_kni_del(nes_remote_t *self, const char *dev_id_name, char *deleted_if_name);

/**
 * @brief Add mirror route entry.<br>
 * INTERNAL. Not supported by RESTful API.
 *
 * @param[in] self - connection entity
 * @param[in] vm_mac_addr - VM MAC address
 * @param[in] lookup_keys - values or ranges of keys for desired entry.
 *                          See @ref lookup_keys for details.
 * @param[in] vmid - ID of VM [obsolete]
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_add_mirror(nes_remote_t *self, struct ether_addr vm_mac_addr, char *lookup_keys,
	int vmid);

/**
 * @brief Show route entry.<br>
 * INTERNAL. Not supported by RESTful API.
 *
 * @param[in] self - connection entity
 * @param[in] lookup_keys - values or ranges of keys for desired entry.
 *                          See @ref lookup_keys for details.
 * @param[out] upstream_route - list of found upstream entries
 * @param[out] downstream_route - list of found downstream entries
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_show(nes_remote_t *self, char *lookup_keys, nes_sq_t *upstream_route,
	nes_sq_t *downstream_route);

/**
 * @brief List routes. <br>
 * INTERNAL. Not supported by RESTful API.
 *
 * @param[in] self - connection entity
 * @param[in] entry_offset - number of existing routes to skip
 * @param[in] max_entry_cnt - specifies the maximum number of entries to read
 * @param[out] routes - array of routes
 * @param[out] route_cnt - routes array size
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_list(nes_remote_t *self, uint16_t entry_offset, uint16_t max_entry_cnt,
	nes_route_data_t **routes, uint16_t *route_cnt);

/**
 * @brief Show mirror route entry.<br>
 * INTERNAL. Not supported by RESTful API.
 *
 * @param[in] self - connection entity
 * @param[in] lookup_keys - values or ranges of keys for desired entry.
 *                          See @ref lookup_keys for details.
 * @param[out] upstream_route - list of found upstream entries
 * @param[out] downstream_route - list of found downstream entries
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_show_mirror(nes_remote_t *self, char *lookup_keys, nes_sq_t *upstream_route,
	nes_sq_t *downstream_route);

/**
 * @brief Remove route entry.
 *
 * @param[in] self - connection entity
 * @param[in] lookup_keys - values or ranges of keys for desired entry.
 *                          See @ref lookup_keys for details.
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_remove(nes_remote_t *self, char *lookup_keys);

/**
 * @brief Remove mirror route entry.<br>
 * INTERNAL. Not supported by RESTful API.
 *
 * @param[in] self connection entity
 * @param[in] lookup_keys - values or ranges of keys for desired entry.
 *                          See @ref lookup_keys for details.
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_remove_mirror(nes_remote_t *self, char *lookup_keys);


/**
 * @brief Retrieves the MAC address for specified port.<br>
 * INTERNAL. Not supported by RESTful API.
 *
 * @param[in] self connection entity.
 * @param[in] port_id dpdk port id.
 * @param[out] mac_addr MAC address string pointer, string must be allocated.
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_dev_port_mac_addr(nes_remote_t *self, uint8_t port_id, char **mac_addr);

/**
 * @brief
 * Clear all NES routes.
 *
 * @param[in] self - connection entity
 * @return NES_SUCCESS on success and NES_FAIL on fail.
 */
int nes_route_clear_all(nes_remote_t *self);

#ifdef __cplusplus
}
#endif
#endif /* _LIBNES_API_H_ */
