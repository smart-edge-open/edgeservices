/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_cli.c
 * @brief nes command line
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <fcntl.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include <unistd.h>

#include "nes_common.h"
#include "libnes_api.h"
#include "nes_cli.h"

#include "nes_client.h"
#include "nes_cmdline_parse_string.h"
#include "nts/nts_route.h"

#define KNI_NAMESIZE 32

typedef struct nis_routing_data_s {
	uint8_t qci;
	uint8_t spid;
} nis_routing_data_t;

typedef struct nis_routing_data_key_s {
	uint32_t teid;
	uint32_t enb_ip;
	nes_direction_t direction;
} __attribute__((__packed__)) nis_routing_data_key_t;
#define ETHER_ADDR_FMT_SIZE 18

nes_remote_t remote_NEV;
static uint8_t is_in_filemode;

typedef enum {
	dst,
	src,
	other
} mac_addr_t;

/* Connection init */
typedef struct cmd_conn_default_init_result {
	cmdline_fixed_string_t connect_string;
} cmd_conn_defaultinit_result;

static void
nes_conn_default_init_parsed(__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {

	if (NES_SUCCESS == nes_conn_init(&remote_NEV, NULL, 0))
		cmdline_printf(nes_cmdline, "Connection is established.\n");
	else
		cmdline_printf(nes_cmdline, "Can't connect NES server!\n");
}

static void
print_mac_addr(struct ether_addr *mac_addr, int type, struct cmdline *nes_cmdline) {
	if (NULL == mac_addr) {
		cmdline_printf(nes_cmdline, "Entry not found!\n");
		return;
	}
	char buf[ETHER_ADDR_FMT_SIZE];

	ether_ntoa_r(mac_addr, buf);

	if (type == dst)
		cmdline_printf(nes_cmdline, "Destination MAC address: %s\n", buf);
	else if (type == src)
		cmdline_printf(nes_cmdline, "Source MAC address: %s\n", buf);
	else
		cmdline_printf(nes_cmdline, "MAC address: %s\n", buf);
}

/* Connection init*/
typedef struct cmd_conn_init_result {
	cmdline_fixed_string_t connect_string;
	cmdline_fixed_string_t ip_addr;
	uint16_t port;
} cmd_conn_init_result;

static void
nes_conn_init_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_conn_init_result *res = parsed_result;
	if (NES_SUCCESS == nes_conn_init(&remote_NEV, res->ip_addr, res->port))
		cmdline_printf(nes_cmdline, "Connection is established.\n");
	else
		cmdline_printf(nes_cmdline, "Can't connect NES server!\n");
}

cmdline_parse_token_string_t cmd_conn_default_init_string =
	TOKEN_STRING_INITIALIZER(struct cmd_conn_default_init_result, connect_string, "connect");

cmdline_parse_token_string_t cmd_conn_init_string =
	TOKEN_STRING_INITIALIZER(struct cmd_conn_init_result, connect_string, "connect");

cmdline_parse_token_string_t cmd_conn_init_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_conn_init_result, ip_addr, NULL);

cmdline_parse_token_num_t cmd_conn_init_port =
	TOKEN_NUM_INITIALIZER(struct cmd_conn_init_result, port, UINT16);

cmdline_parse_inst_t cmd_conn_default_init = {
	.f = nes_conn_default_init_parsed,
	.data = NULL,
	.help_str = "connect",
	.tokens =
	{
		(void *) &cmd_conn_init_string,
		NULL,
	},
};

cmdline_parse_inst_t cmd_conn_init = {
	.f = nes_conn_init_parsed,
	.data = NULL,
	.help_str = "connect [ip_address] [port]",
	.tokens =
	{
		(void *) &cmd_conn_init_string,
		(void *) &cmd_conn_init_ip,
		(void *) &cmd_conn_init_port,
		NULL,
	},
};

typedef struct cmd_ctrl_del_route_result {
	cmdline_fixed_string_t show_string;
	cmdline_fixed_string_t route_string;
	nes_cmdline_acl_string_t route_data;
} cmd_ctrl_del_route_result_t;

static void
nes_ctrl_route_del_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_del_route_result *res = parsed_result;
	if (NES_SUCCESS == nes_route_remove(&remote_NEV, res->route_data))
		cmdline_printf(nes_cmdline, "Routing entry is deleted.\n");
	else
		cmdline_printf(nes_cmdline, "Routing entry could not be deleted!\n");
}

static void
nes_ctrl_route_del_mirror_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	struct cmd_ctrl_del_route_result *res = parsed_result;
	if (NES_SUCCESS == nes_route_remove_mirror(&remote_NEV, res->route_data))
		cmdline_printf(nes_cmdline, "Mirror entry is deleted.\n");
	else
		cmdline_printf(nes_cmdline, "Mirror entry could not be deleted!\n");
}

/* Add routing entry */
typedef struct cmd_ctrl_route_add_result {
	cmdline_fixed_string_t add_string;
	cmdline_fixed_string_t route_string;
	struct ether_addr mac_addr;
	nes_cmdline_acl_string_t route_data;
} cmd_ctrl_route_add_result;

static void
nes_ctrl_route_add_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_route_add_result *res = parsed_result;

	if (NES_SUCCESS != nes_route_add(&remote_NEV, res->mac_addr, res->route_data, -1))
		cmdline_printf(nes_cmdline, "Route entry could not be added!\n");
	else
		cmdline_printf(nes_cmdline, "Route entry added.\n");
}

static void
nes_ctrl_route_add_mirror_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	struct cmd_ctrl_route_add_result *res = parsed_result;

	if (NES_SUCCESS != nes_route_add_mirror(&remote_NEV, res->mac_addr, res->route_data, -1))
		cmdline_printf(nes_cmdline, "Mirroring entry could not be added!\n");
	else
		cmdline_printf(nes_cmdline, "Mirroring entry added.\n");
}

cmdline_parse_token_string_t cmd_ctrl_route_add_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_add_result, add_string, "add");

cmdline_parse_token_string_t cmd_ctrl_route_add_mirror_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_add_result, add_string, "add-mirror");

cmdline_parse_token_string_t cmd_ctrl_route_data_string =
	NES_TOKEN_ACL_STRING_INITIALIZER(struct cmd_ctrl_route_add_result, route_data, NULL);

cmdline_parse_token_string_t cmd_ctrl_route_string_add =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_add_result, route_string, "route");

cmdline_parse_token_etheraddr_t cmd_ctrl_route_add_mac_addr =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_ctrl_route_add_result, mac_addr);


cmdline_parse_inst_t cmd_ctrl_route_add = {
	.f = nes_ctrl_route_add_parsed,
	.data = NULL,
	.help_str = "Add routing entry",
	.tokens =
	{
		(void *) &cmd_ctrl_route_string_add,
		(void *) &cmd_ctrl_route_add_string,
		(void *) &cmd_ctrl_route_add_mac_addr,
		(void *) &cmd_ctrl_route_data_string,
		NULL,
	},
};

cmdline_parse_inst_t cmd_ctrl_route_add_mirror = {
	.f = nes_ctrl_route_add_mirror_parsed,
	.data = NULL,
	.help_str = "Add mirror entry",
	.tokens =
	{
		(void *) &cmd_ctrl_route_string_add,
		(void *) &cmd_ctrl_route_add_mirror_string,
		(void *) &cmd_ctrl_route_add_mac_addr,
		(void *) &cmd_ctrl_route_data_string,
		NULL,
	},
};

/* Show routing entry */
typedef struct cmd_ctrl_show_route_result {
	cmdline_fixed_string_t show_string;
	cmdline_fixed_string_t route_string;
	nes_cmdline_acl_string_t route_data;
} cmd_ctrl_show_route_result_t;

/* Show all routings */
typedef struct cmd_ctrl_show_route_all_result {
	cmdline_fixed_string_t route_string;
	cmdline_fixed_string_t list_string;
} cmd_ctrl_show_route_all_result_t;

#define MODE_NAME_LEN 128

static const char*
nts_edit_mode_to_str(nts_edit_modes_t mode) {

	static char ret[MODE_NAME_LEN];
	switch (mode) {
	case NTS_EDIT_NULL_CALLBACK:
		strncpy(ret, "empty", MODE_NAME_LEN);
		break;
	case NTS_EDIT_DECAP_ONLY:
		strncpy(ret, "decap only", MODE_NAME_LEN);
		break;
	case NTS_EDIT_DECAP_IP_REPLACE:
		strncpy(ret, "decap and replace ip", MODE_NAME_LEN);
		break;
	case NTS_EDIT_MIRROR:
		strncpy(ret, "mirror", MODE_NAME_LEN);
		break;
	case NTS_EDIT_MIRROR_LAST:
		strncpy(ret, "mirror and forward", MODE_NAME_LEN);
		break;
	default:
		strncpy(ret, "unknown!", MODE_NAME_LEN);
		break;
	}
	return ret;
}

static void
nes_ctrl_route_show_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	nes_sq_node_t *item = NULL;
	nes_route_entry_data_t *route = NULL;

	struct cmd_ctrl_show_route_result *res = parsed_result;
	nes_sq_t downstream_route, upstream_route;

	nes_sq_ctor(&upstream_route);
	nes_sq_ctor(&downstream_route);

	if (NES_SUCCESS == nes_route_show(&remote_NEV, res->route_data, &upstream_route,
			&downstream_route)) {
		cmdline_printf(nes_cmdline, "Upstream entries:\n");

		NES_SQ_FOREACH(item, &upstream_route) {
			route = nes_sq_data(item);
			print_mac_addr(&route->macaddr, other, nes_cmdline);
			cmdline_printf(nes_cmdline, "Type: %s\n",
				nts_edit_mode_to_str(route->cbmode));
		}
		cmdline_printf(nes_cmdline, "Downstream entries:\n");

		NES_SQ_FOREACH(item, &downstream_route) {
			route = nes_sq_data(item);
			print_mac_addr(&route->macaddr, other, nes_cmdline);
			cmdline_printf(nes_cmdline, "Type: %s\n",
				nts_edit_mode_to_str(route->cbmode));
		}

	} else
		cmdline_printf(nes_cmdline, "Error. Routing entry not found!\n");

	nes_sq_dtor(&upstream_route);
	nes_sq_dtor(&downstream_route);
}

cmdline_parse_token_string_t cmd_ctrl_route_show_data_string =
	NES_TOKEN_ACL_STRING_INITIALIZER(struct cmd_ctrl_show_route_result, route_data, NULL);

cmdline_parse_token_string_t cmd_ctrl_route_del_data_string =
	NES_TOKEN_ACL_STRING_INITIALIZER(struct cmd_ctrl_del_route_result, route_data, NULL);

cmdline_parse_token_string_t cmd_ctrl_route_show_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_route_result, show_string, "show");

cmdline_parse_token_string_t cmd_ctrl_route_show_mirror_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_route_result, show_string, "show-mirror");

cmdline_parse_token_string_t cmd_ctrl_route_del_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_del_route_result, show_string, "del");
cmdline_parse_token_string_t cmd_ctrl_route_del_mirror_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_del_route_result, show_string, "del-mirror");

cmdline_parse_token_string_t cmd_ctrl_route_string_del =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_del_route_result, route_string, "route");

cmdline_parse_token_string_t cmd_ctrl_route_string_show =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_route_result, route_string, "route");

cmdline_parse_inst_t cmd_ctrl_route_show = {
	.f = nes_ctrl_route_show_parsed,
	.data = NULL,
	.help_str = "Show routing entry",
	.tokens =
	{
		(void *) &cmd_ctrl_route_string_show,
		(void *) &cmd_ctrl_route_show_string,
		(void *) &cmd_ctrl_route_show_data_string,
		NULL,
	},
};

cmdline_parse_inst_t cmd_ctrl_route_show_mirror = {
	.f = nes_ctrl_route_show_parsed,
	.data = NULL,
	.help_str = "Show mirror entry",
	.tokens =
	{
		(void *) &cmd_ctrl_route_string_show,
		(void *) &cmd_ctrl_route_show_mirror_string,
		(void *) &cmd_ctrl_route_show_data_string,
		NULL,
	},
};

#define MAX_IP_NET_STR sizeof("255.255.255.255/32")
#define MAX_PORT_RANGE_STR sizeof("65535-65535")

static void print_ip_net(struct cmdline *nes_cmdline, uint32_t ip, uint32_t mask)
{
	struct in_addr ipaddr;
	char ip_net_str[MAX_IP_NET_STR] = "*";

	ipaddr.s_addr = htonl(ip);
	if (mask) {
		snprintf(ip_net_str, MAX_IP_NET_STR, "%s/%u", inet_ntoa(ipaddr),
			mask);
	}
	cmdline_printf(nes_cmdline, " %-18s |", ip_net_str);
}

static void print_port_range(struct cmdline *nes_cmdline, uint16_t port_min, uint16_t port_max)
{
	char port_range_str[MAX_PORT_RANGE_STR] = "*";

	if (port_max - port_min != UINT16_MAX)
		snprintf(port_range_str, MAX_PORT_RANGE_STR, "%u-%u", port_min, port_max);

	cmdline_printf(nes_cmdline, " %-11s |", port_range_str);
}

static void
nes_ctrl_route_show_all_parsed(__attribute__((unused)) void *parsed_result,
	struct cmdline *nes_cmdline, __attribute__((unused)) void *data)
{
	const char *separator_line =
		"+-------+------------+--------------------+" \
		"--------------------+--------------------+" \
		"--------------------+-------------+" \
		"-------------+--------+----------------------+";
	uint16_t entry_cnt = ROUTES_LIST_MAX_CNT;
	uint16_t entry_offset = 0;
	uint16_t route_cnt = 0;

	cmdline_printf(nes_cmdline, "%s\n", separator_line);
	cmdline_printf(nes_cmdline, "| ID %3s", "");
	cmdline_printf(nes_cmdline, "| PRIO %6s", "");
	cmdline_printf(nes_cmdline, "| ENB IP %12s", "");
	cmdline_printf(nes_cmdline, "| EPC IP %12s", "");
	cmdline_printf(nes_cmdline, "| UE IP %13s", "");
	cmdline_printf(nes_cmdline, "| SRV IP %12s", "");
	cmdline_printf(nes_cmdline, "| UE PORT %4s", "");
	cmdline_printf(nes_cmdline, "| SRV PORT %3s", "");
	cmdline_printf(nes_cmdline, "| ENCAP %1s", "");
	cmdline_printf(nes_cmdline, "| Destination %9s|\n", "");
	cmdline_printf(nes_cmdline, "%s\n", separator_line);

	do {
		nes_route_data_t *routes = NULL;
		uint16_t i;
		uint8_t *mac_addr;

		if (NES_SUCCESS != nes_route_list(&remote_NEV, entry_offset, entry_cnt,
				&routes, &route_cnt)) {
			cmdline_printf(nes_cmdline, "Error. Failed to list routing entries!\n");
			return;
		}

		for (i = 0; i < route_cnt; i++) {
			cmdline_printf(nes_cmdline, "| %-5u |", i + entry_offset);
			cmdline_printf(nes_cmdline, " %-10d |", routes[i].prio);

			if (routes[i].encap_proto) {
				print_ip_net(nes_cmdline, routes[i].enb_ip, routes[i].enb_ip_mask);
				print_ip_net(nes_cmdline, routes[i].epc_ip, routes[i].epc_ip_mask);
			} else {
				cmdline_printf(nes_cmdline, " %-18s |", "n/a");
				cmdline_printf(nes_cmdline, " %-18s |", "n/a");
			}

			print_ip_net(nes_cmdline, routes[i].ue_ip, routes[i].ue_ip_mask);
			print_ip_net(nes_cmdline, routes[i].srv_ip, routes[i].srv_ip_mask);

			print_port_range(nes_cmdline, routes[i].ue_port_min,
				routes[i].ue_port_max);
			print_port_range(nes_cmdline, routes[i].srv_port_min,
				routes[i].srv_port_max);

			cmdline_printf(nes_cmdline, " %-6s |", routes[i].encap_proto ?
				"GTPU" : "IP");
			mac_addr = routes[i].dst_mac_addr.ether_addr_octet;
			cmdline_printf(nes_cmdline, " %02x:%02x:%02x:%02x:%02x:%02x    |\n",
				mac_addr[0], mac_addr[1], mac_addr[2],
				mac_addr[3], mac_addr[4], mac_addr[5]);
		}
		free(routes);

		entry_offset += entry_cnt;
	} while (route_cnt == entry_cnt);
	cmdline_printf(nes_cmdline, "%s\n", separator_line);

}

cmdline_parse_token_string_t cmd_ctrl_route_show_all_route =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_route_all_result, route_string, "route");

cmdline_parse_token_string_t cmd_ctrl_route_show_all_list =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_route_all_result, list_string, "list");

cmdline_parse_inst_t cmd_ctrl_route_show_all = {
	.f = nes_ctrl_route_show_all_parsed,
	.data = NULL,
	.help_str = "Show all routings",
	.tokens =
	{
		(void *) &cmd_ctrl_route_show_all_route,
		(void *) &cmd_ctrl_route_show_all_list,
		NULL,
	},
};

cmdline_parse_inst_t cmd_ctrl_route_del = {
	.f = nes_ctrl_route_del_parsed,
	.data = NULL,
	.help_str = "Delete routing entry",
	.tokens =
	{
		(void *) &cmd_ctrl_route_string_del,
		(void *) &cmd_ctrl_route_del_string,
		(void *) &cmd_ctrl_route_del_data_string,
		NULL,
	},
};

cmdline_parse_inst_t cmd_ctrl_route_del_mirror = {
	.f = nes_ctrl_route_del_mirror_parsed,
	.data = NULL,
	.help_str = "Delete mirror entry",

	.tokens =
	{
		(void *) &cmd_ctrl_route_string_del,
		(void *) &cmd_ctrl_route_del_mirror_string,
		(void *) &cmd_ctrl_route_del_data_string,
		NULL,
	},
};

/* Show device list */
typedef struct cmd_ctrl_show_list_result {
	cmdline_fixed_string_t show_string;
	cmdline_fixed_string_t list_string;
} cmd_ctrl_show_list_result;

static void
nes_ctrl_show_list_parsed(__attribute__((unused))void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	nes_sq_t *list = NULL;
	nes_sq_node_t *item = NULL;
	nes_api_dev_t *device = NULL;
	if (eConnected != remote_NEV.state) {
		cmdline_printf(nes_cmdline, "Connection with server is not established!\n");
		return;
	};

	list = nes_stats_show_list(&remote_NEV);
	if (NULL == list)
		cmdline_printf(nes_cmdline, "Can't read device list!\n");
	else {
		cmdline_printf(nes_cmdline, "ID: ");
		cmdline_printf(nes_cmdline, "%3s Name: \n", "");

		NES_SQ_FOREACH(item, list) {
			device = nes_sq_data(item);
			cmdline_printf(nes_cmdline, "%2u ", device->index);
			cmdline_printf(nes_cmdline, "%9s \n", device->name);
		}
	}
	free(list);
}

cmdline_parse_token_string_t cmd_ctrl_show_list_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_list_result, show_string, "show");

cmdline_parse_token_string_t cmd_ctrl_show_list_list_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_list_result, list_string, "list");

cmdline_parse_inst_t cmd_ctrl_show_list = {
	.f = nes_ctrl_show_list_parsed,
	.data = NULL,
	.help_str = "show list",
	.tokens =
	{
		(void *) &cmd_ctrl_show_list_string,
		(void *) &cmd_ctrl_show_list_list_string,
		NULL,
	},
};

/* Clear all routes */
typedef struct cmd_ctrl_route_flush_result {
	cmdline_fixed_string_t route_string;
	cmdline_fixed_string_t flush_string;
} cmd_ctrl_route_flush_result;

static void
nes_ctrl_route_flush_parsed(__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	if (eConnected != remote_NEV.state) {
		cmdline_printf(nes_cmdline, "Connection with server is not established!\n");
		return;
	}

	if (NES_SUCCESS != nes_route_clear_all(&remote_NEV))
		cmdline_printf(nes_cmdline, "Failed to clear routes\n");
	else
		cmdline_printf(nes_cmdline, "Routes cleared\n");
}

cmdline_parse_token_string_t cmd_ctrl_route_flush_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_flush_result, flush_string, "flush");

cmdline_parse_token_string_t cmd_ctrl_route_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_flush_result, route_string, "route");

cmdline_parse_inst_t cmd_ctrl_route_flush = {
	.f = nes_ctrl_route_flush_parsed,
	.data = NULL,
	.help_str = "flush all routes",
	.tokens =
	{
		(void *) &cmd_ctrl_route_string,
		(void *) &cmd_ctrl_route_flush_string,
		NULL,
	},
};

/* Add kni device */
typedef struct cmd_ctrl_kni_add_result {
	cmdline_fixed_string_t add_string;
	cmdline_fixed_string_t kni_string;
	nes_cmdline_kni_string_t kni_dev_name;
} cmd_ctrl_kni_add_result;

static void
nes_ctrl_kni_add_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_kni_add_result *res = parsed_result;
	char created_if_name[KNI_NAMESIZE];
	if (NES_SUCCESS != nes_kni_add(&remote_NEV, res->kni_dev_name, created_if_name))
		cmdline_printf(nes_cmdline, "KNI device could not be added!\n");
	else
		cmdline_printf(nes_cmdline, "Interface [%s] added for %s\n", created_if_name,
			res->kni_dev_name);
}



cmdline_parse_token_string_t cmd_ctrl_kni_dev_name_string =
	NES_TOKEN_KNI_STRING_INITIALIZER(struct cmd_ctrl_kni_add_result, kni_dev_name, NULL);

cmdline_parse_token_string_t cmd_ctrl_kni_string_add =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_kni_add_result, kni_string, "kni");

cmdline_parse_token_string_t cmd_ctrl_kni_add_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_kni_add_result, add_string, "add");

cmdline_parse_inst_t cmd_ctrl_kni_add = {
	.f = nes_ctrl_kni_add_parsed,
	.data = NULL,
	.help_str = "Add KNI device",
	.tokens =
	{
		(void *) &cmd_ctrl_kni_string_add,
		(void *) &cmd_ctrl_kni_add_string,
		(void *) &cmd_ctrl_kni_dev_name_string,
		NULL,
	},
};


/* Delete kni device */
typedef struct cmd_ctrl_kni_del_result {
	cmdline_fixed_string_t del_string;
	cmdline_fixed_string_t kni_string;
	nes_cmdline_kni_string_t kni_dev_name;
} cmd_ctrl_kni_del_result;

static void
nes_ctrl_kni_del_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_kni_del_result *res = parsed_result;
	char deleted_if_name[KNI_NAMESIZE];

	if (NES_SUCCESS != nes_kni_del(&remote_NEV, res->kni_dev_name, deleted_if_name))
		cmdline_printf(nes_cmdline, "KNI device could not be removed!\n");
	else
		cmdline_printf(nes_cmdline, "Interface [%s] removed for %s\n", deleted_if_name,
			res->kni_dev_name);
}

cmdline_parse_token_string_t cmd_ctrl_kni_dev_name_del_string =
	NES_TOKEN_KNI_STRING_INITIALIZER(struct cmd_ctrl_kni_del_result, kni_dev_name, NULL);

cmdline_parse_token_string_t cmd_ctrl_kni_string_del =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_kni_del_result, kni_string, "kni");

cmdline_parse_token_string_t cmd_ctrl_kni_del_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_kni_del_result, del_string, "del");

cmdline_parse_inst_t cmd_ctrl_kni_del = {
	.f = nes_ctrl_kni_del_parsed,
	.data = NULL,
	.help_str = "Remove KNI device",
	.tokens =
	{
		(void *) &cmd_ctrl_kni_string_del,
		(void *) &cmd_ctrl_kni_del_string,
		(void *) &cmd_ctrl_kni_dev_name_del_string,
		NULL,
	},
};


/* Help */
typedef struct cmd_ctrl_help_result {
	cmdline_fixed_string_t help_string;
} cmd_ctrl_help_result;

static void
nes_ctrl_help(__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	cmdline_printf(nes_cmdline, "Routing entry commands:\n");
	cmdline_printf(nes_cmdline,
		"    route add[-mirror]  [MAC_address]"
		" [prio:PRIO,coma separated lookup fields*]\n");
	cmdline_printf(nes_cmdline,
		"    route del[-mirror] [prio:PRIO,coma separated lookup fields*]\n");
	cmdline_printf(nes_cmdline,
		"    route show[-mirror] [prio:PRIO,coma separated lookup fields*]\n");
	cmdline_printf(nes_cmdline, "    route list\n");
	cmdline_printf(nes_cmdline, "    route flush\n");
	cmdline_printf(nes_cmdline,
		"    Possible lookup fields:\n" \
		"      encap_proto  : gtpu or noencap\n" \
		"      ue_ip        : IP[/IP_MASK]\n" \
		"      srv_ip       : IP[/IP_MASK]\n" \
		"      enb_ip       : IP[/IP_MASK]\n" \
		"      epc_ip       : IP[/IP_MASK]\n" \
		"      ue_port      : PORT_MIN[-PORT_MAX]\n" \
		"      srv_port     : PORT_MIN[-PORT_MAX]\n" \
		"      teid         : TEID_MIN[-TEID_MAX]\n" \
		"      qci          : QCI_MIN[-QCI_MAX]\n" \
		"      spid         : SPID_MIN[-SPID_MAX]\n");
	cmdline_printf(nes_cmdline, "Encapsulation entry commands:\n");
	cmdline_printf(nes_cmdline, "    encap show [ip_addr]\n");
	cmdline_printf(nes_cmdline, "Traffic Flow Template entries commands:\n");
	cmdline_printf(nes_cmdline,
		"    flow add [teid] [spid] [qci]" \
		" [protocol] [src_ip] [mask] [dst_ip] [mask]" \
		" [src_port_min] [src_por_max]" \
		" [dst_port_min] [dst_port_max] [tos] [mask]\n");
	cmdline_printf(nes_cmdline,
		"    flow show [protocol] [src_ip] [mask] [dst_ip] [mask] [src_port_min]" \
		" [src_por_max] [dst_port_min] [dst_port_max] [tos] [mask]\n");
	cmdline_printf(nes_cmdline,
		"    flow del [protocol] [src_ip] [mask] [dst_ip] [mask] [src_port_min]" \
		" [src_por_max] [dst_port_min] [dst_port_max] [tos] [mask]\n");
	cmdline_printf(nes_cmdline, "QCI/SPID data:\n");
	cmdline_printf(nes_cmdline, "    route-data add" \
		" [eNB IP] [teid] [direction] [qci] [spid]\n");
	cmdline_printf(nes_cmdline, "    route-data del [eNB IP] [teid] [direction]\n");
	cmdline_printf(nes_cmdline, "    route-data show [eNB IP] [teid] [direction]\n");
	cmdline_printf(nes_cmdline, "KNI devices: \n");
	cmdline_printf(nes_cmdline, "    kni add [device_id_name]\n");
	cmdline_printf(nes_cmdline, "    kni del [device_id_name]\n");
	cmdline_printf(nes_cmdline,
		"Device stats (device_id, device_name, received packets, sent packets," \
		" dropped packets): \n");
	cmdline_printf(nes_cmdline, "    show [device_id]\n");
	cmdline_printf(nes_cmdline, "    show mac [device_id]\n");
	cmdline_printf(nes_cmdline, "    show list\n");
	cmdline_printf(nes_cmdline, "    show all\n");
	cmdline_printf(nes_cmdline, "    clear all\n");
	cmdline_printf(nes_cmdline,
		"Ring stats (ring_id, ring_name, received packets," \
		" sent packets, ring full dropped packets, no route dropped packets ): \n");
	cmdline_printf(nes_cmdline, "    show ring [ring_id]\n");
	cmdline_printf(nes_cmdline, "    show rings\n");
	cmdline_printf(nes_cmdline, "To start server application after suspension: \n");
	cmdline_printf(nes_cmdline, "    start\n");
	cmdline_printf(nes_cmdline, "To exit CLI application : \n");
	cmdline_printf(nes_cmdline, "    quit\n");
}

cmdline_parse_token_string_t cmd_ctrl_help_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_help_result, help_string, "help");

cmdline_parse_inst_t cmd_ctrl_help = {
	.f = nes_ctrl_help,
	.data = NULL,
	.help_str = "Show command line instructions.",
	.tokens =
	{
		(void *) &cmd_ctrl_help_string,
		NULL,
	},
};

/* Quit */
struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
	struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data)
{
	if (is_in_filemode) {
		nes_conn_close(&remote_NEV);
		return;
	}
	cmdline_stdin_exit(nes_cmdline);
	nes_conn_close(&remote_NEV);
	cmdline_quit(nes_cmdline);
}

cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "exit NES client",
	.tokens =
	{
		(void *) &cmd_quit_quit,
		NULL,
	},
};

/* Show statistics for all devices */
typedef struct cmd_ctrl_show_all_result {
	cmdline_fixed_string_t show_string;
	cmdline_fixed_string_t all_string;
} cmd_ctrl_show_all_result;

static char *show_stat_value(uint64_t value, int indent)
{
	static char buf[32];
	if (UINT64_MAX == value)
		sprintf(buf, "%*s", indent, "N/A");
	else
		sprintf(buf, "%*lu", indent, value);
	return buf;
}


static void
nes_ctrl_show_all_parsed(__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	nes_sq_t *list = NULL;
	nes_sq_node_t *item = NULL;
	nes_api_dev_t *device = NULL;
	char mac_str[18];
	if (eConnected != remote_NEV.state) {
		cmdline_printf(nes_cmdline, "Connection with server is not established!\n");
		return;
	}

	list = nes_stats_all_dev(&remote_NEV);
	if (NULL == list)
		cmdline_printf(nes_cmdline, "Can't read device list!\n");
	else {
		cmdline_printf(nes_cmdline, "ID: ");
		cmdline_printf(nes_cmdline, "%8s Name: ", "");
		cmdline_printf(nes_cmdline, "%16s Received: ", "");
		cmdline_printf(nes_cmdline, "%21s Sent: ", "");
		cmdline_printf(nes_cmdline, "%9s Dropped(TX full): ", "");
		cmdline_printf(nes_cmdline, "%14s Dropped(HW): ", "");
		cmdline_printf(nes_cmdline, "%14s IP Fragmented(Forwarded): \n", "");

		NES_SQ_FOREACH(item, list) {
			device = nes_sq_data(item);
			cmdline_printf(nes_cmdline, "%2u ", device->index);
			cmdline_printf(nes_cmdline, "%13s%8s", device->name, "");

			cmdline_printf(nes_cmdline, "%s pkts ",
				show_stat_value(device->stats.rcv_cnt, 22));
			cmdline_printf(nes_cmdline, "%s pkts ",
				show_stat_value(device->stats.snd_cnt, 22));
			cmdline_printf(nes_cmdline, "%s pkts ",
				show_stat_value(device->stats.drp_cnt_1, 22));
			cmdline_printf(nes_cmdline, "%s pkts ",
				show_stat_value(device->stats.drp_cnt_2, 22));
			cmdline_printf(nes_cmdline, "%s pkts\n",
				show_stat_value(device->stats.ip_fragment, 22));

			sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
				device->macaddr.ether_addr_octet[0],
				device->macaddr.ether_addr_octet[1],
				device->macaddr.ether_addr_octet[2],
				device->macaddr.ether_addr_octet[3],
				device->macaddr.ether_addr_octet[4],
				device->macaddr.ether_addr_octet[5]);

			if (0 == strcmp(mac_str, "00:00:00:00:00:00"))
				cmdline_printf(nes_cmdline, "%6s(not registered)  ", "");
			else
				cmdline_printf(nes_cmdline, "%5s(%s)", "", mac_str);

			cmdline_printf(nes_cmdline, "%s bytes",
				show_stat_value(device->stats.rcv_bytes, 22));
			cmdline_printf(nes_cmdline, "%s bytes",
				show_stat_value(device->stats.snd_bytes, 22));
			cmdline_printf(nes_cmdline, "%s bytes\n",
				show_stat_value(device->stats.drp_bytes_1, 22));
		}
		nes_sq_dtor_free(list);
	}
	free(list);
}

cmdline_parse_token_string_t cmd_ctrl_show_all_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_all_result, show_string, "show");

cmdline_parse_token_string_t cmd_ctrl_show_all_all_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_all_result, all_string, "all");

cmdline_parse_inst_t cmd_ctrl_show_all = {
	.f = nes_ctrl_show_all_parsed,
	.data = NULL,
	.help_str = "show all",
	.tokens =
	{
		(void *) &cmd_ctrl_show_all_string,
		(void *) &cmd_ctrl_show_all_all_string,
		NULL,
	},
};

/* Clear statistics for all devices */
typedef struct cmd_ctrl_clear_all_result {
	cmdline_fixed_string_t clear_string;
	cmdline_fixed_string_t all_string;
} cmd_ctrl_clear_result;

static void
nes_ctrl_clear_all_parsed(__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	if (eConnected != remote_NEV.state) {
		cmdline_printf(nes_cmdline, "Connection with server is not established!\n");
		return;
	}

	nes_clear_all_stats(&remote_NEV);
}

cmdline_parse_token_string_t cmd_ctrl_clear_all_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_clear_all_result, clear_string, "clear");

cmdline_parse_token_string_t cmd_ctrl_clear_all_all_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_clear_all_result, all_string, "all");

cmdline_parse_inst_t cmd_ctrl_clear_all = {
	.f = nes_ctrl_clear_all_parsed,
	.data = NULL,
	.help_str = "clear all",
	.tokens =
	{
		(void *) &cmd_ctrl_clear_all_string,
		(void *) &cmd_ctrl_clear_all_all_string,
		NULL,
	},
};

/* Show device statistics */
typedef struct cmd_ctrl_show_stats_result {
	cmdline_fixed_string_t show_string;
	uint16_t device_id;
} cmd_ctrl_show_stats_result;

static void
nes_ctrl_show_stats_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_show_stats_result *res = parsed_result;

	nes_dev_stats_t stats;
	if (eConnected != remote_NEV.state) {
		cmdline_printf(nes_cmdline, "Connection with server is not established!\n");
		return;
	}

	if (NES_SUCCESS == nes_stats_dev(&remote_NEV, res->device_id, &stats)) {
		cmdline_printf(nes_cmdline, "Received packets: %s\n",
			show_stat_value(stats.rcv_cnt, 0));
		cmdline_printf(nes_cmdline, "Received bytes: %s\n",
			show_stat_value(stats.rcv_bytes, 0));
		cmdline_printf(nes_cmdline, "Sent packets: %s\n",
			show_stat_value(stats.snd_cnt, 0));
		cmdline_printf(nes_cmdline, "Sent bytes: %s\n",
			show_stat_value(stats.snd_bytes, 0));
		cmdline_printf(nes_cmdline, "Dropped packets (TX buffer overflow): %s\n",
			show_stat_value(stats.drp_cnt_1, 0));
		cmdline_printf(nes_cmdline, "Dropped bytes (TX buffer overflow): %s\n",
			show_stat_value(stats.drp_bytes_1, 0));
		cmdline_printf(nes_cmdline, "Dropped packets (HW): %s\n",
			show_stat_value(stats.drp_cnt_2, 0));
	} else
		cmdline_printf(nes_cmdline, "Error getting device stats!\n");
}

cmdline_parse_token_string_t cmd_ctrl_show_stats_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_stats_result, show_string, "show");

cmdline_parse_token_num_t cmd_ctrl_show_stats_device =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_show_stats_result, device_id, UINT16);

cmdline_parse_inst_t cmd_ctrl_show_stats = {
	.f = nes_ctrl_show_stats_parsed,
	.data = NULL,
	.help_str = "show [device]",
	.tokens =
	{
		(void *) &cmd_ctrl_show_stats_string,
		(void *) &cmd_ctrl_show_stats_device,
		NULL,
	},
};

/* Internal API */

typedef struct cmd_ctrl_show_mac_result {
	cmdline_fixed_string_t show_mac_string;
	cmdline_fixed_string_t mac_string;
	uint8_t device_id;
} cmd_ctrl_show_mac_result;

static void nes_ctrl_mac_show_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data)
{
	struct cmd_ctrl_show_mac_result *res = parsed_result;
	static int MAC_ADDR_STR_LEN = 18;
	char *mac_addr = malloc(sizeof(char) * (MAC_ADDR_STR_LEN + 1));
	if (NULL == mac_addr) {
		cmdline_printf(nes_cmdline, "Error! Memory allocation failed\n");
		return;
	}

	if (NES_SUCCESS == nes_dev_port_mac_addr(&remote_NEV, res->device_id, &mac_addr))
		cmdline_printf(nes_cmdline, "Device: %d MAC: %s\n", res->device_id, mac_addr);
	else
		cmdline_printf(nes_cmdline,
			"Error! MAC address could not be found for device %d.\n", res->device_id);

	free(mac_addr);
}

cmdline_parse_token_string_t cmd_ctrl_mac_show_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_mac_result, show_mac_string, "show");

cmdline_parse_token_string_t cmd_ctrl_mac_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_mac_result, mac_string, "mac");

cmdline_parse_token_num_t cmd_ctrl_mac_device =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_show_mac_result, device_id, UINT8);

cmdline_parse_inst_t cmd_ctrl_mac_show = {
	.f = nes_ctrl_mac_show_parsed,
	.data = NULL,
	.help_str = "Show devices mac address",
	.tokens = {
		(void *)&cmd_ctrl_mac_show_string,
		(void *)&cmd_ctrl_mac_string,
		(void *)&cmd_ctrl_mac_device,
		NULL,
	},
};

/* Show encapsulation entry */
enum nes_flow_function_id {
	eNesAddFlow = 100,
	eNesShowFlow,
	eNesDelFlow,
	eNesAddRouteData,
	eNesDelRouteData,
	eNesShowRouteData,
	eNesShowEncap
};

typedef struct nes_cli_param_rab_s {
	uint32_t teid;
	uint8_t qci;
	uint8_t spid;
} nes_cli_param_rab_t;

typedef struct nes_cli_param_flow_s {
	uint8_t proto;
	uint32_t inner_src_ip;
	uint32_t inner_src_ip_mask;
	uint32_t inner_dst_ip;
	uint32_t inner_dst_ip_mask;
	uint16_t inner_src_port;
	uint16_t inner_src_port_max;
	uint16_t inner_dst_port;
	uint16_t inner_dst_port_max;
	uint8_t tos;
	uint8_t tos_mask;
} nes_cli_param_flow_t;

static int
nes_send_api_msg(nes_remote_t *self, nes_api_msg_t *request, nes_api_msg_t **response) {
	assert(NULL != self);
	assert(NULL != request);
	assert(NULL != response);

	nes_api_msg_t response_head;
	*response = NULL;

	if (self->state != eConnected)
		return NES_FAIL;

	if ((send(self->socket_fd, request,
				sizeof (nes_api_msg_t) + request->data_size, 0)) == -1)
		return NES_FAIL;

	if ((recv(self->socket_fd, &response_head, sizeof (response_head), 0)) == -1 ||
		response_head.message_type == eError)
		return NES_FAIL;

	*response = malloc(sizeof (nes_api_msg_t) + response_head.data_size);
	VERIFY_PTR_OR_RET(*response, NES_FAIL);
	memcpy(*response, &response_head, sizeof (response_head));
	if ((recv(self->socket_fd, (*response)->data, (*response)->data_size, 0)) == -1) {
		free(*response);
		*response = NULL;
		return NES_FAIL;
	}

	return NES_SUCCESS;
}

static int
nes_encap_show(nes_remote_t *self, uint32_t ip, nts_enc_entry_t *entry) {
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	uint16_t data_len = sizeof (ip);

	api_msg = malloc(sizeof (nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesShowEncap;
	memcpy(api_msg->data, &ip, sizeof (ip));

	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(&remote_NEV, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof (nts_enc_entry_t) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(entry, api_response->data, sizeof (nts_enc_entry_t));
	free(api_response);
	free(api_msg);
	return NES_SUCCESS;
}

typedef struct cmd_ctrl_show_result {
	cmdline_fixed_string_t show_string;
	cmdline_fixed_string_t encap_string;
	cmdline_ipaddr_t       ip_addr;
} cmd_ctrl_show_result;

static void nes_ctrl_enc_entry_show_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data)
{
	struct cmd_ctrl_show_result *res = parsed_result;
	nts_enc_entry_t *entry = malloc(sizeof(nts_enc_entry_t));
	if (NULL == entry) {
		cmdline_printf(nes_cmdline, "Failed to alloc entry buffer\n");
		return;
	}
	struct in_addr ipaddr;


	if (NES_SUCCESS == nes_encap_show(&remote_NEV, res->ip_addr.addr.ipv4.s_addr, entry)) {
		cmdline_printf(nes_cmdline, "Upstream encapsulation entry:\n");
		print_mac_addr(&entry->upstream.dst_mac_addrs, dst, nes_cmdline);
		print_mac_addr(&entry->upstream.src_mac_addrs, src, nes_cmdline);
		ipaddr.s_addr = entry->upstream.dst_ip;
		cmdline_printf(nes_cmdline,
			"Entry destination IP address: %s\n", inet_ntoa(ipaddr));
		ipaddr.s_addr = entry->upstream.src_ip;
		cmdline_printf(nes_cmdline, "Entry source IP address: %s\n", inet_ntoa(ipaddr));
		cmdline_printf(nes_cmdline, "Entry destination IP port: %" PRIu16 "\n",
			rte_be_to_cpu_16((uint16_t)entry->upstream.dst_ip_port));
		cmdline_printf(nes_cmdline, "Entry source IP port: %" PRIu16 "\n",
			rte_be_to_cpu_16((uint16_t)entry->upstream.src_ip_port));
		cmdline_printf(nes_cmdline, "Entry TE id: %" PRIu32 "\n",
			rte_be_to_cpu_32((uint32_t)entry->upstream.teid));

		cmdline_printf(nes_cmdline, "\n\nDownstream encapsulation entry:\n");
		print_mac_addr(&entry->downstream.dst_mac_addrs, dst, nes_cmdline);
		print_mac_addr(&entry->downstream.src_mac_addrs, src, nes_cmdline);
		ipaddr.s_addr = entry->downstream.dst_ip;
		cmdline_printf(nes_cmdline, "Entry destination IP address: %s\n",
			inet_ntoa(ipaddr));
		ipaddr.s_addr = entry->downstream.src_ip;
		cmdline_printf(nes_cmdline, "Entry source IP address: %s\n", inet_ntoa(ipaddr));
		cmdline_printf(nes_cmdline, "Entry destination IP port: %" PRIu16 "\n",
			rte_be_to_cpu_16((uint16_t)entry->downstream.dst_ip_port));
		cmdline_printf(nes_cmdline, "Entry source IP port: %" PRIu16 "\n",
			rte_be_to_cpu_16((uint16_t)entry->downstream.src_ip_port));
		cmdline_printf(nes_cmdline, "Entry TE id: %" PRIu32 "\n",
			rte_be_to_cpu_32((uint32_t)entry->downstream.teid));
	} else
		cmdline_printf(nes_cmdline, "Error! Encapsulation entry could not be found.\n");

	free(entry);
}

cmdline_parse_token_string_t cmd_ctrl_enc_show_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_result, show_string, "show");

cmdline_parse_token_string_t cmd_ctrl_enc_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_result, encap_string, "encap");

cmdline_parse_token_ipaddr_t cmd_ctrl_enc_show_ip =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_show_result, ip_addr);

cmdline_parse_inst_t cmd_ctrl_enc_entry_show = {
	.f = nes_ctrl_enc_entry_show_parsed,
	.data = NULL,
	.help_str = "Show encapsulation entry",
	.tokens = {
		(void *)&cmd_ctrl_enc_string,
		(void *)&cmd_ctrl_enc_show_string,
		(void *)&cmd_ctrl_enc_show_ip,
		NULL,
	},
};

static int nes_route_data_get_dir(const char *dir_str, nes_direction_t *dir) {
	if (NULL == dir_str || NULL == dir)
		return NES_FAIL;

	if (0 == strncmp(dir_str, "upstream", strlen("upstream")))
		*dir = NES_UPSTREAM;
	else if (0 == strncmp(dir_str, "downstream", strlen("downstream")))
		*dir = NES_DOWNSTREAM;
	else
		return NES_FAIL;

	return NES_SUCCESS;
}

static int
nes_route_data_add(nes_remote_t *self, nis_routing_data_key_t *routing_key,
	nis_routing_data_t *routing_data) {
	assert(self);

	struct routing_msg_s {
		nis_routing_data_key_t routing_key;
		nis_routing_data_t routing_data;
	} *data;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	int ret;

	uint16_t data_len = sizeof (struct routing_msg_s);
	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == routing_key || NULL == routing_data)
		return NES_FAIL;

	api_msg = malloc(sizeof (nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesAddRouteData;
	data = (struct routing_msg_s *) api_msg->data;

	memcpy(&data->routing_key, routing_key, sizeof (nis_routing_data_key_t));
	memcpy(&data->routing_data, routing_data, sizeof (nis_routing_data_t));

	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(&remote_NEV, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof (enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(&ret, api_response->data, sizeof (enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}

static int
nes_route_data_del(nes_remote_t *self, nis_routing_data_key_t *routing_key) {
	assert(self);

	nis_routing_data_key_t *data;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	int ret;

	uint16_t data_len = sizeof (nis_routing_data_key_t);
	if (self->state != eConnected)
		return NES_FAIL;
	if (NULL == routing_key)
		return NES_FAIL;

	api_msg = malloc(sizeof (nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesDelRouteData;
	data = (nis_routing_data_key_t *) api_msg->data;

	memcpy(data, routing_key, sizeof (nis_routing_data_key_t));

	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(&remote_NEV, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof (enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(&ret, api_response->data, sizeof (enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}

static int
nes_route_data_show(nes_remote_t *self, nis_routing_data_key_t *routing_key,
	nis_routing_data_t *routing_data) {
	assert(self);

	nis_routing_data_key_t *data;
	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	uint16_t data_len = sizeof (nis_routing_data_key_t);
	if (self->state != eConnected)
		return NES_FAIL;
	if (NULL == routing_key || NULL == routing_data)
		return NES_FAIL;

	api_msg = malloc(sizeof (nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesShowRouteData;
	data = (nis_routing_data_key_t *) api_msg->data;
	memcpy(data, routing_key, sizeof (nis_routing_data_key_t));

	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(&remote_NEV, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof (nis_routing_data_t) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(routing_data, api_response->data, sizeof (nis_routing_data_t));
	free(api_response);
	free(api_msg);
	return NES_SUCCESS;
}


static int
nes_flow_add(nes_remote_t *self, nes_cli_param_flow_t *flow, nes_cli_param_rab_t *entry) {
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == flow || NULL == entry)
		return NES_FAIL;

	struct add_flow_data {
		nes_cli_param_flow_t flow_params;
		nes_cli_param_rab_t rab_params;
	} *data;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	int ret;
	uint16_t data_len = sizeof (struct add_flow_data);

	api_msg = malloc(sizeof (nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesAddFlow;
	data = (struct add_flow_data *) api_msg->data;
	memcpy(&data->flow_params, flow, sizeof (nes_cli_param_flow_t));
	memcpy(&data->rab_params, entry, sizeof (nes_cli_param_rab_t));

	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(&remote_NEV, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof (enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(&ret, api_response->data, sizeof (enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}

static int
nes_flow_show(nes_remote_t *self, nes_cli_param_flow_t *flow, nes_cli_param_rab_t **entry) {
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == flow || NULL == entry)
		return NES_FAIL;

	struct show_flow_data {
		nes_cli_param_flow_t flow_params;
	} *data;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;

	*entry = malloc(sizeof (nes_cli_param_rab_t));
	VERIFY_PTR_OR_RET(*entry, NES_FAIL);
	uint16_t data_len = sizeof (struct show_flow_data);

	api_msg = malloc(sizeof (nes_api_msg_t) + data_len);
	if (NULL == api_msg) {
		free(*entry);
		return NES_FAIL;
	}
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesShowFlow;
	data = (struct show_flow_data *) api_msg->data;
	memcpy(&data->flow_params, flow, sizeof (nes_cli_param_flow_t));

	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(&remote_NEV, api_msg, &api_response)) {
		free(api_msg);
		free(*entry);
		*entry = NULL;
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof (nes_cli_param_rab_t) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		free(*entry);
		*entry = NULL;
		return NES_FAIL;
	}

	memcpy(*entry, api_response->data, sizeof (nes_cli_param_rab_t));
	free(api_response);
	free(api_msg);
	return NES_SUCCESS;
}

static int
nes_flow_del(nes_remote_t *self, nes_cli_param_flow_t *flow) {
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == flow)
		return NES_FAIL;

	struct del_flow_data {
		nes_cli_param_flow_t flow_params;
	} *data;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	int ret;
	uint16_t data_len = sizeof (struct del_flow_data);

	api_msg = malloc(sizeof (nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesDelFlow;
	data = (struct del_flow_data *) api_msg->data;
	memcpy(&data->flow_params, flow, sizeof (nes_cli_param_flow_t));

	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(&remote_NEV, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof (enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(&ret, api_response->data, sizeof (enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}

struct cmd_ctrl_route_data_add_result {
	cmdline_fixed_string_t route_data_string;
	cmdline_fixed_string_t route_data_add_string;
	cmdline_ipaddr_t enb_ip;
	uint32_t teid;
	uint8_t qci;
	uint8_t spid;
	cmdline_fixed_string_t route_data_dir_string;
};
cmdline_parse_token_string_t cmd_ctrl_route_data_add_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_add_result, route_data_string,
		"route-data");

cmdline_parse_token_string_t cmd_ctrl_route_data_add_add_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_add_result, route_data_add_string,
		"add");

cmdline_parse_token_num_t cmd_ctrl_route_data_teid =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_route_data_add_result, teid, UINT32);
cmdline_parse_token_ipaddr_t cmd_ctrl_route_data_enb_ip =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_route_data_add_result, enb_ip);
cmdline_parse_token_string_t cmd_ctrl_route_data_dir_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_add_result, route_data_dir_string,
		NULL);

cmdline_parse_token_num_t cmd_ctrl_route_data_qci =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_route_data_add_result, qci, UINT8);
cmdline_parse_token_num_t cmd_ctrl_route_data_spid =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_route_data_add_result, spid, UINT8);

static void
cmd_ctrl_route_data_add_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	struct cmd_ctrl_route_data_add_result *res = parsed_result;

	nis_routing_data_key_t routing_key = {
		.enb_ip = res->enb_ip.addr.ipv4.s_addr,
		.teid = res->teid
	};
	if (NES_SUCCESS != nes_route_data_get_dir(res->route_data_dir_string,
			&routing_key.direction)) {
		cmdline_printf(nes_cmdline,
			"Direction provided is not correct, use: upstream/downstream\n");
		return;
	}
	nis_routing_data_t routing_data = {
		.qci = res->qci,
		.spid = res->spid
	};

	if (NES_SUCCESS == nes_route_data_add(&remote_NEV, &routing_key, &routing_data))
		cmdline_printf(nes_cmdline, "Route data added\n");
	else
		cmdline_printf(nes_cmdline, "No route data added\n");
}
cmdline_parse_inst_t cmd_ctrl_route_data_add = {
	.f = cmd_ctrl_route_data_add_parsed,
	.data = NULL,
	.help_str = "route-data add [eNB IP] [teid] [direction] [qci] [spid]",
	.tokens =
	{
		(void *) &cmd_ctrl_route_data_add_string,
		(void *) &cmd_ctrl_route_data_add_add_string,
		(void *) &cmd_ctrl_route_data_enb_ip,
		(void *) &cmd_ctrl_route_data_teid,
		(void *) &cmd_ctrl_route_data_dir_string,
		(void *) &cmd_ctrl_route_data_qci,
		(void *) &cmd_ctrl_route_data_spid,
		NULL,
	},
};

struct cmd_ctrl_route_data_del_result {
	cmdline_fixed_string_t route_data_string;
	cmdline_fixed_string_t route_data_del_string;
	cmdline_ipaddr_t enb_ip;
	uint32_t teid;
	cmdline_fixed_string_t route_data_dir_string;
};
cmdline_parse_token_string_t cmd_ctrl_route_data_del_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_del_result, route_data_string,
		"route-data");

cmdline_parse_token_string_t cmd_ctrl_route_data_del_del_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_del_result, route_data_del_string,
		"del");
cmdline_parse_token_num_t cmd_ctrl_route_data_del_teid =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_route_data_del_result, teid, UINT32);
cmdline_parse_token_ipaddr_t cmd_ctrl_route_data_del_enb_ip =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_route_data_del_result, enb_ip);
cmdline_parse_token_string_t cmd_ctrl_route_data_del_dir_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_del_result, route_data_dir_string,
		NULL);

static void
cmd_ctrl_route_data_del_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	struct cmd_ctrl_route_data_del_result *res = parsed_result;

	nis_routing_data_key_t routing_key = {
		.enb_ip = res->enb_ip.addr.ipv4.s_addr,
		.teid = res->teid
	};
	if (NES_SUCCESS != nes_route_data_get_dir(res->route_data_dir_string,
			&routing_key.direction)) {
		cmdline_printf(nes_cmdline,
			"Direction provided is not correct, use: upstream/downstream\n");
		return;
	}

	if (NES_SUCCESS == nes_route_data_del(&remote_NEV, &routing_key))
		cmdline_printf(nes_cmdline, "Route data deleted\n");
	else
		cmdline_printf(nes_cmdline, "No route data deleted\n");
}
cmdline_parse_inst_t cmd_ctrl_route_data_del = {
	.f = cmd_ctrl_route_data_del_parsed,
	.data = NULL,
	.help_str = "route-data del [eNB IP] [teid] [direction]",
	.tokens =
	{
		(void *) &cmd_ctrl_route_data_del_string,
		(void *) &cmd_ctrl_route_data_del_del_string,
		(void *) &cmd_ctrl_route_data_del_enb_ip,
		(void *) &cmd_ctrl_route_data_del_teid,
		(void *) &cmd_ctrl_route_data_del_dir_string,
		NULL,
	},
};

struct cmd_ctrl_route_data_show_result {
	cmdline_fixed_string_t route_data_string;
	cmdline_fixed_string_t route_data_show_string;
	cmdline_ipaddr_t enb_ip;
	uint32_t teid;
	cmdline_fixed_string_t route_data_dir_string;
};

cmdline_parse_token_string_t cmd_ctrl_route_data_show_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_show_result, route_data_string,
		"route-data");

cmdline_parse_token_string_t cmd_ctrl_route_data_show_del_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_show_result, route_data_show_string,
		"show");
cmdline_parse_token_num_t cmd_ctrl_route_data_show_teid =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_route_data_show_result, teid, UINT32);
cmdline_parse_token_ipaddr_t cmd_ctrl_route_data_show_enb_ip =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_route_data_show_result, enb_ip);
cmdline_parse_token_string_t cmd_ctrl_route_data_show_dir_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_route_data_show_result, route_data_dir_string,
		NULL);

static void
cmd_ctrl_route_data_show_parsed(void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	struct cmd_ctrl_route_data_show_result *res = parsed_result;

	nis_routing_data_key_t routing_key = {
		.enb_ip = res->enb_ip.addr.ipv4.s_addr,
		.teid = res->teid
	};

	if (NES_SUCCESS != nes_route_data_get_dir(res->route_data_dir_string,
			&routing_key.direction)) {
		cmdline_printf(nes_cmdline,
			"Direction provided is not correct, use: upstream/downstream\n");
		return;
	}

	nis_routing_data_t routing_data;

	if (NES_SUCCESS == nes_route_data_show(&remote_NEV, &routing_key, &routing_data)) {
		cmdline_printf(nes_cmdline,
			"NIS routing data:\nQCI: %u\nSPID: %u\n", routing_data.qci,
			routing_data.spid);
	} else
		cmdline_printf(nes_cmdline, "No route data to show\n");
}
cmdline_parse_inst_t cmd_ctrl_route_data_show = {
	.f = cmd_ctrl_route_data_show_parsed,
	.data = NULL,
	.help_str = "route-data show [eNB IP] [teid] [direction]",
	.tokens =
	{
		(void *) &cmd_ctrl_route_data_show_string,
		(void *) &cmd_ctrl_route_data_show_del_string,
		(void *) &cmd_ctrl_route_data_show_enb_ip,
		(void *) &cmd_ctrl_route_data_show_teid,
		(void *) &cmd_ctrl_route_data_show_dir_string,
		NULL,
	},
};

/* Flow add */
typedef struct cmd_ctrl_flow_add_result {
	cmdline_fixed_string_t flow_string;
	cmdline_fixed_string_t add_string;
	uint32_t teid;
	uint8_t spid;
	uint8_t qci;
	uint8_t protocol;
	cmdline_ipaddr_t ip_addr_src;
	uint32_t ip_addr_src_mask;
	cmdline_ipaddr_t ip_addr_dst;
	uint32_t ip_addr_dst_mask;
	uint16_t port_src;
	uint16_t port_src_max;
	uint16_t port_dst;
	uint16_t port_dst_max;
	uint8_t tos;
	uint8_t tos_mask;
} cmd_ctrl_flow_add_result;

static void
nes_flow_add_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_flow_add_result *res = parsed_result;

	nes_cli_param_rab_t rab_param;
	nes_cli_param_flow_t flow_param;

	rab_param.teid = res->teid;
	rab_param.spid = res->spid;
	rab_param.qci = res->qci;

	flow_param.proto = res->protocol;
	flow_param.inner_src_ip = rte_be_to_cpu_32(res->ip_addr_src.addr.ipv4.s_addr);
	flow_param.inner_src_ip_mask = res->ip_addr_src_mask;
	flow_param.inner_dst_ip = rte_be_to_cpu_32(res->ip_addr_dst.addr.ipv4.s_addr);
	flow_param.inner_dst_ip_mask = res->ip_addr_dst_mask;
	flow_param.inner_src_port = res->port_src;
	flow_param.inner_src_port_max = res->port_src_max;
	flow_param.inner_dst_port = res->port_dst;
	flow_param.inner_dst_port_max = res->port_dst_max;
	flow_param.tos = res->tos;
	flow_param.tos_mask = res->tos_mask;

	if (NES_SUCCESS == nes_flow_add(&remote_NEV, &flow_param, &rab_param))
		cmdline_printf(nes_cmdline, "Flow added.\n");
	else
		cmdline_printf(nes_cmdline, "Can't add flow.\n");
}

cmdline_parse_token_string_t cmd_ctrl_flow_add_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_flow_add_result, flow_string, "flow");

cmdline_parse_token_string_t cmd_ctrl_flow_add_add_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_flow_add_result, flow_string, "add");

cmdline_parse_token_num_t cmd_ctrl_flow_add_teid =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, teid, UINT32);

cmdline_parse_token_num_t cmd_ctrl_flow_add_spid =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, spid, UINT8);

cmdline_parse_token_num_t cmd_ctrl_flow_add_qci =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, qci, UINT8);

cmdline_parse_token_num_t cmd_ctrl_flow_add_protocol =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, protocol, UINT8);

cmdline_parse_token_ipaddr_t cmd_ctrl_flow_add_ip_src =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_flow_add_result, ip_addr_src);

cmdline_parse_token_num_t cmd_ctrl_flow_add_ip_src_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, ip_addr_src_mask, UINT32);

cmdline_parse_token_ipaddr_t cmd_ctrl_flow_add_ip_dst =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_flow_add_result, ip_addr_dst);

cmdline_parse_token_num_t cmd_ctrl_flow_add_ip_dst_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, ip_addr_dst_mask, UINT32);

cmdline_parse_token_num_t cmd_ctrl_flow_add_port_src =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, port_src, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_add_port_src_max =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, port_src_max, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_add_port_dst =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, port_dst, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_add_port_dst_max =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, port_dst_max, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_add_tos =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, tos, UINT8);

cmdline_parse_token_num_t cmd_ctrl_flow_add_tos_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_add_result, tos_mask, UINT8);

cmdline_parse_inst_t cmd_ctrl_flow_add = {
	.f = nes_flow_add_parsed,
	.data = NULL,
	.help_str = "flow add [teid] [spid] [qci] [protocol] [src_ip] [mask] [dst_ip] [mask]" \
		" [src_port_min] [src_por_max] [dst_port_min] [dst_port_max] [tos] [mask]",
	.tokens =
	{
		(void *) &cmd_ctrl_flow_add_string,
		(void *) &cmd_ctrl_flow_add_add_string,
		(void *) &cmd_ctrl_flow_add_teid,
		(void *) &cmd_ctrl_flow_add_spid,
		(void *) &cmd_ctrl_flow_add_qci,
		(void *) &cmd_ctrl_flow_add_protocol,
		(void *) &cmd_ctrl_flow_add_ip_src,
		(void *) &cmd_ctrl_flow_add_ip_src_mask,
		(void *) &cmd_ctrl_flow_add_ip_dst,
		(void *) &cmd_ctrl_flow_add_ip_dst_mask,
		(void *) &cmd_ctrl_flow_add_port_src,
		(void *) &cmd_ctrl_flow_add_port_src_max,
		(void *) &cmd_ctrl_flow_add_port_dst,
		(void *) &cmd_ctrl_flow_add_port_dst_max,
		(void *) &cmd_ctrl_flow_add_tos,
		(void *) &cmd_ctrl_flow_add_tos_mask,
		NULL,
	},
};

/* Flow show */
typedef struct cmd_ctrl_flow_show_result {
	cmdline_fixed_string_t flow_string;
	cmdline_fixed_string_t show_string;
	uint8_t protocol;
	cmdline_ipaddr_t ip_addr_src;
	uint32_t ip_addr_src_mask;
	cmdline_ipaddr_t ip_addr_dst;
	uint32_t ip_addr_dst_mask;
	uint16_t port_src;
	uint16_t port_src_max;
	uint16_t port_dst;
	uint16_t port_dst_max;
	uint8_t tos;
	uint8_t tos_mask;
} cmd_ctrl_flow_show_result;

static void
nes_flow_show_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data)
{
	struct cmd_ctrl_flow_show_result *res = parsed_result;

	nes_cli_param_rab_t *rab_param_ptr;
	nes_cli_param_flow_t flow_param;

	flow_param.proto = res->protocol;
	flow_param.inner_src_ip = rte_be_to_cpu_32(res->ip_addr_src.addr.ipv4.s_addr);
	flow_param.inner_src_ip_mask = res->ip_addr_src_mask;
	flow_param.inner_dst_ip = rte_be_to_cpu_32(res->ip_addr_dst.addr.ipv4.s_addr);
	flow_param.inner_dst_ip_mask = res->ip_addr_dst_mask;
	flow_param.inner_src_port = res->port_src;
	flow_param.inner_src_port_max = res->port_src_max;
	flow_param.inner_dst_port = res->port_dst;
	flow_param.inner_dst_port_max = res->port_dst_max;
	flow_param.tos = res->tos;
	flow_param.tos_mask = res->tos_mask;



	if ((NES_SUCCESS == nes_flow_show(&remote_NEV, &flow_param, &rab_param_ptr)) &&
			(NULL != rab_param_ptr)) {
		cmdline_printf(nes_cmdline,
			"Flow: TEID: %"PRIu32", SPID: %"PRIu8", QCI: %"PRIu8".\n",
			rab_param_ptr->teid, rab_param_ptr->spid, rab_param_ptr->qci);
		free(rab_param_ptr);
	} else
		cmdline_printf(nes_cmdline, "No flow found.\n");
}

cmdline_parse_token_string_t cmd_ctrl_flow_show_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_flow_show_result, flow_string, "flow");

cmdline_parse_token_string_t cmd_ctrl_flow_show_show_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_flow_show_result, flow_string, "show");

cmdline_parse_token_num_t cmd_ctrl_flow_show_protocol =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, protocol, UINT8);

cmdline_parse_token_ipaddr_t cmd_ctrl_flow_show_ip_src =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_flow_show_result, ip_addr_src);

cmdline_parse_token_num_t cmd_ctrl_flow_show_ip_src_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, ip_addr_src_mask, UINT32);

cmdline_parse_token_ipaddr_t cmd_ctrl_flow_show_ip_dst =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_flow_show_result, ip_addr_dst);

cmdline_parse_token_num_t cmd_ctrl_flow_show_ip_dst_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, ip_addr_dst_mask, UINT32);

cmdline_parse_token_num_t cmd_ctrl_flow_show_port_src =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, port_src, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_show_port_src_max =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, port_src_max, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_show_port_dst =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, port_dst, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_show_port_dst_max =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, port_dst_max, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_show_tos =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, tos, UINT8);

cmdline_parse_token_num_t cmd_ctrl_flow_show_tos_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_show_result, tos_mask, UINT8);

cmdline_parse_inst_t cmd_ctrl_flow_show = {
	.f = nes_flow_show_parsed,
	.data = NULL,
	.help_str = "flow show [protocol] [src_ip] [mask] [dst_ip] [mask] [src_port_min]" \
		" [src_por_max] [dst_port_min] [dst_port_max] [tos] [mask]",
	.tokens =
	{
		(void *) &cmd_ctrl_flow_show_string,
		(void *) &cmd_ctrl_flow_show_show_string,
		(void *) &cmd_ctrl_flow_show_protocol,
		(void *) &cmd_ctrl_flow_show_ip_src,
		(void *) &cmd_ctrl_flow_show_ip_src_mask,
		(void *) &cmd_ctrl_flow_show_ip_dst,
		(void *) &cmd_ctrl_flow_show_ip_dst_mask,
		(void *) &cmd_ctrl_flow_show_port_src,
		(void *) &cmd_ctrl_flow_show_port_src_max,
		(void *) &cmd_ctrl_flow_show_port_dst,
		(void *) &cmd_ctrl_flow_show_port_dst_max,
		(void *) &cmd_ctrl_flow_show_tos,
		(void *) &cmd_ctrl_flow_show_tos_mask,
		NULL,
	},
};

/* Flow delete */
typedef struct cmd_ctrl_flow_del_result {
	cmdline_fixed_string_t flow_string;
	cmdline_fixed_string_t del_string;
	uint8_t protocol;
	cmdline_ipaddr_t ip_addr_src;
	uint32_t ip_addr_src_mask;
	cmdline_ipaddr_t ip_addr_dst;
	uint32_t ip_addr_dst_mask;
	uint16_t port_src;
	uint16_t port_src_max;
	uint16_t port_dst;
	uint16_t port_dst_max;
	uint8_t tos;
	uint8_t tos_mask;
} cmd_ctrl_flow_del_result;

static void
nes_flow_del_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_flow_del_result *res = parsed_result;

	nes_cli_param_flow_t flow_param;

	flow_param.proto = res->protocol;
	flow_param.inner_src_ip = rte_be_to_cpu_32(res->ip_addr_src.addr.ipv4.s_addr);
	flow_param.inner_src_ip_mask = res->ip_addr_src_mask;
	flow_param.inner_dst_ip = rte_be_to_cpu_32(res->ip_addr_dst.addr.ipv4.s_addr);
	flow_param.inner_dst_ip_mask = res->ip_addr_dst_mask;
	flow_param.inner_src_port = res->port_src;
	flow_param.inner_src_port_max = res->port_src_max;
	flow_param.inner_dst_port = res->port_dst;
	flow_param.inner_dst_port_max = res->port_dst_max;
	flow_param.tos = res->tos;
	flow_param.tos_mask = res->tos_mask;



	if (NES_SUCCESS == nes_flow_del(&remote_NEV, &flow_param))
		cmdline_printf(nes_cmdline, "Flow deleted.\n");
	else
		cmdline_printf(nes_cmdline, "Can't delete flow.\n");
}

cmdline_parse_token_string_t cmd_ctrl_flow_del_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_flow_del_result, flow_string, "flow");

cmdline_parse_token_string_t cmd_ctrl_flow_del_del_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_flow_del_result, flow_string, "del");

cmdline_parse_token_num_t cmd_ctrl_flow_del_protocol =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, protocol, UINT8);

cmdline_parse_token_ipaddr_t cmd_ctrl_flow_del_ip_src =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_flow_del_result, ip_addr_src);

cmdline_parse_token_num_t cmd_ctrl_flow_del_ip_src_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, ip_addr_src_mask, UINT32);

cmdline_parse_token_ipaddr_t cmd_ctrl_flow_del_ip_dst =
	TOKEN_IPADDR_INITIALIZER(struct cmd_ctrl_flow_del_result, ip_addr_dst);

cmdline_parse_token_num_t cmd_ctrl_flow_del_ip_dst_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, ip_addr_dst_mask, UINT32);

cmdline_parse_token_num_t cmd_ctrl_flow_del_port_src =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, port_src, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_del_port_src_max =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, port_src_max, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_del_port_dst =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, port_dst, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_del_port_dst_max =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, port_dst_max, UINT16);

cmdline_parse_token_num_t cmd_ctrl_flow_del_tos =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, tos, UINT8);

cmdline_parse_token_num_t cmd_ctrl_flow_del_tos_mask =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_flow_del_result, tos_mask, UINT8);

cmdline_parse_inst_t cmd_ctrl_flow_del = {
	.f = nes_flow_del_parsed,
	.data = NULL,
	.help_str = "flow del [protocol] [src_ip] [mask] [dst_ip] [mask] [src_port_min]" \
		" [src_por_max] [dst_port_min] [dst_port_max] [tos] [mask]",
	.tokens =
	{
		(void *) &cmd_ctrl_flow_del_string,
		(void *) &cmd_ctrl_flow_del_del_string,
		(void *) &cmd_ctrl_flow_del_protocol,
		(void *) &cmd_ctrl_flow_del_ip_src,
		(void *) &cmd_ctrl_flow_del_ip_src_mask,
		(void *) &cmd_ctrl_flow_del_ip_dst,
		(void *) &cmd_ctrl_flow_del_ip_dst_mask,
		(void *) &cmd_ctrl_flow_del_port_src,
		(void *) &cmd_ctrl_flow_del_port_src_max,
		(void *) &cmd_ctrl_flow_del_port_dst,
		(void *) &cmd_ctrl_flow_del_port_dst_max,
		(void *) &cmd_ctrl_flow_del_tos,
		(void *) &cmd_ctrl_flow_del_tos_mask,
		NULL,
	},
};

/* Show stats for all rings */
typedef struct cmd_ctrl_show_rings_result {
	cmdline_fixed_string_t show_string;
	cmdline_fixed_string_t rings_string;
} cmd_ctrl_show_rings_result;

static void
nes_ctrl_show_rings_parsed(__attribute__((unused)) void *parsed_result,
	__attribute__((unused)) struct cmdline *nes_cmdline, __attribute__((unused)) void *data) {
	nes_sq_t *list = NULL;
	nes_sq_node_t *item = NULL;
	nes_api_ring_t *ring = NULL;
	if (eConnected != remote_NEV.state) {
		cmdline_printf(nes_cmdline, "Connection with server is not established!\n");
		return;
	}

	list = nes_stats_all_ring(&remote_NEV);
	if (NULL == list)
		cmdline_printf(nes_cmdline, "Can't read rings list!\n");
	else {
		cmdline_printf(nes_cmdline, "ID: ");
		cmdline_printf(nes_cmdline, "%3s Name: ", "");
		cmdline_printf(nes_cmdline, "%17s Received: ", "");
		cmdline_printf(nes_cmdline, "%21s Sent: ", "");
		cmdline_printf(nes_cmdline, "%8s Dropped Ring Full: ", "");
		cmdline_printf(nes_cmdline, "%9s Dropped No Route: \n", "");

		NES_SQ_FOREACH(item, list) {
			ring = nes_sq_data(item);
			cmdline_printf(nes_cmdline, "%2u ", ring->index);
			cmdline_printf(nes_cmdline, "%15s ", ring->name);

			cmdline_printf(nes_cmdline, "%s pkts ",
				show_stat_value(ring->stats.rcv_cnt, 22));
			cmdline_printf(nes_cmdline, "%s pkts ",
				show_stat_value(ring->stats.snd_cnt, 22));
			cmdline_printf(nes_cmdline, "%s pkts ",
				show_stat_value(ring->stats.drp_cnt_1, 22));
			cmdline_printf(nes_cmdline, "%s pkts\n",
				show_stat_value(ring->stats.drp_cnt_2, 22));
		}
		nes_sq_dtor_free(list);
	}
	free(list);
}

cmdline_parse_token_string_t cmd_ctrl_show_rings_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_rings_result, show_string, "show");

cmdline_parse_token_string_t cmd_ctrl_show_rings_rings_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_rings_result, rings_string, "rings");

cmdline_parse_inst_t cmd_ctrl_show_rings = {
	.f = nes_ctrl_show_rings_parsed,
	.data = NULL,
	.help_str = "show rings",
	.tokens =
	{
		(void *) &cmd_ctrl_show_rings_string,
		(void *) &cmd_ctrl_show_rings_rings_string,
		NULL,
	},
};

/* Show ring statistics */
typedef struct cmd_ctrl_show_ring_result {
	cmdline_fixed_string_t show_string;
	cmdline_fixed_string_t ring_string;
	uint16_t ring_id;
} cmd_ctrl_show_ring_result;

static void
nes_ctrl_show_ring_parsed(void *parsed_result, __attribute__((unused)) struct cmdline *nes_cmdline,
	__attribute__((unused)) void *data) {
	struct cmd_ctrl_show_ring_result *res = parsed_result;

	nes_ring_stats_t stats;
	if (eConnected != remote_NEV.state) {
		cmdline_printf(nes_cmdline, "Connection with server is not established!\n");
		return;
	}

	if (NES_SUCCESS == nes_stats_ring(&remote_NEV, res->ring_id, &stats)) {
		cmdline_printf(nes_cmdline, "Received packets: %s\n",
			show_stat_value(stats.rcv_cnt, 0));
		cmdline_printf(nes_cmdline, "Sent packets: %s\n",
			show_stat_value(stats.snd_cnt, 0));
		cmdline_printf(nes_cmdline, "Dropped packets Ring Full: %s\n",
			show_stat_value(stats.drp_cnt_1, 0));
		cmdline_printf(nes_cmdline, "Dropped packets No Route: %s\n",
			show_stat_value(stats.drp_cnt_2, 0));
	} else
		cmdline_printf(nes_cmdline, "Error getting ring statistics!\n");
}

cmdline_parse_token_string_t cmd_ctrl_show_ring_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_ring_result, show_string, "show");

cmdline_parse_token_string_t cmd_ctrl_show_ring_ring_string =
	TOKEN_STRING_INITIALIZER(struct cmd_ctrl_show_ring_result, ring_string, "ring");

cmdline_parse_token_num_t cmd_ctrl_show_ring_ring =
	TOKEN_NUM_INITIALIZER(struct cmd_ctrl_show_ring_result, ring_id, UINT16);

cmdline_parse_inst_t cmd_ctrl_show_ring = {
	.f = nes_ctrl_show_ring_parsed,
	.data = NULL,
	.help_str = "show [ring]",
	.tokens =
	{
		(void *) &cmd_ctrl_show_ring_string,
		(void *) &cmd_ctrl_show_ring_ring_string,
		(void *) &cmd_ctrl_show_ring_ring,
		NULL,
	},
};

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *) & cmd_ctrl_help,
	(cmdline_parse_inst_t *) & cmd_conn_init,
	(cmdline_parse_inst_t *) & cmd_conn_default_init,
	(cmdline_parse_inst_t *) & cmd_quit,
	(cmdline_parse_inst_t *) & cmd_ctrl_show_stats,
	(cmdline_parse_inst_t *) & cmd_ctrl_show_all,
	(cmdline_parse_inst_t *) & cmd_ctrl_show_list,
	(cmdline_parse_inst_t *) & cmd_ctrl_show_ring,
	(cmdline_parse_inst_t *) & cmd_ctrl_show_rings,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_data_add,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_data_del,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_data_show,
	(cmdline_parse_inst_t *) & cmd_ctrl_enc_entry_show,
	(cmdline_parse_inst_t *) & cmd_ctrl_mac_show,
	(cmdline_parse_inst_t *) & cmd_ctrl_flow_add,
	(cmdline_parse_inst_t *) & cmd_ctrl_flow_show,
	(cmdline_parse_inst_t *) & cmd_ctrl_flow_del,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_add,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_add_mirror,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_show,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_show_all,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_flush,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_show_mirror,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_del,
	(cmdline_parse_inst_t *) & cmd_ctrl_route_del_mirror,
	(cmdline_parse_inst_t *) & cmd_ctrl_clear_all,
	(cmdline_parse_inst_t *) & cmd_ctrl_kni_del,
	(cmdline_parse_inst_t *) & cmd_ctrl_kni_add,
	NULL,
};

int
nes_cmdline_manager(void) {
	struct cmdline *nes_cmdline = cmdline_stdin_new(main_ctx, "# ");
	cmdline_interact(nes_cmdline);
	cmdline_stdin_exit(nes_cmdline);
	return NES_SUCCESS;
}

int
nes_cmdline_file_manager(const char *path, const char *output_file) {
	int fd, fd_out;
	if (NULL == path)
		return NES_FAIL;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		printf("Failed to open %s\n", path);
		return NES_FAIL;
	}

	if (NULL == output_file)
		fd_out = STDOUT_FILENO;
	else {
		fd_out = open(output_file, O_WRONLY | O_CREAT, 0);
		if (fd_out < 0) {
			close(fd);
			printf("Failed to open %s\n", output_file);
			return NES_FAIL;
		}
	}

	struct cmdline *nes_cmdline = cmdline_new(main_ctx, "# ", fd, fd_out);
	if (NULL == nes_cmdline) {
		printf("Failed to create cmdline instance\n");
		close(fd);
		if (STDOUT_FILENO != fd_out)
			close(fd_out);
		return NES_FAIL;
	}

	is_in_filemode = 1;
	cmdline_interact(nes_cmdline);
	free(nes_cmdline);

	close(fd);
	if (STDOUT_FILENO != fd_out)
		close(fd_out);

	return NES_SUCCESS;
}
