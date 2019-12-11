/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_ctrl.c
 * @brief nes control thread
 */

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <termios.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netdb.h>
#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_kni.h>

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#include "nes_capacity.h"
#include "ctrl/nes_ctrl.h"
#include "nes_ring.h"
#include "nes_common.h"
#include "nts/nts_edit.h"
#include "io/nes_dev.h"
#include "io/nes_dev_kni.h"
#include "io/nes_mac_lookup.h"
#include "nes_ring.h"
#include "nes_ring_lookup.h"
#include "nts/nts_acl.h"
#include "ctrl/nes_tcp_connection.h"
#include "ctrl/nes_configuration.h"
#include "nis/nis_param.h"
#include "nis/nis_acl.h"
#include "nis/nis_routing_data.h"
#include "nts/nts_io.h"
#include "io/nes_io.h"

#include "libnes_sq.h"
#include "libnes_api_protocol.h"
#include "libnes_api.h"
#include "nes_ctrl.h"

#ifdef UNIT_TESTS
	#include "nes_ctrl_decl.h"
#endif

#define MAX_BUFFER_SIZE 512
#define MAXEVENTS 64
#define DATA_SIZE 30
#define LIST_DATA_SIZE 6
#define MAX_CTX_PER_SERVICE 256

nes_acl_ctx_t nes_ctrl_acl_ctx;
nes_acl_ctx_t nis_param_acl_ctx;

static nes_sq_t *dev_list;
static nes_sq_t *ring_list;
static nes_sq_t *client_list;
nes_sq_node_t *node;
configuration_t conf;
tcp_connection_t conn;

struct server_buffer_s {
	uint16_t    buf_count;
	int         fd;
	uint8_t     buffer[MAX_BUFFER_SIZE];
};

static int set_sock_non_blocking(int sock_fd)
{
	int flags, s;

	flags = fcntl(sock_fd, F_GETFL, 0);
	if (flags == -1)
	{
		perror ("fcntl");
		return NES_FAIL;
	}

	flags |= O_NONBLOCK;
	s = fcntl (sock_fd, F_SETFL, flags);
	if (s == -1)
	{
		perror ("fcntl");
		return NES_FAIL;
	}

	return NES_SUCCESS;
}
/* Find rings for enqueue and dequeue */
int nes_ctrl_init(void)
{
	if (NES_SUCCESS != nts_acl_lookup_init(&nes_ctrl_acl_ctx)) {
		NES_LOG(ERR, "Could not initialize nes ACL.\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nis_param_init(&nis_param_acl_ctx)) {
		NES_LOG(ERR, "Could not initialize nis ACL.\n");
		return NES_FAIL;
	}

	if (NES_SUCCESS != nes_server_configure(&conf)) {

		NES_LOG(ERR, "Config file can not be read.\n");
		return NES_FAIL;
	}

	if (NULL == conf.server_socket) {
#ifndef EXT_CTRL_SOCKET
		NES_LOG(ERR, "Server socket is not set up.\n");
		return NES_FAIL;
#else
		if (NES_SUCCESS != nes_connection_setup(conf.server_ip, conf.server_port, &conn)) {
			NES_LOG(ERR, "Server connection can not be established.\n");
			return NES_FAIL;
		}
#endif
	} else {
		if (NES_SUCCESS != nes_connection_un_setup(conf.server_socket, &conn)) {
			NES_LOG(ERR, "Server connection can not be established.\n");
			return NES_FAIL;
		}
	}

	client_list = rte_malloc(NULL, sizeof(nes_sq_t),0);
	VERIFY_PTR_OR_RET(client_list, NES_FAIL);
	nes_sq_ctor(client_list);
	return NES_SUCCESS;
}

static int nes_ctrl_show_vhost_stats(nes_ctrl_dev_t *dev, nes_dev_stats_t *stats)
{
	if (NULL == dev || NULL == stats)
		return NES_FAIL;

	*stats = dev->stats;

	return  NES_SUCCESS;
}

static int nes_ctrl_show_eth_stats(nes_ctrl_dev_t *dev, nes_dev_stats_t *stats)
{
	struct rte_eth_stats eth_stats;
	if (NULL == dev || NULL == stats)
		return NES_FAIL;

	*stats = dev->stats;
	if (NES_FAIL == rte_eth_stats_get(dev->dev_ptr->dev.eth.port_id, &eth_stats))
		return NES_FAIL;

	stats->rcv_cnt = eth_stats.ipackets;
	stats->snd_cnt = eth_stats.opackets;
	stats->rcv_bytes = eth_stats.ibytes;
	stats->snd_bytes = eth_stats.obytes;

	return  NES_SUCCESS;
}

static int nes_ctrl_show_per_ring_stats(nes_ctrl_ring_t *ring, nes_ring_stats_t *stats)
{
	if (NULL == ring || NULL == stats)
		return NES_FAIL;

	*stats = ring->stats;

	return  NES_SUCCESS;
}

int nes_ctrl_show_dev_stats(uint16_t id, nes_dev_stats_t *stats)
{
	nes_ctrl_dev_t *dev;
	nes_sq_node_t *node = nes_sq_get(dev_list, id);
	if (NULL == node)
		return NES_FAIL;

	dev = nes_sq_data(node);

	if (NULL == dev)
		return NES_FAIL;

	dev->show(dev, stats);
	return NES_SUCCESS;
}

int nes_ctrl_show_ring_stats(uint16_t id, nes_ring_stats_t *stats)
{
	nes_ctrl_ring_t *ring;
	nes_sq_node_t *node = nes_sq_get(ring_list, id);
	if (NULL == node)
		return NES_FAIL;

	ring = nes_sq_data(node);

	if (NULL == ring)
		return NES_FAIL;

	ring->show(ring, stats);
	return NES_SUCCESS;
}

int nes_ctrl_ctor_dev_list(void)
{
	dev_list = rte_malloc(NULL, sizeof(nes_sq_t), 0);
	VERIFY_PTR_OR_RET(dev_list, NES_FAIL);

	nes_sq_ctor(dev_list);

	return NES_SUCCESS;
}

int nes_ctrl_ctor_ring_list(void)
{
	ring_list = rte_malloc(NULL, sizeof(nes_sq_t), 0);
	VERIFY_PTR_OR_RET(ring_list, NES_FAIL);

	nes_sq_ctor(ring_list);

	return NES_SUCCESS;
}

int nes_ctrl_add_device(nes_dev_t *dev, const char *name)
{
	assert(dev == NULL);
	assert(name == NULL);

	nes_ctrl_dev_t *dev_to_add;

	dev_to_add = rte_zmalloc(NULL, sizeof(nes_ctrl_dev_t), 0);
	VERIFY_PTR_OR_RET(dev_to_add, NES_FAIL);
	dev_to_add->index = dev_list->cnt;
	strncpy(dev_to_add->name, name, sizeof(dev_to_add->name) - 1);
	dev_to_add->dev_ptr = dev;
	if (strcmp(VHOST_NAME_STRING, name) == 0 ||
		strcmp(KNI_NAME_STRING, name) == 0)
		dev_to_add->show = nes_ctrl_show_vhost_stats;
	else
		dev_to_add->show = nes_ctrl_show_eth_stats;

	NES_STATS_INIT_DEV(dev_to_add);

	if (NES_FAIL == nes_sq_enq(dev_list, dev_to_add))
		return NES_FAIL;

	dev->dev_stats = dev_to_add;
	return NES_SUCCESS;
}

int nes_ctrl_add_ring(nes_ring_t *ring, const char *name)
{
	assert(ring == NULL);
	assert(name == NULL);

	nes_ctrl_ring_t *ring_to_add;

	ring_to_add = rte_zmalloc(NULL, sizeof(nes_ctrl_ring_t), 0);
	VERIFY_PTR_OR_RET(ring_to_add, NES_FAIL);
	ring_to_add->index = ring_list->cnt;
	strncpy(ring_to_add->name, name, sizeof(ring_to_add->name) - 1);
	ring_to_add->ring_ptr = ring;
	ring_to_add->show = nes_ctrl_show_per_ring_stats;

	NES_STATS_INIT_RING(ring_to_add);

	if (NES_FAIL == nes_sq_enq(ring_list, ring_to_add))
		return NES_FAIL;

	ring->ring_stats = ring_to_add;
	return NES_SUCCESS;
}

int nes_ctrl_del_device(nes_dev_t *dev)
{
	assert(dev);
	nes_ctrl_dev_t *data;

	if (VHOST == dev->dev_type || KNI == dev->dev_type) {
		uint32_t j;
		struct mac_entry *mac_data;
		if (NES_SUCCESS == nes_mac_lookup_entry_find(&dev->mac_address, &mac_data)) {
			mac_data->ring = NULL;
			mac_data->ring_name = NULL;
		}
		rte_spinlock_lock(&nes_ctrl_acl_ctx.acl_lock);
		for (j = 0; j < nes_ctrl_acl_ctx.max_entries; j++) {
			if (NULL != nes_ctrl_acl_ctx.entries[j]) {
				nes_sq_t *acl_entries = (nes_sq_t *)nes_ctrl_acl_ctx.entries[j];
				nes_sq_node_t *node;
				NES_SQ_FOREACH(node, acl_entries) {
					nts_route_entry_t *entry = nes_sq_data(node);
					if (0 == memcmp(&entry->mac_addr, &dev->mac_address,
							sizeof(struct ether_addr))) {
						entry->dst_ring = NULL;
						entry->ring_name = NULL;
					}
				}
			}
		}
		rte_spinlock_unlock(&nes_ctrl_acl_ctx.acl_lock);
	}

	int i = dev->dev_stats->index;

	if (NULL == (node = nes_sq_get(dev_list, i)))
		return NES_FAIL;

	nes_sq_remove(dev_list, node);
	/* Change indexing for following nodes */
	for (; i < dev_list->cnt; i++) {
		node = nes_sq_get(dev_list, i);
		data = nes_sq_data(node);
		data->index = data->index - 1;
	}

	return NES_SUCCESS;
}

int nes_ctrl_del_ring(nes_ring_t *ring)
{
	assert(ring);
	int i;
	nes_ctrl_ring_t *data;

	i = ring->ring_stats->index;

	if (NULL == (node = nes_sq_get(ring_list, i)))
		return NES_FAIL;

	nes_sq_remove(ring_list, node);
	/* Change indexing for following nodes */
	for (; i < ring_list->cnt; i++)
	{
		node = nes_sq_get(ring_list, i);
		data = nes_sq_data(node);
		data->index = data->index - 1;
	}

	return NES_SUCCESS;
}

static nes_api_msg_t *nes_ctrl_show_list(void)
{
	size_t offset = 0;

	nes_ctrl_dev_t *dev;
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + (dev_list->cnt * LIST_DATA_SIZE), 0);
	VERIFY_PTR_OR_RET(response, NULL);
	response->data_size = 0;
	response->message_type = eResponse;
	response->function_id = eNesStatsShowList;

	NES_SQ_FOREACH(node, dev_list) {
		dev = nes_sq_data(node);
		rte_memcpy(response->data + offset, &dev->index, sizeof(dev->index));
		offset = offset + sizeof(dev->index);
		rte_memcpy(response->data + offset, &dev->name, sizeof(dev->name));
		offset = offset + sizeof(dev->name);
		response->data_size += sizeof(dev->index) + sizeof(dev->name);
	}
	return response;
}

static nes_api_msg_t *nes_ctrl_route_add_impl(nes_api_msg_t *api_msg, uint8_t is_mirror)
{
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);
	int ret;
	struct add_route_data {
		struct ether_addr vm_mac_addr;
		char lookup[];
	} *data;
	data = (struct add_route_data*)api_msg->data;
	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nts_acl_lookup_add_vm(&nes_ctrl_acl_ctx,
			data->lookup,
			data->vm_mac_addr,
			is_mirror ? NTS_EDIT_MIRROR : NTS_EDIT_DECAP_ONLY))) {
		response->message_type = eError;
		response->data_size = 0;
	} else {
		struct mac_entry *vm_mac_data;
		if (NES_SUCCESS != nes_mac_lookup_entry_find(&data->vm_mac_addr, &vm_mac_data)) {
			struct mac_entry mac_data = { 0 };
			if (NES_SUCCESS != nes_mac_lookup_entry_add(&data->vm_mac_addr,
					&mac_data)) {
				response->message_type = eError;
				response->data_size = 0;
				return response;
			}
		}
		rte_memcpy(response->data, &ret, sizeof(ret));
		response->data_size = sizeof(ret);
	}

	return response;
}

static nes_api_msg_t *nes_ctrl_route_add(nes_api_msg_t *api_msg)
{
	return nes_ctrl_route_add_impl(api_msg, 0);
}

static nes_api_msg_t *nes_ctrl_mirror_add(nes_api_msg_t *api_msg)
{
	return nes_ctrl_route_add_impl(api_msg, 1);
}

static int read_vm_id(const char* ring_name) {
	//IO_VM0_ANY
	if (NULL == ring_name)
		return -1;

	if (strlen(ring_name) + 1 < sizeof("IO_VM0_ANY"))
		return -1;

	return strtol(ring_name + sizeof("IO_VM") - 1, NULL, 10);
}

static int
get_nes_route_entry(const struct nts_acl_lookup_field *lookup_rule, nes_route_data_t *route_data)
{
	int ret = 0;
	uint32_t route_id;
	nts_route_entry_t *route_entry;

	if (NULL == lookup_rule || NULL == route_data) {
		NES_LOG(ERR, "Invalid input\n");
		return NES_FAIL;
	}
	route_data->prio = lookup_rule->data.priority;

	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "qci",
		&route_data->qci_min,
		&route_data->qci_max,
		sizeof(route_data->qci_min)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "spid",
		&route_data->spid_min,
		&route_data->spid_max,
		sizeof(route_data->spid_min)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "teid",
		&route_data->teid_min,
		&route_data->teid_max,
		sizeof(route_data->teid_min)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "ue_port",
		&route_data->ue_port_min,
		&route_data->ue_port_max,
		sizeof(route_data->ue_port_min)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "srv_port",
		&route_data->srv_port_min,
		&route_data->srv_port_max,
		sizeof(route_data->srv_port_min)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "enb_ip",
		&route_data->enb_ip,
		&route_data->enb_ip_mask,
		sizeof(route_data->enb_ip)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "epc_ip",
		&route_data->epc_ip,
		&route_data->epc_ip_mask,
		sizeof(route_data->epc_ip)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "ue_ip",
		&route_data->ue_ip,
		&route_data->ue_ip_mask,
		sizeof(route_data->ue_ip)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "srv_ip",
		&route_data->srv_ip,
		&route_data->srv_ip_mask,
		sizeof(route_data->srv_ip)));
	ret |= (NES_SUCCESS != nts_acl_get_field_from_lookup(lookup_rule, "encap_proto",
		&route_data->encap_proto,
		NULL,
		sizeof(route_data->encap_proto)));

	if (ret) {
		NES_LOG(ERR, "Extracting data from lookup failed\n");
		return NES_FAIL;
	}

	route_id = lookup_rule->data.userdata - USER_DATA_OFFSET;
	if ((uint32_t)route_id > nes_ctrl_acl_ctx.max_entries ||
			NULL == nes_ctrl_acl_ctx.entries[route_id] ||
			NULL == nes_sq_head(nes_ctrl_acl_ctx.entries[route_id])) {

		NES_LOG(ERR, "Invalid entry %d\n", route_id);
		return NES_FAIL;
	}

	route_entry = nes_sq_data(nes_sq_head(nes_ctrl_acl_ctx.entries[route_id]));
	if (NULL == route_entry) {
		NES_LOG(ERR, "Failed to read route entry\n");
		return NES_FAIL;
	}

	route_data->dst_mac_addr = route_entry->mac_addr;
	return NES_SUCCESS;
}

static nes_api_msg_t *
nes_ctrl_empty_response(nes_api_msg_type_t msg_type, nes_api_function_id_t func_id)
{
	nes_api_msg_t *response = NULL;

	response = rte_zmalloc(NULL, sizeof(nes_api_msg_t), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	response->message_type = msg_type;
	response->function_id = func_id;
	response->data_size = 0;

	return response;
}

static nes_api_msg_t *nes_ctrl_route_list(__attribute__((unused))nes_api_msg_t *api_msg)
{
	uint32_t i, route_cnt;
	uint32_t skipped_routes = 0;
	uint32_t added_routes = 0;
	uint16_t data_len;
	nes_route_list_req_t *route_list_req;
	nes_api_msg_t *response = NULL;

	if (api_msg->data_size != sizeof(nes_route_list_req_t))
		return nes_ctrl_empty_response(eError, eNesRouteList);

	route_list_req = (nes_route_list_req_t*)api_msg->data;

	rte_spinlock_lock(&nes_ctrl_acl_ctx.data_lock);
	route_cnt = nes_ctrl_acl_ctx.entries_cnt;

	// No (more) routes
	if (0 == route_cnt ||
			route_list_req->entry_offset >= route_cnt) {

		rte_spinlock_unlock(&nes_ctrl_acl_ctx.data_lock);
		return nes_ctrl_empty_response(eResponse, eNesRouteList);
	}

	if (route_list_req->max_entry_cnt > ROUTES_LIST_MAX_CNT) {
		rte_spinlock_unlock(&nes_ctrl_acl_ctx.data_lock);
		return nes_ctrl_empty_response(eError, eNesRouteList);
	}

	route_cnt -= route_list_req->entry_offset;
	if (route_cnt > route_list_req->max_entry_cnt)
		route_cnt = route_list_req->max_entry_cnt;

	data_len = sizeof(nes_route_data_t) * route_cnt;
	response = rte_zmalloc(NULL, sizeof(nes_api_msg_t) + data_len, 0);
	if (NULL == response) {
		rte_spinlock_unlock(&nes_ctrl_acl_ctx.data_lock);
		return nes_ctrl_empty_response(eError, eNesRouteList);
	}

	response->data_size = data_len;
	response->function_id = eNesRouteList;

	nes_route_data_t *nes_routes = (nes_route_data_t *)response->data;

	for (i = 0; i < nes_ctrl_acl_ctx.max_entries; i++) {
		if (NULL == nes_ctrl_acl_ctx.rules[i])
			continue;

		if (skipped_routes++ < route_list_req->entry_offset)
			continue;

		if (NES_SUCCESS != get_nes_route_entry((struct nts_acl_lookup_field*)
				nes_ctrl_acl_ctx.rules[i], &nes_routes[added_routes])) {
			rte_free(response);
			rte_spinlock_unlock(&nes_ctrl_acl_ctx.data_lock);
			return nes_ctrl_empty_response(eError, eNesRouteList);
		}

		if (++added_routes == route_cnt)
			break;
	}
	rte_spinlock_unlock(&nes_ctrl_acl_ctx.data_lock);
	return response;
}

static nes_api_msg_t *nes_ctrl_route_show(nes_api_msg_t *api_msg)
{
	nes_sq_t *upstream_route = NULL, *downstream_route = NULL;
	nes_api_msg_t *response = NULL;
	nes_sq_node_t *item = NULL, *upstream_tail = NULL;
	uint16_t cnt_len, data_len;

	int i;
	if (NES_SUCCESS != nts_acl_lookup_find(&nes_ctrl_acl_ctx, (char*)api_msg->data,
			&upstream_route, &downstream_route)) {
		response = rte_zmalloc(NULL, sizeof(nes_api_msg_t),0);
		VERIFY_PTR_OR_RET(response, NULL);
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}

	// data format: int upstream_routes count,int downstream_routes count,
	// nes_route_entry_data_t[] routes
	cnt_len = sizeof(upstream_route->cnt) * 2;
	data_len = (upstream_route->cnt + (NULL != downstream_route ? downstream_route->cnt : 0)) *
		sizeof(nes_route_entry_data_t) + cnt_len;

	response = rte_zmalloc(NULL, sizeof(nes_api_msg_t) + data_len, 0);
	VERIFY_PTR_OR_RET(response, NULL);
	response->message_type = eResponse;
	response->data_size = data_len;
	rte_memcpy(response->data, &upstream_route->cnt, sizeof(upstream_route->cnt));

	if (NULL != downstream_route) {
		rte_memcpy(response->data + sizeof(upstream_route->cnt),
			&downstream_route->cnt, sizeof(downstream_route->cnt));
	} else {
		int len = 0;
		rte_memcpy(response->data + sizeof(upstream_route->cnt), &len, sizeof(len));
	}
	i = 0;

	// join two queues to iterate once
	upstream_tail = nes_sq_tail(upstream_route);
	if (NULL != upstream_tail && (NULL != downstream_route))
		upstream_tail->next = nes_sq_head(downstream_route);

	NES_SQ_FOREACH(item, upstream_route) {
		nts_route_entry_t *route_data = nes_sq_data(item);
		nes_route_entry_data_t data;
		data.ipaddr.s_addr = route_data->ip_addr;
		data.cbmode = nts_route_entry_edit_get(route_data);
		data.macaddr = route_data->mac_addr;
		data.vmid = read_vm_id(route_data->ring_name);
		rte_memcpy(response->data + cnt_len + i * sizeof(data), &data, sizeof(data));
		i++;
	}
	if (NULL != upstream_tail && (NULL != downstream_route))
		upstream_tail->next = NULL;

	return response;
}

static nes_api_msg_t *nes_ctrl_route_del(nes_api_msg_t *api_msg)
{
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);
	int ret;

	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nts_acl_lookup_remove(&nes_ctrl_acl_ctx, (char*)api_msg->data))) {
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}
	/* nes_mac_lookup_entry_del(&data->vm_mac_addr); */

	rte_memcpy(response->data, &ret, sizeof(ret));
	response->data_size = sizeof(ret);
	return response;
}

static nes_api_msg_t *nes_ctrl_get_mac_addr(nes_api_msg_t *api_msg)
{
	nes_api_msg_t *response;
	uint8_t port_id = *(uint8_t*)api_msg->data;
	struct ether_addr addr;
	if (NES_FAIL == nes_dev_eth_mac_addr_get(port_id, &addr)) {
		response = rte_zmalloc(NULL, sizeof(nes_api_msg_t),0);
		VERIFY_PTR_OR_RET(response, NULL);
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}
	response = rte_zmalloc(NULL, sizeof(nes_api_msg_t) + sizeof(struct ether_addr), 0);
	VERIFY_PTR_OR_RET(response, NULL);
	response->data_size = sizeof(struct ether_addr);
	response->message_type = eResponse;
	rte_memcpy(response->data, &addr, sizeof(addr));
	return response;
}

nes_api_msg_t *nes_ctrl_stats_dev(nes_api_msg_t *api_msg)
{
	nes_dev_stats_t stats, *data_ptr;

	if (NES_FAIL == nes_ctrl_show_dev_stats((uint16_t)api_msg->data[0], &stats)) {
		nes_api_msg_t *response = rte_zmalloc(NULL, sizeof(nes_api_msg_t),0);
		VERIFY_PTR_OR_RET(response, NULL);
		response->message_type = eError;
		return response;
	}
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(nes_dev_stats_t), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	response->data_size = sizeof(nes_dev_stats_t);
	response->message_type = eResponse;
	data_ptr = (nes_dev_stats_t*)response->data;
	*data_ptr = stats;
	return response;
}

nes_api_msg_t *nes_ctrl_stats_ring(nes_api_msg_t *api_msg)
{
	nes_ring_stats_t stats;
	nes_ring_stats_t *data_ptr;

	if (NES_FAIL == nes_ctrl_show_ring_stats((uint16_t)api_msg->data[0], &stats)) {
		nes_api_msg_t *response = rte_zmalloc(NULL, sizeof(nes_api_msg_t),0);
		VERIFY_PTR_OR_RET(response, NULL);
		response->message_type = eError;
		return response;
	}
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(nes_ring_stats_t), 0);
	VERIFY_PTR_OR_RET(response, NULL);
	response->data_size = sizeof(nes_ring_stats_t);
	response->message_type = eResponse;
	data_ptr = (nes_ring_stats_t*)response->data;
	*data_ptr = stats;

	return response;
}

static nes_sq_t *nes_ctrl_show_all(void)
{
	struct rte_eth_stats stats;
	nes_sq_node_t *item = NULL;
	nes_ctrl_dev_t *device = NULL;

	NES_SQ_FOREACH(item, dev_list) {
		device = nes_sq_data(item);
		if (0 != strcmp(device->name, VHOST_NAME_STRING) &&
				0 != strcmp(device->name, KNI_NAME_STRING)) {
			rte_eth_stats_get(device->dev_ptr->dev.eth.port_id, &stats);
			device->stats.rcv_cnt = stats.ipackets;
			device->stats.drp_cnt_2 = stats.oerrors + stats.ierrors;
			device->stats.snd_cnt = stats.opackets;
			device->stats.rcv_bytes = stats.ibytes;
			device->stats.snd_bytes = stats.obytes;
		}
	}

	return dev_list;
}

static nes_api_msg_t *nes_ctrl_show_dev_all(void)
{
	size_t data_size = 0;
	size_t dev_data_size = 0;

	nes_ctrl_dev_t *dev;
	nes_sq_t *list = nes_ctrl_show_all();

	dev_data_size = sizeof(nes_api_dev_t);

	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + dev_list->cnt * dev_data_size, 0);
	VERIFY_PTR_OR_RET(response, NULL);
	nes_api_dev_t *dev_stats = (nes_api_dev_t*)response->data;

	NES_SQ_FOREACH(node, list) {
		dev = nes_sq_data(node);
		dev_stats->index = dev->index;
		memcpy(dev_stats->name, dev->name, sizeof(dev_stats->name));
		dev_stats->stats = dev->stats;
		dev_stats->macaddr = dev->dev_ptr->mac_address;
		dev_stats++;
		data_size += dev_data_size;
	}
	response->message_type = eResponse;
	response->function_id = eNesStatsDevAll;
	response->data_size = data_size;

	return response;
}

static nes_api_msg_t *nes_ctrl_show_ring_all(void)
{
	size_t data_size = 0;
	size_t ring_data_size = 0;

	nes_ctrl_ring_t *ring;
	nes_sq_t *list = ring_list;

	ring_data_size = sizeof(nes_api_ring_t);

	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + list->cnt * ring_data_size, 0);
	VERIFY_PTR_OR_RET(response, NULL);
	nes_api_ring_t *ring_stats = (nes_api_ring_t*)response->data;

	NES_SQ_FOREACH(node, list) {
		ring = nes_sq_data(node);
		ring_stats->index = ring->index;
		memcpy(ring_stats->name, ring->name, sizeof(ring_stats->name));
		ring_stats->stats = ring->stats;
		ring_stats++;
		data_size += ring_data_size;
	}

	response->message_type = eResponse;
	response->function_id = eNesStatsDevAll;
	response->data_size = data_size;

	return response;

}

static nes_api_msg_t *nes_ctrl_routing_data_add(nes_api_msg_t *api_msg) {
	assert(api_msg);

	int ret;
	struct routing_msg_s {
		nis_routing_data_key_t routing_key;
		nis_routing_data_t routing_data;
	} *routing_msg;

	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);
	if (NULL == response)
		return response;

	if ((sizeof(struct routing_msg_s)) != api_msg->data_size) {
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}

	routing_msg = (struct routing_msg_s*)api_msg->data;
	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nis_routing_data_add(&routing_msg->routing_key,
			&routing_msg->routing_data))) {
		response->message_type = eError;
		response->data_size = 0;
	} else {
		rte_memcpy(response->data, &ret, sizeof(ret));
		response->data_size = sizeof(ret);
	}
	return response;
}

static nes_api_msg_t *nes_ctrl_routing_data_del(nes_api_msg_t *api_msg) {
	assert(api_msg);

	int ret;
	nis_routing_data_key_t *routing_key;

	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	if (sizeof(nis_routing_data_key_t) != api_msg->data_size) {
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}

	routing_key = (nis_routing_data_key_t*)api_msg->data;
	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nis_routing_data_del(routing_key))) {
		response->message_type = eError;
		response->data_size = 0;
	} else {
		rte_memcpy(response->data, &ret, sizeof(ret));
		response->data_size = sizeof(ret);
	}
	return response;
}

static nes_api_msg_t *nes_ctrl_routing_data_show(nes_api_msg_t *api_msg)
{
	assert(api_msg);

	nis_routing_data_key_t *routing_key;
	nis_routing_data_t *data;
	int ret;
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(nis_routing_data_t), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	routing_key = (nis_routing_data_key_t*)api_msg->data;
	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nis_routing_data_get(routing_key, &data))) {
		response->message_type = eError;
		response->data_size = 0;
	} else {
		rte_memcpy(response->data, data, sizeof(nis_routing_data_t));
		response->data_size = sizeof(nis_routing_data_t);
	}
	return response;
}

static nes_api_msg_t *nes_ctrl_encap_show(nes_api_msg_t *api_msg)
{
	assert(api_msg);

	nts_enc_entry_t *encap_entry = NULL;
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(nts_enc_entry_t), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	uint32_t *ip = (uint32_t*)api_msg->data;
	response->message_type = eResponse;

	nes_lookup_entry_find(nts_io_routing_tables_get()->learning, ip, (void**) &encap_entry);
	if (NULL == encap_entry) {
		response->message_type = eError;
		response->data_size = 0;
	} else {
		rte_memcpy(response->data, encap_entry, sizeof(nts_enc_entry_t));
		response->data_size = sizeof(nts_enc_entry_t);
	}
	return response;
}

static nes_api_msg_t *nes_ctrl_flow_add(nes_api_msg_t *api_msg)
{
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	int ret;
	struct add_flow_data {
		nis_param_pkt_flow_t flow_params;
		nis_param_rab_t rab_params;
	} *data;
	data = (struct add_flow_data*)api_msg->data;
	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nis_param_rab_set(&nis_param_acl_ctx,
			&data->flow_params, &data->rab_params))) {
		response->message_type = eError;
		response->data_size = 0;
	}
	rte_memcpy(response->data, &ret, sizeof(ret));
	response->data_size = sizeof(ret);
	return response;
}

static nes_api_msg_t *nes_ctrl_flow_show(nes_api_msg_t *api_msg)
{
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(nis_param_rab_t), 0);
	VERIFY_PTR_OR_RET(response, NULL);
	nis_param_rab_t *rab_params;

	int ret;
	struct del_flow_data {
		nis_param_pkt_flow_t flow_params;
	} *data;
	data = (struct del_flow_data*)api_msg->data;
	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nis_param_rab_get(&nis_param_acl_ctx,
			&data->flow_params, &rab_params))) {
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}
	rte_memcpy(response->data, rab_params, sizeof(nis_param_rab_t));
	response->data_size = sizeof(nis_param_rab_t);
	return response;
}

static nes_api_msg_t *nes_ctrl_flow_del(nes_api_msg_t *api_msg)
{
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	int ret;
	struct del_flow_data {
		nis_param_pkt_flow_t flow_params;
	} *data;
	data = (struct del_flow_data*)api_msg->data;
	response->message_type = eResponse;
	if (NES_SUCCESS != (ret = nis_param_rab_del(&nis_param_acl_ctx, &data->flow_params))) {
		response->message_type = eError;
		response->data_size = 0;
	}
	rte_memcpy(response->data, &ret, sizeof(ret));
	response->data_size = sizeof(ret);
	return response;
}

static nes_api_msg_t *nes_ctrl_clear_stats(void)
{
	enum NES_ERROR ret;
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	nes_sq_node_t *item = NULL;
	nes_ctrl_dev_t *device = NULL;
	nes_ctrl_ring_t *ring = NULL;

	NES_SQ_FOREACH(item, dev_list) {
		device = nes_sq_data(item);

		if (0 == strcmp(device->name, VHOST_NAME_STRING) ||
				0 == strcmp(device->name, KNI_NAME_STRING))
			NES_STATS_INIT_DEV(device);
		else {
			NES_STATS_INIT_DEV(device);
			rte_eth_stats_reset(device->dev_ptr->dev.eth.port_id);
		}
	}

	NES_SQ_FOREACH(node, ring_list) {
		ring = nes_sq_data(node);
		NES_STATS_INIT_RING(ring);
	}

	/* prepare response */
	response->message_type = eResponse;
	response->function_id = eNesStatsClearAll;
	ret = NES_SUCCESS;
	rte_memcpy(response->data, &ret, sizeof(ret));
	response->data_size = sizeof(ret);
	return response;
}

static nes_api_msg_t *nes_ctrl_clear_routes(void)
{
	enum NES_ERROR ret;
	nes_api_msg_t *response = rte_zmalloc(NULL,
		sizeof(nes_api_msg_t) + sizeof(enum NES_ERROR), 0);
	VERIFY_PTR_OR_RET(response, NULL);

	response->message_type = eResponse;
	response->function_id = eNesRouteClearAll;
	nts_acl_flush(&nes_ctrl_acl_ctx);
	ret = NES_SUCCESS;
	rte_memcpy(response->data, &ret, sizeof(ret));
	response->data_size = sizeof(ret);
	return response;
}

static nes_api_msg_t *nes_ctrl_kni_add(nes_api_msg_t *api_msg)
{
	char kni_if_name[RTE_KNI_NAMESIZE];
	nes_api_msg_t *response = rte_zmalloc(NULL, sizeof(nes_api_msg_t) + sizeof(kni_if_name),0);
	VERIFY_PTR_OR_RET(response, NULL);

	response->message_type = eResponse;
	if (NES_SUCCESS != nes_dev_kni_create_port((char*) api_msg->data, kni_if_name)) {
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}

	rte_memcpy(response->data, kni_if_name, sizeof(kni_if_name));
	response->data_size = sizeof(kni_if_name);
	return response;
}

static nes_api_msg_t *nes_ctrl_kni_del(nes_api_msg_t *api_msg)
{
	char kni_if_name[RTE_KNI_NAMESIZE];
	nes_api_msg_t *response = rte_zmalloc(NULL, sizeof(nes_api_msg_t) + sizeof(kni_if_name),0);
	VERIFY_PTR_OR_RET(response, NULL);

	response->message_type = eResponse;
	if (NES_SUCCESS != nes_dev_kni_delete_port((char*) api_msg->data, kni_if_name)) {
		response->message_type = eError;
		response->data_size = 0;
		return response;
	}

	rte_memcpy(response->data, kni_if_name, sizeof(kni_if_name));
	response->data_size = sizeof(kni_if_name);
	return response;
}

enum nes_flow_function_id {
	eNesAddFlow = 100,
	eNesShowFlow,
	eNesDelFlow,
	eNesAddRouteData,
	eNesDelRouteData,
	eNesShowRouteData,
	eNesShowEncap
};

NES_STATIC int nes_handle_msg(nes_api_msg_t *api_msg, nes_api_msg_t **response)
{
	if (NULL == api_msg || NULL == response) {
		NES_LOG(DEBUG, "%s bad params, buffer: %p response: %p\n",
			__FUNCTION__, api_msg, response);
		return -1;
	}

	*response = NULL;
	if (api_msg->message_type == eRequest) {
		switch (api_msg->function_id) {
		case eNesStatsDev: {
			*response = nes_ctrl_stats_dev(api_msg);
			if (NULL == *response)
				NES_LOG(ERR, "Device stats can't be read!\n");
			break;
		}
		case eNesStatsDevAll: {
			*response = nes_ctrl_show_dev_all();
			if (NULL == *response)
				NES_LOG(ERR, "Device stats can't be read!\n");
			break;
		}
		case eNesStatsShowList: {
			*response = nes_ctrl_show_list();
			if (NULL == *response)
				NES_LOG(ERR, "Device stats can't be read!\n");
			break;
		}
		case eNesMacAddressGet: {
			if (NULL == (*response = nes_ctrl_get_mac_addr(api_msg)))
				NES_LOG(ERR, "Mac address get failed\n");
			break;
		}
		case eNesAddRoute: {
			if (NULL == (*response = nes_ctrl_route_add(api_msg)))
				NES_LOG(ERR, "Route add failed\n");
			break;
		}
		case eNesAddMirror: {
			if (NULL == (*response = nes_ctrl_mirror_add(api_msg)))
				NES_LOG(ERR, "Add mirror failed\n");
			break;
		}
		case eNesDelRoute: {
			if (NULL == (*response = nes_ctrl_route_del(api_msg)))
				NES_LOG(ERR, "Del route failed\n");
			break;
		}
		case eNesRouteClearAll: {
			*response = nes_ctrl_clear_routes();
			if (NULL == *response)
				NES_LOG(ERR, "Routes can't be cleared!\n");
			break;
		}
		case eNesShowRoute: {
			if (NULL == (*response = nes_ctrl_route_show(api_msg)))
				NES_LOG(ERR, "Show route failed\n");
			break;
		}
		case eNesRouteList: {
			if (NULL == (*response = nes_ctrl_route_list(api_msg)))
				NES_LOG(ERR, "Show routes failed\n");
			break;
		}
		case eNesStatsClearAll: {
			*response = nes_ctrl_clear_stats();
			if (NULL == *response)
				NES_LOG(ERR, "Device stats can't be cleared!\n");
			break;
		}
		case eNesStatsRing: {
			*response = nes_ctrl_stats_ring(api_msg);
			if (NULL == *response)
				NES_LOG(ERR, "Ring stats can't be read!\n");
			break;
		}
		case eNesStatsRingAll: {
			*response = nes_ctrl_show_ring_all();
			if (NULL == *response)
				NES_LOG(ERR, "Ring stats can't be read!\n");
			break;
		}
		case eNesAddKni: {
			if (NULL == (*response = nes_ctrl_kni_add(api_msg)))
				NES_LOG(ERR, "KNI add failed\n");
			break;
		}
		case eNesDelKni: {
			if (NULL == (*response = nes_ctrl_kni_del(api_msg)))
				NES_LOG(ERR, "KNI delete failed\n");
			break;
		}
		default:
			break;
		}

		switch ((enum nes_flow_function_id) api_msg->function_id) {
		case eNesAddFlow: {
			if (NULL == (*response = nes_ctrl_flow_add(api_msg)))
				NES_LOG(ERR, "Add flow failed\n");
			break;
		}
		case eNesShowFlow: {
			if (NULL == (*response = nes_ctrl_flow_show(api_msg)))
				NES_LOG(ERR, "Show flow failed\n");
			break;
		}
		case eNesDelFlow: {
			if (NULL == (*response = nes_ctrl_flow_del(api_msg)))
				NES_LOG(ERR, "Del flow failed\n");
			break;
		}
		case eNesAddRouteData: {
			if (NULL == (*response = nes_ctrl_routing_data_add(api_msg)))
				NES_LOG(ERR, "Route data add failed\n");
			break;
		}
		case eNesDelRouteData: {
			if (NULL == (*response = nes_ctrl_routing_data_del(api_msg)))
				NES_LOG(ERR, "Route data del failed\n");
			break;
		}
		case eNesShowRouteData: {
			if (NULL == (*response = nes_ctrl_routing_data_show(api_msg)))
				NES_LOG(ERR, "Route data show failed\n");
			break;
		}
		case eNesShowEncap: {
			if (NULL == (*response = nes_ctrl_encap_show(api_msg)))
				NES_LOG(ERR, "Encap show failed\n");
			break;
		}
		default:
			break;
		}
	}
	if (NULL != *response)
		return ((*response)->data_size + sizeof(nes_api_msg_t));

	return -1;
}

static int analyze_buffer(struct server_buffer_s *client)
{
	nes_api_msg_t *msg = (nes_api_msg_t *)client->buffer;
	nes_api_msg_t *response;
	char *buf_ptr;
	int ret_val = 0;
	int resp_size;

	while (client->buf_count) {
		if (msg->data_size <= client->buf_count - sizeof(nes_api_msg_t)) {
			uint16_t data_len = sizeof(nes_api_msg_t) + msg->data_size;
			client->buf_count -= data_len;
			resp_size = nes_handle_msg((nes_api_msg_t*)client->buffer, &response);
			if (0 < resp_size) {
				buf_ptr = (char*)response;
				while (resp_size) {
					ret_val = write(client->fd, buf_ptr, resp_size);
					if (0 > ret_val) {
						NES_LOG(ERR, "Error writing to socket!\n");
						break;
					} else {
						buf_ptr += ret_val;
						resp_size -= ret_val;
					}
				}
				rte_free(response);
				if (client->buf_count) {
					/* in this case we need to copy byte by byte,
					not the whole block as rte_memcpy does */
					memcpy(client->buffer, &client->buffer[data_len],
						client->buf_count);
				}
			} else {
				client->buf_count = 0;
				break;
			}
		} else
			break;
	}
	return NES_SUCCESS;
}

int nes_ctrl_main(__attribute__((unused))void *arg)
{
	int ret_val = 0;
	int epoll_fd = -1;
	int n, i;
	struct epoll_event event;
	struct epoll_event *events = NULL;

	struct nes_lookup_params_s lookup_table_params = {
		.name = "server_lookup_table",
		.number_of_entries = MAX_CTX_PER_SERVICE,
		.key_len = sizeof(int),
		.entry_len = sizeof(struct server_buffer_s)
	};
	char *buffer = rte_zmalloc(NULL, MAX_BUFFER_SIZE, 0);
	VERIFY_PTR_OR_RET(buffer, NES_FAIL);

	NES_LOG(INFO, "Starting nes_ctrl_main\n");

	if (NES_FAIL == nes_ctrl_init()) {
		NES_LOG(ERR, "Could not initialize ctrl.\n");
		return NES_FAIL;
	}

	ret_val = set_sock_non_blocking(conn.listen_sock);
	if (NES_SUCCESS != ret_val) {
		NES_LOG(ERR, "set_sock_non_blocking(listen_sock) error\n");
		return NES_FAIL;
	}

	epoll_fd = epoll_create1(0);
	if (-1 == epoll_fd) {
		NES_LOG(ERR, "epoll_create() error\n");
		return NES_FAIL;
	}

	event.data.fd = conn.listen_sock;
	event.events = EPOLLIN | EPOLLET;
	ret_val = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn.listen_sock, &event);
	if (-1 == ret_val) {
		NES_LOG(ERR, "epoll_ctl error\n");
		return NES_FAIL;
	}

	events = rte_zmalloc(NULL, MAXEVENTS * sizeof event, 0);
	if (NULL == events) {
		NES_LOG(ERR, "events allocation error\n");
		return NES_FAIL;
	}

	nes_lookup_table_t *server_table =
		rte_malloc("NES CTRL server lookup table", sizeof(nes_lookup_table_t), 0);
	if (NULL == server_table) {
		NES_LOG(ERR, "Unable to allocate memory for nes ctrl lookup table.\n");
		return NES_FAIL;
	}
	if (NES_SUCCESS != nes_lookup_ctor(server_table, &lookup_table_params)) {
		NES_LOG(ERR, "Unable to create nes ctrl server lookup table.\n");
		rte_free(server_table);
		return NES_FAIL;
	}

	rte_atomic32_add(&threads_started, THREAD_NES_CTRL_ID);
	for (NES_FOREVER_LOOP) {
		n = epoll_wait (epoll_fd, events, MAXEVENTS, -1);
		for (i = 0; i < n; ++i) {
			if (conn.listen_sock == events[i].data.fd) {
				/*
				 * We have a notification on the listening socket,
				 * which means one or more incoming connections.
				 */
				for (;;) {
					struct sockaddr in_addr;
					socklen_t in_len = sizeof(struct in_addr);
					int infd;
					char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

					infd = accept(conn.listen_sock, &in_addr, &in_len);
					if (-1 == infd) {
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
							/* We have processed all incoming
							   connections. */
							break;
						} else {
							NES_LOG(ERR, "accept() error: %s\n",
								strerror(errno));
							break;
						}
					}
					ret_val = getnameinfo(&in_addr, in_len,
						hbuf, sizeof(hbuf),
						sbuf, sizeof(sbuf),
						NI_NAMEREQD | NI_NUMERICHOST);
					if (0 == ret_val) {
						NES_LOG(INFO,
							"Accepted connection on descriptor %d" \
							" (host=%s, port=%s)\n",
							infd, hbuf, sbuf);
					} else if (strlen(conn.local_un_addr.sun_path)) {
						NES_LOG(INFO, "Accepted connection" \
							" on descriptor %d (%s)\n",
							infd, conn.local_un_addr.sun_path);
					}
					/* Make the incoming socket non-blocking and add it to the
					   list of fds to monitor. */
					ret_val = set_sock_non_blocking(infd);
					if (-1 == ret_val) {
						NES_LOG(ERR, "set_sock_non_blocking() error\n");
						close(infd);
						break;
					}

					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					ret_val = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, infd, &event);
					if (-1 == ret_val) {
						NES_LOG(ERR, "set_sock_non_blocking() error\n");
						close(infd);
						break;
					}
					struct server_buffer_s *client_buf_ptr;
					if (NES_FAIL == nes_lookup_entry_get(server_table, &infd,
							(void**)&client_buf_ptr)) {
						NES_LOG(ERR, "unable to add client fd" \
							" to lookup table\nDisconnecting\n");
						close(infd);
						break;
					}
					memset(client_buf_ptr, 0, sizeof(struct server_buffer_s));
					client_buf_ptr->fd = infd;
				}
			} else if ((events[i].events & EPOLLIN)) {
				/* We have data on the fd waiting to be read.
				 * Read and display it.
				 * We must read whatever data is available completely,
				 * as we are running in edge-triggered mode
				 * and won't get a notification again for the same data. */
				int disconnect = 0;
				struct server_buffer_s *client_buf_ptr;
				if (unlikely(NES_FAIL == nes_lookup_entry_find(server_table,
						&events[i].data.fd, (void**)&client_buf_ptr))) {
					if (NES_SUCCESS == nes_lookup_entry_get(server_table,
							&events[i].data.fd,
							(void**)&client_buf_ptr)) {
						memset(client_buf_ptr, 0,
							sizeof(struct server_buffer_s));
						client_buf_ptr->fd = events[i].data.fd;
					} else {
						NES_LOG(ERR, "unable to add client fd" \
							" to lookup table\nDisconnecting\n");
						close(events[i].data.fd);
						continue;
					}
				}
				uint16_t room_size = MAX_BUFFER_SIZE - client_buf_ptr->buf_count;
				ret_val = read(events[i].data.fd,
					&client_buf_ptr->buffer[client_buf_ptr->buf_count],
					room_size);
				if (-1 == ret_val) {
					/* If errno == EAGAIN, that means we have read all
					   data. So go back to the main loop. */
					if (EAGAIN != errno) {
						NES_LOG(ERR, "read error\n");
						disconnect = 1;
					}
				} else if (0 == ret_val || room_size == ret_val)
					disconnect = 1;
				else
					client_buf_ptr->buf_count += ret_val;

				if (disconnect) {
					NES_LOG(INFO, "Client disconnected, sock_fd: %d\n",
						events[i].data.fd);
					if (NES_SUCCESS == nes_lookup_entry_find(server_table,
							&events[i].data.fd,
							(void**)&client_buf_ptr)) {
						nes_lookup_entry_del(server_table,
							&events[i].data.fd);
					}
					/* Closing the descriptor will make epoll remove it
					from the set of descriptors which are monitored. */
					close(events[i].data.fd);
					continue;
				}
				analyze_buffer(client_buf_ptr);
			} else if ((events[i].events & EPOLLERR) ||
					(events[i].events & EPOLLHUP) ||
					(!(events[i].events & EPOLLIN))) {
				/* An error has occured on this fd,
				 * or the socket is not ready for reading
				 * (why were we notified then?)
				 */
				NES_LOG(ERR, "epoll error\n");
				close (events[i].data.fd);
			}
		}
	}
	nes_lookup_dtor(server_table);
	rte_free(server_table);
	return NES_SUCCESS;
}
