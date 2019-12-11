/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file libnes_api.c
 * @brief NES API library
 */

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <net/ethernet.h>

#include "nes_api_common.h"
#include "libnes_api.h"
#include "libnes_api_protocol.h"
#include "libnes_cfgfile.h"
#ifdef UNIT_TESTS
	#include "libnes_api_decl.h"
#endif

#define KNI_NAMESIZE 32

enum KNI_ACTION {
	KNI_ADD = 0,
	KNI_DEL
};

static int nes_send_api_msg(nes_remote_t *self, nes_api_msg_t *request, nes_api_msg_t **response)
{
	assert(NULL != self);
	assert(NULL != request);
	assert(NULL != response);

	nes_api_msg_t response_head = {0};
	*response = NULL;
	size_t size;
	uint8_t *buf;
	ssize_t ret;

	if (self->state != eConnected)
		return NES_FAIL;

	if (-1 == (send(self->socket_fd, request,
			sizeof(nes_api_msg_t) + request->data_size, MSG_NOSIGNAL))) {
		self->state = eDisconnected;
		return NES_FAIL;
	}

	if (-1 == (recv(self->socket_fd, &response_head, sizeof(response_head), MSG_NOSIGNAL))) {
		self->state = eDisconnected;
		return NES_FAIL;
	}

	if (eError == response_head.message_type)
		return NES_FAIL;

	*response = malloc(sizeof(nes_api_msg_t) + response_head.data_size);
	VERIFY_PTR_OR_RET(*response, NES_FAIL);
	memcpy(*response, &response_head, sizeof(response_head));

	size = (*response)->data_size;
	buf = (*response)->data;
	while (size) {
		ret = recv(self->socket_fd, buf, size, MSG_NOSIGNAL);
		if (-1 == ret || 0 == ret) {
			free(*response);
			*response = NULL;
			self->state = eDisconnected;
			return NES_FAIL;
		}
		buf += ret;
		size -= ret;
	}

	return NES_SUCCESS;
}

int nes_conn_start(nes_remote_t *self, const char *unix_sock_path)
{
	struct sockaddr_in  serverINAddr = { 0 };
	struct sockaddr_un  serverUNAddr = { 0 };
	struct sockaddr     *serverAddr;
	socklen_t           addr_size = -1;
	int                 status = 0;

	if (NULL == unix_sock_path) {
		if (NULL == self->ip_address || 0 == self->port_nr)
			return NES_FAIL;

		self->socket_fd = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		serverINAddr.sin_family = AF_INET;
		serverINAddr.sin_port = htons(self->port_nr);
		serverINAddr.sin_addr.s_addr = inet_addr(self->ip_address);
		addr_size = sizeof(serverINAddr);
		serverAddr = (struct sockaddr *)&serverINAddr;
	} else {
		strncpy(serverUNAddr.sun_path, unix_sock_path, sizeof(serverUNAddr.sun_path) - 1);
		self->socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		serverUNAddr.sun_family = AF_UNIX;
		addr_size = sizeof(serverUNAddr);
		serverAddr = (struct sockaddr *)&serverUNAddr;
	}

	if (-1 == self->socket_fd)
		return NES_FAIL;

	/* set timeout to 1 sec */
	int sock_fl = fcntl(self->socket_fd, F_GETFL, NULL);
	sock_fl |= O_NONBLOCK;
	fcntl(self->socket_fd, F_SETFL, sock_fl);

	status = connect(self->socket_fd, (struct sockaddr *)serverAddr, addr_size);
	if (0 > status) {
		if (EINPROGRESS == errno) {
			fd_set conn_fd;
			struct timeval tv;
			socklen_t socklen;
			int sockopt;
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			FD_ZERO(&conn_fd);
			FD_SET(self->socket_fd, &conn_fd);
			status = select(self->socket_fd + 1, NULL, &conn_fd, NULL, &tv);
			if (0 >= status) { /* timeout or error */
				close(self->socket_fd);
				self->state = eInvalid;
				return NES_FAIL;
			}
			socklen = sizeof(sockopt);
			status = getsockopt(self->socket_fd, SOL_SOCKET, SO_ERROR, &sockopt,
				&socklen);
			if (0 > status || 0 != sockopt) {
				close(self->socket_fd);
				self->state = eInvalid;
				return NES_FAIL;
			}
		} else {
			close(self->socket_fd);
			self->state = eInvalid;
			return NES_FAIL;
		}
	}

	sock_fl = fcntl(self->socket_fd, F_GETFL, NULL);
	sock_fl &= ~(O_NONBLOCK);
	fcntl(self->socket_fd, F_SETFL, sock_fl);

	self->state = eConnected;
	return NES_SUCCESS;
}

#ifndef LIB_NES_SHARED
#define NES_SERVER_CONF_DEFAULT_PATH "/opt/intel/nev_sdk/nes_root/scripts/nes.cfg"
int
nes_conn_init(nes_remote_t *self,  __attribute__((unused))char *ip_addr,
	__attribute__((unused))uint16_t port)
{
	static const char *nes_default_ctrl_socket = "/tmp/nes_server";
	char                *nes_conf_path = NULL;
#ifdef EXT_CTRL_SOCKET
	const char          *ctrl_ip;
	const char          *ctrl_port;
#endif
	const char          *ctrl_socket = NULL;
	static char         ip_address[INET_ADDRSTRLEN + 1];

	assert(NULL != self);
	if (eConnected == self->state)
		return NES_SUCCESS;

	self->ip_address = NULL;
	self->port_nr = 0;
	memset(ip_address, 0, sizeof(ip_address));

	nes_conf_path = getenv("NES_SERVER_CONF");
	if (NULL == nes_conf_path)
		nes_conf_path = (char*)(uintptr_t)NES_SERVER_CONF_DEFAULT_PATH;

	if (NES_SUCCESS == nes_cfgfile_load(nes_conf_path)) {
		/*
		 * if ctrl_socket param exists skip read ip and port
		 * if ctrl_socket and ctrl_ip and ctrl_port doesn't exist
		 * try ip and port from function arguments
		 */
		if (NES_FAIL == nes_cfgfile_entry("NES_SERVER", "ctrl_socket", &ctrl_socket)) {
#ifndef EXT_CTRL_SOCKET
			return NES_FAIL;
#else
			nes_cfgfile_entry("NES_SERVER", "ctrl_ip", &ctrl_ip);
			nes_cfgfile_entry("NES_SERVER", "ctrl_port", &ctrl_port);
			if (ctrl_ip && ctrl_port) {
				strncpy(ip_address, ctrl_ip, sizeof(ip_address)-1);
				self->ip_address = ip_address;
				self->port_nr = (uint16_t)atoi(ctrl_port);
			}
#endif
		}
		nes_cfgfile_close();
	}

	/* if there was no parameters read from file get them from function arguments */
	if (NULL == ctrl_socket && NULL == self->ip_address) {
		if (NULL != ip_addr) {
			self->ip_address = ip_addr;
			self->port_nr = port;
		} else
			ctrl_socket = nes_default_ctrl_socket;
	}
	return nes_conn_start(self, ctrl_socket);
}
#endif

int nes_conn_close(nes_remote_t *self)
{
	assert(NULL != self);

	if (self->state != eConnected || close(self->socket_fd) != 0)
		return NES_FAIL;

	self->state = eDisconnected;
	return NES_SUCCESS;
}

nes_sq_t *nes_stats_show_list(nes_remote_t *self)
{
	assert(NULL != self);

	if (self->state != eConnected)
		return NULL;

	nes_sq_t *device_list = NULL;
	nes_api_msg_t *api_msg;
	api_msg = malloc(sizeof(nes_api_msg_t));
	VERIFY_PTR_OR_RET(api_msg, NULL);
	nes_api_msg_t *response;
	size_t offset = 0;

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesStatsShowList;
	api_msg->data_size = 0;

	if (NES_FAIL == nes_send_api_msg(self, api_msg, &response)) {
		free(api_msg);
		return NULL;
	}

	if (eError == response->message_type) {
		free(response);
		free(api_msg);
		return NULL;
	}
	device_list = malloc(sizeof(nes_sq_t));
	if (NULL == device_list) {
		free(response);
		free(api_msg);
		return NULL;
	}
	nes_sq_ctor(device_list);
	nes_api_dev_t *new_elem;

	while (offset < (size_t)response->data_size) {
		new_elem = malloc(sizeof(nes_api_dev_t));
		if (NULL == new_elem) {
			nes_sq_dtor_free(device_list);
			free(device_list);
			free(response);
			free(api_msg);
			return NULL;
		}
		memcpy(&new_elem->index, response->data + offset, sizeof(new_elem->index));
		offset = offset + sizeof(new_elem->index);
		memcpy(new_elem->name, response->data + offset, sizeof(new_elem->name));
		offset = offset + sizeof(new_elem->name);

		nes_sq_enq(device_list, new_elem);
	}
	free(response);
	free(api_msg);
	return device_list;
}

nes_sq_t *nes_stats_all_dev(nes_remote_t *self)
{
	assert(NULL != self);

	nes_api_msg_t *api_msg;
	nes_api_msg_t *response;

	if (self->state != eConnected)
		return NULL;

	api_msg = malloc(sizeof(nes_api_msg_t));
	VERIFY_PTR_OR_RET(api_msg, NULL);

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesStatsDevAll;
	api_msg->data_size = 0;

	if (NES_FAIL == nes_send_api_msg(self, api_msg, &response)) {
		free(api_msg);
		return NULL;
	}

	if (eError == response->message_type) {
		free(response);
		free(api_msg);
		return NULL;
	}

	nes_sq_t *device_list = malloc(sizeof(nes_sq_t));
	if (NULL == device_list) {
		free(response);
		free(api_msg);
		return NULL;
	}

	nes_sq_ctor(device_list);

	nes_api_dev_t *new_elem;
	nes_api_dev_t *dev_stats = (nes_api_dev_t*)response->data;
	size_t i = response->data_size / sizeof(nes_api_dev_t);

	while (i--) {
		new_elem = malloc(sizeof(nes_api_dev_t));
		if (NULL == new_elem) {
			nes_sq_dtor_free(device_list);
			free(device_list);
			free(response);
			free(api_msg);
			return NULL;
		}
		new_elem->index = dev_stats->index;
		memcpy(new_elem->name, dev_stats->name, sizeof(new_elem->name));
		new_elem->stats = dev_stats->stats;
		new_elem->macaddr = dev_stats->macaddr;
		dev_stats++;
		nes_sq_enq(device_list, new_elem);
	}
	free(response);
	free(api_msg);
	return device_list;
}

int nes_stats_dev(nes_remote_t *self, uint16_t id, nes_dev_stats_t *stats)
{
	assert(NULL != self);

	nes_api_msg_t *api_msg;
	nes_api_msg_t *response;

	if (self->state != eConnected)
		return NES_FAIL;

	api_msg = malloc(sizeof(nes_api_msg_t) + sizeof(id));
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesStatsDev;
	api_msg->data_size = sizeof(id);
	memcpy(api_msg->data, &id, sizeof(uint16_t));

	if (NES_FAIL == nes_send_api_msg(self, api_msg, &response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == response->message_type) {
		free(response);
		free(api_msg);

		return NES_FAIL;
	}
	nes_dev_stats_t *dev_stats = (nes_dev_stats_t*)response->data;
	*stats = *dev_stats;

	free(response);
	free(api_msg);

	return NES_SUCCESS;
}

nes_sq_t *nes_stats_all_ring(nes_remote_t *self)
{
	assert(NULL != self);

	nes_api_msg_t *api_msg;
	nes_api_msg_t *response;

	if (self->state != eConnected)
		return NULL;

	api_msg = malloc(sizeof(nes_api_msg_t));
	VERIFY_PTR_OR_RET(api_msg, NULL);

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesStatsRingAll;
	api_msg->data_size = 0;

	if (NES_FAIL == nes_send_api_msg(self, api_msg, &response)) {
		free(api_msg);
		return NULL;
	}

	if (eError == response->message_type) {
		free(response);
		free(api_msg);
		return NULL;
	}

	nes_sq_t *ring_list = malloc(sizeof(nes_sq_t));
	if (NULL == ring_list) {
		free(response);
		free(api_msg);
		return NULL;
	}

	nes_sq_ctor(ring_list);

	nes_api_ring_t *new_elem;
	nes_api_ring_t *ring_stats = (nes_api_ring_t *)response->data;
	size_t i = response->data_size / sizeof(nes_api_ring_t);

	while (i--) {
		new_elem = malloc(sizeof(nes_api_ring_t));
		if (NULL == new_elem) {
			nes_sq_dtor_free(ring_list);
			free(ring_list);
			free(response);
			free(api_msg);
			return NULL;
		}
		new_elem->index = ring_stats->index;
		memcpy(new_elem->name, ring_stats->name, sizeof(new_elem->name));
		new_elem->stats = ring_stats->stats;
		ring_stats++;
		nes_sq_enq(ring_list, new_elem);
	}
	free(response);
	free(api_msg);
	return ring_list;
}

int nes_stats_ring(nes_remote_t *self, uint16_t id, nes_ring_stats_t *stats)
{
	assert(NULL != self);

	nes_api_msg_t *api_msg;
	nes_api_msg_t *response;

	if (self->state != eConnected)
		return NES_FAIL;

	api_msg = malloc(sizeof(nes_api_msg_t) + sizeof(id));
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesStatsRing;
	api_msg->data_size = sizeof(id);
	memcpy(api_msg->data, &id, sizeof(uint16_t));

	if (NES_FAIL == nes_send_api_msg(self, api_msg, &response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == response->message_type) {
		free(response);
		free(api_msg);

		return NES_FAIL;
	}
	nes_ring_stats_t *data_ptr = (nes_ring_stats_t*)response->data;
	*stats = *data_ptr;

	free(response);
	free(api_msg);

	return NES_SUCCESS;
}

int nes_clear_all_stats(nes_remote_t *self)
{
	assert(NULL != self);

	nes_api_msg_t *api_msg;
	nes_api_msg_t *api_response;
	enum NES_ERROR ret;

	if (self->state != eConnected)
		return NES_FAIL;

	api_msg = malloc(sizeof(nes_api_msg_t));
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesStatsClearAll;
	api_msg->data_size = 0;

	if (NES_SUCCESS != nes_send_api_msg(self, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof(enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(&ret, api_response->data, sizeof(enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}

#define MAC_ADDR_STR_LEN 18
int nes_dev_port_mac_addr(nes_remote_t *self, uint8_t port_id, char **mac_addr_str)
{
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == mac_addr_str || NULL == *mac_addr_str)
		return NES_FAIL;

	memset(*mac_addr_str, 0, MAC_ADDR_STR_LEN + 1);
	nes_api_msg_t *api_msg = malloc(sizeof(nes_api_msg_t) + sizeof(port_id));
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	nes_api_msg_t *api_response = NULL;

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesMacAddressGet;
	*api_msg->data = port_id;
	api_msg->data_size = sizeof(port_id);

	if (NES_SUCCESS != nes_send_api_msg(self, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}
	if (eError == api_response->message_type || ETHER_ADDR_LEN != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	struct ether_addr *mac_addr = (struct ether_addr*)api_response->data;
	if ((MAC_ADDR_STR_LEN - 1) != snprintf(*mac_addr_str, MAC_ADDR_STR_LEN,
			"%02x:%02x:%02x:%02x:%02x:%02x",
			mac_addr->ether_addr_octet[0], mac_addr->ether_addr_octet[1],
			mac_addr->ether_addr_octet[2], mac_addr->ether_addr_octet[3],
			mac_addr->ether_addr_octet[4], mac_addr->ether_addr_octet[5])) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	free(api_response);
	free(api_msg);
	return NES_SUCCESS;
}

static int
nes_route_add_impl(nes_remote_t *self, struct ether_addr vm_mac_addr, char *lookup_keys,
	uint8_t is_mirror)
{
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == lookup_keys)
		return NES_FAIL;

	struct add_route_data {
		struct ether_addr vm_mac_addr;
		char lookup[];
	} *data;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	int ret;
	uint16_t keys_len = strnlen(lookup_keys, NES_MAX_LOOKUP_ENTRY_LEN) + 1;
	uint16_t data_len = sizeof(struct add_route_data) + sizeof(char) * keys_len;

	api_msg = malloc(sizeof(nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = is_mirror ? eNesAddMirror : eNesAddRoute;
	data = (struct add_route_data*)api_msg->data;
	data->vm_mac_addr = vm_mac_addr;

	strncpy(data->lookup, lookup_keys, keys_len);
	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(self, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof(enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(&ret, api_response->data, sizeof(enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}

static int
nes_kni_modify(nes_remote_t *self, const char *dev_id_name, int kni_action, char* if_name)
{
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == dev_id_name)
		return NES_FAIL;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	uint16_t keys_len = strnlen(dev_id_name, NES_MAX_KNI_ENTRY_LEN) + 1;
	uint16_t data_len = sizeof(char) * keys_len;

	api_msg = malloc(sizeof(nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = (kni_action == KNI_DEL) ? eNesDelKni : eNesAddKni;


	strncpy((char*)api_msg->data, dev_id_name, keys_len);
	api_msg->data_size = data_len;

	if (NES_SUCCESS != nes_send_api_msg(self, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type || KNI_NAMESIZE != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(if_name, api_response->data, KNI_NAMESIZE);
	free(api_response);
	free(api_msg);
	return NES_SUCCESS;
}

int nes_kni_add(nes_remote_t *self, const char *dev_id_name, char *created_if_name)
{
	return nes_kni_modify(self, dev_id_name, KNI_ADD, created_if_name);
}

int nes_kni_del(nes_remote_t *self, const char *dev_id_name, char *deleted_if_name)
{
	return nes_kni_modify(self, dev_id_name, KNI_DEL, deleted_if_name);
}

int nes_route_add(nes_remote_t *self, struct ether_addr vm_mac_addr, char *lookup_keys,
	__attribute__((unused))int vmid)
{
	return nes_route_add_impl(self, vm_mac_addr, lookup_keys, 0);
}

int nes_route_add_mirror(nes_remote_t *self, struct ether_addr vm_mac_addr, char *lookup_keys,
	__attribute__((unused))int vmid)
{
	return nes_route_add_impl(self, vm_mac_addr, lookup_keys, 1);
}

int nes_route_show(nes_remote_t *self, char *lookup_keys, nes_sq_t *upstream_route,
	nes_sq_t *downstream_route)
{
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == lookup_keys || NULL == upstream_route || NULL == downstream_route)
		return NES_FAIL;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	int upstream_routes_cnt, downstream_routes_cnt;
	uint16_t i, cnt_len;
	uint16_t data_len = strnlen(lookup_keys, NES_MAX_LOOKUP_ENTRY_LEN) + 1;

	api_msg = malloc(sizeof(nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesShowRoute;
	api_msg->data_size = data_len;
	memcpy(api_msg->data, lookup_keys, data_len);

	if (NES_SUCCESS != nes_send_api_msg(self, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	// data format: int upstream_routes count,int downstream_routes count,
	// nes_route_entry_data_t[] routes
	if (api_response->data_size <=
			sizeof(upstream_routes_cnt) + sizeof(downstream_routes_cnt)) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}

	memcpy(&upstream_routes_cnt, api_response->data, sizeof(upstream_routes_cnt));
	memcpy(&downstream_routes_cnt, api_response->data + sizeof(upstream_routes_cnt),
		sizeof(downstream_routes_cnt));
	cnt_len = sizeof(upstream_routes_cnt) + sizeof(downstream_routes_cnt);
	data_len = (upstream_routes_cnt + downstream_routes_cnt) *
		sizeof(nes_route_entry_data_t) + cnt_len;
	if (eError == api_response->message_type || data_len != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}

	for (i = 0; i < upstream_routes_cnt + downstream_routes_cnt; i++) {
		nes_route_entry_data_t* route = malloc(sizeof(nes_route_entry_data_t));
		if (NULL == route) {
			nes_sq_dtor_free(upstream_route);
			nes_sq_dtor_free(downstream_route);
			free(api_response);
			free(api_msg);
			return NES_FAIL;
		}
		memcpy(route, api_response->data + cnt_len + sizeof(nes_route_entry_data_t) * i,
			sizeof(nes_route_entry_data_t));
		if (i < upstream_routes_cnt)
			nes_sq_enq(upstream_route, route);
		else
			nes_sq_enq(downstream_route, route);
	}

	free(api_response);
	free(api_msg);
	return NES_SUCCESS;
}

int nes_route_list(nes_remote_t *self, uint16_t entry_offset, uint16_t max_entry_cnt,
	nes_route_data_t** routes, uint16_t *route_cnt)
{
	assert(NULL != self);

	nes_api_msg_t *api_msg;
	nes_api_msg_t *response;
	nes_route_list_req_t req = {
		.entry_offset = entry_offset,
		.max_entry_cnt = max_entry_cnt
	};

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == route_cnt || NULL == routes)
		return NES_FAIL;

	if (max_entry_cnt > ROUTES_LIST_MAX_CNT)
		return NES_FAIL;

	api_msg = malloc(sizeof(nes_api_msg_t) + sizeof(req));
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesRouteList;
	api_msg->data_size = sizeof(req);
	memcpy(api_msg->data, &req, sizeof(req));

	if (NES_FAIL == nes_send_api_msg(self, api_msg, &response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == response->message_type) {
		free(response);
		free(api_msg);
		return NES_FAIL;
	}

	*route_cnt = response->data_size / sizeof(nes_route_data_t);
	// No routes
	if (0 == *route_cnt) {
		*routes = NULL;
		free(response);
		free(api_msg);
		return NES_SUCCESS;
	}

	*routes = malloc(response->data_size);
	if (NULL == routes) {
		free(response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(*routes, response->data, response->data_size);
	free(response);
	free(api_msg);
	return NES_SUCCESS;
}
int nes_route_show_mirror(nes_remote_t *self, char *lookup_keys, nes_sq_t *upstream_route,
	nes_sq_t *downstream_route)
{
	return nes_route_show(self, lookup_keys, upstream_route, downstream_route);
}

int nes_route_remove(nes_remote_t *self, char *lookup_keys)
{
	assert(self);

	if (self->state != eConnected)
		return NES_FAIL;

	if (NULL == lookup_keys)
		return NES_FAIL;

	nes_api_msg_t *api_msg = NULL;
	nes_api_msg_t *api_response = NULL;
	uint16_t data_len = strnlen(lookup_keys, NES_MAX_LOOKUP_ENTRY_LEN) + 1;
	enum NES_ERROR ret;

	api_msg = malloc(sizeof(nes_api_msg_t) + data_len);
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);
	api_msg->message_type = eRequest;
	api_msg->function_id = eNesDelRoute;
	api_msg->data_size = data_len;
	memcpy(api_msg->data, lookup_keys, data_len);

	if (NES_SUCCESS != nes_send_api_msg(self, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof(enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}

	memcpy(&ret, api_response->data, sizeof(enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}

int nes_route_remove_mirror(nes_remote_t *self, char *lookup_keys)
{
	return nes_route_remove(self, lookup_keys);
}

int
nes_route_clear_all(nes_remote_t *self)
{
	assert(NULL != self);

	nes_api_msg_t *api_msg;
	nes_api_msg_t *api_response;
	enum NES_ERROR ret;

	if (self->state != eConnected)
		return NES_FAIL;

	api_msg = malloc(sizeof(nes_api_msg_t));
	VERIFY_PTR_OR_RET(api_msg, NES_FAIL);

	api_msg->message_type = eRequest;
	api_msg->function_id = eNesRouteClearAll;
	api_msg->data_size = 0;

	if (NES_SUCCESS != nes_send_api_msg(self, api_msg, &api_response)) {
		free(api_msg);
		return NES_FAIL;
	}

	if (eError == api_response->message_type ||
			sizeof(enum NES_ERROR) != api_response->data_size) {
		free(api_response);
		free(api_msg);
		return NES_FAIL;
	}
	memcpy(&ret, api_response->data, sizeof(enum NES_ERROR));
	free(api_response);
	free(api_msg);
	return ret;
}
