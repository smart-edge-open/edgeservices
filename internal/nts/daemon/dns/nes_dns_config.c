/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Intel Corporation
 */

/**
 * @file nes_dns_config.c
 * @brief implementation of nes_dns_config
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#include <rte_udp.h>
#include <rte_ether.h>

#include "nes_common.h"
#include "libnes_cfgfile.h"
#include "nes_dns_config.h"
#ifdef UNIT_TESTS
	#include "nes_dns_config_decl.h"
#endif

NES_STATIC int
nes_dns_ether_aton(const char *mac, struct ether_addr *ether_address) {
	int i;
	char *end;
	unsigned long data[ETHER_ADDR_LEN];

	i = 0;
	do {
		errno = 0;
		data[i] = strtoul(mac, &end, 16);
		if (errno != 0 || end == mac || (end[0] != ':' && end[0] != 0))
			return NES_FAIL;
		mac = end + 1;
	} while (++i != sizeof (data) / sizeof (data[0]) && end[0] != 0);

	if (end[0] != 0)
		return NES_FAIL;

	/* format XX:XX:XX:XX:XX:XX */
	if (i == ETHER_ADDR_LEN) {
		while (i-- != 0) {
			if (data[i] > UINT8_MAX)
				return NES_FAIL;
			ether_address->addr_bytes[i] = (uint8_t) data[i];
		}
		return NES_SUCCESS;
	}
	return NES_FAIL;
}

int
nes_dns_mac_from_cfg(const char *mac_entry, struct ether_addr *mac) {
	const char *buffer;

	if (NES_SUCCESS != nes_cfgfile_entry(DNS_AGENT_SECTION, mac_entry, &buffer)) {
		NES_LOG(ERR, "Missing: entry %s, in config file.\n", mac_entry);
		return NES_FAIL;
	}

	return nes_dns_ether_aton(buffer, mac);
}

int
nes_dns_ip_from_cfg(const char *ip_entry, uint32_t *ip) {
	struct in_addr retval;
	const char *buffer;

	if (NES_SUCCESS != nes_cfgfile_entry(DNS_AGENT_SECTION, ip_entry, &buffer)) {
		NES_LOG(ERR, "Missing: entry %s, in config file.\n", ip_entry);
		return NES_FAIL;
	}

	if (0 == inet_aton(buffer, &retval)) {
		NES_LOG(ERR, "Invalid IP address in section %s in config file.\n", buffer);
		return NES_FAIL;
	}

	*ip = retval.s_addr;

	return NES_SUCCESS;
}

int
nes_dns_check_forward_unresolved(const char *forward_unresolved_entry, uint8_t *forward) {
	const char *buffer;
	*forward = DNS_FORWARD_OFF;
	if (NES_SUCCESS != nes_cfgfile_entry(DNS_AGENT_SECTION,
			forward_unresolved_entry, &buffer)) {
		NES_LOG(ERR, "Missing: entry %s, in config file.\n", forward_unresolved_entry);
		return NES_FAIL;
	}

	if (strncmp("y", buffer, 1) == 0)
		*forward = DNS_FORWARD_ON;

	return NES_SUCCESS;
}

int
nes_dns_tap_create(const char* name, struct ether_addr *mac_addr, uint32_t *ip_addr,
	uint8_t non_block) {
	struct ifreq ifr;
	struct sockaddr_in tap_addr;
	int fd, s, ret;

	if (NULL == name) {
		NES_LOG(ERR, "Empty TAP device name\n");
		return -1;
	}

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		NES_LOG(ERR, "Failed to open TAP device(%s) %s\n", name, strerror(errno));
		return fd;
	}

	memset(&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

	if ((ret = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		NES_LOG(ERR, "Failed to create TAP device(%s) queue %s\n", name, strerror(errno));
		close(fd);
		return ret;
	}

	if ((ret = fcntl(fd, F_GETFL, 0)) < 0) {
		NES_LOG(ERR, "Failed to get status flags: %s\n", strerror(errno));
		close(fd);
		return ret;
	}

	// Set non blocking operations
	if (non_block) {
		if ((ret = fcntl(fd, F_SETFL, ret | O_NONBLOCK)) < 0) {
			NES_LOG(ERR, "Failed to set O_NONBLOCK flag: %s\n", strerror(errno));
			close(fd);
			return ret;
		}
	}

	if (mac_addr) {
		memcpy(&ifr.ifr_hwaddr.sa_data, mac_addr, sizeof (struct ether_addr));
		ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
		if ((ret = ioctl(fd, SIOCSIFHWADDR, (void *) &ifr)) < 0) {
			NES_LOG(ERR, "Failed to set TAP device(%s) mac %s\n",
				name, strerror(errno));
			close(fd);
			return ret;
		}
	}

	if (ip_addr) {

		memset(&tap_addr, 0, sizeof (struct sockaddr));
		tap_addr.sin_family = AF_INET;
		tap_addr.sin_addr.s_addr = *ip_addr;
		ifr.ifr_addr = *(struct sockaddr*) &tap_addr;
		s = socket(tap_addr.sin_family, SOCK_DGRAM, 0);

		if (-1 == s) {
			NES_LOG(ERR, "Failed to create socket for TAP device %s ip_addr: %s\n",
				name, strerror(errno));
			close(fd);
			return s;
		}

		if ((ret = ioctl(s, SIOCSIFADDR, (void *) &ifr)) < 0) {
			NES_LOG(ERR, "Failed to set TAP device(%s) ip %s\n", name, strerror(errno));
			close(fd);
			close(s);
			return ret;
		}

		tap_addr.sin_addr.s_addr = rte_cpu_to_be_32(0xFFFFFF00); // 255.255.255.0
		ifr.ifr_addr = *(struct sockaddr*) &tap_addr;
		if ((ret = ioctl(s, SIOCSIFNETMASK, (void *) &ifr)) < 0) {
			NES_LOG(ERR, "Failed to set TAP device(%s) netmask %s\n",
				name, strerror(errno));
			close(fd);
			close(s);
			return ret;
		}
		ioctl(fd, SIOCGIFFLAGS, (void *) &ifr);
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if ((ret = ioctl(s, SIOCSIFFLAGS, (void *) &ifr)) < 0) {
			NES_LOG(ERR, "Failed to turn on TAP device(%s) ip %s\n",
				name, strerror(errno));
			close(fd);
			close(s);
			return ret;
		}
		NES_LOG(INFO, "TAP device(%s) ip %s is up\n", name,
			inet_ntoa(*(struct in_addr*)ip_addr));
		close(s);
	}

	return fd;
}
