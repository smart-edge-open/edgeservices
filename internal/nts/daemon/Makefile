# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

ifeq ($(NES_ROOT_DIR),)
$(error "Please define NES_ROOT_DIR environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

APP = nes-daemon

include $(RTE_SDK)/mk/rte.vars.mk

#COVFLAGS =  -fprofile-arcs
#COVFLAGS += -ftest-coverage
#COVFLAGS += -DCOVERAGE_ENABLED
#CFLAGS += $(COVFLAGS)

RTE_OUTPUT = $(NES_ROOT_DIR)/build

CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_queue
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_sq
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_daemon
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_cfgfile
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_lookup
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_acl
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_api
CFLAGS += -I$(NES_ROOT_DIR)/daemon

CFLAGS += -DNES_DAEMON

# all source are stored in SRCS-y

SRCS-y := \
	nis/nis_io.c \
	nis/nis_param.c \
	nis/nis_routing_data.c \
	nis/nis_acl.c \
	nts/nts_io.c \
	nts/nts_edit.c \
	nts/nts_lookup.c \
	ctrl/nes_ctrl.c \
	nes_main.c \
	nes_ring.c \
	nes_ring_lookup.c \
	ctrl/nes_tcp_connection.c \
	ctrl/nes_configuration.c \
	nts/nts_acl.c \
	nts/nts_acl_cfg.c \
	dns/nes_dns_hosts.c \
	dns/nes_dns_config.c \
	dns/nes_dns_tools.c \
	dns/nes_dns.c \
	nes_arp.c \
	nes_latency.c \
	io/nes_io.c  \
	io/nes_mac_lookup.c \
	io/nes_dev_eth.c \
	io/nes_dev_vhost.c \
	io/nes_dev_kni.c \
	io/nes_dev_port.c \
	io/nes_dev_addons.c

LDLIBS += -L$(NES_ROOT_DIR)/libs/libnes_daemon/build -lnes_daemon
LDLIBS += -L$(NES_ROOT_DIR)/libs/libnes_queue/build -lnes_queue
LDLIBS += -L$(NES_ROOT_DIR)/libs/libnes_cfgfile/build -lnes_cfgfile
LDLIBS += -L$(NES_ROOT_DIR)/libs/libnes_lookup/build -lnes_lookup
LDLIBS += -L$(NES_ROOT_DIR)/libs/libnes_sq/build -lnes_sq
LDLIBS += -L$(NES_ROOT_DIR)/libs/libnes_acl/build -lnes_acl
LDLIBS += -L$(NES_ROOT_DIR)/libs/libnes_api/build -lnes_api


CFLAGS += -O3
CFLAGS += -g
CFLAGS += -DDSTATS
CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)

CFLAGS += $(SEC_CFLAGS)
LDFLAGS += $(SEC_LDFLAGS)
include $(RTE_SDK)/mk/rte.extapp.mk
