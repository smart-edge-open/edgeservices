# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

NES_ROOT_DIR ?= $(shell pwd)/../../..
export NES_ROOT_DIR

ASSERT_FLAG=-DNDEBUG
export ASSERT_FLAG

ifeq ($(NES_ROOT_DIR),)
$(error "Please define NES_ROOT_DIR environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

APP = nes-daemon-unit-tests

include $(RTE_SDK)/mk/rte.vars.mk

COVFLAGS =  -fprofile-arcs
COVFLAGS += -ftest-coverage
COVFLAGS += -DCOVERAGE_ENABLED
CFLAGS += $(COVFLAGS)

CUNIT_DIR = /usr

RTE_OUTPUT = build

CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_queue
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_sq
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_daemon
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_cfgfile
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_lookup
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_acl
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_api
CFLAGS += -I$(NES_ROOT_DIR)/daemon
CFLAGS += -I..

CFLAGS += -DNES_DAEMON
ifeq ($(UNIT_TESTS),all)
CFLAGS += -DUNIT_TESTS
endif
CFLAGS += -I$(CUNIT_DIR)/include
#CFLAGS += -DNES_LATENCY
#CFLAGS += -DMIRROR_DECAP
#CFLAGS += -DNES_DEBUG
# all source are stored in SRCS-y
NES_DAEMON_DIR=$(NES_ROOT_DIR)/daemon
VPATH += $(NES_DAEMON_DIR)/
SRCS-y := \
	test_main.c \
	nes_main.c \
	test_libnes_api.c \
	test_nes_tcp_connection.c \
	pkt_generator.c \
	test_nes_arp.c \
	test_nes_ring.c \
	test_nes_common.c \
	test_nes_configuration.c \
	test_nes_main.c \
	test_nes_dev_eth.c \
	test_nes_dev_port.c \
	test_nes_dev_vhost.c \
	test_nes_ring_lookup.c \
	test_nes_ctrl.c \
	test_nes_dns_tools.c \
	test_nes_dns_hosts.c \
	test_nes_dns_config.c \
	test_nes_dns.c \
	test_nts_edit.c \
	test_nes_mac_lookup.c \
	test_nts_lookup.c \
	test_nis_acl.c \
	test_nis_io.c \
	test_nis_routing_data.c \
	test_nis_param.c \
	test_nts_io.c \
	test_nts_acl.c \
	test_nes_io.c \
	nis/nis_io.c \
	nis/nis_param.c \
	nis/nis_routing_data.c \
	nis/nis_acl.c \
	nts/nts_io.c \
	nts/nts_edit.c \
	nts/nts_lookup.c \
	ctrl/nes_ctrl.c \
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

LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_daemon
LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_queue
LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_cfgfile
LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_lookup
LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_sq
LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_acl
LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_api
LDLIBS += -lcunit

LDFLAGS += -L$(CUNIT_DIR)/lib

#CFLAGS += -O3
CFLAGS += -g
CFLAGS += -DDSTATS
CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)

include $(RTE_SDK)/mk/rte.extapp.mk
