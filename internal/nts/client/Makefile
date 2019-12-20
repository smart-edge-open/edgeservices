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

APP = nes_client

include $(RTE_SDK)/mk/rte.vars.mk

RTE_OUTPUT = ./build

CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_api
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_sq
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_lookup
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_acl
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_queue
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_cfgfile
CFLAGS += -I$(NES_ROOT_DIR)/daemon

# all source are stored in SRCS-y
SRCS-y := \
        nes_cli.c \
        nes_client.c \
        nes_cmdline_parse_string.c

LDLIBS += -L$(NES_ROOT_DIR)/build -lnes_api


CFLAGS += -O3
CFLAGS += -g
CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)

CFLAGS += $(SEC_CFLAGS)
LDFLAGS += $(SEC_LDFLAGS)
include $(RTE_SDK)/mk/rte.extapp.mk
