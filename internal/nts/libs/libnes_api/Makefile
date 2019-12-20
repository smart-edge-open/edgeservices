# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

RTE_OUTPUT = $(NES_ROOT_DIR)/build

# binary name
LIB = libnes_api.a

CFLAGS += -DLIBNES_API
# all source are stored in SRCS-y
SRCS-y := libnes_api.c
SRCS-y += $(NES_ROOT_DIR)/libs/libnes_sq/libnes_sq.c
SRCS-y += $(NES_ROOT_DIR)/libs/libnes_cfgfile/libnes_cfgfile.c

#CFLAGS += -DEXT_CTRL_SOCKET
CFLAGS += -O3
#CFLAGS += -g
CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)
CFLAGS += -I$(NES_ROOT_DIR)/daemon
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_api
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_sq
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_lookup
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_acl
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_queue
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_cfgfile

ifeq ($(UNIT_TESTS),all)
CFLAGS += -I$(NES_ROOT_DIR)/tests/daemon
CFLAGS += -DUNIT_TESTS
CFLAGS += -g
endif

CFLAGS += $(SEC_CFLAGS)
LDFLAGS += $(SEC_LDFLAGS)
include $(RTE_SDK)/mk/rte.extlib.mk
