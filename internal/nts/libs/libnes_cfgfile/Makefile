# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

RTE_OUTPUT = $(NES_ROOT_DIR)/build

# binary name
LIB = libnes_cfgfile.a

# all source are stored in SRCS-y
SRCS-y := libnes_cfgfile.c

ifeq ($(UNIT_TESTS),all)
CFLAGS += -DUNIT_TESTS
endif

CFLAGS += -O3
#CFLAGS += -g
CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)
CFLAGS += -I$(NES_ROOT_DIR)/daemon
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_api

CFLAGS += $(SEC_CFLAGS)
LDFLAGS += $(SEC_LDFLAGS)
include $(RTE_SDK)/mk/rte.extlib.mk
