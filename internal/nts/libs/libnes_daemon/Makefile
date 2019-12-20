# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

RTE_OUTPUT = $(NES_ROOT_DIR)/build

# binary name
LIB = libnes_daemon.a

# all source are stored in SRCS-y
SRCS-y := libnes_daemon.c

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)
CFLAGS += -I$(NES_ROOT_DIR)/nes

CFLAGS += $(SEC_CFLAGS)
LDFLAGS += $(SEC_LDFLAGS)
include $(RTE_SDK)/mk/rte.extlib.mk
