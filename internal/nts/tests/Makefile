# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

NES_ROOT_DIR ?= $(shell pwd)/../
export NES_ROOT_DIR

ASSERT_FLAG=-DNDEBUG
export ASSERT_FLAG

UNIT_TESTS=all
export UNIT_TESTS

CFLAGS = -O0 -g
DIRS-y += $(NES_ROOT_DIR)/libs
DIRS-y += daemon

include $(RTE_SDK)/mk/rte.extsubdir.mk
