# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

NES_ROOT_DIR ?= $(shell pwd)/
export NES_ROOT_DIR

SEC_CFLAGS = -fstack-protector-strong -fPIC -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
SEC_CFLAGS += -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector
export SEC_CFLAGS

SEC_LDFLAGS = -z noexecstack -z relro -z now
export SEC_LDFLAGS

ASSERT_FLAG=-DNDEBUG
export ASSERT_FLAG

include $(RTE_SDK)/mk/rte.vars.mk

DIRS-y += libs
DIRS-y += daemon
DIRS-y += client

include $(RTE_SDK)/mk/rte.extsubdir.mk
