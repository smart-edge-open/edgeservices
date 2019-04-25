############################################################################
# Copyright 2019 Intel Corporation. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############################################################################

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
