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
