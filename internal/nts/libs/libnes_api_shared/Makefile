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
VPATH = $(NES_ROOT_DIR)/libs
# binary name
SHARED = libnes_api_shared.so


CFLAGS += -DLIB_NES_SHARED
CFLAGS += -DLIBNES_API
# all source are stored in SRCS-y
SRCS-y := libnes_api/libnes_api.c
SRCS-y += libnes_sq/libnes_sq.c

CFLAGS += -O3

CFLAGS += $(WERROR_FLAGS)
CFLAGS += $(ASSERT_FLAG)
CFLAGS += -I$(NES_ROOT_DIR)/daemon
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_api
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_sq
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_lookup
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_acl
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_queue
CFLAGS += -I$(NES_ROOT_DIR)/libs/libnes_cfgfile

CFLAGS += $(SEC_CFLAGS)
LDFLAGS += $(SEC_LDFLAGS)
include $(RTE_SDK)/mk/rte.extshared.mk
