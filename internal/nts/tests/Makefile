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
