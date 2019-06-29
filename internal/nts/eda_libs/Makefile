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

CC=gcc
MAKE=make

LIBAPI_DIR=libnes_api
LIBSQ_DIR=libnes_sq
BUILD_DIR=./build

build:
	$(MAKE) -C $(LIBAPI_DIR);
	$(MAKE) -C $(LIBSQ_DIR);
clean: 
	$(MAKE) -C $(LIBAPI_DIR) clean;
	$(MAKE) -C $(LIBSQ_DIR) clean;
	rm -rf $(BUILD_DIR)
