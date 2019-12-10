# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

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
