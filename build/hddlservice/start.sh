#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

source /opt/intel/openvino/bin/setupvars.sh
${HDDL_INSTALL_DIR}/bin/hddldaemon & ./hddllog -syslog=$LOCAL_SYSLOG
