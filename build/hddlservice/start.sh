#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

sudo rm -f /dev/shm/hddl_*
source /opt/intel/hddl/bin/setupvars.sh
cd /opt/intel/hddl/deployment_tools/inference_engine/external/hddl/bin
./hddldaemon & /hddllog -syslog="$LOCAL_SYSLOG"
