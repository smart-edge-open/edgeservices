#!/bin/bash

source /opt/intel/openvino/bin/setupvars.sh
${HDDL_INSTALL_DIR}/bin/hddldaemon & ./hddllog -syslog=$LOCAL_SYSLOG
