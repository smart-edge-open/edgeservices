#!/usr/bin/env bash

# Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved.
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

ctrl_cert_path="/host_certs/controller-root-ca.pem"
ctrl_dest_path="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"

check_if_cert_added() {
    python - << END
import sys
bundle = open('${ctrl_dest_path}').read()
ctrl_cert = open('${ctrl_cert_path}').read()
if not ctrl_cert in bundle:
	sys.exit(1)
END

    return $?
}

if [ -f "${ctrl_cert_path}" ]; then
    if ! check_if_cert_added; then
        cat "${ctrl_cert_path}" >> "${ctrl_dest_path}"
    fi
else
    msg="Controller's Root CA not found. Put it into: /etc/pki/tls/certs/controller-root-ca.pem"
    echo "${msg}"
    logger \
        --server syslog.community.appliance.mec \
        --tag "${BASENAME}" \
        "${msg}"
fi

HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= exec ./appliance

