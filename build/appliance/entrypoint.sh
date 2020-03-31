#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

ctrl_cert_path="/host_certs/controller-root-ca.pem"
ctrl_dest_path="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"

check_if_cert_added() {
    python3 - << END
import sys
bundle = open('${ctrl_dest_path}', 'rb').read()
ctrl_cert = open('${ctrl_cert_path}', 'rb').read()
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
        --server ${SYSLOG_ADDR} \
        --tag "${BASENAME}" \
        "${msg}"
fi

HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= exec ./appliance

