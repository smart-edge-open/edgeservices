#!/bin/sh
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

# This script generates key using P-384 curve and certificate for it. Certificate is
# valid for 3 years and signed with CA if CA key and certificate directory is defined

mkdir /root/ca && cp "$3/"* /root/ca/ && cp "$3/cert.pem" "$2/root.pem" && /root/certgen/tls_pair.sh "$1" "$2" /root/ca
