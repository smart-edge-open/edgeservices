#!/bin/sh
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

# This script generates key using P-384 curve and certificate for it. Certificate is
# valid for 3 years and signed with CA if CA key and certificate directory is defined

echo "Generating key..."

if [ -f "$2/key.pem" ] && [ -f "$2/cert.pem" ]; then
    echo "Key and certificate pair already exist, skipping..."
    exit 0
fi

# Use openssl11 in Centos 7
if command -v openssl11 >/dev/null 2>&1; then
    alias openssl=openssl11
fi

if ! openssl version | awk '$2 ~ /(^0\.)|(^1\.(0\.|1\.0))/ { exit 1 }'; then
	echo "Not supported openssl:"
	openssl version
fi

openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt -out "$2/key.pem"

if [ -z "$3" ]; then
    echo "Generating certificate..."
    openssl req -key "$2/key.pem" -new -x509 -days 365 -out "$2/cert.pem" -subj "/CN=$1"
else
    echo "Generating certificate signing request..."
    openssl req -new -key "$2/key.pem" -out "$2/request.csr" -subj "/CN=$1"
    echo "Signing certificate with $3..."
    openssl x509 -req -in "$2/request.csr" -CA "$3/cert.pem" -CAkey "$3/key.pem" -days 365 -out "$2/cert.pem" -CAcreateserial
    cd "$2"
    ln -s root.pem "$(openssl x509 -hash -noout -in root.pem).0"
fi

chmod 644 "$2/key.pem"
