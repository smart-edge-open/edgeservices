#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation


NTS_SOCKET0_MEM="${NTS_SOCKET0_MEM:-2048}"
NTS_SOCKET1_MEM="${NTS_SOCKET1_MEM:-2048}"
sigterm_handler() {
    if [ "${kni_pid}" -ne 0 ]; then
        kill -SIGTERM "${kni_pid}"
        wait "${kni_pid}"
    fi

    if [ "${nts_pid}" -ne 0 ]; then
        kill -SIGTERM "${nts_pid}"
        wait "${nts_pid}"
    fi


    exit 143
}

trap 'sigterm_handler' SIGTERM

umask 002
exec ./nes-daemon \
    -n 4 \
    --lcores='(0,3,4,5)@0,1@2,2@3' \
    --huge-dir /hugepages \
    --file-prefix=vhost-1 \
    --socket-mem ${NTS_SOCKET0_MEM},${NTS_SOCKET1_MEM} \
    -- \
    /var/lib/appliance/nts/nts.cfg &
nts_pid="$!"

exec ./kni_docker_daemon.py \
    --library ./libnes_api_shared.so \
    --config /var/lib/appliance/nts/nts.cfg &
kni_pid="$!"

exec ./ovs_docker_daemon.py \
    --bridge "${OVS_BRIDGE_NAME}" \
    --enable "${OVS_ENABLED}" &
ovs_pid="$!"

wait $nts_pid

