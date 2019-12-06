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
    --lcores='(0,3,4,5)@0,1@3,2@4' \
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
    --bridge ${OVS_BRIDGE_NAME} \
    --enable ${OVS_ENABLED} &
ovs_pid="$!"

wait $nts_pid

