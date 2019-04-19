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

exec /root/nes-daemon \
    -n 4 \
    --lcores='(0,3,4,5)@0,1@3,2@4' \
    --huge-dir /hugepages \
    --file-prefix=vhost-1 \
    --socket-mem 2048,2048 \
    -- \
    /root/nes.cfg &

exec /root/kni_docker_daemon.py \
    -v DEBUG \
    --library /root/libnes_api_shared.so \
    --config /root/nes.cfg
