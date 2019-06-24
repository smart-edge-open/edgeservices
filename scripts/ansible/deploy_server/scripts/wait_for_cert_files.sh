#!/usr/bin/env bash
# Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

base_path="/var/lib/appliance/certs/"
while true; do
  found=0
  [ -f ${base_path}/cacerts.pem ] && let found=$found+1
  [ -f ${base_path}/key.pem ] && let found=$found+1
  [ -f ${base_path}/cert.pem ] && let found=$found+1
  [ -f ${base_path}/root.pem ] && let found=$found+1
  [[ $found -eq 4 ]] && break
  sleep 5
done
cd ${base_path}
ln -s root.pem `openssl x509 -hash -noout -in root.pem`.0
cd -
