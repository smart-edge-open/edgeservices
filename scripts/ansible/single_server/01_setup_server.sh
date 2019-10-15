#!/usr/bin/env bash
#
# Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

../common/scripts/remove-proxy.sh
# check if proxy setting is enabled
proxy_enabled=$(grep ../common/vars/defaults.yml -e 'proxy_enable' | awk '{print substr($2, 1, length($2))}')
if "$proxy_enabled" == "true"; then

    http_proxy=$(grep ../common/vars/defaults.yml -e 'proxy_http:' | tr -d "\ |\'|\"" | cut -d: -f2-) 
    https_proxy=$(grep ../common/vars/defaults.yml -e 'proxy_https' | tr -d "\ |\'|\"" | cut -d: -f2-)
    ftp_proxy=$(grep ../common/vars/defaults.yml -e 'proxy_ftp' | tr -d "\ |\'|\"" | cut -d: -f2-)
    no_proxy=$(grep ../common/vars/defaults.yml -e 'proxy_noproxy' | tr -d "\ |\'|\"" | cut -d: -f2-)

    export http_proxy="$http_proxy"
    export https_proxy="$https_proxy"
    export ftp_proxy="$ftp_proxy"
    export no_proxy="$no_proxy"
    export HTTP_PROXY="$http_proxy"
    export HTTPS_PROXY="$https_proxy"
    export FTP_PROXY="$ftp_proxy"
    export NO_PROXY="$no_proxy"

    # check proxy setting for yum
    proxy=$(grep ../common/vars/defaults.yml -e 'proxy_yum' | tr -d "\ |'|\"" | cut -d: -f2- | tr -d '\n')
    if ! grep -q "$proxy" /etc/yum.conf; then
        echo "proxy="$proxy"/" >> /etc/yum.conf
    fi
fi

source ../common/scripts/ansible-precheck.sh
source ../common/vars/task_log_file.sh
ansible-playbook ./tasks/setup_server.yml -i ../common/vars/hosts --connection=local
