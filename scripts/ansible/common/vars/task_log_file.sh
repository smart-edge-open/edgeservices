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

# Enable logging of screen output (Ansible scripts) to files in given folder.
# Logs will be saved to folder: <appliance-ce_repository/scripts/ansible/logs/

currdir=${PWD##*/} 

if [ -z "$1" ]
then
    BASE_PATH="$( cd "$(dirname "$0")" ; pwd -P )"
else
    BASE_PATH="$1"
fi

[ -d ${BASE_PATH}/../logs ] || mkdir  ${BASE_PATH}/../logs
FILENAME="`date +%Y-%m-%d_%H-%M-%S_ansible.log`"

# Comment out below export to disable console logs saving to files.
export ANSIBLE_LOG_PATH="${BASE_PATH}/../logs/${FILENAME}"
