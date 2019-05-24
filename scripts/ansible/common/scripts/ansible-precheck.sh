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
#
#
#
# This script checks whether Ansible rpm package is installed and installs it
# from EPEL Centos repository if missing (EPEL repo is added automatically).
#
# Script shall be sourced before running any Ansible playbook only if
# we are not sure whether Ansible had already been installed on local
# machine or had not.
#
# Script is aimed for yum package management distributions  distributions, like
# CentOS/Fedora/RedHat.

id -u 1>/dev/null
if [[ $? -ne 0 ]]; then
  echo "ERROR: Script requires root permissions"
  exit 1
fi

if [ ${0##*/} == ${BASH_SOURCE[0]##*/} ]; then
    echo "ERROR: This script cannot be executed directly"
    exit 1
fi

command -v ansible-playbook 1>/dev/null
if [[ $? -ne 0 ]]; then
  echo "Ansible not installed..."
  rpm -qa | grep -q ^epel-release
  if [[ $? -ne 0 ]]; then
    echo "EPEL repository not present in system, adding EPEL repository..."
    yum -y install epel-release
    if [[ $? -ne 0 ]]; then
      echo "ERROR: Could not add EPEL repository. Check above for possible root cause"
      exit 1
    fi
  fi
  echo "Installing ansible..."
  yum -y install ansible
  if [[ $? -ne 0 ]]; then
    echo "ERROR: Could not install Ansible package from EPEL repository"
    exit 1
  fi
  echo "Ansible successfully instaled"
fi
