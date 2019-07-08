#!/usr/bin/env bash
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

# This script resolves dependencies problem with python urllib3 package.
# The most common symptom of invalid module version is when building images
# step from Ansible script "03_build_and_deploy.sh" stops unexpectedly
# and says about failing run of docker-compose command.

if rpm -qa --quiet python-urllib3 ; then
  rpm -e --nodeps python-urllib3
fi

# Remove urllib3 native pip package
pip list | grep urllib3
if [[ $? -eq 0 ]]; then
  pip uninstall urllib3 -y
fi

# Remove it again, as some files might still remain on disk from
# older versions of python-urllib3 package installed via rpm subsystem
pip list | grep urllib3
if [[ $? -eq 0 ]]; then
  pip uninstall urllib3 -y
fi

# Install correct (higher) version of urllib3 module than from yum
pip install urllib3

echo -e "\nDone.\nCorrect version of urllib3 module has been installed."
