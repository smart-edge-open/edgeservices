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

set -e     # every single step failure causes script to stop immediatelly

extract_location="${HOME}/openness_release_packages"
package_name='openness_release_package.tgz'

echo -en "\nEnter location to extract packages [ ${extract_location} ]: "
read user_location

[[ "$user_location" ]] && extract_location="$user_location"

if ! [[ -f "$package_name" ]]; then
  echo "ERROR: OpenNESS release package not found. File missing in current folder: $package_name"
  exit 1
fi

if [[ -d "$extract_location" ]]; then
  echo "ERROR: Folder already exists"
  exit 1
fi

echo "Extracting package..."
mkdir -p "$extract_location"
tar xfz "$package_name" -C "$extract_location"
echo "...done"

echo "Copying offline content to user home folder"
[[ -d ${HOME}/go ]] || mkdir ${HOME}/go
tar xf $extract_location/edgecontroller/cached-modules.tgz -C ${HOME}/go/
echo "...done"
echo -e "\n SUCCESS !\nAll packages extracted successfully to: $extract_location\n"
