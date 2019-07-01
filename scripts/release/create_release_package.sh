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

# IMPORTANT !!!
# BEFORE RUNNING THIS SCRIPT...
# Modify your /${HOME}/.netrc to access SE log private github.com repositories
# Otherwise, script will ask you many times to pass your credentials

# Example .netrc file:
# machine github.com
# username <your_github_username>
# password <token_generated_on_github_not_your_github_password>

# DO NOT MODIFY
download_dir="downloaded_components"
root_dir="$(pwd)"
go_cached_modules_path="$root_dir/go_modules_cache"
rm -rf $download_dir
go_filename='go1.12.4.linux-amd64.tar.gz'
go_web_link="https://dl.google.com/go/$go_filename"
[[ -d $download_dir ]] || mkdir $download_dir
[[ -d $root_dir/release_packages ]] || mkdir $root_dir/release_packages

# CHANGE VALUES HERE
release_package_name='openness_release_package.tgz'

#################################################
# CLONE REPOSITORIES
#################################################

# edgenode
git clone -b master https://github.com/smartedgemec/appliance-ce.git "$download_dir/edgenode"

# edgeapps - a subset of edgenode (appliace-ce repo)
mkdir "$download_dir/edgeapps"
mkdir -p "$download_dir/edgeapps/scripts/ansible/examples"
cp -r "$download_dir/edgenode/scripts/ansible/examples/setup_baidu_openedge" "$download_dir/edgeapps/scripts/ansible/examples/"
cp "$download_dir/edgenode/LICENSE" "$download_dir/edgeapps/"
mkdir "$download_dir/edgeapps/build"
cp -r "$download_dir/edgenode/build/openvino" "$download_dir/edgeapps/build/"

# edgecontroller
git clone -b master https://github.com/smartedgemec/controller-ce.git "$download_dir/edgecontroller"

# doc
git clone -b master https://github.com/smartedgemec/doc.git "$download_dir/spec"

# epcforedge
git clone -b master https://github.com/smartedgemec/epc-oam.git "$download_dir/epcforedge"

# common
git clone -b master https://github.com/smartedgemec/log.git "$download_dir/common"

#################################################
# REMOVE UNWANTED FOLDERS/FILES FROM EACH REPO
#################################################

# Remove .git subfolders from each repo
for dir in $(ls -1 $download_dir); do
  rm -rf "$download_dir/$dir/.git"
done

# Remove folder we do not want to have in output release package
rm -rf "$download_dir/edgenode/scripts/release"

rm -rf "$download_dir/edgenode/scripts/ansible/examples/setup_baidu_openedge"
rm -rf "$download_dir/edgenode/build/openvino"

#################################################
# CUSTOMIZATIONS FOR EACH DOWNLOADED REPO
#################################################

sed -i '/RUN apk add git/a RUN tar xf cached-modules.tgz -C \/go\/' downloaded_components/edgecontroller/docker/build/Dockerfile

#################################################
# DOWNLOAD GO LANG TO LOCAL SUBFOLDER
#################################################
if ! [[ -d ./go ]]; then
  mkdir go
  wget -c $go_web_link -O - | tar -xz
fi


#################################################
# GET AND PACK MODULES FROM PRIVATE REPOS
#################################################

# Download packages using locally downloaded go lang binary
export GOPATH=${go_cached_modules_path}
export PATH=$root_dir/go/bin:$PATH
export GOROOT=$root_dir/go
( GOPATH=${go_cached_modules_path} go get github.com/smartedgemec/log )

# Store them in a .tgz package (to be decompressed in extract script)
[[ -f $go_cached_modules_path/cached-modules.tgz ]] && rm -f $go_cached_modules_path/cached-modules.tgz
(cd $go_cached_modules_path && tar cvfz cached-modules.tgz pkg/mod/cache/download/github.com/smartedgemec )
# Move file to log repo (common folder on disk)
mv $go_cached_modules_path/cached-modules.tgz $root_dir/$download_dir/edgecontroller/

#################################################
# CREATE OUTPUT RELEASE PACKAGE (+cached go mods)
#################################################

[[ -f "../release_packages/$release_package_name" ]] && rm -rf ../release_packages/$release_package_name
(cd "$download_dir" && tar cfz ../release_packages/$release_package_name * )
echo -e "\nRelease package created: $release_package_name"
