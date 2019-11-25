#!/usr/bin/expect

# Copyright 2019 Intel Corporation. All rights reserved.
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

set timeout -1

# Some pattern that matches your prompt
set prompt ":"

spawn ./n3000-1.3.5-beta-rte-setup.sh

expect "Do you wish to install OPAE Software ? (Y/n):"
send "Y"
send "\r"

expect "Do you wish to install OPAE PACSign ? (Y/n):"
send "Y"
send "\r"

expect "Do you wish to install OPAE SDK Source ? (Y/n):"
send "Y"
send "\r"

expect "Do you wish to install OPAE Software Samples ? (Y/n):"
send "Y"
send "\r"

expect "Do you wish to install Environment Initialization ? (Y/n):"
send "Y"
send "\r"

expect "Is this ok \\\[y/d/N\\\]:" 
send "y"
send "\r"

expect "Is this ok \\\[y/N\\\]:"
send "y"
send "\r"

expect "Is this ok \\\[y/d/N\\\]:"
send "y"
send "\r"

expect "Installation done"
send " "
send "\r"

#expect $prompt
#send "Y"
#send "\r"

exit

