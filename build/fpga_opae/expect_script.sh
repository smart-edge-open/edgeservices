#!/usr/bin/expect

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

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

