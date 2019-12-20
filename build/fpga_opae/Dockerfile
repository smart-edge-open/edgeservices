# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

FROM centos:7.6.1810

WORKDIR /root/opae

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy

RUN yum install -y gcc gcc-c++ cmake make autoconf automake libxml2 libxml2-devel json-c-devel boost ncurses ncurses-devel ncurses-libs boost-devel libuuid libuuid-devel python2-jsonschema doxygen hwloc-devel libpng12 rsync openssl-devel bc python-devel python-libs python-sphinx openssl unzip which wget python36 epel-release sudo

#Install Kernel headers
RUN yum install -y "http://linuxsoft.cern.ch/centos-vault/7.6.1810/os/x86_64/Packages/kernel-devel-3.10.0-957.el7.x86_64.rpm"
RUN mkdir -p /lib/modules/$(uname -r)
RUN ln -s /usr/src/kernels/$(uname -r) /lib/modules/$(uname -r)/build

#copy packages
COPY n3000-1-3-5-beta-rte-setup.zip .
COPY n3000-1-3-5-beta-cfg-2x2x25g-setup.zip .

#unzip packages
RUN unzip n3000-1-3-5-beta-rte-setup.zip
RUN unzip n3000-1-3-5-beta-cfg-2x2x25g-setup.zip

#make scripts executable
RUN chmod +x n3000-1.3.5-beta-rte-setup.sh
RUN chmod +x n3000-1.3.5-beta-cfg-2x2x25G-setup.sh

#install and copy expect
RUN yum install -y expect-5.45-14.el7_1.x86_64
COPY expect_script.sh .

#install OPAE packages
RUN ./expect_script.sh
RUN source /root/intelrtestack/bin/init_env.sh

#install PAC N3000 configuration
RUN ./n3000-1.3.5-beta-cfg-*-setup.sh -y

#install pip and intelhex
RUN easy_install pip && pip install intelhex

#create non-root user
ARG username=fpga_opae
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

#copy module checking script
COPY check_if_modules_loaded.sh .
