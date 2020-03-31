# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

FROM centos:7.6.1810

WORKDIR /root/opae

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy

RUN yum install -y gcc gcc-c++ cmake make autoconf automake libxml2 libxml2-devel json-c-devel boost ncurses ncurses-devel ncurses-libs boost-devel libuuid libuuid-devel python2-jsonschema doxygen hwloc-devel libpng12 rsync openssl-devel bc python-devel python-libs python-sphinx openssl unzip which wget python36 epel-release sudo
RUN easy_install pip && pip install intelhex

# RT repo
RUN wget http://linuxsoft.cern.ch/cern/centos/7/rt/CentOS-RT.repo -O /etc/yum.repos.d/CentOS-RT.repo
RUN wget http://linuxsoft.cern.ch/cern/centos/7/os/x86_64/RPM-GPG-KEY-cern -O /etc/pki/rpm-gpg/RPM-GPG-KEY-cern

# install kernel sources to compile DPDK
RUN export isRT=$(uname -r | grep rt -c) && if [ $isRT = "1" ] ; then yum install -y "kernel-rt-devel-uname-r == $(uname -r)"; else yum install -y "kernel-devel-uname-r == $(uname -r)"; fi
RUN mkdir -p /lib/modules/$(uname -r)
RUN ln -s /usr/src/kernels/$(uname -r) /lib/modules/$(uname -r)/build

#create non-root user
ARG username=fpga_opae
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

#copy packages
COPY n3000-1-3-5-beta-rte-setup.zip .
COPY n3000-1-3-5-beta-cfg-2x2x25g-setup.zip .

#unzip packages
RUN unzip n3000-1-3-5-beta-rte-setup.zip
RUN unzip n3000-1-3-5-beta-cfg-2x2x25g-setup.zip

#make scripts executable
RUN chmod +x n3000-1.3.5-beta-rte-setup.sh
RUN chmod +x n3000-1.3.5-beta-cfg-2x2x25G-setup.sh

#install OPAE packages
RUN echo "proxy=$http_proxy/" | sudo tee -a /etc/yum.conf
RUN sudo yum clean expire-cache
RUN sudo ./n3000-1.3.5-beta-rte-setup.sh -y --owner fpga_opae:sudo
RUN source /home/fpga_opae/intelrtestack/bin/init_env.sh

#install PAC N3000 configuration
RUN sudo ./n3000-1.3.5-beta-cfg-*-setup.sh -y

#copy module checking script
COPY check_if_modules_loaded.sh .
