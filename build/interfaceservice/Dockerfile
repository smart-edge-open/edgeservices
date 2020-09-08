# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

FROM centos:7.6.1810 AS interfaceservice-deps-image

RUN yum install -y pciutils which unbound iproute sudo \
	&& yum clean all
RUN rpm -ivh https://github.com/alauda/ovs/releases/download/2.12.0-5/openvswitch-2.12.0-5.el7.x86_64.rpm

FROM interfaceservice-deps-image

ARG username=interfaceservice
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

# This 'hack' will enable building without DPDK - ./dpdk-devbind.py will be copied if existing
# but will also not fail if file will be not available
COPY ./interfaceservice ./dpdk-devbind.p[y] ./
COPY ./entrypoint_interfaceservice.sh ./

CMD ["sudo", "./entrypoint_interfaceservice.sh"]
