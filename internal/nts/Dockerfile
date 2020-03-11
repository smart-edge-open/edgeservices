# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

FROM centos:7.6.1810 AS nts-deps-image

RUN yum upgrade -y ca-certificates && \
    yum install -y epel-release && \
    yum install -y numactl-devel libhugetlbfs-utils iproute python3 python3-pip sudo && \
    pip3 install docker && \
    pip3 install configparser

FROM nts-deps-image

ARG username=nts
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./build/nes-daemon ./
COPY ./kni_docker_daemon.py ./
COPY ./ovs_docker_daemon.py ./
COPY ./entrypoint.sh ./
COPY ./build/libnes_api_shared.so ./

ENTRYPOINT ["sudo", "-E", "./entrypoint.sh"]
