# Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM centos:7.6.1810 AS nts-deps-image

RUN yum upgrade -y ca-certificates && \
    yum install -y epel-release && \
    yum install -y numactl-devel libhugetlbfs-utils iproute python python-pip sudo && \
    pip install docker && \
    pip install configparser

FROM nts-deps-image

ARG username=nts
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./nts/nes-daemon ./
COPY ./nts/kni_docker_daemon.py ./
COPY ./nts/ovs_docker_daemon.py ./
COPY ./nts/entrypoint.sh ./
COPY ./nts/libnes_api_shared.so ./

ENTRYPOINT ["sudo", "./entrypoint.sh"]
