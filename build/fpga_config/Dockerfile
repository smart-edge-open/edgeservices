# Copyright 2019 Intel Corporation. All rights reserved.
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

FROM centos:7.6.1810 AS builder

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
ENV INIH_PATH=/root/bbdev_config/inih/extra

RUN yum install -y git build-essential cmake gcc-c++ make

WORKDIR /root/bbdev_config
COPY bbdev_config_service .

RUN git clone https://github.com/benhoyt/inih
RUN cd inih/extra && make -f Makefile.static && cp ../ini.h .
RUN make

FROM centos:7.6.1810

RUN yum install -y sudo

ARG username=fpga_config
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY --from=builder /root/bbdev_config/config_bbdev .
