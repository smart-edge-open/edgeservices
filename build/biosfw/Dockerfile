# Copyright 2019 Intel Corporation. All rights reserved
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


FROM centos:7.6.1810

WORKDIR /root/

RUN yum install -y unzip sudo \
        && yum clean all

COPY syscfg_package.zip .
RUN mkdir -p /root/syscfg \
        && unzip syscfg_package.zip -d /root/syscfg_package \
        && rpm -ivh --prefix=/usr/bin /root/syscfg_package/Linux_x64/RHEL/*.rpm

ARG username=biosfw
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./biosfw.sh ./

ENTRYPOINT ["sudo", "./biosfw.sh"]
