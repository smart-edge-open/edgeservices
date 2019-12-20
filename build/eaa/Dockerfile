# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

FROM centos:7.6.1810 AS eaa-deps-image

RUN yum install -y openssl sudo \
    && yum clean all

FROM eaa-deps-image

ARG username=eaa
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./eaa ./
COPY ./entrypoint_eaa.sh ./

CMD ["sudo", "./entrypoint_eaa.sh"]
