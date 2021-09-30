# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2020 Intel Corporation

FROM centos:8.3.2011

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
ENV no_proxy=$no_proxy,eaa.openness

RUN yum install -y sudo \
	&& yum clean all

RUN yum -y upgrade bind-license glib2 bind-export-libs gnutls systemd systemd-udev systemd-pam nettle openssl-libs

ARG username=vas
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./vas-sidecar ./
ENTRYPOINT ["./vas-sidecar"]
