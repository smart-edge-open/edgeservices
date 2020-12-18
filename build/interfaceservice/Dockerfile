# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

FROM alpine:3.12.0 AS interfaceservice-deps-image

RUN apk add --no-cache bash sudo wget python3 py3-six build-base linux-headers \
    openssl-dev libcap-ng-dev autoconf automake libtool pciutils which unbound \
    iproute2

RUN wget https://www.openvswitch.org/releases/openvswitch-2.14.0.tar.gz
RUN tar -xzf openvswitch-2.14.0.tar.gz

RUN cd openvswitch-2.14.0 && ./boot.sh && autoconf && \
    ./configure  --prefix=/usr --localstatedir=/var --sysconfdir=/etc && make && make install && \
    rm -rf openvswitch-2.14.0

RUN sudo ln -s /usr/bin/python3 /usr/bin/python

FROM interfaceservice-deps-image

ARG username=interfaceservice
ARG user_dir=/home/$username

RUN addgroup -S sudo && adduser -S $username -G sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

# This 'hack' will enable building without DPDK - ./dpdk-devbind.py will be copied if existing
# but will also not fail if file will be not available
COPY ./interfaceservice ./dpdk-devbind.p[y] ./
COPY ./entrypoint_interfaceservice.sh ./

CMD ["sudo", "./entrypoint_interfaceservice.sh"]
