# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

FROM centos:7.6.1810 AS appliance-deps-image

RUN yum install -y libvirt-devel \
	pciutils which \
	unbound \
	sudo \
	epel-release \
	python3 \
	firewalld-filesystem \
	&& yum clean all
RUN rpm -ivh https://github.com/alauda/ovs/releases/download/2.12.0-5/openvswitch-2.12.0-5.el7.x86_64.rpm \
	https://github.com/alauda/ovs/releases/download/2.12.0-5/ovn-2.12.0-5.el7.x86_64.rpm \
	https://github.com/alauda/ovs/releases/download/2.12.0-5/ovn-central-2.12.0-5.el7.x86_64.rpm \
	https://github.com/alauda/ovs/releases/download/2.12.0-5/ovn-host-2.12.0-5.el7.x86_64.rpm \
	https://github.com/alauda/ovs/releases/download/2.12.0-5/ovn-vtep-2.12.0-5.el7.x86_64.rpm

FROM appliance-deps-image

ARG username=appliance
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN groupadd sudo
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./appliance ./
COPY ./dpdk-devbind.py ./
COPY ./entrypoint.sh ./

CMD ["sudo", "-E", "./entrypoint.sh"]
