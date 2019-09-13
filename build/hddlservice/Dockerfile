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

FROM ubuntu:16.04

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
RUN apt-get update && apt-get install -y \
	build-essential \
	sed \
	sudo \
	tar \
	udev \
	wget \
	rpm \
	python \
	usbutils \
	unzip  \
	git  \
	cmake  \
	kmod  \
	libusb-1.0-0-dev libudev-dev libssl-dev rpm cmake libboost-program-options1.58-dev libboost-thread1.58 libboost-filesystem1.58 git vim\
	build-essential gcc g++ \
    	cpio \
    	lsb-core \
    	autoconf libtool \
    	ffmpeg libav-tools x264 \
    	util-linux \
	&& apt-get clean

RUN useradd -m -s /bin/bash hddl
RUN adduser hddl sudo
RUN echo 'hddl:hddl' | chpasswd
RUN echo "hddl ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers
USER hddl 
# Set the current working directory to the cloned ncsdk directory
WORKDIR "/home/hddl/"
RUN sudo usermod -a -G users,video hddl 

ARG OPENVINO_LINK=http://registrationcenter-download.intel.com/akdlm/irc_nas/15791/l_openvino_toolkit_fpga_p_2019.2.275.tgz

# OpenVino installation
RUN cd /home/hddl && \
    wget $OPENVINO_LINK && \
    tar xf l_openvino_toolkit*.tgz && \
    pwd && ls && \
    cd l_openvino_toolkit* && \
    sed -i 's/decline/accept/g' silent.cfg && \
    sudo -E ./install_openvino_dependencies.sh && \
    sudo -E ./install.sh -s silent.cfg && \
    rm -rf /tmp/l_openvino_toolkit* 
# Edit hddl_autoboot config and hddl_service config in order to stop failing on reset and enabling additional logs for service
RUN sudo -E sed -i '/"abort_if_hw_reset_failed"/ s/true/false/' /opt/intel/openvino_2019.2.275/deployment_tools/inference_engine/external/hddl/config/hddl_autoboot.config && \
    sudo -E sed -i '/"device_snapshot_mode"/ s/none/full/' /opt/intel/openvino_2019.2.275/deployment_tools/inference_engine/external/hddl/config/hddl_service.config 
RUN echo "source /opt/intel/openvino/bin/setupvars.sh" >> ~/.bashrc

COPY start.sh ./
COPY ./hddllog ./
CMD ["./start.sh"]
