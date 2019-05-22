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

FROM centos:7.6.1810

RUN yum upgrade ca-certificates && \
    yum install -y epel-release && \
    yum install -y numactl-devel libhugetlbfs-utils iproute python python-pip && \
    pip install docker && \
    pip install configparser

ADD ./nts/nes-daemon /root/
ADD ./nts/kni_docker_daemon.py /root/
ADD ./nts/entrypoint.sh /root/
ADD ./nts/libnes_api_shared.so /root/

VOLUME [ "/hugepages", "/var/lib/nts", "/var/run/docker/netns", "/var/run", "/var/host_ns" ]

ENTRYPOINT ["/root/entrypoint.sh"]
