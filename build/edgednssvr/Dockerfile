# Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
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

FROM alpine:latest

RUN apk add --no-cache sudo

ENV DNS_FWDR=""

ARG username=edgednssvr
ARG user_dir=/home/$username

RUN addgroup -S sudo && adduser -S $username -G sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./edgednssvr ./
ENTRYPOINT ["sudo", "./edgednssvr"]
CMD ["-port=53", "-fwdr=$DNS_FWDR", "-syslog=$LOCAL_SYSLOG"]
