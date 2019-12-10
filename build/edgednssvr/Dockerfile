# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

FROM alpine:latest AS edgedns-deps-image

RUN apk add --no-cache sudo

FROM edgedns-deps-image

ENV DNS_FWDR=""

ARG username=edgednssvr
ARG user_dir=/home/$username

RUN addgroup -S sudo && adduser -S $username -G sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./edgednssvr ./
ENTRYPOINT ["sudo", "./edgednssvr"]
CMD ["-port=53", "-fwdr=8.8.8.8"]
