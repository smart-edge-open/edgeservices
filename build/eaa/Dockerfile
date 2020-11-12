# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

FROM alpine:3.12.0 AS eaa-deps-image

RUN apk add --no-cache bash sudo

FROM eaa-deps-image

ARG username=eaa
ARG user_dir=/home/$username

RUN addgroup -S sudo && adduser -S $username -G sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./eaa ./
COPY ./entrypoint_eaa.sh ./

CMD ["sudo", "./entrypoint_eaa.sh"]
