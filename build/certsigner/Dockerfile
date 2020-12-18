# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

FROM alpine:3.12.0 AS certsigner-deps-image

RUN printf "http://nl.alpinelinux.org/alpine/v3.12/main\nhttp://nl.alpinelinux.org/alpine/v3.12/community" >> /etc/apk/repositories
RUN apk add --no-cache bash sudo

FROM certsigner-deps-image

ARG username=certsigner
ARG user_dir=/home/$username

RUN addgroup -S sudo && adduser -S $username -G sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./certsigner ./

CMD ["sudo", "-E", "./certsigner"]
