# Copyright 2019 Smart-Edge.com, Inc. All rights reserved.
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

export GO111MODULE = on

.PHONY: help clean build build-docker lint test
TMP_DIR:=$(shell mktemp -d)
BUILD_DIR:=dist
VER:=1.0

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo "  clean          to clean up build artifacts and docker"
	@echo "  build          to build the appliance application"
	@echo "  build-docker   to build the release docker image"
	@echo "  lint           to run linters and static analysis on the code"
	@echo "  test           to run unit tests"

clean:
	rm -rf "${BUILD_DIR}"

build:
	mkdir -p "${BUILD_DIR}"
	CGO_ENABLED=0 GOOS=linux go build -o "${BUILD_DIR}/appliance" ./cmd/appliance

build-docker: build
	cp build/pkg/Dockerfile "${TMP_DIR}"
	cp -r configs "${TMP_DIR}"
	cp "${BUILD_DIR}/appliance" "${TMP_DIR}"
	docker build -t appliance:${VER} "${TMP_DIR}"
	ls "${TMP_DIR}"
	rm -rf "${TMP_DIR}"

lint:
	golangci-lint run

test:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites --failOnPending --skipPackage=vendor
