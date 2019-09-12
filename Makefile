################################################################################
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
################################################################################

export GO111MODULE = on

.PHONY: build appliance edgedns clean build-docker lint test help build-docker-hddl hddllog 
TMP_DIR:=$(shell mktemp -d)
BUILD_DIR ?=dist

VER:=1.0

build: edalibs appliance edgedns nts

appliance:
	mkdir -p "${BUILD_DIR}"
	GOOS=linux go build -o "${BUILD_DIR}/appliance" ./cmd/appliance

edgedns:
	mkdir -p "${BUILD_DIR}"
	GOOS=linux go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o "${BUILD_DIR}/edgednssvr" ./cmd/edgednssvr

nts:
	make -C internal/nts

edalibs:
	make -C internal/nts/eda_libs

hddllog:
	mkdir -p "${BUILD_DIR}"
	GOOS=linux go build -o "${BUILD_DIR}/hddllog" ./cmd/hddllog

clean:
	rm -rf "${BUILD_DIR}"
	make clean -C internal/nts
	make clean -C internal/nts/eda_libs

build-docker: build
	cp build/appliance/Dockerfile "${TMP_DIR}/Dockerfile_appliance"
	cp build/appliance/entrypoint.sh "${TMP_DIR}"
	cp /opt/dpdk-18.11.2/usertools/dpdk-devbind.py "${TMP_DIR}"
	cp "${BUILD_DIR}/appliance" "${TMP_DIR}"
	cp build/edgednssvr/Dockerfile "${TMP_DIR}/Dockerfile_edgednssvr"
	cp "${BUILD_DIR}/edgednssvr" "${TMP_DIR}"
	cp docker-compose.yml "${TMP_DIR}"
ifeq ($(KUBE_OVN_MODE), True)
	cd "${TMP_DIR}" && VER=${VER} docker-compose build
else
	cp docker-compose.nts.yml "${TMP_DIR}"
	mkdir -p "${TMP_DIR}/nts"
	cp internal/nts/build/nes-daemon "${TMP_DIR}/nts"
	cp internal/nts/kni_docker_daemon.py "${TMP_DIR}/nts"
	cp internal/nts/ovs_docker_daemon.py "${TMP_DIR}/nts"
	cp internal/nts/entrypoint.sh "${TMP_DIR}/nts"
	cp internal/nts/build/libnes_api_shared.so "${TMP_DIR}/nts"
	cp internal/nts/Dockerfile "${TMP_DIR}/Dockerfile_nts"
	cd "${TMP_DIR}" && VER=${VER} docker-compose -f docker-compose.yml -f docker-compose.nts.yml build
endif	
	ls "${TMP_DIR}"
	rm -rf "${TMP_DIR}"

build-docker-hddl: hddllog
	cp build/hddlservice/Dockerfile "${TMP_DIR}/Dockerfile_hddlservice"
	cp build/hddlservice/start.sh "${TMP_DIR}"
	cp build/hddlservice/docker-compose.yml "${TMP_DIR}"
	cp "${BUILD_DIR}/hddllog" "${TMP_DIR}"
	cd "${TMP_DIR}" && VER=${VER} docker-compose build
	ls "${TMP_DIR}"
	rm -rf "${TMP_DIR}"

run-docker:
ifeq ($(KUBE_OVN_MODE), True)
	VER=${VER} docker-compose up --no-build
else
	VER=${VER} docker-compose -f docker-compose.yml -f docker-compose.nts.yml up --no-build
endif

lint: edalibs
	golangci-lint run

test: edalibs
	ginkgo -v -r --randomizeSuites --failOnPending --skipPackage=vendor

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo "  build                  to build the appliance application, edgedns server and NTS"
	@echo "  appliance              to build the appliance application"
	@echo "  edgedns                to build the edgedns server"
	@echo "  nts                    to build the NTS"
	@echo "  hddllog                to build the log supporting hddl service"
	@echo "  clean                  to clean up build artifacts and docker"
	@echo "  build-docker           to build the release docker image"
	@echo "  build-docker-hddl      to build optional docker image for hddl-service"
	@echo "  run-docker             to start containers"
	@echo "  lint                   to run linters and static analysis on the code"
	@echo "  test                   to run unit tests"
