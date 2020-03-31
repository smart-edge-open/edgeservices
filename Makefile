# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

export GO111MODULE = on

.PHONY: \
	onprem-nts onprem-ovncni \
	appliance appliance-cni appliance-nts \
	run-onprem-nts clean \
	eaa  edgednssvr nts edalibs ovncni hddllog  syslog-ng \
	networkedge networkedge-kubeovn \
	interfaceservice biosfw fpga-cfg fpga-opae \
	lint test help build pull-syslog
COPY_DOCKERFILES := $(shell /usr/bin/cp -rfT ./build/ ./dist/)
VER ?= 1.0
RTE_SDK ?= /opt/dpdk-18.11.2

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo ""
	@echo "Build all the required Docker images for OpenNESS' deployment mode:"
	@echo "  onprem-nts             to build components of On-Premises with NTS dataplane (EAA, Edge DNS Service, Appliance, NTS)"
	@echo "  onprem-ovncni          to build components of On-Premises with OVN CNI dataplane (EAA, Edge DNS Service, Appliance)"
	@echo "  networkedge            to build components of Network Edge deployment (EAA, Edge DNS Service)"
	@echo "  networkedge-kubeovn    to build components of Kube-OVN Network Edge deployment (EAA, Edge DNS Service, Interface Service)"
	@echo "  common-services        to build component common for both On-Premises and Network Edge deployments"
	@echo ""
	@echo "Start On-Premises services:"
	@echo "  run-onprem-nts         to start components of On-Premises with NTS as a dataplane (EAA, Edge DNS Service, Appliance, NTS)"
	@echo ""
	@echo "Helper targets:"
	@echo "  clean                  to clean build artifacts"
	@echo "  lint                   to run linter on Go code"
	@echo "  test                   to run tests on Go code"
	@echo "  help                   to show this message"
	@echo "  build                  to build all executables without images"
	@echo ""
	@echo "Single targets:"
	@echo "  appliance-nts          to build only docker image of the Appliance for NTS dataplane"
	@echo "  appliance-cni          to build only docker image of the Appliance for OVN CNI dataplane"
	@echo "  eaa                    to build only docker image of the EAA"
	@echo "  interfaceservice       to build only docker image of the Interface Service"
	@echo "  edgednssvr             to build only docker image of the Edge DNS Service"
	@echo "  nts                    to build only docker image of the NTS"
	@echo "  edalibs                to build EDA libs"
	@echo "  ovncni                 to build only ovncni executable"
	@echo "  hddllog                to build only docker image of the HDDL Service"
	@echo "  biosfw                 to build only docker image of the BIOSFW"
	@echo "  fpga-cfg               to build only docker image of the FPGA Config"
	@echo "  fpga-opae              to build only docker image of the FPGA OPAE"
	@echo "  syslog-ng              to build only docker image of the syslog-ng"
	@echo "  pull-syslog            to pull docker image of the syslog-ng"

common-services: eaa edgednssvr syslog-ng

onprem-nts: common-services appliance-nts

onprem-ovncni: common-services appliance-cni

networkedge: common-services

networkedge-kubeovn: networkedge interfaceservice

run-onprem-nts:
	VER=${VER} docker-compose up appliance nts eaa edgednssvr syslog-ng --no-build

clean:
	rm -rf ./dist
	$(MAKE) clean -C internal/nts
	$(MAKE) clean -C internal/nts/eda_libs

lint: edalibs
	golangci-lint run --build-tags=nts
	golangci-lint run --build-tags=cni

test: edalibs
	http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= ginkgo -v -r --randomizeSuites --failOnPending --skipPackage=vendor,edants,wrappers,stubs

appliance-nts: edalibs
	$(MAKE) appliance APPLIANCE_MODE=nts

appliance-cni:
	$(MAKE) appliance APPLIANCE_MODE=cni

APPLIANCE_MODE ?= nts
appliance:
	GOOS=linux go build -tags ${APPLIANCE_MODE} -o ./dist/$@/$@ ./cmd/$@
ifndef SKIP_DOCKER_IMAGES
	cp ${RTE_SDK}/usertools/dpdk-devbind.py ./dist/$@/
	VER=${VER} docker-compose build $@
endif

eaa:
	GOOS=linux go build -o ./dist/$@/$@ ./cmd/$@
ifndef SKIP_DOCKER_IMAGES
	VER=${VER} docker-compose build $@
endif

interfaceservice:
	GOOS=linux go build -o ./dist/$@/$@ ./cmd/$@
ifndef SKIP_DOCKER_IMAGES
	# This 'hack' will enable building without DPDK - ./dpdk-devbind.py will be copied if existing
	# but will also not fail if file will be not available
	-cp ${RTE_SDK}/usertools/dpdk-devbind.py ./dist/$@/
	VER=${VER} docker-compose build $@
endif

edgednssvr:
	GOOS=linux go build -a --ldflags '-extldflags "-static"' -tags netgo -installsuffix netgo -o ./dist/$@/$@ ./cmd/$@
ifndef SKIP_DOCKER_IMAGES
	VER=${VER} docker-compose build $@
endif

syslog-ng:
ifndef SKIP_DOCKER_IMAGES
	VER=${VER} docker-compose build $@
endif

nts:
	$(MAKE) -C internal/nts
ifndef SKIP_DOCKER_IMAGES
	VER=${VER} docker-compose build $@
endif

edalibs:
	$(MAKE) -C internal/nts/eda_libs

ovncni:
	GOOS=linux go build -o ./dist/$@/$@ ./cmd/$@

hddllog:
	GOOS=linux go build -o ./dist/hddlservice/$@ ./cmd/$@
ifndef SKIP_DOCKER_IMAGES
	VER=${VER} docker-compose -f dist/hddlservice/docker-compose.yml build
endif

biosfw:
	docker build -t openness-$@ -f ./dist/$@/Dockerfile ./dist/$@/

fpga-cfg:
	docker build -t fpga-config-utility:1.0 -f ./dist/fpga_config/Dockerfile ./dist/fpga_config/

fpga-opae:
	docker build -t fpga-opae-pacn3000:1.0 -f ./dist/fpga_opae/Dockerfile ./dist/fpga_opae/

build:
	$(MAKE) SKIP_DOCKER_IMAGES=1 common-services appliance-nts edalibs nts interfaceservice

pull-syslog:
	docker-compose pull --quiet syslog-ng
