# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

export GO111MODULE = on

.PHONY: \
	clean \
	eaa  edgednssvr hddllog \
	networkedge networkedge-kubeovn \
	interfaceservice biosfw fpga-opae \
	lint test help build
COPY_DOCKERFILES := $(shell /usr/bin/cp -rfT ./build/ ./dist/)
VER ?= 1.0
RTE_SDK ?= /opt/dpdk-18.11.6

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo ""
	@echo "Build all the required Docker images for OpenNESS' deployment mode:"
	@echo "  networkedge            to build components of Network Edge deployment (EAA, Edge DNS Service)"
	@echo "  networkedge-kubeovn    to build components of Kube-OVN Network Edge deployment (EAA, Edge DNS Service, Interface Service)"
	@echo "  common-services        to build component common services for Network Edge deployments"
	@echo ""
	@echo "Helper targets:"
	@echo "  clean                  to clean build artifacts"
	@echo "  lint                   to run linter on Go code"
	@echo "  test                   to run tests on Go code"
	@echo "  test-cov               to run coverage tests on Go code"
	@echo "  help                   to show this message"
	@echo "  build                  to build all executables without images"
	@echo ""
	@echo "Single targets:"
	@echo "  eaa                    to build only docker image of the EAA"
	@echo "  interfaceservice       to build only docker image of the Interface Service"
	@echo "  edgednssvr             to build only docker image of the Edge DNS Service"
	@echo "  hddllog                to build only docker image of the HDDL Service"
	@echo "  biosfw                 to build only docker image of the BIOSFW"
	@echo "  fpga-opae              to build only docker image of the FPGA OPAE"

common-services: eaa edgednssvr

networkedge: common-services

networkedge-kubeovn: networkedge interfaceservice

clean:
	rm -rf ./dist

test: 
	http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= ginkgo -v -r --randomizeSuites --failOnPending --skipPackage=vendor,interfaceservicecli,edgednscli

test-cov:
	rm -rf coverage.out*
	http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= ginkgo -v -r --randomizeSuites --failOnPending --skipPackage=vendor,interfaceservicecli,edgednscli \
	-cover -coverprofile=coverage.out -outputdir=.
	sed '1!{/^mode/d;}' coverage.out > coverage.out.fix
	go tool cover -html=coverage.out.fix

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

hddllog:
	GOOS=linux go build -o ./dist/hddlservice/$@ ./cmd/$@
ifndef SKIP_DOCKER_IMAGES
	VER=${VER} docker-compose -f dist/hddlservice/docker-compose.yml build
endif

biosfw:
	docker build -t openness-$@ -f ./dist/$@/Dockerfile ./dist/$@/

fpga-opae:
	docker build -t fpga-opae-pacn3000:1.0 -f ./dist/fpga_opae/Dockerfile ./dist/fpga_opae/

build:
	$(MAKE) SKIP_DOCKER_IMAGES=1 common-services interfaceservice
