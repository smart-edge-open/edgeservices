# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

export GO111MODULE = on

.PHONY: help clean build build-ifsvccli build-dnscli vas-sidecar \
	lint test test-ifsvccli test-dnscli

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo "Building:"
	@echo "  clean             to clean up build artifacts and docker volumes"
	@echo "  build             to build the project to the ./dist/ folder"
	@echo "  build-ifsvccli    to build interfaceservice CLI to the ./dist/ folder"
	@echo "  build-dnscli      to build edgednscli to the ./dist/ folder"
	@echo "  vas-sidecar       to build video analytics serving sidecar"
	@echo ""
	@echo "Testing:"
	@echo "  lint              to run linters and static analysis on the code"
	@echo "  test              to run all tests"
	@echo "  test-ifsvccli     to run interfaceservicecli tests"
	@echo "  test-dnscli       to run edgednscli tests"
	@echo "  test-cov          to run coverage with html output"

clean:
	rm -rf dist certificates artifacts

build: build-ifsvccli build-dnscli

build-ifsvccli:
	go build -o dist/interfaceservicecli ./cmd/interfaceservicecli

build-dnscli:
	go build -o dist/edgednscli ./cmd/edgednscli

vas-sidecar:
	cd ./vas-sidecar && go build -o ./vas-sidecar

lint:
	golangci-lint run

test:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites \
		--skipPackage=vendor,k8s
test-cov:
	rm -rf coverage.out*
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites \
		-cover -coverprofile=coverage.out -outputdir=. \
                --skipPackage=vendor,k8s
	sed '1!{/^mode/d;}' coverage.out > coverage.out.fix
	go tool cover -html=coverage.out.fix

test-ifsvccli:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites cmd/interfaceservicecli

test-dnscli:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites edgednscli
