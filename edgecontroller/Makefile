# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019-2020 Intel Corporation

export GO111MODULE = on
export MINIKUBE_WANTUPDATENOTIFICATION=false
export MINIKUBE_WANTREPORTERRORPROMPT=false
export MINIKUBE_HOME=$(HOME)
export CHANGE_MINIKUBE_NONE_USER=true
export KUBECONFIG=$(HOME)/.kube/config

# Build CCE run flags to be passed to docker-compose. This must be declared
# before any command declarations since docker-compose depends on this variable
# to always be set.
define CCE_FLAGS_BASE
	-adminPass $(CCE_ADMIN_PASSWORD) \
	-dsn root:$(MYSQL_ROOT_PASSWORD)@tcp(mysql:3306)/controller_ce \
	-log-level $(CCE_LOG_LEVEL)
endef

# Pass kubernetes related flags if and only if the user specified kubernetes
# as the orchestration mode. Otherwise, assume native orchestration mode and
# pass in base flags.
ifeq ($(CCE_ORCHESTRATION_MODE),$(filter $(CCE_ORCHESTRATION_MODE),kubernetes kubernetes-ovn))
define CCE_FLAGS
	$(CCE_FLAGS_BASE) \
	-orchestration-mode $(CCE_ORCHESTRATION_MODE) \
	-k8s-client-ca-path /artifacts/k8s/ca.pem \
	-k8s-client-cert-path /artifacts/k8s/cert.pem \
	-k8s-client-key-path /artifacts/k8s/key.pem \
	-k8s-master-host $(CCE_K8S_MASTER_HOST) \
	-k8s-api-path $(CCE_K8S_API_PATH) \
	-k8s-master-user $(CCE_K8S_MASTER_USER)
endef
	export CCE_FLAGS
else
	export CCE_FLAGS=$(CCE_FLAGS_BASE)
endif

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

test-ifsvccli:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites cmd/interfaceservicecli

test-dnscli:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites edgednscli
