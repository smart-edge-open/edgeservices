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

define bring_ui_up
	docker-compose up -d landing-ui
	docker-compose up -d ui
endef

define bring_ui_down
	docker-compose stop landing-ui
	docker-compose stop ui
endef

.PHONY: help all-up all-down clean build build-dnscli lint test \
	db-down \
	minikube-install kubectl-install minikube-wait \
	ui-down \
	nfd-master-up nfd-master-down \
	vas-sidecar \
	test-k8s test-api-k8s \
	test-unit test-api test-dnscli

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo "Building:"
	@echo "  clean             to clean up build artifacts and docker volumes"
	@echo "  build             to build the project to the ./dist/ folder"
	@echo "  build-ifsvccli    to build interfaceservice CLI to the ./dist/ folder"
	@echo "  build-dnscli      to build edgednscli to the ./dist/ folder"
	@echo "  vas-sidecar       to build video analytics serving sidecar"
	@echo ""
	@echo "Services:"
	@echo "  all-up            to start the full controller stack"
	@echo "  all-down          to stop the full controller stack"
	@echo ""
	@echo "  db-down           to stop the MySQL database service"
	@echo ""
	@echo "  ui-down           to stop all of the production UI containers"
	@echo ""
	@echo "  cce-ui-up         to start the production UI Container"
	@echo "  cce-ui-down       to stop the production UI container"
	@echo "  cce-ui-dev-up     to start local developer instance of the UI"
	@echo "  cce-ui-test       run the UI project tests"
	@echo ""
	@echo "  landing-ui-up     to start the production UI Container"
	@echo "  landing-ui-down   to stop the production UI container"
	@echo "  landing-ui-dev-up to start local developer instance of the UI"
	@echo "  landing-ui-test   run the UI project tests"
	@echo ""
	@echo "  nfd-master-up     to start the nfd-master container"
	@echo "  nfd-master-down   to stop the nfd-master container"
	@echo ""
	@echo "  kubectl-install   to install kubectl"
	@echo "  minikube-install  to install minikube"
	@echo "  minikube-start    to start minikube"
	@echo "  minikube-wait     to wait for minikube to be ready"
	@echo "  minikube-stop     to stop minikube"
	@echo ""
	@echo "Testing:"
	@echo "  lint              to run linters and static analysis on the code"
	@echo "  test              to run all tests"
	@echo "  test-unit         to run unit tests"
	@echo "  test-dnscli       to run edgednscli tests"

clean:
	@docker-compose stop
	@docker-compose rm
	rm -rf dist certificates artifacts

all-down: db-down ui-down

build: build-ifsvccli build-dnscli

build-ifsvccli:
	go build -o dist/interfaceservicecli ./cmd/interfaceservicecli

lint:
	golangci-lint run

db-down:
	docker-compose stop mysql

kubectl-install:
ifeq ($(shell uname -s),Darwin)
	brew install kubernetes-cli
else
	curl -Lo kubectl \
		https://storage.googleapis.com/kubernetes-release/release/v1.14.2/bin/linux/amd64/kubectl \
		&& sudo install kubectl /usr/local/bin/
endif

minikube-install:
ifeq ($(shell uname -s),Darwin)
	brew cask install minikube
else
	curl -Lo minikube \
		https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 \
		&& sudo install minikube /usr/local/bin/
	mkdir -p $(HOME)/.kube $(HOME)/.minikube
	touch $(KUBECONFIG)
endif

minikube-start:
ifeq ($(shell uname -s),Darwin)
	minikube start
else
	sudo -E minikube start --vm-driver=none
	sudo chown -R travis: $(HOME)/.minikube/
endif

minikube-wait:
	kubectl cluster-info
	@# kube-addon-manager is responsible for managing other kubernetes components, such as kube-dns, dashboard, storage-provisioner.
	until kubectl -n kube-system get pods -lcomponent=kube-addon-manager -o jsonpath="{range .items[*]}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}" 2>&1 | grep -q "Ready=True"; do \
		sleep 1; \
		echo "waiting for kube-addon-manager to be available"; \
		kubectl get pods --all-namespaces; \
	done
	@# Wait for kube-dns to be ready.
	until kubectl -n kube-system get pods -lk8s-app=kube-dns -o jsonpath="{range .items[*]}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}" 2>&1 | grep -q "Ready=True"; do \
		sleep 1; \
		echo "waiting for kube-dns to be available"; \
		kubectl get pods --all-namespaces; \
	done

minikube-stop:
ifeq ($(shell uname -s),Darwin)
	minikube delete
else
	sudo -E minikube delete
endif

ui-down:
	$(call bring_ui_down)

cce-ui-up:
	docker-compose up -d ui

cce-ui-down:
	docker-compose stop ui

cce-ui-dev-up:
	cd ui/controller && yarn install && yarn start

cce-ui-test:
	cd ui/controller && yarn install && yarn build && yarn test

landing-ui-up:
	docker-compose up -d landing-ui

landing-ui-down:
	docker-compose stop landing-ui

landing-ui-dev-up:
	cd ui/landing && yarn install && yarn start

landing-ui-test:
	cd ui/landing && yarn install && yarn build && yarn test

build-dnscli:
	go build -o dist/edgednscli ./cmd/edgednscli

nfd-master-up:
	go build -o dist/nfd-master ./cmd/nfd-master
	docker-compose up -d nfd-master

nfd-master-down:
	docker-compose stop nfd-master

vas-sidecar:
	cd ./vas-sidecar && go build -o ./vas-sidecar

test-unit:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites \
		--skipPackage=vendor,k8s,cmd/cce,cmd/cce/k8s

test-dnscli:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites edgednscli

test: test-unit test-dnscli
