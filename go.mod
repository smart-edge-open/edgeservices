// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

module github.com/otcshare/edgenode

go 1.15

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/Shopify/sarama v1.26.0
	github.com/ThreeDotsLabs/watermill v1.1.1
	github.com/ThreeDotsLabs/watermill-kafka/v2 v2.2.0
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.7
	github.com/digitalocean/go-openvswitch v0.0.0-20191122155805-8ce3b4218729
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.3.3 // indirect
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.4.2
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/grpc-ecosystem/grpc-gateway v1.14.7
	github.com/kata-containers/runtime v0.0.0-20190505030513-a7e2bbd31c56
	github.com/kr/text v0.2.0 // indirect
	github.com/miekg/dns v1.1.31
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/otcshare/common/log v0.0.0-20200918073610-af29aa2e340a
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.5.1 // indirect
	github.com/undefinedlabs/go-mpatch v1.0.6
	go.etcd.io/bbolt v1.3.5
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a // indirect
	google.golang.org/genproto v0.0.0-20200831141814-d751682dd103
	google.golang.org/grpc v1.31.0
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.19.3
	k8s.io/kubernetes v1.19.3
)

replace k8s.io/api => k8s.io/api v0.19.3

replace k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.3

replace k8s.io/apimachinery => k8s.io/apimachinery v0.19.4-rc.0

replace k8s.io/apiserver => k8s.io/apiserver v0.19.3

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.3

replace k8s.io/client-go => k8s.io/client-go v0.19.3

replace k8s.io/cloud-provider => k8s.io/cloud-provider v0.19.3

replace k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.19.3

replace k8s.io/code-generator => k8s.io/code-generator v0.19.4-rc.0

replace k8s.io/component-base => k8s.io/component-base v0.19.3

replace k8s.io/controller-manager => k8s.io/controller-manager v0.19.4-rc.0

replace k8s.io/cri-api => k8s.io/cri-api v0.19.4-rc.0

replace k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.19.3

replace k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.19.3

replace k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.19.3

replace k8s.io/kube-proxy => k8s.io/kube-proxy v0.19.3

replace k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.19.3

replace k8s.io/kubectl => k8s.io/kubectl v0.19.3

replace k8s.io/kubelet => k8s.io/kubelet v0.19.3

replace k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.19.3

replace k8s.io/metrics => k8s.io/metrics v0.19.3

replace k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.19.3

replace k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.19.3

replace k8s.io/sample-controller => k8s.io/sample-controller v0.19.3
