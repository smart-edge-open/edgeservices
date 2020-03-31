// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

module github.com/open-ness/edgenode

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.4.12 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.8.5
	github.com/digitalocean/go-openvswitch v0.0.0-20190729213829-6de2edd48e71
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.3.3 // indirect
	github.com/gogo/protobuf v1.2.1 // indirect
	github.com/golang/protobuf v1.3.3
	github.com/google/go-cmp v0.4.0 // indirect
	github.com/gorilla/mux v1.7.0
	github.com/gorilla/websocket v1.4.0
	github.com/grpc-ecosystem/grpc-gateway v1.8.5
	github.com/kata-containers/runtime v0.0.0-20190505030513-a7e2bbd31c56
	github.com/kr/pretty v0.2.0 // indirect
	github.com/libvirt/libvirt-go v5.1.0+incompatible
	github.com/libvirt/libvirt-go-xml v5.1.0+incompatible
	github.com/miekg/dns v1.1.8
	github.com/onsi/ginkgo v1.12.0
	github.com/onsi/gomega v1.9.0
	github.com/open-ness/common/log v0.0.0-20191220144925-273a86a3f0d0
	github.com/open-ness/common/proxy v0.0.0-20191220144925-273a86a3f0d0
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	github.com/vishvananda/netlink v0.0.0-20181108222139-023a6dafdcdf
	go.etcd.io/bbolt v1.3.2
	golang.org/x/crypto v0.0.0-20200214034016-1d94cc7ab1c6 // indirect
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2 // indirect
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
	golang.org/x/sys v0.0.0-20200212091648-12a6c2dcc1e4 // indirect
	golang.org/x/text v0.3.2 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	google.golang.org/genproto v0.0.0-20200212174721-66ed5ce911ce
	google.golang.org/grpc v1.27.1
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/ini.v1 v1.42.0
	gopkg.in/yaml.v2 v2.2.8 // indirect
	gotest.tools v2.2.0+incompatible // indirect
)

replace github.com/docker/docker => github.com/docker/engine v0.0.0-20190423201726-d2cfbce3f3b0
