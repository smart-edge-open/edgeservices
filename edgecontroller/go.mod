// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

module github.com/smart-edge-open/edgeservices/edgecontroller

go 1.16

require (
	github.com/golang/protobuf v1.4.2
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1
	github.com/undefinedlabs/go-mpatch v1.0.6
	google.golang.org/genproto v0.0.0-20200831141814-d751682dd103 // indirect
	google.golang.org/grpc v1.31.0
)

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20190226215855-775f8194d0f9
