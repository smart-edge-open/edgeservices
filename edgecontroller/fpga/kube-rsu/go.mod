// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

module kube-rsu

require (
	gopkg.in/yaml.v2 v2.2.7 // indirect
	k8s.io/api v0.0.0-20191016110246-af539daaa43a
	k8s.io/apimachinery v0.0.0-20191123233150-4c4803ed55e3
	k8s.io/client-go v0.0.0-20190819141724-e14f31a72a77
	rsu v0.0.0 // indirect
)

replace rsu v0.0.0 => ./cmd

go 1.13
