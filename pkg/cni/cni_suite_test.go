// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package cni_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCni(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CNI Suite")
}
