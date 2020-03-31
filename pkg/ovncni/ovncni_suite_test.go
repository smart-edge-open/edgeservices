// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package ovncni_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestOvncni(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ovncni Suite")
}
