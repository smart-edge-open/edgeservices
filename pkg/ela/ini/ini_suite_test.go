// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ini_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var ntsConfigTestFilePath = "testdata/nts.cfg"

func TestIni(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ini Suite")
}
