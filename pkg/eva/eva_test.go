// Copyright 2019 Intel Corporation. All rights reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package eva_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/otcshare/edgenode/pkg/eva"
)

var _ = Describe("EvaRun", func() {
	var cfgFilePath = "testdata/eva.json"
	When("EVA is started", func() {
		Context("with valid config file", func() {
			It("it starts with no error", func() {
				stopInd := make(chan bool)
				err := runEVA(cfgFilePath, stopInd)
				Expect(err).ToNot(HaveOccurred())
				stopEVA(stopInd)
			})
		})
		Context("with valid config file in K8s mode", func() {
			It("it starts with no error", func() {
				// Config file with K8s
				cfgFilePath = "testdata/eva_kube.json"
				stopInd := make(chan bool)
				err := runEVA(cfgFilePath, stopInd)
				Expect(err).ToNot(HaveOccurred())
				stopEVA(stopInd)
			})
		})
		Context("with invalid config file", func() {
			It("it starts with an error", func() {
				// Invalid config file
				cfgFilePath = "testdata/eva_invalid.json"
				// eva.json config file is invalid, directory for certificates
				// is defined in a variable
				certsDir := "testdata/certs"

				prepareCredentials(certsDir)

				// Starting EVA with invalid config file.
				srvCtx, srvCancel = context.WithCancel(context.Background())
				Expect(eva.Run(srvCtx, cfgFilePath)).To(HaveOccurred())
			})
		})
	})
})
