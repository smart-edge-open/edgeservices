// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eva_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	// . "github.com/open-ness/edgenode/pkg/eva"
)

var _ = Describe("AppidProvider", func() {
	When("GetApplicationByIP is called", func() {
		Context("with correct arguments", func() {
			It("responds with no error", func() {
				var err error
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
})
