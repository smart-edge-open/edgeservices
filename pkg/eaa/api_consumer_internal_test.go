// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eaa

import (
	g "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = g.Describe("internal errors", func() {
	g.When("there is internal error with initialization", func() {
		g.Specify("getConsumerSubscriptions should fail with an error", func() {
			ctx := &Context{}
			s, e := getConsumerSubscriptions("some unimportant name", ctx)

			Expect(s).To(BeNil())
			Expect(e).To(HaveOccurred())
		})
	})
})
