// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation
package edgedns_test

import (
	"fmt"
	"os"

	"github.com/miekg/dns"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"
	"github.com/open-ness/edgenode/pkg/edgedns/storage"
)

var _ = Describe("BoltDB Storage", func() {

	var stg *storage.BoltDB
	BeforeEach(func() {
		f := fmt.Sprintf("unit_%d.db", config.GinkgoConfig.ParallelNode)
		stg = &storage.BoltDB{
			Filename: f,
		}
	})

	AfterEach(func() {
		Expect(stg.Stop()).To(Succeed())
		os.Remove(stg.Filename)
	})

	It("Handles unsupported types", func() {
		Expect(stg.Start()).To(Succeed())
		err := stg.DelRRSet(dns.TypeAVC, []byte("foo.example.com"))
		Expect(err).NotTo(BeNil())
	})
})
