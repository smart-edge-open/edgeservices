// Copyright 2019 Smart-Edge.com, Inc. All rights reserved.
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
