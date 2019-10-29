// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
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

package ela_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/open-ness/edgenode/pkg/ela"
)

var _ = Describe("ELA Blacklisting interfaces", func() {
	var (
		elaConfBackup ela.Configuration
		isBlacklisted bool
	)
	const (
		pci1 = "0000:02:00.0"
		pci2 = "0000:02:00.1"
		pci3 = "0000:04:00.0"
		pci4 = "0000:04:00.3"
	)

	BeforeEach(func() {
		elaConfBackup = ela.Config
	})

	AfterEach(func() {
		ela.Config = elaConfBackup
	})

	Describe("Blacklist checking", func() {

		Specify("Should not blacklist anything, list is empty", func() {

			ela.Config.PCIBlacklist = []string{}

			isBlacklisted = ela.IsPCIportBlacklisted(pci1)
			Expect(isBlacklisted).To(Equal(false))

			isBlacklisted = ela.IsPCIportBlacklisted(pci2)
			Expect(isBlacklisted).To(Equal(false))

			isBlacklisted = ela.IsPCIportBlacklisted(pci3)
			Expect(isBlacklisted).To(Equal(false))

		})

		Specify("Should not blacklist anything", func() {

			ela.Config.PCIBlacklist = []string{pci1, pci2}

			isBlacklisted = ela.IsPCIportBlacklisted(pci3)
			Expect(isBlacklisted).To(Equal(false))

			isBlacklisted = ela.IsPCIportBlacklisted(pci4)
			Expect(isBlacklisted).To(Equal(false))

			isBlacklisted = ela.IsPCIportBlacklisted("")
			Expect(isBlacklisted).To(Equal(false))

		})

		Specify("Should blacklist ports", func() {

			ela.Config.PCIBlacklist = []string{pci1, pci2, pci3, pci4}

			isBlacklisted = ela.IsPCIportBlacklisted(pci1)
			Expect(isBlacklisted).To(Equal(true))

			isBlacklisted = ela.IsPCIportBlacklisted(pci2)
			Expect(isBlacklisted).To(Equal(true))

			isBlacklisted = ela.IsPCIportBlacklisted(pci3)
			Expect(isBlacklisted).To(Equal(true))

		})
	})
})
