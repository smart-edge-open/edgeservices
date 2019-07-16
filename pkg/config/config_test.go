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

package config

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config suite")
}

var _ = Describe("LoadJSONonfig", func() {

	Describe("Load a json config file", func() {
		It("Will load a config file and unmarshall it to provided structure",
			func() {
				Expect(LoadJSONConfig("nonexistent-file", nil)).NotTo(BeNil())
				Expect(LoadJSONConfig("conf", nil)).NotTo(BeNil())
				conf := struct {
					Val int `json:"Val"`
				}{}
				Expect(LoadJSONConfig("testdata/conf.json", &conf)).To(BeNil())
				Expect(conf.Val).To(Equal(0))
			})
	})
})
