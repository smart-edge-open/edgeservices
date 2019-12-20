// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

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
