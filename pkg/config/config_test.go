// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
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

type testStruct struct {
	Field string
}

var _ = Describe("LoadJSONConfigWithLimit", func() {
	When("file is missing", func() {
		It("should fail", func() {
			var cfg testStruct
			Expect(LoadJSONConfigWithLimit("", 0, &cfg)).NotTo(Succeed())
		})
	})

	When("file is larger than the limit", func() {
		It("should fail", func() {
			limit := int64(1024 * 1024)

			path := "large_file.json"
			f, err := os.Create(path)
			Expect(err).NotTo(HaveOccurred())
			defer os.Remove(path)

			err = f.Truncate(limit + 1)
			Expect(err).NotTo(HaveOccurred())

			var cfg testStruct
			Expect(LoadJSONConfigWithLimit(path, limit, &cfg)).NotTo(Succeed())
		})
	})

	When("file is smaller than the limit", func() {
		It("should succeed", func() {
			cfg := testStruct{Field: "test"}
			data, err := json.MarshalIndent(cfg, "", " ")
			Expect(err).ShouldNot(HaveOccurred())

			path := "cfg.json"
			err = ioutil.WriteFile(path, data, 0644)
			Expect(err).ShouldNot(HaveOccurred())
			defer os.Remove(path)

			var cfgRead testStruct
			Expect(LoadJSONConfigWithLimit(path, int64(len(data)+1), &cfgRead)).To(Succeed())
			Expect(cfgRead).To(Equal(cfg))
		})
	})
})
