// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cli_test

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/otcshare/edgecontroller/edgednscli"
)

var _ = Describe("CLI test", func() {

	const (
		setJSONFileTemplate = `{
		 "record_type":"%s",
		 "fqdn":"%s",
		 "addresses":["%s"]
		}`
		delJSONFileTemplate = `{
			 "record_type":"%s",
			 "fqdn":"%s"
		}`
	)

	AfterEach(func() {
		fakeSvr.setRequest = nil
		fakeSvr.delRequest = nil
	})

	When("DNS CLI SetA is called", func() {
		Context("With correct set file path", func() {
			It("Should pass", func() {

				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     path.Join(testTmpFolder, "set.json"),
					Del:     "",
					PKI:     &cliPKI,
				}

				rt := "A"
				fqdn := "baz.bar.foo.com."
				addrsIn := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}

				err := ioutil.WriteFile(cliCfg.Set, []byte(fmt.Sprintf(
					setJSONFileTemplate, rt, fqdn,
					strings.Join(addrsIn, `", "`))), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(fakeSvr.setRequest.addresses).Should(Equal(addrsIn))
				Expect(fakeSvr.setRequest.recordType).Should(Equal(rt))
				Expect(fakeSvr.setRequest.fqdn).Should(Equal(fqdn))
			})
		})
		Context("Correct set, empty record_type field", func() {
			It("Should pass", func() {

				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     path.Join(testTmpFolder, "set.json"),
					Del:     "",
					PKI:     &cliPKI,
				}

				rt := ""
				fqdn := "baz.bar.foo.com."
				addrsIn := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}

				err := ioutil.WriteFile(cliCfg.Set, []byte(fmt.Sprintf(
					setJSONFileTemplate, rt, fqdn,
					strings.Join(addrsIn, `", "`))), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(fakeSvr.setRequest.addresses).Should(Equal(addrsIn))
				Expect(fakeSvr.setRequest.recordType).Should(Equal("A"))
				Expect(fakeSvr.setRequest.fqdn).Should(Equal(fqdn))
			})
		})
		Context("correct set, without record_type field", func() {
			It("Should pass", func() {

				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     path.Join(testTmpFolder, "set.json"),
					Del:     "",
					PKI:     &cliPKI,
				}

				rt := "A"
				fqdn := "baz.bar.foo.com."
				addrsIn := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}

				err := ioutil.WriteFile(cliCfg.Set, []byte(fmt.Sprintf(
					`{
						 "fqdn":"%s",
						 "addresses":["%s"]
						}`, fqdn, strings.Join(addrsIn, `", "`))), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(fakeSvr.setRequest.addresses).Should(Equal(addrsIn))
				Expect(fakeSvr.setRequest.recordType).Should(Equal(rt))
				Expect(fakeSvr.setRequest.fqdn).Should(Equal(fqdn))
			})
		})
		Context("Wrong dnsserver address", func() {
			It("Should fail", func() {

				cliCfg := cli.AppFlags{
					Address: ":1",
					Set:     path.Join(testTmpFolder, "set.json"),
					Del:     "",
					PKI:     &cliPKI,
				}

				rt := "A"
				fqdn := "baz.bar.foo.com."
				addrsIn := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}

				err := ioutil.WriteFile(cliCfg.Set, []byte(fmt.Sprintf(
					setJSONFileTemplate, rt, fqdn,
					strings.Join(addrsIn, `", "`))), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("Wrong IP address", func() {
			It("Should fail", func() {

				cliCfg := cli.AppFlags{
					Address: "localhost:4204",
					Set:     path.Join(testTmpFolder, "set.json"),
					Del:     "",
					PKI:     &cliPKI,
				}

				rt := "A"
				fqdn := "baz.bar.foo.com."
				addrsIn := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}

				err := ioutil.WriteFile(cliCfg.Set, []byte(fmt.Sprintf(
					setJSONFileTemplate, rt, fqdn,
					strings.Join(addrsIn, `", "`))), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("Wrong record_type", func() {
			It("Should fail", func() {

				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     path.Join(testTmpFolder, "set.json"),
					Del:     "",
					PKI:     &cliPKI,
				}

				rt := "some_incorrect_type"
				fqdn := "baz.bar.foo.com."
				addrsIn := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}

				err := ioutil.WriteFile(cliCfg.Set, []byte(fmt.Sprintf(
					setJSONFileTemplate, rt, fqdn,
					strings.Join(addrsIn, `", "`))), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("With non existing file", func() {
			It("Should trigger an error", func() {
				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     "/some/not/existing/file",
					Del:     "",
					PKI:     &cliPKI,
				}

				err := cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("With folder path instead of file", func() {
			It("Should trigger an error", func() {
				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     path.Dir(testTmpFolder),
					Del:     "",
					PKI:     &cliPKI,
				}

				err := cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	When("DNS CLI DelA is called", func() {
		Context("With correct del file path", func() {
			It("Should pass", func() {

				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     "",
					Del:     path.Join(testTmpFolder, "del.json"),
					PKI:     &cliPKI,
				}

				rt := "A"
				fqdn := "baz.bar.foo.com."

				err := ioutil.WriteFile(cliCfg.Del, []byte(fmt.Sprintf(
					delJSONFileTemplate, rt, fqdn)), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(fakeSvr.delRequest.recordType).Should(Equal(rt))
				Expect(fakeSvr.delRequest.fqdn).Should(Equal(fqdn))
			})
		})
		Context("Correct del, empty record_type field", func() {
			It("Should pass", func() {
				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     "",
					Del:     path.Join(testTmpFolder, "del.json"),
					PKI:     &cliPKI,
				}

				rt := ""
				fqdn := "baz.bar.foo.com."

				err := ioutil.WriteFile(cliCfg.Del, []byte(fmt.Sprintf(
					delJSONFileTemplate, rt, fqdn)), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(fakeSvr.delRequest.recordType).Should(Equal("A"))
				Expect(fakeSvr.delRequest.fqdn).Should(Equal(fqdn))
			})
		})
		Context("Correct del, without record_type field", func() {
			It("Should pass", func() {

				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     "",
					Del:     path.Join(testTmpFolder, "del.json"),
					PKI:     &cliPKI,
				}

				rt := "A"
				fqdn := "baz.bar.foo.com."

				err := ioutil.WriteFile(cliCfg.Del, []byte(fmt.Sprintf(
					`{
						 "record_type":"%s",
						 "fqdn":"%s"
					}`, rt, fqdn)), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(fakeSvr.delRequest.recordType).Should(Equal(rt))
				Expect(fakeSvr.delRequest.fqdn).Should(Equal(fqdn))
			})
		})
		Context("Wrong address", func() {
			It("Should fail", func() {
				cliCfg := cli.AppFlags{
					Address: ":1",
					Set:     "",
					Del:     path.Join(testTmpFolder, "del.json"),
					PKI:     &cliPKI,
				}

				rt := "A"
				fqdn := "baz.bar.foo.com."

				err := ioutil.WriteFile(cliCfg.Del, []byte(fmt.Sprintf(
					delJSONFileTemplate, rt, fqdn)), 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("Wrong record_type", func() {
			It("Should fail", func() {

				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     "",
					Del:     path.Join(testTmpFolder, "del.json"),
					PKI:     &cliPKI,
				}
				delJSON := []byte(`{
							"record_type":"incorrect_type_passed",
							 "fqdn":"baz.foo.noa.com."
							}`)
				err := ioutil.WriteFile(cliCfg.Del, delJSON, 0644)
				Expect(err).ShouldNot(HaveOccurred())

				err = cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("With non existing file", func() {
			It("Should trigger an error", func() {
				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     "",
					Del:     "/some/not/existing/file",
					PKI:     &cliPKI,
				}
				err := cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("With folder path instead of file", func() {
			It("Should trigger an error", func() {
				cliCfg := cli.AppFlags{
					Address: serverTestAddress,
					Set:     "",
					Del:     path.Dir(testTmpFolder),
					PKI:     &cliPKI,
				}
				err := cli.ExecuteCommands(&cliCfg)
				Expect(err).Should(HaveOccurred())
			})
		})
	})
})
