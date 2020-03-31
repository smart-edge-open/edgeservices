// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package cni

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	evapb "github.com/open-ness/edgenode/pkg/eva/pb"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetTypeFromCNIConfig", func() {
	When("given config with type field", func() {
		It("returns the value of type field", func() {
			cniType, err := GetTypeFromCNIConfig(`{"cniVersion": "0.4.0", "name": "openness-ovn", "type": "ovn" }`)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cniType).To(Equal("ovn"))
		})
	})

	When("given config with type field missing", func() {
		It("returns an error and empty value", func() {
			cniType, err := GetTypeFromCNIConfig(`{"cniVersion": "0.4.0", "name": "openness-ovn" }`)
			Expect(err).Should(HaveOccurred())
			Expect(cniType).To(Equal(""))
		})
	})
})

var _ = Describe("CNIInvoker", func() {
	testCniScript := `#!/bin/sh
STDIN=$(cat -)                          # read stdin
STDIN=${STDIN//\"/\'}                   # switch quotes to single quotes
ENVS=$(env | grep CNI_ | tr '\n' ',')   # get CNI envs and make it one line
echo "{\"cniVersion\":\"0.4.0\",\"interfaces\":[{\"name\":\"eth1\"}],\"stdin\":\"${STDIN}\",\"envs\":\"${ENVS}\"}"
>&2 echo "dummy log with stdin on stderr: ${STDIN}"
`
	defaultCniBinDir = "/tmp"
	hostNSPath = "/proc/1/ns/net"
	testCniScriptName := "openness-cni-test-script"

	cniPath := filepath.Join(defaultCniBinDir, testCniScriptName)

	cniConf := &evapb.CNIConfiguration{
		CniConfig:     fmt.Sprintf(`{ "type": "%s" }`, testCniScriptName),
		InterfaceName: "eth0",
		Path:          "/root",
		Args:          "appID=test;subnetID=ovn-default;mtu=0",
	}

	BeforeEach(func() {
		err := ioutil.WriteFile(cniPath, []byte(testCniScript), 0755)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		err := os.Remove(cniPath)
		Expect(err).ToNot(HaveOccurred())
	})

	It("invokes CNI executable and returns the result", func() {
		cniInvoker := NewCNIInvoker(InfrastructureContainerInfo{ID: "1111-2222", PID: 13}, cniConf, Add)
		result, err := cniInvoker.Invoke()

		Expect(err).ToNot(HaveOccurred())

		var res struct {
			CniVersion string
			Stdin      string
			Envs       string
		}

		err = json.Unmarshal([]byte(result), &res)
		Expect(err).ToNot(HaveOccurred())
		Expect(res.CniVersion).To(Equal("0.4.0"))
		Expect(res.Stdin).To(ContainSubstring("'type': 'openness-cni-test-script'"))
		Expect(res.Envs).To(ContainSubstring("CNI_COMMAND=ADD"))
		Expect(res.Envs).To(ContainSubstring("CNI_IFNAME=eth0"))
		Expect(res.Envs).To(ContainSubstring("CNI_NETNS=/proc/13/ns/net"))
		Expect(res.Envs).To(ContainSubstring("CNI_CONTAINERID=1111-2222"))
		Expect(res.Envs).To(ContainSubstring("CNI_PATH=/root"))
	})
})
