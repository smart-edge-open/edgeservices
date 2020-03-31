// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package ovncni_test

import (
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"

	"encoding/json"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	. "github.com/open-ness/edgenode/pkg/ovncni"
)

func createNamespace(nsName string) error {

	if nsName == "" {
		return errors.Errorf("Namespace name is empty")
	}
	cmd := exec.Command("ip", "netns", "add", nsName)
	err := cmd.Run()
	return err
}

func destroyNamespace(nsName string) error {

	if nsName == "" {
		return errors.Errorf("Namespace name is empty")
	}
	cmd := exec.Command("ip", "netns", "delete", nsName)
	err := cmd.Run()
	return err
}

// checks if namespace contains interface
func namespaceContainsInterface(nsName, nsIf string) bool {

	if nsName == "" || nsIf == "" {
		Fail("Namespace or interface name is empty")
	}
	cmd := exec.Command("ip", "netns", "exec", "ovncni_ns", "ip", "link")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Fail("Failed to list interfaces in namespace " + nsName)
	}

	return strings.Contains(string(out), nsIf)

}

var _ = Describe("Ovncni", func() {

	Context("OVNCNI context ", func() {

		var (
			argStruct     skel.CmdArgs
			testContext   CNIContext
			namespaceName string
			namespacePath string
			ifName        string
			testAppID     string
			testSubnetID  string
		)
		const (
			correctIPandMask = "192.0.120.1/24"
			correctMacAndIP  = "0a:0a:0a:0a:0a:0a 192.100.2.100"
		)
		BeforeEach(func() {

			ipamConfig := IPAMConfig{
				Type:    "ovn",
				Gateway: net.ParseIP("8.8.8.8"),
			}

			cniConfig := CNIConfig{
				IPAM: ipamConfig,
			}

			cniConfigJSON, err := json.Marshal(cniConfig)
			if err != nil {
				Fail(err.Error())
			}
			testAppID = "test_app_id"
			testSubnetID = "subnet_id"

			argStruct.StdinData = cniConfigJSON
			argStruct.Args = ""
			argStruct.Args += "appID=" + testAppID + ";"
			argStruct.Args += "subnetID=" + testSubnetID + ";"

			namespaceName = "ovncni_ns"
			namespacePath = "/var/run/netns/" + namespaceName
			ifName = "ovncni_if"
			testContext, err = GetContext(&argStruct)
			if err != nil {
				Fail(err.Error())
			}
			testContext.Args.Netns = namespacePath
			testContext.Args.IfName = ifName

			err = createNamespace(namespaceName)
			Expect(err).To(BeNil())
		})

		AfterEach(func() {
			err := destroyNamespace(namespaceName)
			if err != nil {
				Fail(err.Error())
			}
		})

		Specify("adds port", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbCtlCommand

			// pass configIF function
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", nil

			}
			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Add()
			Expect(err).To(BeNil())
			nsExists := namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeTrue())
		})

		Specify("Add fails if ovs fails to add port", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				return "", errors.Errorf("Faild to find port")
			}
			NbCtlCommand = testNbCtlCommand

			// pass configIF function
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", errors.Errorf("Failed to add port")
			}
			OvsVsctlExec = testOvsVsctlExec

			err := testContext.Add()
			Expect(err).NotTo(BeNil())
			nsExists := namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeFalse())
		})

		Specify("adds the same port twice and fails second time", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbCtlCommand

			// pass configIF function
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", nil
			}

			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Add()
			Expect(err).To(BeNil())
			nsExists := namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeTrue())
			//adding second time
			err = testContext.Add()
			Expect(err).NotTo(BeNil())
		})

		Specify("deletes existing port", func() {

			var testNbctlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbctlCommand

			// pass configIF function
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", nil

			}
			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Add()
			Expect(err).To(BeNil())
			nsExists := namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeTrue())

			err = testContext.Del()
			Expect(err).To(BeNil())
			nsExists = namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeFalse())

		})

		Specify("Del fails while ovs fails to remove from bridge", func() {

			var testNbctlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbctlCommand

			// pass configIF function
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", nil

			}
			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Add()
			Expect(err).To(BeNil())
			nsExists := namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeTrue())

			testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", errors.Errorf("Failed to remove from ovs bridge")
			}
			OvsVsctlExec = testOvsVsctlExec
			err = testContext.Del()
			Expect(err).NotTo(BeNil())

		})

		Specify("deletes non existing port", func() {
			var err error
			// pass configIF function
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", nil
			}
			OvsVsctlExec = testOvsVsctlExec
			nsExists := namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeFalse())

			err = testContext.Del()
			Expect(err).NotTo(BeNil())
			nsExists = namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeFalse())

		})

		Specify("deletes existing port twice", func() {

			var testNbctlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbctlCommand

			// pass configIF function
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", nil

			}
			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Add()
			Expect(err).To(BeNil())
			nsExists := namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeTrue())

			err = testContext.Del()
			Expect(err).To(BeNil())
			nsExists = namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeFalse())

			err = testContext.Del()
			Expect(err).NotTo(BeNil())
			nsExists = namespaceContainsInterface(namespaceName, ifName)
			Expect(nsExists).To(BeFalse())
		})

		Specify("check fails with no ovn port", func() {

			var testNbctlCommand = func(path string, timeout int, args ...string) (string, error) {
				return "", errors.Errorf("Ovn doesn't find port")
			}
			NbCtlCommand = testNbctlCommand

			err := testContext.Check()

			Expect(err).NotTo(BeNil())

		})

		Specify("check fails with no ovs interface", func() {

			var testNbctlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbctlCommand

			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", errors.Errorf("Failed to find interface")
			}
			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Check()

			Expect(err).NotTo(BeNil())

		})

		Specify("check fails if appID and interface ID doesn't match", func() {

			var testNbctlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbctlCommand

			//function passes with no error but id is invalid
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return "", nil
			}
			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Check()

			Expect(err).NotTo(BeNil())

		})
		Specify("check passes with correct input", func() {

			var testNbctlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", testContext.AppID)) {
					return correctMacAndIP, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", testContext.Subnet)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbctlCommand

			//function passes with no error but id is invalid
			var testOvsVsctlExec = func(path string, args ...string) (string, error) {
				return testAppID, nil
			}
			OvsVsctlExec = testOvsVsctlExec
			err := testContext.Check()

			Expect(err).To(BeNil())

		})
	})

	Context("OVNCNI GetContext", func() {
		var (
			argStruct skel.CmdArgs
		)
		BeforeEach(func() {

			ipamConfig := IPAMConfig{
				Type:    "ovn",
				Gateway: net.ParseIP("8.8.8.8"),
			}

			cniConfig := CNIConfig{
				IPAM: ipamConfig,
			}

			cniConfigJSON, err := json.Marshal(cniConfig)
			if err != nil {
				Fail(err.Error())
			}
			argStruct.StdinData = cniConfigJSON
			argStruct.Args = ""
			argStruct.Args += "appID=app_id;"
			argStruct.Args += "subnetID=subnet_id;"
		})

		Specify("changes default bridgename", func() {
			testBridgeName := "testBridge"
			argStruct.Args += "ovsBrName=" + testBridgeName + ";"
			c, err := GetContext(&argStruct)

			Expect(err).To(BeNil())
			Expect(c.OvsBrName).To(Equal(testBridgeName))
		})

		Specify("nbCtlPath path in args", func() {
			newPath := "/path/to/nbCtlPath"
			argStruct.Args += "nbCtlPath=" + newPath + ";"
			c, err := GetContext(&argStruct)

			Expect(err).To(BeNil())
			Expect(c.OVNCli.GetNbCtlPath()).To(Equal(newPath))
		})

		Specify("changes default ovs ctl path", func() {
			testPath := "./path/example/path"
			argStruct.Args += "ovsCtlPath=" + testPath + ";"
			c, err := GetContext(&argStruct)

			Expect(err).To(BeNil())
			Expect(c.OvsCtlPath).To(Equal(testPath))
		})

		Specify("changes default ovs ctl path", func() {
			testPath := "./path/example/path"
			argStruct.Args += "ovsCtlPath=" + testPath + ";"
			c, err := GetContext(&argStruct)

			Expect(err).To(BeNil())
			Expect(c.OvsCtlPath).To(Equal(testPath))
		})

		Specify("changes default mtu setting", func() {
			argStruct.Args += "mtu=2;"
			c, err := GetContext(&argStruct)

			Expect(err).To(BeNil())
			Expect(c.IfMTU).To(Equal(uint64(2)))
		})

		Specify("mut setting must number", func() {
			argStruct.Args += "mtu=3zt;"
			_, err := GetContext(&argStruct)

			Expect(err).NotTo(BeNil())
		})

		Specify("hostname longer than 15 chars will be clipped", func() {
			argStruct.Args = ""
			argStruct.Args += "appID=appidthatislongerthanfifteen;"
			argStruct.Args += "subnetID=test_subnet_id;"
			c, err := GetContext(&argStruct)

			Expect(err).To(BeNil())
			Expect(c.HostIfName).To(Equal("appidthatislong"))
		})

		Specify("fails without app id", func() {
			argStruct.Args = "ovsCtlPath=/root/example/path;"
			argStruct.Args += "subnetID=subnet543;"
			_, err := GetContext(&argStruct)

			Expect(err).NotTo(BeNil())
		})

		Specify("fails without subnet id", func() {
			argStruct.Args = "ovsCtlPath=/root/example/path;"
			argStruct.Args += "appID=app_id;"
			_, err := GetContext(&argStruct)

			Expect(err).NotTo(BeNil())
		})

		Specify("fails with invalid input json", func() {
			//invalid json
			argStruct.StdinData = []byte("{}}")
			_, err := GetContext(&argStruct)
			Expect(err).NotTo(BeNil())
		})

		Specify("checks and fails if IPAM type is different than 'ovn'", func() {
			ipamConfig := IPAMConfig{
				Type:    "kubeovn",
				Gateway: net.ParseIP("8.8.8.8"),
			}

			cniConfig := CNIConfig{
				IPAM: ipamConfig,
			}

			cniConfigJSON, err := json.Marshal(cniConfig)
			if err != nil {
				Fail(err.Error())
			}
			argStruct.StdinData = cniConfigJSON

			_, err = GetContext(&argStruct)
			Expect(err).NotTo(BeNil())
		})
	})

})
