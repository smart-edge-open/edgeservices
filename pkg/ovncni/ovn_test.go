// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package ovncni_test

import (
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/open-ness/edgenode/pkg/ovncni"
	"github.com/pkg/errors"
)

func buildArgList(args ...string) string {
	return strings.Join(args, " ")
}

var _ = Describe("Ovn", func() {

	Context("OVNClient get port ", func() {
		const (
			lSwitch          = "lSwitch"
			id               = "exampleID"
			correctIPandMac  = "0a:0a:0a:0a:0a:0a 192.100.2.100"
			correctIPandMask = "192.0.120.1/24"
		)

		Specify("receives wrong ovs port address", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("logical_switch_port", id)) {
					return "00:00:00:00:00:00192.0.2.100", nil
				}
				return "", nil
			}

			NbCtlCommand = testNbCtlCommand
			ovnClient := GetOVNClient("", 100)

			_, err := ovnClient.GetPort(lSwitch, id)
			Expect(err).NotTo(BeNil())

		})

		Specify("receives invalid mac address", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("logical_switch_port", id)) {
					return "00:00:00:00:0z:00 192.0.2.100", nil
				}
				return "", nil
			}

			NbCtlCommand = testNbCtlCommand
			ovnClient := GetOVNClient("", 100)

			_, err := ovnClient.GetPort(lSwitch, id)
			Expect(err).NotTo(BeNil())

		})

		Specify("receives invalid IP address", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("logical_switch_port", id)) {
					return "0a:0a:0a:0a:0a:0a 192.300.2.100", nil
				}
				return "", nil
			}

			NbCtlCommand = testNbCtlCommand
			ovnClient := GetOVNClient("", 100)

			_, err := ovnClient.GetPort(lSwitch, id)
			Expect(err).NotTo(BeNil())

		})

		Specify("fails to get subnet OVN switch", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {

				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("logical_switch_port", id)) {
					return correctIPandMac, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", lSwitch)) {
					return correctIPandMask, errors.Errorf("get subnet ovn fail")
				}
				return "", nil
			}

			NbCtlCommand = testNbCtlCommand
			ovnClient := GetOVNClient("", 100)

			_, err := ovnClient.GetPort(lSwitch, id)
			Expect(err).NotTo(BeNil())

		})

		Specify("gets invalid subnet address", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("logical_switch_port", id)) {
					return correctIPandMac, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", lSwitch)) {
					return "192.0.320.1/24", nil
				}
				return "", nil
			}

			NbCtlCommand = testNbCtlCommand
			ovnClient := GetOVNClient("", 100)

			_, err := ovnClient.GetPort(lSwitch, id)
			Expect(err).NotTo(BeNil())

		})

		Specify("fails to get dynamic address", func() {

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("logical_switch_port", id, "dynamic-addresses")) {
					return correctIPandMac, errors.Errorf("getting dynamic address fails")
				}
				return "", nil
			}

			NbCtlCommand = testNbCtlCommand
			ovnClient := GetOVNClient("", 100)

			_, err := ovnClient.GetPort(lSwitch, id)
			Expect(err).NotTo(BeNil())

		})
	})

	Context("OVNClinet ", func() {

		Specify("can be created", func() {
			c := GetOVNClient("", 100)

			Expect(c).NotTo(BeNil())
		})

		Specify("can create port with ip provided", func() {

			id := "example_id"
			ipOut := "192.0.2.100"
			mac := "00:00:00:00:00:00"
			ipIn := ""
			lSwitch := "test_lswitch"

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("set", "logical_switch_port", id)) {
					return mac + " " + ipOut, nil
				}
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port")) {
					return mac + " " + ipOut, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch")) {
					return ipOut + "/24", nil
				}
				if strings.Contains(concArgs, buildArgList("dhcp_options")) {
					return "dhcp_option_id", nil
				}

				return "", nil
			}

			NbCtlCommand = testNbCtlCommand

			ovnClient := GetOVNClient("", 100)
			Expect(ovnClient).NotTo(BeNil())
			os.Setenv("HOST_HOSTNAME", "test")
			lport, err := ovnClient.CreatePort(lSwitch, id, ipIn)
			os.Unsetenv("HOST_HOSTNAME")
			Expect(err).To(BeNil())
			Expect(lport.ID).To(Equal(id))
			Expect(lport.IP.String()).To(Equal(ipOut))
		})

	})

	Context("Create port", func() {

		const (
			correctIPandMac  = "0a:0a:0a:0a:0a:0a 192.100.2.100"
			correctIPandMask = "192.0.120.1/24"
			lSwitchName      = "logicalSwitch"
		)

		Specify("fails without lSwitch AND id", func() {

			ovnClient := GetOVNClient("", 100)
			Expect(ovnClient).NotTo(BeNil())

			_, err := ovnClient.CreatePort("", "", "192.168.1.1")
			Expect(err).NotTo(BeNil())

		})

		Specify("fails to create port security", func() {

			id := "testexampleid"
			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, "lsp-set-port-security") {
					return "lsp-set-port-security", errors.Errorf("Setting port security failed")
				}
				// pass GetPort function
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port", id)) {
					return correctIPandMac, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch", lSwitchName)) {
					return correctIPandMask, nil
				}
				return "", nil
			}
			NbCtlCommand = testNbCtlCommand

			ovnClient := GetOVNClient("", 0)
			Expect(ovnClient).NotTo(BeNil())

			_, err := ovnClient.CreatePort(lSwitchName, id, "192.168.1.1")
			Expect(err).NotTo(BeNil())
		})

		Specify("fails to create dynamic port", func() {
			id := "newID"
			ip := "192.168.1.201"

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("lsp-add", lSwitchName, id)) &&
					strings.Contains(concArgs, buildArgList("lsp-set-addresses", id, "dynamic", ip)) {

					return "", errors.Errorf("Failed to create dynamic port")
				}

				return "", nil
			}

			NbCtlCommand = testNbCtlCommand

			ovnClient := GetOVNClient("", 100)
			Expect(ovnClient).NotTo(BeNil())

			_, err := ovnClient.CreatePort(lSwitchName, id, ip)
			Expect(err).NotTo(BeNil())
		})

		Specify("fails to create dynamic port", func() {
			id := "123-543-avc"
			ip := ""

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("lsp-add", lSwitchName, id)) &&
					strings.Contains(concArgs, buildArgList("set logical_switch_port", id, "addresses=dynamic")) {
					return correctIPandMac, errors.Errorf("Failed to create dynamic port without ip")
				}

				return "", nil
			}

			NbCtlCommand = testNbCtlCommand

			ovnClient := GetOVNClient("some/path", 100)
			Expect(ovnClient).NotTo(BeNil())

			_, err := ovnClient.CreatePort(lSwitchName, id, ip)
			Expect(err).NotTo(BeNil())
		})

	})

	Context("Delete port ", func() {

		Specify("fails with failure", func() {
			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {

				return "", errors.Errorf("Failed to delete port")
			}
			NbCtlCommand = testNbCtlCommand

			ovnClient := GetOVNClient("some/path", 100)
			Expect(ovnClient).NotTo(BeNil())

			err := ovnClient.DeletePort("id")
			Expect(err).NotTo(BeNil())

		})

		Specify("success when command passes", func() {
			id := "example_id"
			ipOut := "192.0.2.100"
			mac := "00:00:00:00:00:00"

			var testNbCtlCommand = func(path string, timeout int, args ...string) (string, error) {
				concArgs := strings.Join(args, " ")
				if strings.Contains(concArgs, buildArgList("set", "logical_switch_port", id)) {
					return mac + " " + ipOut, nil
				}
				if strings.Contains(concArgs, buildArgList("wait-until", "logical_switch_port")) {
					return mac + " " + ipOut, nil
				}
				if strings.Contains(concArgs, buildArgList("get", "logical_switch")) {
					return ipOut + "/24", nil
				}
				return "", nil
			}
			NbCtlCommand = testNbCtlCommand

			ovnClient := GetOVNClient("some/path", 100)
			Expect(ovnClient).NotTo(BeNil())

			err := ovnClient.DeletePort(id)
			Expect(err).To(BeNil())

		})

	})
})
