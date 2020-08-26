// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package main_test

import (
	"log"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	Iserv InterfaceServiceServer //fake server

	HelpOut = `
    Get or attach/detach network interfaces to OVS on remote edge node

    -endpoint      Endpoint to be requested
    -servicename   Name to be used as server name for TLS handshake
    -cmd           Supported commands: get, attach, detach
    -pci           PCI address for attach and detach commands. Multiple addresses can be passed
                   and must be separated by commas: -pci=0000:00:00.0,0000:00:00.1
    -brg           OVS bridge an interface would be attached to: -brg=br-local
    -drv           Driver that would be used: -drv=kernel
    -certsdir      Directory where cert.pem and key.pem for client and root.pem for CA resides   
    -timeout       Timeout value [s] for grpc requests

	`

	WarningOut = "Unrecognized action: " + "test123\n" + HelpOut
)

func TestCli(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "interfaceservicecli suite")
}

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)

	CertsDir := "./certs"
	err := os.MkdirAll(CertsDir, os.ModePerm)
	Expect(err).ShouldNot(HaveOccurred())

	Expect(prepareTestCredentials(CertsDir)).ToNot(HaveOccurred())
	Iserv = InterfaceServiceServer{
		Endpoint: "localhost:2020",
	}
	Expect(Iserv.StartServer()).ToNot(HaveOccurred())
	time.Sleep(1 * time.Second)
})

var _ = AfterSuite(func() {
	err := os.RemoveAll("./certs")
	Expect(err).ShouldNot(HaveOccurred())
	Expect(Iserv.GracefulStop()).ToNot(HaveOccurred())
})
