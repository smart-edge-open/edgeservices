// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cli_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/otcshare/edgecontroller/edgednscli"
)

var (
	testTmpFolder string
	cliPKI        cli.PKIPaths
	fakeSvr       *ControlServer
)

const serverTestAddress = "localhost:14204"

func TestCli(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cli Suite")
}

var _ = BeforeSuite(func() {

	var err error

	testTmpFolder, err = ioutil.TempDir("/tmp", "dns_test")
	Expect(err).ShouldNot(HaveOccurred())

	Expect(prepareTestCredentials(testTmpFolder)).ToNot(HaveOccurred())

	cliPKI = cli.PKIPaths{
		CrtPath:            filepath.Join(testTmpFolder, "c_cert.pem"),
		KeyPath:            filepath.Join(testTmpFolder, "c_key.pem"),
		CAPath:             filepath.Join(testTmpFolder, "cacerts.pem"),
		ServerNameOverride: "",
	}

	pki := &ControlServerPKI{
		Crt: filepath.Join(testTmpFolder, "cert.pem"),
		Key: filepath.Join(testTmpFolder, "key.pem"),
		CA:  filepath.Join(testTmpFolder, "cacerts.pem"),
	}

	fakeSvr = &ControlServer{
		Address: serverTestAddress,
		PKI:     pki,
	}

	Expect(fakeSvr.StartServer()).ToNot(HaveOccurred())

	time.Sleep(1 * time.Second)
})

var _ = AfterSuite(func() {
	Expect(fakeSvr.GracefulStop()).ToNot(HaveOccurred())

	err := os.RemoveAll(testTmpFolder)
	Expect(err).ShouldNot(HaveOccurred())
})
