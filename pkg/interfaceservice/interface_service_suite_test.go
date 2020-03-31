// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package interfaceservice_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/internal/authtest"
	"github.com/open-ness/edgenode/pkg/interfaceservice"
	"google.golang.org/grpc/credentials"
)

var (
	testEndpoint   = "localhost:42201"
	transportCreds credentials.TransportCredentials
)

func TestInterfaceService(t *testing.T) {
	RegisterFailHandler(Fail)

	// Generate certs
	certsDir, err := ioutil.TempDir("", "elaCerts")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(certsDir)
	Expect(authtest.EnrollStub(certsDir)).ToNot(HaveOccurred())
	transportCreds, err = authtest.ClientCredentialsStub()
	Expect(err).NotTo(HaveOccurred())

	prepareMocks()
	vsctlMock.AddResult("", nil) //resp for reattachDpdkPorts()

	// Write ELA's config
	err = ioutil.WriteFile("interfaceservice.json", []byte(fmt.Sprintf(`
	{
		"endpoint": "%s",
		"certsDirectory": "%s"
	}`, testEndpoint, certsDir)), os.FileMode(0644))
	Expect(err).NotTo(HaveOccurred())

	// Set up InterfaceService server
	srvErrChan := make(chan error)
	srvCtx, srvCancel := context.WithCancel(context.Background())
	go func() {
		err := ioutil.WriteFile("./dpdk-devbind.py", []byte{}, os.ModePerm)
		Expect(err).NotTo(HaveOccurred())
		err = interfaceservice.Run(srvCtx, "interfaceservice.json")
		if err != nil {
			log.Errf("interfaceservice.Run exited with error: %+v", err)
		}
		srvErrChan <- err
	}()
	defer func() {
		srvCancel()
		<-srvErrChan
	}()

	//waiting for interfaceservice.json
	for start := time.Now(); time.Since(start) < 3*time.Second; {
		if interfaceservice.Config.Endpoint != "" {
			break
		}
	}
	Expect(interfaceservice.Config.Endpoint).ToNot(Equal(""))
	RunSpecs(t, "InterfaceService test suite")
}

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)
})

var _ = AfterSuite(func() {
	os.Remove("interfaceservice.json")
	os.Remove("./dpdk-devbind.py")
})
