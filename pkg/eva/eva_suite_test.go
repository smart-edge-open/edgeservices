// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eva_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/open-ness/common/log"
	"github.com/open-ness/common/proxy/progutil"
	"github.com/open-ness/edgenode/internal/authtest"
	"github.com/open-ness/edgenode/pkg/config"
	"github.com/open-ness/edgenode/pkg/eva"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	cfgFile         eva.Config
	transportCreds  credentials.TransportCredentials
	evaStartTimeout = time.Duration(10) // Starting EVA timeout in seconds
	srvCtx          context.Context     // Context for EVA
	srvCancel       context.CancelFunc
	prefaceLis      *progutil.PrefaceListener
)

// It tak some time for EVA to start services
// waitTillEVAisReady is checking if EVA internal service has started
func waitTillEVAisReady(errorIndication chan error) error {
	timeout := time.After(evaStartTimeout * time.Second)
	tick := time.Tick(100 * time.Millisecond)

	for {
		select {
		case <-timeout:
			// Test is stopped in case timeout
			Fail("Starting EVA: timeout")
		case <-tick:
			conn, err := net.Dial("tcp", cfgFile.EndpointInternal)
			if err == nil {
				conn.Close()
				return nil
			}
		case err := <-errorIndication:
			return err
		}
	}
}

func prepareCredentials(certsDir string) {
	if err := os.MkdirAll(certsDir, 0700); err != nil {

		// In case directory for certificates cannot be created
		// it is not possible to proceed with test.
		Fail(fmt.Sprintf("Creating temp directory for certs failed: %v", err))
	}

	// Run enrollment stub and prepare transport credential
	// In case of error it is not possible to proceed with test.

	Expect(authtest.EnrollStub(certsDir)).ToNot(HaveOccurred())
	var err error
	transportCreds, err = authtest.ClientCredentialsStub()
	_ = transportCreds
	if err != nil {
		Fail(fmt.Sprintf("Creating credentials failed: %v", err))
	}
}

// runEVA set up test framework and starts Edge Virtualization Agent
func runEVA(cfgFilePath string, stopIndication chan bool) error {
	By("Starting EVA")

	if err := config.LoadJSONConfig(cfgFilePath, &cfgFile); err != nil {
		// In case of problem with loading config
		// it is not possible to proceed with test.
		Fail(fmt.Sprintf("LoadJSONConfig() failed: %+v", err))
	}

	//waiting for config file
	for start := time.Now(); time.Since(start) < 3*time.Second; {
		if cfgFile.CertsDir != "" {
			break
		}
	}
	Expect(cfgFile.CertsDir).ToNot(Equal(""))
	Expect(cfgFile.AppImageDir).ToNot(Equal(""))

	prepareCredentials(cfgFile.CertsDir)

	// Starting EVA in a go routine. stopIndication is used to send notice to
	// stopEVA function.
	srvCtx, srvCancel = context.WithCancel(context.Background())
	srvErrChan := make(chan error)
	go func() {
		err := eva.Run(srvCtx, cfgFilePath)
		if err != nil {
			log.Errf("eva.Run exited with error: %+v", err)
			srvErrChan <- err
		}
		stopIndication <- true
	}()

	// Wait until EVA is ready before running tests
	err := waitTillEVAisReady(srvErrChan)

	if err != nil {
		return err
	}
	By("EVA ready")

	return nil
}

// stopEVA stops EVA services after test
func stopEVA(stopIndication chan bool) {
	By("Stopping EVA")
	srvCancel()
	<-stopIndication
}

// createConnection creates all necessary  contexts and connection to EVA
// Following actions must be added in test to cancel timeout and close listener
// and connection:
//
// defer prefaceLis.Close()
// defer conn.Close()
func createConnection() *grpc.ClientConn {
	go prefaceLis.Accept() // Only one connection is expected
	// OP-1742: ContextDialler not supported by Gateway
	//nolint:staticcheck
	conn, err := grpc.Dial("127.0.0.1",
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithDialer(prefaceLis.DialEva))
	if err != nil {
		Fail(fmt.Sprintf("Failed to dial EVA: %v", err))
	}
	return conn
}

func TestEdgeVirtualizationAgent(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Edge Virtualization Agent Suite")
}

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)

	lis, err := net.Listen("tcp", "127.0.0.1:8081")
	if err != nil {
		Fail(fmt.Sprintf("Failed to create server: %v", err))
	}
	prefaceLis = progutil.NewPrefaceListener(lis)
	prefaceLis.RegisterHost("127.0.0.1")
	go prefaceLis.Accept() // Only one connection is expected
})

var _ = AfterSuite(func() {
	// Clean directory for certicates
	os.RemoveAll(cfgFile.CertsDir)
	// Clean directory for applications' data
	os.RemoveAll(cfgFile.AppImageDir)
	prefaceLis.Close()
})
