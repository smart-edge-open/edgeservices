// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	log "github.com/otcshare/common/log"
	"github.com/otcshare/edgenode/internal/authtest"
	"github.com/otcshare/edgenode/pkg/config"
	"github.com/otcshare/edgenode/pkg/eva"
	"google.golang.org/grpc/credentials"
)

var (
	cfgFile            eva.Config
	transportCreds     credentials.TransportCredentials
	controllerEndpoint = "127.0.0.1:8081"
	evaStartTimeout    = time.Duration(10) // Timeout in seconds for starting EVA
	srvCtx             context.Context     // Context for EVA
	srvCancel          context.CancelFunc
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

// runEVA set up test framework and starts Edge Virtualization Agent
func runEVA(cfgFilePath string, stopIndication chan bool) error {
	By("Starting EVA")

	if err := config.LoadJSONConfig(cfgFilePath, &cfgFile); err != nil {
		// In case of problem with loading config
		// it is not possible to proceed with test.
		Fail(fmt.Sprintf("LoadJSONConfig() failed: %+v", err))
	}

	if err := os.MkdirAll(cfgFile.CertsDir, 0700); err != nil {
		// In case directory for certificates cannot be created
		// it is not possible to proceed with test.
		Fail(fmt.Sprintf("Creating temp directory for certs failed: %v", err))
	}

	// Run enrollment stub and prepare transport credential
	// In case of error it is not possible to proceed with test.
	Expect(authtest.EnrollStub(cfgFile.CertsDir)).ToNot(HaveOccurred())
	transportCreds, err := authtest.ClientCredentialsStub()
	_ = transportCreds
	if err != nil {
		Fail(fmt.Sprintf("Creating credentials failed: %v", err))
	}

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
	err = waitTillEVAisReady(srvErrChan)
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

func TestEdgeVirtualizationAgent(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Edge Virtualization Agent Suite")
}

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)
})
var _ = AfterSuite(func() {
	// Remove directory for certicates
	os.RemoveAll(cfgFile.CertsDir)
	// Remove direcotry for applications' data
	os.RemoveAll(cfgFile.AppImageDir)
})
