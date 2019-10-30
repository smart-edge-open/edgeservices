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
	log "github.com/otcshare/common/log"
	"github.com/otcshare/edgenode/internal/authtest"
	"github.com/otcshare/edgenode/pkg/interfaceservice"
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
		err := interfaceservice.Run(srvCtx, "interfaceservice.json")
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
})
