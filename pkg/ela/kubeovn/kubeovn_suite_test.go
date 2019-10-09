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

package kubeovn_test

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
	"github.com/otcshare/edgenode/pkg/ela"
	"google.golang.org/grpc/credentials"
)

var (
	elaTestEndpoint    = "localhost:42201"
	transportCreds     credentials.TransportCredentials
	controllerEndpoint = "127.0.0.1:8081"
)

func TestKubeovn(t *testing.T) {
	RegisterFailHandler(Fail)

	// Generate certs
	certsDir, err := ioutil.TempDir("", "elaCerts")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(certsDir)
	Expect(authtest.EnrollStub(certsDir)).ToNot(HaveOccurred())
	transportCreds, err = authtest.ClientCredentialsStub()
	Expect(err).NotTo(HaveOccurred())

	// Write ELA's config
	err = ioutil.WriteFile("ela.json", []byte(fmt.Sprintf(`
	{
		"endpoint": "%s",
		"certsDirectory": "%s",
		"KubeOVNMode": true,
		"ControllerEndpoint": "%s"
	}`, elaTestEndpoint, certsDir, controllerEndpoint)), os.FileMode(0644))
	Expect(err).NotTo(HaveOccurred())

	// Set up ELA server
	srvErrChan := make(chan error)
	srvCtx, srvCancel := context.WithCancel(context.Background())
	go func() {
		err := ela.Run(srvCtx, "ela.json")
		if err != nil {
			log.Errf("ela.Run exited with error: %+v", err)
		}
		srvErrChan <- err
	}()
	defer func() {
		srvCancel()
		<-srvErrChan
	}()

	//waiting for ela.json
	for start := time.Now(); time.Since(start) < 3*time.Second; {
		if ela.Config.ControllerEndpoint != "" {
			break
		}
	}
	Expect(ela.Config.ControllerEndpoint).ToNot(Equal(""))

	RunSpecs(t, "kube-ovn mode ELA suite")
}

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)
})

var _ = AfterSuite(func() {
	os.Remove("ela.json")
})
