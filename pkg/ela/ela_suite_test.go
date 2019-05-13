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

package ela_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Flaque/filet"
	"github.com/smartedgemec/appliance-ce/pkg/ela"
	"github.com/smartedgemec/log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var elaTestEndpoint = "localhost:42101"

func TestEdgeLifecycleAgent(t *testing.T) {
	defer filet.CleanUp(t)
	RegisterFailHandler(Fail)
	filet.File(t, "ela.json", fmt.Sprintf(`
	{
		"endpoint": "%s"
	}`, elaTestEndpoint))

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

	RunSpecs(t, "Edge Life Cycle Agent suite")
}

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)
})
