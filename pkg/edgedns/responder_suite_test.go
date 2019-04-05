// Copyright 2019 Smart-Edge.com, Inc. All rights reserved.
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
package edgedns_test

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	. "github.com/onsi/gomega"

	"github.com/smartedgemec/appliance-ce/pkg/edgedns"
	"github.com/smartedgemec/appliance-ce/pkg/edgedns/grpc"
	"github.com/smartedgemec/appliance-ce/pkg/edgedns/storage"
)

var dnsServer *edgedns.Responder
var idleConnsClosed chan struct{}

func TestDns(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Edge DNS Integration Suite")
}

const eport = 60420

var _ = BeforeSuite(func() {
	var err error
	pn := config.GinkgoConfig.ParallelNode
	port := eport + pn
	addr4 := "127.0.0.1"
	sock := fmt.Sprintf("dns_%d.sock", pn)
	db := fmt.Sprintf("dns_%d.db", pn)

	cfg := edgedns.Config{
		Addr4: addr4,
		Port:  port,
	}

	stg := &storage.BoltDB{
		Filename: db,
	}

	ctl := &grpc.ControlServer{
		Sock: sock,
	}

	dnsServer = edgedns.NewResponder(cfg, stg, ctl)
	idleConnsClosed = make(chan struct{})
	go func() {
		err = dnsServer.Start()

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		signal.Notify(dnsServer.Sig, syscall.SIGINT, syscall.SIGTERM)

		// Receive OS signals and listener errors from Start()
		s := <-dnsServer.Sig
		switch s {
		case syscall.SIGCHLD:
			fmt.Println("Child listener/service unexpectedly died")
		default:
			fmt.Printf("Signal (%v) received\n", s)
		}
		dnsServer.Stop()
		os.Remove(stg.Filename)
		close(idleConnsClosed)
	}()

	// Wait for listeners
	time.Sleep(1 * time.Second)
})

var _ = AfterSuite(func() {
	// Signal Shutdown
	select {
	case dnsServer.Sig <- syscall.SIGINT:
		fmt.Println("Stopping test server")
	default:
		fmt.Println("Shutdown receiver already executed.")
	}

	// Wait for Shutdown to complete
	<-idleConnsClosed
})
