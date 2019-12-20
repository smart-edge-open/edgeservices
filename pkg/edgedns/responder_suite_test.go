// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation
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

	"github.com/open-ness/edgenode/pkg/edgedns"
	"github.com/open-ness/edgenode/pkg/edgedns/grpc"
	"github.com/open-ness/edgenode/pkg/edgedns/storage"
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
