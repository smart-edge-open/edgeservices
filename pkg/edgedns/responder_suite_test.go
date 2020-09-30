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
var dnsServerErrDbFile *edgedns.Responder
var dnsServerErrAddr4Missing *edgedns.Responder
var dnsServerAddrSockMissing *edgedns.Responder
var dnsServerServer4Error *edgedns.Responder
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
	dbErrAddr4Missing := fmt.Sprintf("dns_aadr4_missing_%d.db", pn)
	dbErraddrSockMissing := fmt.Sprintf("dns_aadr_sock_missing_%d.db", pn)
	dbServer4Error := fmt.Sprintf("dns_server4_err_%d.db", pn)

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

	//Error scenario config. It cause error in Start() function by missing
	//db filename missing..
	stgErrDbNameMissing := &storage.BoltDB{Filename: ""}
	cfgErrDbNameMissing := edgedns.Config{
		Addr4: addr4,
		Port:  port + 1,
	}

	sockDbNameMissing := fmt.Sprintf("dns_%d.sock", pn+1)
	ctlErrDbNameMissing := &grpc.ControlServer{
		Sock: sockDbNameMissing,
	}

	dnsServerErrDbFile = edgedns.NewResponder(cfgErrDbNameMissing,
		stgErrDbNameMissing, ctlErrDbNameMissing)

	//Error scenario config. It cause error in Start() function
	//by Addr4 config missing.
	stgErrAddr4eMissing := &storage.BoltDB{Filename: dbErrAddr4Missing}
	cfgErrAddr4Missing := edgedns.Config{
		Addr4: "",
		Port:  0,
	}
	sockAddr4Missing := fmt.Sprintf("dns_%d.sock", pn+1)
	ctlErrAddr4Missing := &grpc.ControlServer{
		Sock: sockAddr4Missing,
	}

	dnsServerErrAddr4Missing = edgedns.NewResponder(cfgErrAddr4Missing,
		stgErrAddr4eMissing, ctlErrAddr4Missing)

	//Error scenario config. It cause error in Start() function
	//by missing address and socket in ControlServer structure.
	stgErraddrSockMissing := &storage.BoltDB{Filename: dbErraddrSockMissing}
	cfgErraddrSockMissing := edgedns.Config{
		Addr4: addr4,
		Port:  port + 2,
	}

	ctlErraddrSockMissing := &grpc.ControlServer{
		Sock:    "",
		Address: "",
	}

	dnsServerAddrSockMissing = edgedns.NewResponder(cfgErraddrSockMissing,
		stgErraddrSockMissing, ctlErraddrSockMissing)

	//Errors cause by dns.Server invalid IPv4 IP address.
	cfgErrInvalidIpv4 := edgedns.Config{
		Addr4: "In.valid.addres",
		Port:  port + 2,
	}

	stgErrInvalidIpv4 := &storage.BoltDB{Filename: dbServer4Error}

	sockServer4InvalidIpv4 := "invalid_ip_v4.sock"
	ctlErrInvalidIpv4 := &grpc.ControlServer{
		Sock: sockServer4InvalidIpv4,
	}

	dnsServerServer4Error = edgedns.NewResponder(cfgErrInvalidIpv4,
		stgErrInvalidIpv4, ctlErrInvalidIpv4)

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

	go func() {
		os.Remove(sockDbNameMissing)
		os.Remove(sockAddr4Missing)
		os.Remove(dbErrAddr4Missing)
		os.Remove(dbErraddrSockMissing)
		os.Remove(sockServer4InvalidIpv4)
		os.Remove(dbServer4Error)
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
