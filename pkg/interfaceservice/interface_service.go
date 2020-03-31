// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package interfaceservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/config"

	"github.com/open-ness/edgenode/pkg/auth"
	pb "github.com/open-ness/edgenode/pkg/interfaceservice/pb"
	"github.com/open-ness/edgenode/pkg/util"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Configuration describes JSON configuration
type Configuration struct {
	Endpoint          string        `json:"Endpoint"`
	HeartbeatInterval util.Duration `json:"HeartbeatInterval"`
	CertsDir          string        `json:"CertsDirectory"`
}

var (
	log = logger.DefaultLogger.WithField("interface-service", nil)
	// Config instantiate a configuration
	Config Configuration

	// DpdkEnabled var specifies if interface service can use DPDK drivers
	DpdkEnabled = true
)

func runServer(ctx context.Context) error {
	crtPath := filepath.Join(Config.CertsDir, auth.CertName)
	keyPath := filepath.Join(Config.CertsDir, auth.KeyName)
	caPath := filepath.Join(Config.CertsDir, auth.CAPoolName)

	srvCert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		log.Errf("Failed load server key pair: %v", err)
		return err
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(filepath.Clean(caPath))
	if err != nil {
		log.Errf("Failed read ca certificates: %v", err)
		return err
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Errf("Failed appends CA certs from %s", caPath)
		return errors.Errorf("Failed appends CA certs from %s", caPath)
	}

	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    certPool,
	})

	lis, err := net.Listen("tcp", Config.Endpoint)

	if err != nil {
		log.Errf("net.Listen error: %+v", err)
		return err
	}

	grpcServer := grpc.NewServer(grpc.Creds(creds))

	interfaceService := InterfaceService{}
	pb.RegisterInterfaceServiceServer(grpcServer, &interfaceService)

	go func() {
		<-ctx.Done()
		log.Info("Executing graceful stop")
		grpcServer.GracefulStop()
	}()

	defer log.Info("Stopped serving")

	log.Infof("Serving on: %s", Config.Endpoint)

	util.Heartbeat(ctx, Config.HeartbeatInterval, func() {
		log.Info("Heartbeat")
	})

	// When Serve() returns, listener is closed
	err = grpcServer.Serve(lis)
	if err != nil {
		log.Errf("grpcServer.Serve error: %+v", err)
	}
	return err
}

// Run function runs a Interface Service
func Run(ctx context.Context, cfgPath string) error {
	log.Infof("Starting with config: '%s'", cfgPath)

	err := config.LoadJSONConfig(cfgPath, &Config)
	if err != nil {
		log.Errf("Failed to load config: %+v", err)
		return err
	}

	if _, err := os.Stat("./dpdk-devbind.py"); err != nil {
		DpdkEnabled = false
	} else {
		if err := reattachDpdkPorts(); err != nil {
			log.Errf("Failed to reattach Dpdk ports: %s", err.Error())
		}
	}

	return runServer(ctx)
}
