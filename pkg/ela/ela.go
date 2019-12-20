// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"path/filepath"

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/config"

	"github.com/open-ness/common/proxy/progutil"
	"github.com/open-ness/edgenode/pkg/auth"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"github.com/open-ness/edgenode/pkg/util"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Configuration describes JSON configuration
type Configuration struct {
	Endpoint           string        `json:"Endpoint"`
	HeartbeatInterval  util.Duration `json:"HeartbeatInterval"`
	EDAEndpoint        string        `json:"EdaEndpoint"`
	NtsConfigPath      string        `json:"NtsConfigPath"`
	CertsDir           string        `json:"CertsDirectory"`
	DNSIP              string        `json:"DnsIP"`
	PCIBlacklist       []string      `json:"PCIBlacklist"`
	InterfaceMTU       uint16        `json:"InterfaceMTU"`
	ControllerEndpoint string        `json:"ControllerEndpoint"`
}

var (
	log = logger.DefaultLogger.WithField("ela", nil)
	// Config instantiate a configuration
	Config Configuration
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

	if err != nil {
		log.Errf("net.Listen error: %+v", err)
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", Config.ControllerEndpoint)
	if err != nil {
		log.Errf("Failed to resolve the controller address: %v", err)
		return err
	}
	lis := &progutil.DialListener{RemoteAddr: addr, Name: "ELA"}
	defer func() {
		if err1 := lis.Close(); err1 != nil {
			log.Errf("Failed to close ELA listener: %v", err1)
		}
	}()

	grpcServer := grpc.NewServer(grpc.Creds(creds))

	applicationPolicyService := ApplicationPolicyServiceServerImpl{}
	pb.RegisterApplicationPolicyServiceServer(grpcServer,
		&applicationPolicyService)

	interfaceService := InterfaceService{}
	pb.RegisterInterfaceServiceServer(grpcServer, &interfaceService)

	interfacePolicyService := InterfacePolicyService{}
	pb.RegisterInterfacePolicyServiceServer(grpcServer,
		&interfacePolicyService)

	dnsService := DNSServiceServer{}
	pb.RegisterDNSServiceServer(grpcServer, &dnsService)

	go func() {
		<-ctx.Done()
		log.Info("Executing graceful stop")
		grpcServer.GracefulStop()
	}()

	defer log.Info("Stopped serving")

	log.Infof("Serving on: %s", Config.Endpoint)

	util.Heartbeat(ctx, Config.HeartbeatInterval, func() {
		// TODO: implementation of modules checking
		log.Info("Heartbeat")
	})

	// When Serve() returns, listener is closed
	err = grpcServer.Serve(lis)
	if err != nil {
		log.Errf("grpcServer.Serve error: %+v", err)
	}
	return err
}

// Run function runs a Edge Lifecycle Agent
func Run(ctx context.Context, cfgPath string) error {
	log.Infof("Starting with config: '%s'", cfgPath)

	err := config.LoadJSONConfig(cfgPath, &Config)
	if err != nil {
		log.Errf("Failed to load config: %+v", err)
		return err
	}
	return runServer(ctx)
}
