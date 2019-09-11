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

package ela

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"path/filepath"

	logger "github.com/otcshare/common/log"
	"github.com/otcshare/edgenode/pkg/config"
	"github.com/otcshare/edgenode/pkg/ela/kubeovn"

	"github.com/otcshare/edgenode/pkg/auth"
	pb "github.com/otcshare/edgenode/pkg/ela/pb"
	"github.com/otcshare/edgenode/pkg/util"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Configuration describes JSON configuration
type Configuration struct {
	Endpoint          string        `json:"Endpoint"`
	HeartbeatInterval util.Duration `json:"HeartbeatInterval"`
	EDAEndpoint       string        `json:"EdaEndpoint"`
	NtsConfigPath     string        `json:"NtsConfigPath"`
	CertsDir          string        `json:"CertsDirectory"`
	DNSIP             string        `json:"DnsIP"`
	PCIBlacklist      []string      `json:"PCIBlacklist"`
	KubeOVNMode       bool          `json:"KubeOVNMode"`
	InterfaceMTU      uint16        `json:"InterfaceMTU"`
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

	lis, err := net.Listen("tcp", Config.Endpoint)

	if err != nil {
		log.Errf("net.Listen error: %+v", err)
		return err
	}
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	if Config.KubeOVNMode {
		log.Info("kube-ovn mode")
		// No ApplicationPolicyService in kube-ovn mode

		interfaceService := kubeovn.InterfaceService{}
		pb.RegisterInterfaceServiceServer(grpcServer, &interfaceService)
	} else {
		applicationPolicyService := ApplicationPolicyServiceServerImpl{}
		pb.RegisterApplicationPolicyServiceServer(grpcServer,
			&applicationPolicyService)

		interfaceService := InterfaceService{}
		pb.RegisterInterfaceServiceServer(grpcServer, &interfaceService)

		interfacePolicyService := InterfacePolicyService{}
		pb.RegisterInterfacePolicyServiceServer(grpcServer,
			&interfacePolicyService)
	}

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
