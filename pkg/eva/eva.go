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

package eva

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	metadata "github.com/smartedgemec/appliance-ce/pkg/app-metadata"
	"github.com/smartedgemec/appliance-ce/pkg/auth"
	"github.com/smartedgemec/appliance-ce/pkg/config"
	apppb "github.com/smartedgemec/appliance-ce/pkg/eva/internal_pb"
	evapb "github.com/smartedgemec/appliance-ce/pkg/eva/pb"
	"github.com/smartedgemec/appliance-ce/pkg/util"
	logger "github.com/smartedgemec/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	log = logger.DefaultLogger.WithField("eva", nil)
)

// Config describes a global eva JSON config
type Config struct {
	Endpoint          string        `json:"endpoint"`
	EndpointInternal  string        `json:"endpointInternal"`
	MaxCores          int32         `json:"maxCores"`
	MaxAppMem         int32         `json:"maxAppMem"` /* this is in KB */
	AppImageDir       string        `json:"appImageDir"`
	HeartbeatInterval util.Duration `json:"heartbeatInterval"`
	AppStartTimeout   util.Duration `json:"appStartTimeout"`
	AppStopTimeout    util.Duration `json:"appStopTimeout"`
	AppRestartTimeout util.Duration `json:"appRestartTimeout"`
	CertsDir          string        `json:"certsDirectory"`
	KubernetesMode    bool          `json:"kubernetesMode"`
	VhostSocket       string        `json:"vhostSocket"`
}

// Wait for cancellation event and then stop the server from other goroutine
func waitForCancel(ctx context.Context, server *grpc.Server) {
	<-ctx.Done()
	log.Info("EVA agent shutting down")
	server.GracefulStop()
}

func runEva(ctx context.Context, cfg *Config) error {
	creds, err := prepareCreds(cfg)
	if err != nil {
		log.Errf("Failed to prepare credentials: %v", err)
		return err
	}

	lis, err := net.Listen("tcp", cfg.Endpoint)
	if err != nil {
		log.Errf("Failed tcp listen on %s: %v", cfg.Endpoint, err)
		return err
	}

	server := grpc.NewServer(grpc.Creds(creds))

	/* Register our interfaces. */
	metadata := metadata.AppMetadata{RootPath: cfg.AppImageDir}
	adss := DeploySrv{cfg, &metadata}
	evapb.RegisterApplicationDeploymentServiceServer(server, &adss)
	alss := ApplicationLifecycleServiceServer{cfg, &metadata}
	evapb.RegisterApplicationLifecycleServiceServer(server, &alss)

	go waitForCancel(ctx, server) // goroutine to wait for cancellation event

	util.Heartbeat(ctx, cfg.HeartbeatInterval, func() {
		// TODO: implementation of modules checking
		log.Info("Heartbeat")
	})

	errs := make(chan error)
	done := make(chan bool)

	go func() {
		log.Infof("serving on %s", cfg.Endpoint)
		err = server.Serve(lis)
		if err != nil {
			log.Errf("Failed grpcServe(): %v", err)
			errs <- err
		}
		log.Info("stopped serving")
		done <- true
	}()

	// Application ID provider server
	lApp, err := net.Listen("tcp", cfg.EndpointInternal)
	if err != nil {
		log.Errf("net.Listen error: %+v", err)
		return err
	}

	serverApp := grpc.NewServer()
	ipAppLookupService := IPApplicationLookupServiceServerImpl{}
	apppb.RegisterIPApplicationLookupServiceServer(serverApp,
		&ipAppLookupService)

	go waitForCancel(ctx, serverApp)

	go func() {
		log.Infof("internal serving on %s", cfg.EndpointInternal)
		err = serverApp.Serve(lApp)
		if err != nil {
			log.Errf("Failed grpcServe(): %v", err)
			errs <- err
		}
		log.Info("stopped internal serving")
		done <- true
	}()

	select {
	case err := <-errs:
		return err
	case <-done:
		return nil
	}
}

func prepareCreds(cfg *Config) (credentials.TransportCredentials, error) {
	crtPath := filepath.Join(cfg.CertsDir, auth.CertName)
	keyPath := filepath.Join(cfg.CertsDir, auth.KeyName)
	caPath := filepath.Join(cfg.CertsDir, auth.CAPoolName)

	srvCert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load server key pair")
	}
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read ca certificates")
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil,
			errors.New("Failed to append CA certs from " + caPath)
	}

	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    certPool,
	})
	return creds, nil
}

func sanitizeConfig(cfg *Config) error {
	if cfg.MaxCores <= 0 {
		return fmt.Errorf("MaxCores value invalid: %d", cfg.MaxCores)
	}
	if cfg.MaxAppMem <= 0 {
		return fmt.Errorf("MaxCores value invalid: %d", cfg.MaxAppMem)
	}
	err := os.MkdirAll(cfg.AppImageDir, 0750)
	if err != nil {
		log.Errf("Unable to create AppImageDir: %v", err)
	}

	return nil
}

// Run runs eva
func Run(ctx context.Context, cfgFile string) error {
	var cfg Config

	log.Infof("EVA agent initialized. Using '%s' as config.", cfgFile)

	err := config.LoadJSONConfig(cfgFile, &cfg)
	if err != nil {
		log.Errf("Failed to read config %s: %v", cfgFile, err)
		return err
	}
	err = sanitizeConfig(&cfg)
	if err != nil {
		log.Errf("Configuration invalid: %v", err)
		return err
	}
	log.Debugf("Configuration read: %+v", cfg)

	return runEva(ctx, &cfg)
}
