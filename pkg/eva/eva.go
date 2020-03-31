// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

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

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/common/proxy/progutil"
	metadata "github.com/open-ness/edgenode/pkg/app-metadata"
	"github.com/open-ness/edgenode/pkg/auth"
	"github.com/open-ness/edgenode/pkg/config"
	apppb "github.com/open-ness/edgenode/pkg/eva/internal_pb"
	evapb "github.com/open-ness/edgenode/pkg/eva/pb"
	"github.com/open-ness/edgenode/pkg/util"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	log = logger.DefaultLogger.WithField("eva", nil)
)

// Config describes a global eva JSON config
type Config struct {
	Endpoint           string        `json:"Endpoint"`
	EndpointInternal   string        `json:"EndpointInternal"`
	MaxCores           int32         `json:"MaxCores"`
	MaxAppMem          int32         `json:"MaxAppMem"` /* this is in MB */
	AppImageDir        string        `json:"AppImageDir"`
	HeartbeatInterval  util.Duration `json:"HeartbeatInterval"`
	AppStartTimeout    util.Duration `json:"AppStartTimeout"`
	AppStopTimeout     util.Duration `json:"AppStopTimeout"`
	AppRestartTimeout  util.Duration `json:"AppRestartTimeout"`
	CertsDir           string        `json:"CertsDirectory"`
	VhostSocket        string        `json:"VhostSocket"`
	DownloadTimeout    util.Duration `json:"DownloadTimeout"`
	ControllerEndpoint string        `json:"ControllerEndpoint"`
	OpenvSwitchBridge  string        `json:"OpenvSwitchBridge"`
	OpenvSwitch        bool          `json:"OpenvSwitch"`
	KubernetesMode     bool          `json:"KubernetesMode"`
	UseCNI             bool          `json:"UseCNI"`
}

// Wait for cancellation event and then stop the server from other goroutine
func waitForCancel(ctx context.Context, server *grpc.Server) {
	<-ctx.Done()
	log.Info("EVA agent shutting down")
	server.GracefulStop()
}

func runEva(ctx context.Context, cfg *Config) error {
	srvCreds, err := prepareServerCreds(cfg)
	if err != nil {
		log.Errf("Failed to prepare server credentials: %v", err)
		return err
	}

	clientCreds, err := prepareClientCreds(cfg)
	if err != nil {
		log.Errf("Failed to prepare client credentials: %v", err)
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", cfg.ControllerEndpoint)
	if err != nil {
		log.Errf("Failed to resolve the controller address: %v", err)
		return err
	}
	lis := &progutil.DialListener{RemoteAddr: addr, Name: "EVA"}
	defer func() {
		if err1 := lis.Close(); err1 != nil {
			log.Errf("Failed to close connection: %v", err1)
		}
	}()

	server := grpc.NewServer(grpc.Creds(srvCreds))

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
	ipAppLookupService := IPApplicationLookupServiceServerImpl{cfg, clientCreds}
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

func getNodeCerts(cfg *Config) (*tls.Certificate, *x509.CertPool, error) {
	crtPath := filepath.Join(cfg.CertsDir, auth.CertName)
	keyPath := filepath.Join(cfg.CertsDir, auth.KeyName)
	caPath := filepath.Join(cfg.CertsDir, auth.CAPoolName)

	x509KeyPair, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, nil,
			errors.Wrap(err, "failed to load x509 key pair")
	}

	ca, err := ioutil.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to load ca")
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(ca); !ok {
		return nil, nil,
			errors.New("Failed to append CA certs from " + caPath)
	}

	return &x509KeyPair, pool, nil
}

func prepareClientCreds(cfg *Config) (credentials.TransportCredentials,
	error) {

	cert, pool, err := getNodeCerts(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load node certs")
	}

	return credentials.NewTLS(&tls.Config{
		ServerName:   auth.ControllerServerName,
		Certificates: []tls.Certificate{*cert},
		RootCAs:      pool,
	}), nil
}

func prepareServerCreds(cfg *Config) (credentials.TransportCredentials, error) {
	cert, pool, err := getNodeCerts(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load node certs")
	}

	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    pool,
	})
	return creds, nil
}

func sanitizeConfig(cfg *Config) error {
	if cfg.ControllerEndpoint == "" {
		return fmt.Errorf("ControllerEndpoint is not set")
	}
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
