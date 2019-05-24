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
	"fmt"
	"net"
	"os"

	metadata "github.com/smartedgemec/appliance-ce/pkg/app-metadata"
	"github.com/smartedgemec/appliance-ce/pkg/config"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	evapb "github.com/smartedgemec/appliance-ce/pkg/eva/pb"
	"github.com/smartedgemec/appliance-ce/pkg/util"
	logger "github.com/smartedgemec/log"
	"google.golang.org/grpc"
)

var (
	log = logger.DefaultLogger.WithField("eva", nil)
	cfg Config
)

type Config struct {
	Endpoint          string
	EndpointInternal  string
	MaxCores          int32
	MaxAppMem         int32 /* this is in KB */
	AppImageDir       string
	HeartbeatInterval util.Duration
}

// Wait for cancellation event and then stop the server from other goroutine
func waitForCancel(ctx context.Context, server *grpc.Server) {
	<-ctx.Done()
	log.Info("EVA agent shutting down")
	server.GracefulStop()
}

func runEva(ctx context.Context, cfg *Config) error {
	lis, err := net.Listen("tcp", cfg.Endpoint)

	if err != nil {
		log.Errf("failed tcp listen on %s: %v", cfg.Endpoint, err)
		return err
	}

	server := grpc.NewServer()

	/* Register our interfaces. */
	metadata := metadata.AppMetadata{RootPath: cfg.AppImageDir}
	adss := DeploySrv{cfg, &metadata}
	pb.RegisterApplicationDeploymentServiceServer(server, &adss)
	alss := ApplicationLifecycleServiceServer{&metadata}
	pb.RegisterApplicationLifecycleServiceServer(server, &alss)

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
	evapb.RegisterIPApplicationLookupServiceServer(serverApp,
		&ipAppLookupService)

	go waitForCancel(ctx, serverApp)

	go func() {
		log.Infof("serving on %s", cfg.EndpointInternal)
		err = serverApp.Serve(lApp)
		if err != nil {
			log.Errf("Failed grpcServe(): %v", err)
			errs <- err
		}
		log.Info("stopped serving")
		done <- true
	}()

	select {
	case err := <-errs:
		return err
	case <-done:
		return nil
	}
}

func sanitizeConfig(cfg *Config) error {
	if cfg.MaxCores <= 0 {
		return fmt.Errorf("MaxCores value invalid: %d", cfg.MaxCores)
	}
	if cfg.MaxAppMem <= 0 {
		return fmt.Errorf("MaxCores value invalid: %d", cfg.MaxAppMem)
	}
	err := os.MkdirAll(cfg.AppImageDir, 0777)
	if err != nil {
		log.Errf("Unable to create AppImageDir: %v", err)
	}

	return nil
}

func Run(ctx context.Context, cfgFile string) error {

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
