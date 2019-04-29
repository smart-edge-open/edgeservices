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
	"github.com/smartedgemec/appliance-ce/pkg/config"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	logger "github.com/smartedgemec/log"
	"google.golang.org/grpc"
	"net"
)

var log = logger.DefaultLogger.WithField("component", "eva")

// Wait for cancellation event and then stop the server from other goroutine
func waitForCancel(ctx context.Context, server *grpc.Server) {
	<-ctx.Done()
	log.Info("EVA agent shutting down")
	server.GracefulStop()
}

func runEva(ctx context.Context, endpoint string) error {
	lis, err := net.Listen("tcp", endpoint)

	if err != nil {
		log.Errf("failed tcp listen on %s: %#v", endpoint, err)
		return err
	}

	server := grpc.NewServer()

	/* Register our interfaces. */
	var adss pb.UnimplementedApplicationDeploymentServiceServer
	pb.RegisterApplicationDeploymentServiceServer(server, &adss)
	var alss pb.UnimplementedApplicationLifecycleServiceServer
	pb.RegisterApplicationLifecycleServiceServer(server, &alss)

	go waitForCancel(ctx, server) // goroutine to wait for cancellation event

	log.Infof("serving on %s", endpoint)
	err = server.Serve(lis)
	if err != nil {
		log.Errf("Failed grpcServe(): %#v", err)
		return err
	}
	log.Info("stopped serving")

	return nil
}

func Run(ctx context.Context, cfgFile string) error {
	cfg := struct {
		Endpoint string
	}{}

	log.Infof("EVA agent initialized. Using '%s' as config.", cfgFile)

	err := config.LoadJSONConfig(cfgFile, &cfg)
	if err != nil {
		log.Errf("Failed to read config %s: %#v", cfgFile, err)
		return err
	}

	return runEva(ctx, cfg.Endpoint)
}
