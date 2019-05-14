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
	"net"

	"github.com/smartedgemec/appliance-ce/pkg/config"
	logger "github.com/smartedgemec/log"

	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"google.golang.org/grpc"
)

type Configuration struct {
	Endpoint      string `json:"endpoint"`
	NtsConfigPath string `json:"ntsConfigPath"`
}

var (
	log    = logger.DefaultLogger.WithField("ela", nil)
	Config Configuration
)

func runServer(ctx context.Context) error {
	// TODO: Add auth
	lis, err := net.Listen("tcp", Config.Endpoint)

	if err != nil {
		log.Errf("net.Listen error: %+v", err)
		return err
	}

	grpcServer := grpc.NewServer()
	applicationPolicyService := ApplicationPolicyServiceServerImpl{}
	pb.RegisterApplicationPolicyServiceServer(grpcServer,
		&applicationPolicyService)

	dnsService := DNSServiceServer{}
	pb.RegisterDNSServiceServer(grpcServer, &dnsService)
	interfaceService := InterfaceService{}
	pb.RegisterInterfaceServiceServer(grpcServer, &interfaceService)

	go func() {
		<-ctx.Done()
		log.Info("Executing graceful stop")
		grpcServer.GracefulStop()
	}()

	defer log.Info("Stopped serving")

	log.Infof("Serving on: %s", Config.Endpoint)

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
