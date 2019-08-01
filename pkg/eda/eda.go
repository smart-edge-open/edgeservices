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

package eda

import (
	"context"
	"net"

	"github.com/otcshare/edgenode/pkg/config"
	pb "github.com/otcshare/edgenode/pkg/ela/pb"
	"github.com/otcshare/edgenode/pkg/util"
	logger "github.com/otcshare/common"
	"google.golang.org/grpc"
)

// Configuration JSON file
type Configuration struct {
	Endpoint          string        `json:"Endpoint"`
	HeartbeatInterval util.Duration `json:"HeartbeatInterval"`
}

var (
	// Config is a global config
	Config Configuration
	log    = logger.DefaultLogger.WithField("eda", nil)
)

func runServer(ctx context.Context) error {

	lis, err := net.Listen("tcp", Config.Endpoint)

	if err != nil {
		log.Errf("Error listenning: %v", err)
		return err
	}
	server := grpc.NewServer()
	edaTrafficPolicyService := edaTrafficPolicyServerImpl{}
	pb.RegisterApplicationPolicyServiceServer(server,
		&edaTrafficPolicyService)
	AppTrafficPolicies = make(map[string]*AppTrafficPolicy)

	go func() {
		<-ctx.Done()
		log.Info("Executing graceful stop")
		server.GracefulStop()
	}()
	defer log.Info("Stopped serving")
	log.Infof("EDA Server started listening on: %s",
		Config.Endpoint)

	util.Heartbeat(ctx, Config.HeartbeatInterval, func() {
		// TODO: implementation of modules checking
		log.Info("Heartbeat")
	})

	if err := server.Serve(lis); err != nil {
		log.Errf("Failed to serve: %v", err)
		return err
	}
	return nil
}

// Run start EDA
func Run(ctx context.Context, cfgPath string) error {

	log.Infof("Starting with config: '%s'", cfgPath)

	err := config.LoadJSONConfig(cfgPath, &Config)
	if err != nil {
		log.Errf("Failed to load configuration: %v", err)
		return err
	}
	return runServer(ctx)
}
