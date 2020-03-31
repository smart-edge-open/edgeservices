// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eda

import (
	"context"
	"net"

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/pkg/config"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"github.com/open-ness/edgenode/pkg/util"
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
