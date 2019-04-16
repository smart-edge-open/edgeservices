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

package eaa

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/smartedgemec/appliance-ce/pkg/config"
	"github.com/smartedgemec/appliance-ce/pkg/logger"
)

type services map[string]Service

type eaaContext struct {
	serviceInfo services
}

var (
	cfg    Config
	eaaCtx eaaContext

	log = logger.NewLogger("eaa")
)

// Initialize EAA context structures
func Init() error {
	if eaaCtx.serviceInfo != nil {
		return errors.New("EAA is already initialized")
	}

	eaaCtx.serviceInfo = services{}
	return nil
}

func configLogger(cfgPath string) error {
	err := config.LoadJSONConfig(cfgPath, &cfg)
	if err != nil {
		return err
	}

	err = logger.ConfigLogger(log, &cfg.Log)
	if err != nil {
		return err
	}

	return nil
}

// Start Edge Application Agent server listening on port read from config file
func RunServer(parentCtx context.Context) error {
	if err := Init(); err != nil {
		log.Errorf("init error: %#v", err)
		return errors.New("Running EAA module failure: " + err.Error())
	}

	lis, err := net.Listen("tcp",
		cfg.ServerAddr.Hostname+":"+cfg.ServerAddr.Port)
	if err != nil {
		log.Errorf("net.Listen error: %#v", err)
		return err
	}
	router := NewRouter()
	server := http.Server{Handler: router}

	go func() {
		<-parentCtx.Done()
		log.Info("Executing graceful stop")
		server.Close()
	}()

	defer log.Info("Stopped serving")

	log.Infof("EAA Server started and listening on port %s",
		cfg.ServerAddr.Port)
	if err = server.Serve(lis); err != http.ErrServerClosed {
		log.Errorf("server.Serve error: %#v", err)
		return err
	}

	return nil
}

func Run(parentCtx context.Context, configFile string) error {

	if err := configLogger(configFile); err != nil {
		log.Errorf("Failed to config logger: %#v", err)
		return err
	}

	return RunServer(parentCtx)
}
