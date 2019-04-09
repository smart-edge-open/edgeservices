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
	"github.com/smartedgemec/appliance-ce/pkg/logger"
	"net"
	"net/http"
)

const (
	eaaServerIP   = "localhost"
	eaaServerPort = "8080"
)

var (
	log = logger.NewLogger("eaa")
)

// Start Edge Application Agent server listening on port read from config file
func RunServer(parentCtx context.Context) error {
	lis, err := net.Listen("tcp", eaaServerIP+":"+eaaServerPort)
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

	log.Infof("EAA Server started and listening on port %s", eaaServerPort)
	if err = server.Serve(lis); err != http.ErrServerClosed {
		log.Errorf("server.Serve error: %#v", err)
		return err
	}

	return nil
}

func Run(parentCtx context.Context, cfg string) error {

	//TODO add config check
	return RunServer(parentCtx)

}
