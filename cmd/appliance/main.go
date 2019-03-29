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

package main

import (
	"context"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"sync"
	"syscall"

	"github.com/smartedgemec/appliance-ce/pkg/logger"
)

// ServiceStartFunction is func typedef for starting service
type ServiceStartFunction func(context.Context) error

// EdgeServices array contains function pointers to services start functions
var EdgeServices = []ServiceStartFunction{}

var log = logger.NewLogger("main")

func init() {
	//TODO: Load logger configuration from a config file
	//Configure a connection to the local syslog server
	err := logger.ConfigSyslog(log, "", "", "")
	if err != nil {
		log.Errorf("Failed to configure syslog: %s", err.Error())
	}
}

func waitForServices(wg *sync.WaitGroup,
	errors <-chan error, cancel context.CancelFunc) bool {

	waitFinished := make(chan struct{})
	ret := true
	go func() {
		defer close(waitFinished)
		wg.Wait()
	}()

	for {
		select {
		case <-waitFinished:
			return ret
		case err := <-errors:
			if err != nil {
				log.Tracef("Cancelling services because of error"+
					" from one of the services: %#v", err)
				cancel()
				ret = false
			}
		}
	}
}

func runServices(services []ServiceStartFunction) bool {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Handle SIGINT and SIGTERM by calling cancel()
	// which is propagated to services
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-osSignals
		log.Infof("Received signal: %#v", sig)
		cancel()
	}()

	results := make(chan error)

	log.Infof("Starting services")
	for _, runner := range services {
		log.Infof("Starting: %v",
			runtime.FuncForPC(reflect.ValueOf(runner).Pointer()).Name())
		wg.Add(1)
		go func(wg *sync.WaitGroup, start ServiceStartFunction) {
			defer wg.Done()
			err := start(ctx)
			results <- err
		}(&wg, runner)
	}

	log.Infof("Services started")

	return waitForServices(&wg, results, cancel)
}

func main() {
	if !runServices(EdgeServices) {
		os.Exit(1)
	}

	log.Infof("Services stopped gracefully")
}
