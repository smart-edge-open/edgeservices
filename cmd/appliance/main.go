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
	"os"
	"time"

	"github.com/otcshare/edgenode/pkg/auth"

	// Imports required to run agents
	"github.com/otcshare/edgenode/pkg/eda"
	"github.com/otcshare/edgenode/pkg/ela"
	"github.com/otcshare/edgenode/pkg/eva"
	"github.com/otcshare/edgenode/pkg/service"
)

// EdgeServices array contains function pointers to services start functions
var EdgeServices = []service.StartFunction{ela.Run, eva.Run, eda.Run}

const enrollBackoff = time.Second * 10

func main() {

	for {
		if err := auth.Enroll(service.Cfg.Enroll.CertsDir, service.Cfg.Enroll.Endpoint,
			service.Cfg.Enroll.ConnTimeout.Duration, auth.EnrollClient{}); err != nil {
			service.Log.Errf("Enrollment failed %v\n", err)
			service.Log.Infof("Retrying enrollment in %s...", enrollBackoff)
			time.Sleep(enrollBackoff)
		} else {
			service.Log.Info("Successfully enrolled")
			break
		}
	}

	if !service.RunServices(EdgeServices) {
		os.Exit(1)
	}

	service.Log.Infof("Services stopped gracefully")
}
