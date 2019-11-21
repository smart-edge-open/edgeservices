// Copyright 2019 Intel Corporation. All rights reserved
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

	// Imports required to run agent
	"github.com/otcshare/edgenode/pkg/interfaceservice"
	"github.com/otcshare/edgenode/pkg/service"
)

// EdgeServices array contains function pointers to services start functions
var EdgeServices = []service.StartFunction{interfaceservice.Run}

func main() {

	if !service.RunServices(EdgeServices) {
		os.Exit(1)
	}

	service.Log.Infof("Service stopped gracefully")
}
