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

// NOTE
// This test file uses the Go testing framework, while rest of the
// test code in OpenNESS uses Ginko / Gomeka.
// This file needs to be updated to match the other test files.
// (Or other test files updated to match this one)

package eva_test

import (
	"context"
	"github.com/smartedgemec/appliance-ce/pkg/eva"
	"sync"
	"testing"
)

func TestEva(t *testing.T) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	wg.Add(1)
	go func() {
		err := eva.Run(ctx, "../../configs/eva.json")
		wg.Done()
		if err != nil {
			t.Errorf("eva.Run() failed: %#v", err)
		}
	}()

	cancel()  // stop the EVA running in other thread
	wg.Wait() // wait for the other thread to terminate!
}
