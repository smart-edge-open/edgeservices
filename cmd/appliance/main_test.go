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
	"errors"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = func() (_ struct{}) {
	os.Args = []string{"", "-config=../../configs/appliance.json"}
	return
}()

func TestMain(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Main suite")
}

type fakeAgent struct {
	ContextCancelled bool
	EndedWork        bool
	CfgPath          string
}

func (a *fakeAgent) run(parentCtx context.Context, cfg string) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	select {
	case <-time.After(10 * time.Millisecond):
		a.EndedWork = true
	case <-ctx.Done():
		a.ContextCancelled = true
	}
	a.CfgPath = cfg
	return nil
}

func failingRun(parentCtx context.Context, cfg string) error {
	return errors.New("Fail")
}

func successfulRun(parentCtx context.Context, cfg string) error {
	return nil
}

var _ = Describe("runServices", func() {
	var (
		controlAgent fakeAgent
		controlRun   ServiceStartFunction = controlAgent.run
	)

	BeforeEach(func() {
		controlAgent = fakeAgent{}
		cfg.Services = make(map[string]string)
		funcName := runtime.FuncForPC(
			reflect.ValueOf(controlRun).Pointer()).Name()
		srvName := funcName[:strings.LastIndex(funcName, ".")]
		cfg.Services[srvName] = "config.json"
	})

	Describe("Starts an Agent that will fail", func() {
		It("Will return failure and context cancellation will be issued",
			func() {
				Expect(runServices([]ServiceStartFunction{failingRun,
					successfulRun, controlRun})).Should(BeFalse())
				Expect(controlAgent.ContextCancelled).Should(BeTrue())
				Expect(controlAgent.EndedWork).Should(BeFalse())
				Expect(controlAgent.CfgPath).Should(Equal("config.json"))
			})
	})

	Describe("Starts an Agent that will succeed", func() {
		It("Will return success and other agents will finish work normally",
			func() {
				Expect(runServices([]ServiceStartFunction{successfulRun,
					controlRun})).Should(BeTrue())
				Expect(controlAgent.EndedWork).Should(BeTrue())
				Expect(controlAgent.ContextCancelled).Should(BeFalse())
				Expect(controlAgent.CfgPath).Should(Equal("config.json"))
			})
	})
})
