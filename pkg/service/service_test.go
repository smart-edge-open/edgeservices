// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package service

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
		controlRun   StartFunction = controlAgent.run
	)

	BeforeEach(func() {
		controlAgent = fakeAgent{}
		Cfg.Services = make(map[string]string)
		funcName := runtime.FuncForPC(
			reflect.ValueOf(controlRun).Pointer()).Name()
		srvName := funcName[:strings.LastIndex(funcName, ".")]
		Cfg.Services[srvName] = "config.json"
	})

	Describe("Starts an Agent that will fail", func() {
		It("Will return failure and context cancellation will be issued",
			func() {
				Expect(RunServices([]StartFunction{failingRun,
					successfulRun, controlRun})).Should(BeFalse())
				Expect(controlAgent.ContextCancelled).Should(BeTrue())
				Expect(controlAgent.EndedWork).Should(BeFalse())
				Expect(controlAgent.CfgPath).Should(Equal("config.json"))
			})
	})

	Describe("Starts an Agent that will succeed", func() {
		It("Will return success and other agents will finish work normally",
			func() {
				Expect(RunServices([]StartFunction{successfulRun,
					controlRun})).Should(BeTrue())
				Expect(controlAgent.EndedWork).Should(BeTrue())
				Expect(controlAgent.ContextCancelled).Should(BeFalse())
				Expect(controlAgent.CfgPath).Should(Equal("config.json"))
			})
	})
})
