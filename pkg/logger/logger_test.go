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

package logger

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLogger(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logger suite")
}

var _ = Describe("NewLogger", func() {

	Describe("Create a new logger instance for a component", func() {
		It("Will be created successfully and have a component field set",
			func() {
				log := NewLogger("Test")
				Expect(log).NotTo(BeNil())
				Expect(log.Data["component"]).To(Equal("Test"))
			})
	})
})

var _ = Describe("SetLevel", func() {
	log := NewLogger("Test")

	Describe("Set a logging level", func() {
		It("Will set a level if supported",
			func() {
				Expect(SetLevel(nil, "")).NotTo(BeNil())
				Expect(SetLevel(log, "info")).To(BeNil())
				Expect(SetLevel(log, "unsupported")).NotTo(BeNil())
			})
	})
})

var _ = Describe("ConfigSyslog", func() {
	log := NewLogger("Test")

	Describe("Configure a syslog endpoint", func() {
		It("Will connect to a syslog endpoint or throw an error",
			func() {
				Expect(ConfigSyslog(nil, "", "", "")).NotTo(BeNil())
				Expect(ConfigSyslog(log, "", "", "")).To(BeNil())
				Expect(ConfigSyslog(log, "udp", "badaddr", "")).NotTo(BeNil())
			})
	})
})

var _ = Describe("ConfigLogger", func() {
	log := NewLogger("Test")

	Describe("Configure logger", func() {
		It("Will set a level and configure the syslog connection",
			func() {
				cfg := Config{
					Level: "error",
				}

				Expect(ConfigLogger(nil, &cfg)).NotTo(BeNil())
				Expect(ConfigLogger(log, &cfg)).To(BeNil())
				cfg.Level = "unsupported"
				Expect(ConfigLogger(log, &cfg)).NotTo(BeNil())
				cfg.SyslogConfig.Enable = true
				cfg.SyslogConfig.Protocol = "udp"
				cfg.SyslogConfig.Address = "unreachable"
				Expect(ConfigLogger(log, &cfg)).NotTo(BeNil())
			})
	})
})
