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

package eaa_test

import (
	"crypto/tls"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ApiEaa", func() {

	Describe("This is dummy test", func() {
		Context("With just one Dial to server", func() {
			Specify("which should return no error", func() {

				cert, err := tls.LoadX509KeyPair(
					tempConfServerCertPath, tempConfServerKeyPath)
				Expect(err).ShouldNot(HaveOccurred())

				//nolint
				conf := tls.Config{Certificates: []tls.Certificate{cert},
					InsecureSkipVerify: true}

				conn, err := tls.Dial("tcp", cfg.TLSEndpoint, &conf)
				Expect(err).ShouldNot(HaveOccurred())
				conn.Close()
			})
		})
	})
})
