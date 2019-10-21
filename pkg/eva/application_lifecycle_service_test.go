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

package eva_test

import (
	"context"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/otcshare/edgenode/internal/metadatahelpers"
	"github.com/otcshare/edgenode/internal/stubs"
	"github.com/otcshare/edgenode/internal/wrappers"
	evapb "github.com/otcshare/edgenode/pkg/eva/pb"
	"google.golang.org/grpc"
)

var _ = Describe("ApplicationLifecycleService", func() {
	stopInd := make(chan bool)

	BeforeEach(func() {
		err := runEVA("testdata/eva.json", stopInd)
		Expect(err).ToNot(HaveOccurred())
		// Clean directories
		os.RemoveAll(cfgFile.CertsDir)
		os.RemoveAll(cfgFile.AppImageDir)
		metadatahelpers.CreateDir(cfgFile.AppImageDir)
		stubs.DockerCliStub = stubs.DockerClientStub{}
	})

	AfterEach(func() {
		stopEVA(stopInd)
	})

	When("Start is called", func() {
		Context("with -testapp- container application deployed", func() {
			It("responds with no error", func() {
				wrappers.CreateDockerClient = stubs.CreateDockerClientStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "DockerContainer","App":{"id":"testapp",
					"name":"testapp","status":2}}`)

				conn, cancelTimeout, prefaceLis := createConnection()
				defer cancelTimeout()
				defer prefaceLis.Close()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_START}
				_, err := client.Start(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				appid := evapb.ApplicationID{Id: "testapp"}
				status, err := client.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_RUNNING))
			})
		})
	})

	When("Stop is called", func() {
		Context("with -testapp- container application deployed", func() {
			It("responds with no error", func() {
				wrappers.CreateDockerClient = stubs.CreateDockerClientStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "DockerContainer","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn, cancelTimeout, prefaceLis := createConnection()
				defer cancelTimeout()
				defer prefaceLis.Close()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_STOP}
				_, err := client.Stop(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				appid := evapb.ApplicationID{Id: "testapp"}
				status, err := client.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_STOPPED))
			})
		})
	})

	When("Restart is called", func() {
		Context("with -testapp- container application deployed", func() {
			It("responds with no error", func() {
				wrappers.CreateDockerClient = stubs.CreateDockerClientStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "DockerContainer","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn, cancelTimeout, prefaceLis := createConnection()
				defer cancelTimeout()
				defer prefaceLis.Close()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_RESTART}
				_, err := client.Restart(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				appid := evapb.ApplicationID{Id: "testapp"}
				status, err := client.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_RUNNING))
			})
		})
	})
})
