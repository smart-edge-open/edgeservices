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
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/otcshare/edgenode/internal/metadatahelpers"
	"github.com/otcshare/edgenode/internal/stubs"
	"github.com/otcshare/edgenode/internal/wrappers"
	evapb "github.com/otcshare/edgenode/pkg/eva/pb"
	"google.golang.org/grpc"
)

var _ = Describe("EVA: DeployContainer", func() {
	stopInd := make(chan bool)

	BeforeEach(func() {
		err := runEVA("testdata/eva.json", stopInd)
		Expect(err).ToNot(HaveOccurred())
		// Clean directories
		os.RemoveAll(cfgFile.CertsDir)
		os.RemoveAll(cfgFile.AppImageDir)
		metadatahelpers.CreateDir(cfgFile.AppImageDir)
	})

	AfterEach(func() {
		stopEVA(stopInd)
	})

	When("DeployContainer is called", func() {
		Context("with correct arguments", func() {
			It("responds with no error", func() {
				body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
				stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
					StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
					ProtoMinor: 1, Body: body, ContentLength: 11}
				body2 := ioutil.NopCloser(strings.NewReader(
					`{"stream":"Loaded image ID: sha256:53f3fd8007f76bd23bf66` +
						`3ad5f5009c8941f63828ae458cef584b5f85dc0a7bf\n"}`))
				stubs.DockerCliStub.ImLoadResp = types.ImageLoadResponse{
					Body: body2, JSON: true}

				wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
				wrappers.CreateDockerClient = stubs.CreateDockerClientStub

				// Create connection
				conn, cancelTimeout, prefaceLis := createConnection()
				defer cancelTimeout()
				defer prefaceLis.Close()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				uri := evapb.Application_HttpUri{
					HttpUri: &evapb.Application_HTTPSource{
						HttpUri: "https://localhost/test_img.tar.gz"},
				}
				app := evapb.Application{Id: "test-app-deploy",
					Cores: 2, Memory: 40, Source: &uri}

				_, err := client.DeployContainer(ctx, &app,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-deploy"}
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))
			})
		})
	})
})

var _ = Describe("EVA: Redeploy", func() {
	stopInd := make(chan bool)

	BeforeEach(func() {
		err := runEVA("testdata/eva.json", stopInd)
		Expect(err).ToNot(HaveOccurred())
		// Clean directories
		os.RemoveAll(cfgFile.CertsDir)
		os.RemoveAll(cfgFile.AppImageDir)
		metadatahelpers.CreateDir(cfgFile.AppImageDir)
		stubs.HTTPCliStub = stubs.HTTPClientStub{}
		stubs.DockerCliStub = stubs.DockerClientStub{}
	})

	AfterEach(func() {
		stopEVA(stopInd)
	})

	When("Redeploy is called", func() {
		Context("for container app with correct arguments", func() {
			It("responds with no error", func() {

				body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
				stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
					StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
					ProtoMinor: 1, Body: body, ContentLength: 11}
				body2 := ioutil.NopCloser(strings.NewReader(
					`{"stream":"Loaded image ID: sha256:23456\n"}`))
				stubs.DockerCliStub.ImLoadResp = types.ImageLoadResponse{
					Body: body2, JSON: true}
				stubs.DockerCliStub.ImRemResp =
					[]types.ImageDeleteResponseItem{{Deleted: "1"}}

				wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
				wrappers.CreateDockerClient = stubs.CreateDockerClientStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"test-app-redeploy")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(filepath.Join(expectedAppPath,
					"metadata.json"),
					`{"Type":"DockerContainer","URL":"https://localhost/test_`+
						`img.tar.gz","App":{"id":"test-app-redeploy","cores":`+
						`2,"memory":40,"status":2,"Source":null}}`)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"),
					"test-app-redeploy\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "test_img.tar.gz"),
					"TEST IMAGE")

				// Create connection
				conn, cancelTimeout, prefaceLis := createConnection()
				defer cancelTimeout()
				defer prefaceLis.Close()
				defer conn.Close()

				uri := evapb.Application_HttpUri{
					HttpUri: &evapb.Application_HTTPSource{
						HttpUri: "https://localhost/test_img.tar.gz"},
				}

				app := evapb.Application{Id: "test-app-redeploy",
					Cores:  2,
					Memory: 40,
					Source: &uri}

				client := evapb.NewApplicationDeploymentServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				_, err := client.Redeploy(ctx, &app, grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-redeploy"}
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))
			})
		})
	})
})

var _ = Describe("EVA: Undeploy", func() {
	stopInd := make(chan bool)

	BeforeEach(func() {
		err := runEVA("testdata/eva.json", stopInd)
		Expect(err).ToNot(HaveOccurred())
		// Clean directories
		os.RemoveAll(cfgFile.CertsDir)
		os.RemoveAll(cfgFile.AppImageDir)
		metadatahelpers.CreateDir(cfgFile.AppImageDir)
	})

	AfterEach(func() {
		stopEVA(stopInd)
	})

	When("Undeploy is called", func() {
		Context("for container app with correct arguments", func() {
			It("responds with no error", func() {

				stubs.DockerCliStub.ImRemResp =
					[]types.ImageDeleteResponseItem{{Deleted: "1"}}
				wrappers.CreateDockerClient = stubs.CreateDockerClientStub

				appid := evapb.ApplicationID{Id: "test-app-undeploy"}

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"test-app-undeploy")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(filepath.Join(expectedAppPath,
					"metadata.json"),
					`{"Type":"DockerContainer","URL":"https://localhost/test_`+
						`img.tar.gz","App":{"id":"test-app-undeploy","cores":`+
						`2,"memory":40,"status":2,"Source":null}}`)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"),
					"test-app-undeploy\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "test_img.tar.gz"),
					"TEST IMAGE")

				// Create connection
				conn, cancelTimeout, prefaceLis := createConnection()
				defer cancelTimeout()
				defer prefaceLis.Close()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				_, err := client.Undeploy(ctx, &appid, grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after undeployment
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err)
				Expect(status).To(BeNil())
			})
		})
	})
})
