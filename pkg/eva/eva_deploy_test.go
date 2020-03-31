// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

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
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/go-connections/nat"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/open-ness/edgenode/internal/metadatahelpers"
	"github.com/open-ness/edgenode/internal/stubs"
	"github.com/open-ness/edgenode/internal/wrappers"
	"github.com/open-ness/edgenode/pkg/eva"
	evapb "github.com/open-ness/edgenode/pkg/eva/pb"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

var _ = Describe("EVA: Docker tests", func() {

	stopInd := make(chan bool)

	BeforeEach(func() {
		err := runEVA("testdata/eva.json", stopInd)
		Expect(err).ToNot(HaveOccurred())

		stubs.HTTPCliStub = stubs.HTTPClientStub{}
		stubs.DockerCliStub = stubs.DockerClientStub{}
	})

	AfterEach(func() {
		stopEVA(stopInd)

		// Clean directories
		err2 := os.RemoveAll(cfgFile.CertsDir)
		Expect(err2).ToNot(HaveOccurred())
		err2 = os.RemoveAll(cfgFile.AppImageDir)
		Expect(err2).ToNot(HaveOccurred())

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
				conn := createConnection()
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

				go prefaceLis.Accept()
				_, err := client.DeployContainer(ctx, &app,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-deploy"}
				go prefaceLis.Accept()
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))
			})
		})
		Context("with correct arguments and ImageLoad returns error", func() {
			It("responds with error", func() {
				body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
				stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
					StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
					ProtoMinor: 1, Body: body, ContentLength: 11}
				body2 := ioutil.NopCloser(strings.NewReader(
					`{"stream":"Loaded image ID: sha256:53f3fd8007f76bd23bf66` +
						`3ad5f5009c8941f63828ae458cef584b5f85dc0a7bf\n"}`))
				stubs.DockerCliStub.ImLoadResp = types.ImageLoadResponse{
					Body: body2, JSON: true}
				stubs.DockerCliStub.ImLoadErr = errors.New("Image Load Failed")

				wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
				wrappers.CreateDockerClient = stubs.CreateDockerClientStub

				// Create connection
				conn := createConnection()
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
				Expect(err)

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-deploy"}
				go prefaceLis.Accept()
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_ERROR))
			})
		})
		Context("with correct arguments and ImageLoad responds with JSON=false",
			func() {
				It("responds with no error", func() {
					body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
					stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
						StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
						ProtoMinor: 1, Body: body, ContentLength: 11}
					body2 := ioutil.NopCloser(strings.NewReader(
						`{"stream":"Loaded image ID: sha256:53f3fd8007f76bd23` +
							`bf663ad5f5009c8941f63828ae458cef584b5f85dc0a7bf\n"}`))
					stubs.DockerCliStub.ImLoadResp = types.ImageLoadResponse{
						Body: body2, JSON: false}

					wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
					wrappers.CreateDockerClient = stubs.CreateDockerClientStub

					// Create connection
					conn := createConnection()
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
					Expect(err)

					time.Sleep(100 * time.Millisecond)

					// Verify status after deployment
					appid := evapb.ApplicationID{Id: "test-app-deploy"}
					go prefaceLis.Accept()
					alsClient :=
						evapb.NewApplicationLifecycleServiceClient(conn)
					status, err := alsClient.GetStatus(ctx, &appid,
						grpc.WaitForReady(true))
					Expect(err).ToNot(HaveOccurred())
					Expect(status.Status).To(Equal(evapb.LifecycleStatus_ERROR))
				})
			})
		Context("with correct arguments and ContainerCreate responds error",
			func() {
				It("responds with no error", func() {
					body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
					stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
						StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
						ProtoMinor: 1, Body: body, ContentLength: 11}
					body2 := ioutil.NopCloser(strings.NewReader(
						`{"stream":"Loaded image ID: sha256:53f3fd8007f76bd23` +
							`bf663ad5f5009c8941f63828ae458cef584b5f85dc0a7bf\n"}`))
					stubs.DockerCliStub.ImLoadResp = types.ImageLoadResponse{
						Body: body2, JSON: true}
					stubs.DockerCliStub.CCreateErr =
						errors.New("ContainerCreate Failed")
					wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
					wrappers.CreateDockerClient = stubs.CreateDockerClientStub

					// Create connection
					conn := createConnection()
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
					Expect(err)

					time.Sleep(100 * time.Millisecond)

					// Verify status after deployment
					appid := evapb.ApplicationID{Id: "test-app-deploy"}
					go prefaceLis.Accept()
					alsClient :=
						evapb.NewApplicationLifecycleServiceClient(conn)
					status, err := alsClient.GetStatus(ctx, &appid,
						grpc.WaitForReady(true))
					Expect(err).ToNot(HaveOccurred())
					Expect(status.Status).To(Equal(evapb.LifecycleStatus_ERROR))
				})
			})

		Context("with correct EAC environment variable arguments", func() {
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
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				uri := evapb.Application_HttpUri{
					HttpUri: &evapb.Application_HTTPSource{
						HttpUri: "https://localhost/test_img.tar.gz"},
				}

				eacVal := `[{"Key": "env_vars", "Value": "testVar=sample"},
						{"Key": "cmd", "Value": "/bin/test"}]`
				app := evapb.Application{Id: "test-app-deploy",
					Cores: 2, Memory: 40, Source: &uri,
					EACJsonBlob: eacVal}

				go prefaceLis.Accept()
				_, err := client.DeployContainer(ctx, &app,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-deploy"}
				go prefaceLis.Accept()
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))
			})
		})

		Context("with correct EAC CPU Pinning arguments", func() {
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
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				uri := evapb.Application_HttpUri{
					HttpUri: &evapb.Application_HTTPSource{
						HttpUri: "https://localhost/test_img.tar.gz"},
				}

				eacVal := `[{"Key": "cpu_pin", "Value": "4-7"}]`
				app := evapb.Application{Id: "test-app-deploy",
					Cores: 2, Memory: 40, Source: &uri,
					EACJsonBlob: eacVal}

				go prefaceLis.Accept()
				_, err := client.DeployContainer(ctx, &app,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-deploy"}
				go prefaceLis.Accept()
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))
			})
		})

		Context("with correct EAC port forwarding arguments", func() {
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
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				uri := evapb.Application_HttpUri{
					HttpUri: &evapb.Application_HTTPSource{
						HttpUri: "https://localhost/test_img.tar.gz"},
				}

				port := evapb.PortProto{Port: 1234, Protocol: "tcp"}
				ports := []*evapb.PortProto{&port}
				app := evapb.Application{Id: "test-app-deploy",
					Cores: 2, Memory: 40, Source: &uri,
					Ports: ports,
				}

				go prefaceLis.Accept()
				_, err := client.DeployContainer(ctx, &app,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-deploy"}
				go prefaceLis.Accept()
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))

				Expect(stubs.DockerCliStub.CCreateArgs.Config.ExposedPorts).To(Equal(nat.PortSet{"1234/tcp": {}}))
			})
		})
		Context("with correct EAC mount arguments", func() {
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
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				uri := evapb.Application_HttpUri{
					HttpUri: &evapb.Application_HTTPSource{
						HttpUri: "https://localhost/test_img.tar.gz"},
				}

				eacVal := `[{"Key": "mount", "Value": "volume,testvol,/vol,false"},
					{"Key": "mount", "Value": "bind,/home/test,/bind,false"}]`
				app := evapb.Application{Id: "test-app-deploy",
					Cores: 2, Memory: 40, Source: &uri,
					EACJsonBlob: eacVal}

				go prefaceLis.Accept()
				_, err := client.DeployContainer(ctx, &app,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				// Verify status after deployment
				appid := evapb.ApplicationID{Id: "test-app-deploy"}
				go prefaceLis.Accept()
				alsClient := evapb.NewApplicationLifecycleServiceClient(conn)
				status, err := alsClient.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))

				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts).To(HaveLen(2))

				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[0].Type).To(Equal(mount.TypeVolume))
				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[0].Source).To(Equal("testvol"))
				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[0].Target).To(Equal("/vol"))
				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[0].ReadOnly).To(Equal(false))

				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[1].Type).To(Equal(mount.TypeBind))
				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[1].Source).To(Equal("/home/test"))
				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[1].Target).To(Equal("/bind"))
				Expect(stubs.DockerCliStub.CCreateArgs.HostConfig.Mounts[1].ReadOnly).To(Equal(false))
			})
		})
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
				stubs.DockerCliStub.ImRemoveResp =
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
				conn := createConnection()
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
				go prefaceLis.Accept()
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

	When("Undeploy is called", func() {
		Context("for container app with correct arguments", func() {
			It("responds with no error", func() {

				stubs.DockerCliStub.ImRemoveResp =
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
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				go prefaceLis.Accept()
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

var _ = Describe("EVA Libvirt tests", func() {

	stopInd := make(chan bool)

	BeforeEach(func() {
		err := runEVA("testdata/eva.json", stopInd)
		Expect(err).ToNot(HaveOccurred())
		// Clean directories
		os.RemoveAll(cfgFile.CertsDir)
		os.RemoveAll(cfgFile.AppImageDir)
		metadatahelpers.CreateDir(cfgFile.AppImageDir)
		stubs.HTTPCliStub = stubs.HTTPClientStub{}
		stubs.ConnStub = stubs.LibvirtConnectStub{}
		stubs.DomStub = stubs.LibvirtDomainStub{}
	})

	AfterEach(func() {
		stopEVA(stopInd)
	})

	When("Deploy is called", func() {
		Context("for vm with correct arguments", func() {
			It("responds with no error", func() {

				wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.DomByName = stubs.DomStub

				body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
				stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
					StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
					ProtoMinor: 1, Body: body, ContentLength: 11}

				// Create connection
				conn := createConnection()
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

				go prefaceLis.Accept()
				_, err := client.DeployVM(ctx, &app,
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
		Context("for vm with correct EAC CPU Pinning arguments", func() {
			It("responds with no error", func() {

				wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.DomByName = stubs.DomStub

				body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
				stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
					StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
					ProtoMinor: 1, Body: body, ContentLength: 11}

				// Create connection
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				uri := evapb.Application_HttpUri{
					HttpUri: &evapb.Application_HTTPSource{
						HttpUri: "https://localhost/test_img.tar.gz"},
				}

				eacVal := `[{"Key": "cpu_pin", "Value": "4-7"}]`
				app := evapb.Application{Id: "test-app-deploy",
					Cores: 2, Memory: 40, Source: &uri,
					EACJsonBlob: eacVal}

				go prefaceLis.Accept()
				_, err := client.DeployVM(ctx, &app,
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

	When("Undeploy is called", func() {
		Context("for vm with correct arguments", func() {
			It("responds with no error", func() {

				wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.DomByName = stubs.DomStub

				appid := evapb.ApplicationID{Id: "test-app-undeploy"}

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"test-app-undeploy")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(filepath.Join(expectedAppPath,
					"metadata.json"),
					`{"Type":"LibvirtDomain","URL":"https://localhost/test_`+
						`img.tar.gz","App":{"id":"test-app-undeploy","cores":`+
						`2,"memory":40,"status":2,"Source":null}}`)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"),
					"test-app-undeploy\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "test_img.tar.gz"),
					"TEST IMAGE")

				// Create connection
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationDeploymentServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				go prefaceLis.Accept()
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

	When("Redeploy is called", func() {
		Context("for vm with correct arguments", func() {
			It("responds with no error", func() {

				body := ioutil.NopCloser(strings.NewReader("TEST IMAGE"))
				stubs.HTTPCliStub.HTTPResp = http.Response{Status: "200 OK",
					StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
					ProtoMinor: 1, Body: body, ContentLength: 11}

				wrappers.CreateHTTPClient = stubs.CreateHTTPClientStub
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"test-app-redeploy")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(filepath.Join(expectedAppPath,
					"metadata.json"),
					`{"Type":"LibvirtDomain","URL":"https://localhost/test_`+
						`img.tar.gz","App":{"id":"test-app-redeploy","cores":`+
						`2,"memory":40,"status":2,"Source":null}}`)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"),
					"test-app-redeploy\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "test_img.tar.gz"),
					"TEST IMAGE")

				// Create connection
				conn := createConnection()
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
				go prefaceLis.Accept()
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
