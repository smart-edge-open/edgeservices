// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eva_test

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"errors"
	libvirt "github.com/libvirt/libvirt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/open-ness/edgenode/internal/metadatahelpers"
	"github.com/open-ness/edgenode/internal/stubs"
	"github.com/open-ness/edgenode/internal/wrappers"
	"github.com/open-ness/edgenode/pkg/eva"
	evapb "github.com/open-ness/edgenode/pkg/eva/pb"
	"google.golang.org/grpc"
)

var _ = Describe("ApplicationLifecycleService", func() {
	stopInd := make(chan bool)

	BeforeEach(func() {
		err := runEVA("testdata/eva.json", stopInd)
		Expect(err).ToNot(HaveOccurred())

		stubs.DockerCliStub = stubs.DockerClientStub{}
		stubs.ConnStub = stubs.LibvirtConnectStub{}
		stubs.DomStub = stubs.LibvirtDomainStub{}
	})

	AfterEach(func() {
		stopEVA(stopInd)

		// Clean directories
		err2 := os.RemoveAll(cfgFile.CertsDir)
		Expect(err2).ToNot(HaveOccurred())

		err2 = os.RemoveAll(cfgFile.AppImageDir)
		Expect(err2).ToNot(HaveOccurred())
	})

	When("GetStatus is called", func() {
		Context("with no application deployed", func() {
			It("responds with error", func() {
				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				appid := evapb.ApplicationID{Id: "testapp"}
				go prefaceLis.Accept()
				_, err := client.GetStatus(ctx, &appid, grpc.WaitForReady(true))
				Expect(err)
			})
		})
	})

	//docker test cases
	When("GetStatus is called", func() {
		Context("with -testpp- application deployed", func() {
			It("responds with no error", func() {
				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "DockerContainer","App":{"id":"testapp",
					"name":"testapp","status":2}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				appid := evapb.ApplicationID{Id: "testapp"}
				go prefaceLis.Accept()
				status, err := client.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_READY))
			})
		})
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

				conn := createConnection()
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
				go prefaceLis.Accept()
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

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_STOP}
				go prefaceLis.Accept()
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

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				go prefaceLis.Accept()
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

	//libvirt test cases
	When("Start is called", func() {
		Context("with -testpp- VM application deployed", func() {
			It("responds with no error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub

				stubs.DomStub.DomState = libvirt.DOMAIN_RUNNING
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":2}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				go prefaceLis.Accept()
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

			It("responds with connection create error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.ConnCreateErr = errors.New("Conn create error")

				stubs.DomStub.DomState = libvirt.DOMAIN_RUNNING
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":2}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, close := context.WithTimeout(context.Background(),
					10*time.Second)
				defer close()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_START}
				go prefaceLis.Accept()
				_, err := client.Start(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with connection close error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.ConnCloseErr = errors.New("Conn close error")

				stubs.DomStub.DomState = libvirt.DOMAIN_RUNNING
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":2}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, close := context.WithTimeout(context.Background(),
					10*time.Second)
				defer close()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_START}
				go prefaceLis.Accept()
				_, err := client.Start(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with LookupDomainByName error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.DomByNameErr =
					errors.New("LookupDomainByName error")

				stubs.DomStub.DomState = libvirt.DOMAIN_RUNNING
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":2}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, close := context.WithTimeout(context.Background(),
					10*time.Second)
				defer close()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_START}
				go prefaceLis.Accept()
				_, err := client.Start(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with application type identification failed", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub

				stubs.DomStub.DomState = libvirt.DOMAIN_RUNNING
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":2}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, close := context.WithTimeout(context.Background(),
					10*time.Second)
				defer close()

				//command without parameters
				cmd := evapb.LifecycleCommand{}
				go prefaceLis.Accept()
				_, err := client.Start(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})
		})
	})

	When("Stop is called", func() {
		Context("with -testpp- VM application deployed and running", func() {
			It("responds with no error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()
				go prefaceLis.Accept()
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

			It("responds with connection create error", func() {

				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.ConnCreateErr = errors.New("Conn create error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_STOP}
				go prefaceLis.Accept()
				_, err := client.Stop(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with connection close error", func() {

				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.ConnCloseErr = errors.New("Conn close error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_STOP}
				go prefaceLis.Accept()
				_, err := client.Stop(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with LookupDomainByName error", func() {

				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.DomByNameErr =
					errors.New("LookupDomainByName error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_STOP}
				go prefaceLis.Accept()
				_, err := client.Stop(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with get state error", func() {

				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.DomStub.DomStateErr = errors.New("GetState error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_STOP}
				go prefaceLis.Accept()
				_, err := client.Stop(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with shutdown error", func() {

				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.DomStub.DomShutdownErr = errors.New("Shutdown error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_STOP}
				go prefaceLis.Accept()
				_, err := client.Stop(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with application type identification failed", func() {

				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{} // command without parameters
				go prefaceLis.Accept()
				_, err := client.Stop(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})
		})
	})

	When("Restart is called", func() {
		Context("with -testpp- VM application deployed and running", func() {
			It("responds with no error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_RESTART}
				go prefaceLis.Accept()
				_, err := client.Restart(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())

				time.Sleep(100 * time.Millisecond)

				appid := evapb.ApplicationID{Id: "testapp"}
				status, err := client.GetStatus(ctx, &appid,
					grpc.WaitForReady(true))
				Expect(err).ToNot(HaveOccurred())
				Expect(status.Status).To(Equal(evapb.LifecycleStatus_RUNNING))
			})

			It("responds with connection create error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.ConnCreateErr = errors.New("Conn create error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_RESTART}
				go prefaceLis.Accept()
				_, err := client.Restart(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with connection close error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.ConnCloseErr = errors.New("Conn close error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_RESTART}
				go prefaceLis.Accept()
				_, err := client.Restart(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with LookupDomainByName error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.ConnStub.DomByNameErr =
					errors.New("LookupDomainByName error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_RESTART}
				go prefaceLis.Accept()
				_, err := client.Restart(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with get state error", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub
				stubs.DomStub.DomStateErr = errors.New("GetState error")

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{Id: "testapp",
					Cmd: evapb.LifecycleCommand_RESTART}
				go prefaceLis.Accept()
				_, err := client.Restart(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})

			It("responds with application type identification failed", func() {
				eva.CreateLibvirtConnection = stubs.CreateLibvirtConnectionStub

				stubs.DomStub.DomState = libvirt.DOMAIN_SHUTDOWN
				stubs.ConnStub.DomByName = stubs.DomStub

				expectedAppPath := filepath.Join(cfgFile.AppImageDir,
					"testapp")
				metadatahelpers.CreateDir(expectedAppPath)
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "deployed"), "testapp\n")
				metadatahelpers.CreateFile(
					filepath.Join(expectedAppPath, "metadata.json"),
					`{"Type": "LibvirtDomain","App":{"id":"testapp",
					"name":"testapp","status":4}}`)

				conn := createConnection()
				defer conn.Close()

				client := evapb.NewApplicationLifecycleServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(),
					10*time.Second)
				defer cancel()

				cmd := evapb.LifecycleCommand{} // command without parameters
				go prefaceLis.Accept()
				_, err := client.Restart(ctx, &cmd, grpc.WaitForReady(true))
				Expect(err)
			})
		})
	})

})
