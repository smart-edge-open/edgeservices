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

package interfaceservice_test

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	k "github.com/otcshare/edgenode/pkg/interfaceservice"

	h "github.com/otcshare/edgenode/pkg/ela/helpers"
	pb "github.com/otcshare/edgenode/pkg/ela/pb"
)

type vsctlResult struct {
	// ResultOutcome is a string which will be provided as ovs-vsctl output
	ResultOutcome string

	// ResultError is an error for simulating command's Run() errors
	ResultError error
}

type VsctlMock struct {
	// ReceivedArgs stores received argument which would be passed to ovs-vsctl
	ReceivedArgs [][]string

	// VsctlResponses contain list of vsctl's exec results
	VsctlResults []vsctlResult
}

// Exec saves given args and returns output and error set by test
func (v *VsctlMock) Exec(args ...string) ([]byte, error) {
	v.ReceivedArgs = append(v.ReceivedArgs, args)

	if len(v.VsctlResults) == 0 {
		return nil, errors.New("VsctlMock - results not set")
	}

	out, err := v.VsctlResults[0].ResultOutcome, v.VsctlResults[0].ResultError
	v.VsctlResults = v.VsctlResults[1:]

	return []byte(out), err
}

// Reset clears mock - Called flag and ReceivedArgs slice
func (v *VsctlMock) Reset() {
	v.ReceivedArgs = [][]string{}
}

// AddResult add next result for vsctl mock
func (v *VsctlMock) AddResult(outcome string, err error) {
	v.VsctlResults = append(v.VsctlResults, vsctlResult{outcome, err})
}

var _ = Describe("InterfaceService", func() {
	var vsctlMock VsctlMock

	BeforeEach(func() {
		vsctlMock = VsctlMock{}
		k.Vsctl = vsctlMock.Exec

		k.KernelNetworkDevicesProvider = func() ([]h.NetworkDevice,
			error) {
			return []h.NetworkDevice{
				{
					PCI:    "0000:00:00.0",
					Name:   "eth0",
					Driver: pb.NetworkInterface_KERNEL,
				},
				{
					PCI:    "0000:00:00.1",
					Name:   "eth1",
					Driver: pb.NetworkInterface_KERNEL,
				},
				{
					PCI:    "0000:00:00.2",
					Name:   "eth2",
					Driver: pb.NetworkInterface_KERNEL,
				},
				{
					PCI:    "0000:00:00.3",
					Name:   "eth3",
					Driver: pb.NetworkInterface_KERNEL,
				},
			}, nil
		}
	})

	Describe("GetAll", func() {
		interfaceServiceGetAll := func() (*pb.NetworkInterfaces, error) {
			conn, err := grpc.Dial(testEndpoint,
				grpc.WithTransportCredentials(transportCreds))
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewInterfaceServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer cancel()

			return client.GetAll(ctx, &empty.Empty{}, grpc.WaitForReady(true))
		}

		Context("no error occurred", func() {
			It("should return all the interfaces", func() {
				vsctlMock.AddResult("eth2\neth3", nil)

				ifs, err := interfaceServiceGetAll()
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(1))
				Expect(vsctlMock.ReceivedArgs[0]).
					To(Equal([]string{"list-ports", "br-local"}))
				Expect(err).ToNot(HaveOccurred())
				Expect(ifs).ToNot(BeNil())
				Expect(ifs.NetworkInterfaces).To(HaveLen(4))

				Expect(ifs.NetworkInterfaces[0].Id).To(Equal("0000:00:00.0"))
				Expect(ifs.NetworkInterfaces[0].Driver).
					To(Equal(pb.NetworkInterface_KERNEL))

				Expect(ifs.NetworkInterfaces[1].Id).To(Equal("0000:00:00.1"))
				Expect(ifs.NetworkInterfaces[1].Driver).
					To(Equal(pb.NetworkInterface_KERNEL))

				Expect(ifs.NetworkInterfaces[2].Id).To(Equal("0000:00:00.2"))
				Expect(ifs.NetworkInterfaces[2].Driver).
					To(Equal(pb.NetworkInterface_USERSPACE))

				Expect(ifs.NetworkInterfaces[3].Id).To(Equal("0000:00:00.3"))
				Expect(ifs.NetworkInterfaces[3].Driver).
					To(Equal(pb.NetworkInterface_USERSPACE))
			})
		})

		Context("no error occurred, but 0 ports attached to OVS", func() {
			It("all interfaces should be with kernel driver", func() {
				vsctlMock.AddResult("", nil)

				ifs, err := interfaceServiceGetAll()
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(1))
				Expect(vsctlMock.ReceivedArgs[0]).
					To(Equal([]string{"list-ports", "br-local"}))
				Expect(err).ToNot(HaveOccurred())
				Expect(ifs).ToNot(BeNil())
				Expect(ifs.NetworkInterfaces).To(HaveLen(4))

				Expect(ifs.NetworkInterfaces[0].Id).To(Equal("0000:00:00.0"))
				Expect(ifs.NetworkInterfaces[0].Driver).
					To(Equal(pb.NetworkInterface_KERNEL))

				Expect(ifs.NetworkInterfaces[1].Id).To(Equal("0000:00:00.1"))
				Expect(ifs.NetworkInterfaces[1].Driver).
					To(Equal(pb.NetworkInterface_KERNEL))

				Expect(ifs.NetworkInterfaces[2].Id).To(Equal("0000:00:00.2"))
				Expect(ifs.NetworkInterfaces[2].Driver).
					To(Equal(pb.NetworkInterface_KERNEL))

				Expect(ifs.NetworkInterfaces[3].Id).To(Equal("0000:00:00.3"))
				Expect(ifs.NetworkInterfaces[3].Driver).
					To(Equal(pb.NetworkInterface_KERNEL))
			})
		})

		Context("failed to obtain kernel interfaces", func() {
			It("should return an error", func() {
				k.KernelNetworkDevicesProvider = func() ([]h.NetworkDevice,
					error) {
					return nil, errors.New("failed to exec lspci command")
				}

				ifs, err := interfaceServiceGetAll()
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(0))
				Expect(err).To(HaveOccurred())
				Expect(ifs).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to exec lspci"))
				Expect(err.Error()).To(ContainSubstring(
					"failed to obtain kernel devices"))
			})
		})

		Context("failed to call ovs-vsctl", func() {
			It("should return an error", func() {
				vsctlMock.AddResult("", errors.New("command not found"))

				ifs, err := interfaceServiceGetAll()
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(1))
				Expect(vsctlMock.ReceivedArgs[0]).
					To(Equal([]string{"list-ports", "br-local"}))
				Expect(err).To(HaveOccurred())
				Expect(ifs).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("command not found"))
			})
		})
	})

	Describe("Get", func() {
		interfaceServiceGet := func(pci string) (*pb.NetworkInterface, error) {
			conn, err := grpc.Dial(testEndpoint,
				grpc.WithTransportCredentials(transportCreds))
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewInterfaceServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer cancel()

			return client.Get(ctx, &pb.InterfaceID{Id: pci},
				grpc.WaitForReady(true))
		}

		Context("no error occurred", func() {
			It("should return requested interface", func() {
				vsctlMock.AddResult("eth2\neth3", nil)
				vsctlMock.AddResult("eth2\neth3", nil)

				iface, err := interfaceServiceGet("0000:00:00.0")
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(1))
				Expect(vsctlMock.ReceivedArgs[0]).
					To(Equal([]string{"list-ports", "br-local"}))
				Expect(err).ToNot(HaveOccurred())
				Expect(iface).ToNot(BeNil())
				Expect(iface.Id).To(Equal("0000:00:00.0"))
				Expect(iface.Driver).To(Equal(pb.NetworkInterface_KERNEL))

				vsctlMock.Reset()

				iface, err = interfaceServiceGet("0000:00:00.2")
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(1))
				Expect(vsctlMock.ReceivedArgs[0]).
					To(Equal([]string{"list-ports", "br-local"}))
				Expect(err).ToNot(HaveOccurred())
				Expect(iface).ToNot(BeNil())

				Expect(iface.Id).To(Equal("0000:00:00.2"))
				Expect(iface.Driver).To(Equal(pb.NetworkInterface_USERSPACE))
			})
		})

		Context("failed to obtain interfaces", func() {
			It("should return an error", func() {
				k.KernelNetworkDevicesProvider = func() ([]h.NetworkDevice,
					error) {
					return nil, errors.New("failed to exec lspci command")
				}

				ifs, err := interfaceServiceGet("0000:00:00.0")
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(0))
				Expect(err).To(HaveOccurred())
				Expect(ifs).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("failed to exec lspci"))
				Expect(err.Error()).To(ContainSubstring(
					"failed to obtain kernel devices"))
			})
		})

		Context("given ID is empty", func() {
			It("should return an error", func() {
				ifs, err := interfaceServiceGet("")
				Expect(vsctlMock.ReceivedArgs).To(HaveLen(0))
				Expect(err).To(HaveOccurred())
				Expect(ifs).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("empty id"))
			})
		})
	})

	Describe("BulkUpdate", func() {
		interfaceServiceBulkUpdate := func(ifs *pb.NetworkInterfaces) error {
			conn, err := grpc.Dial(testEndpoint,
				grpc.WithTransportCredentials(transportCreds))
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewInterfaceServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer cancel()

			_, err = client.BulkUpdate(ctx, ifs, grpc.WaitForReady(true))
			return err
		}

		Context("invalid request parameter", func() {
			When("given NetworkInterfaces is invalid", func() {
				It("should return error", func() {
					By("testing if Driver is either KERNEL or USERSPACE")
					err := interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Driver: 3,
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"Driver is expected to be KERNEL or USERSPACE"))

					By("testing if Type is NONE")
					err = interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Type: pb.NetworkInterface_BIDIRECTIONAL,
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"Type is expected to be NONE"))

					err = interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Type: pb.NetworkInterface_UPSTREAM,
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"Type is expected to be NONE"))

					err = interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Type: pb.NetworkInterface_DOWNSTREAM,
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"Type is expected to be NONE"))

					err = interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Type: pb.NetworkInterface_BREAKOUT,
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"Type is expected to be NONE"))

					By("testing if Vlan is set")
					err = interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Vlan: 1,
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"Vlan is not supported"))

					By("testing if Zones are set")
					err = interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Zones: []string{""},
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"Zones are not supported"))

					By("testing if FallbackInterface is set")
					err = interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								FallbackInterface: "0000:00:00.5",
							},
						}})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"FallbackInterface is expected to be empty"))
				})
			})
		})

		Context("valid request parameters", func() {
			It("should detach/attach ports", func() {
				vsctlMock.AddResult("eth2\neth3", nil) // list-ports br-local
				vsctlMock.AddResult("", nil)           // add-port br-local eth0
				vsctlMock.AddResult("", nil)           // add-port br-local eth1
				vsctlMock.AddResult("", nil)           // del-port br-local eth2

				err := interfaceServiceBulkUpdate(&pb.NetworkInterfaces{
					NetworkInterfaces: []*pb.NetworkInterface{
						{
							Id:     "0000:00:00.0",
							Driver: pb.NetworkInterface_USERSPACE,
						},
						{
							Id:     "0000:00:00.1",
							Driver: pb.NetworkInterface_USERSPACE,
						},
						{
							Id:     "0000:00:00.2",
							Driver: pb.NetworkInterface_KERNEL,
						},
						{
							Id:     "0000:00:00.3",
							Driver: pb.NetworkInterface_USERSPACE,
						},
					}})
				Expect(err).ToNot(HaveOccurred())

				Expect(vsctlMock.ReceivedArgs).To(HaveLen(4))
				Expect(vsctlMock.ReceivedArgs[0]).
					To(Equal([]string{"list-ports", "br-local"}))

				Expect(vsctlMock.ReceivedArgs[1]).To(Equal(
					[]string{"--may-exist", "add-port", "br-local", "eth0"}))
				Expect(vsctlMock.ReceivedArgs[2]).To(Equal(
					[]string{"--may-exist", "add-port", "br-local", "eth1"}))
				Expect(vsctlMock.ReceivedArgs[3]).To(Equal(
					[]string{"--if-exist", "del-port", "br-local", "eth2"}))
			})
		})
	})

	Describe("Update", func() {
		interfaceServiceUpdate := func(iface *pb.NetworkInterface) error {
			conn, err := grpc.Dial(testEndpoint,
				grpc.WithTransportCredentials(transportCreds))
			Expect(err).NotTo(HaveOccurred())
			defer conn.Close()

			client := pb.NewInterfaceServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(),
				3*time.Second)
			defer cancel()

			_, err = client.Update(ctx, iface, grpc.WaitForReady(true))
			return err
		}

		Context("valid request parameters", func() {
			When("ovs-vsctl failes", func() {
				It("should return error", func() {
					By("testing ovs-vsctl del-port")
					vsctlMock.AddResult("eth0", nil) // list-ports br-local
					vsctlMock.AddResult("",          // del-port br-local eth0
						errors.New("failed to delete port"))

					err := interfaceServiceUpdate(&pb.NetworkInterface{
						Id:     "0000:00:00.0",
						Driver: pb.NetworkInterface_KERNEL,
					})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"failed to detach " +
							"interface 0000:00:00.0 (eth0) from OVS"))

					Expect(vsctlMock.ReceivedArgs).To(HaveLen(2))
					Expect(vsctlMock.ReceivedArgs[0]).
						To(Equal([]string{"list-ports", "br-local"}))
					Expect(vsctlMock.ReceivedArgs[1]).To(Equal(
						[]string{"--if-exist", "del-port", "br-local", "eth0"}))

					vsctlMock.Reset()

					By("testing ovs-vsctl add-port")
					vsctlMock.AddResult("", nil) // list-ports br-local
					vsctlMock.AddResult("",      // add-port br-local eth0
						errors.New("failed to add port"))

					err = interfaceServiceUpdate(&pb.NetworkInterface{
						Id:     "0000:00:00.0",
						Driver: pb.NetworkInterface_USERSPACE,
					})
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(
						"failed to attach " +
							"interface 0000:00:00.0 (eth0) to OVS"))

					Expect(vsctlMock.ReceivedArgs).To(HaveLen(2))
					Expect(vsctlMock.ReceivedArgs[0]).
						To(Equal([]string{"list-ports", "br-local"}))
					Expect(vsctlMock.ReceivedArgs[1]).To(Equal(
						[]string{"--may-exist", "add-port", "br-local",
							"eth0"}))
				})
			})
		})
	})
})
