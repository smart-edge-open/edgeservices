// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package interfaceservice_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	log "github.com/open-ness/common/log"
	"github.com/open-ness/edgenode/internal/authtest"
	"github.com/open-ness/edgenode/pkg/auth"
	"github.com/open-ness/edgenode/pkg/config"
	elahelpers "github.com/open-ness/edgenode/pkg/ela/helpers"
	ifs "github.com/open-ness/edgenode/pkg/interfaceservice"
	pb "github.com/open-ness/edgenode/pkg/interfaceservice/pb"
	monkey "github.com/undefinedlabs/go-mpatch"
)

var (
	vsctlMock     VsctlMock
	devbindMock   DevbindMock
	debugMocks    = true
	originVsctl   = ifs.Vsctl
	originDevbind = ifs.Devbind

	// store function pointers from interfaceservice pkg
	// to be able to call them if ifs.ReattachDpdkPorts & ifs.KernelNetworkDevicesProvider
	// are overwritten by mocks
	ifsReattachDpdkPortsFunction    = ifs.ReattachDpdkPorts
	ifsKernelNetworkDevicesProvider = ifs.KernelNetworkDevicesProvider
)

var bindOut = `Network devices using DPDK-compatible driver
============================================
0000:00:01.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb' drv=igb_uio unused=

Network devices using kernel driver
===================================
0000:00:00.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb' if=eth0 drv=ixgbe unused=igb_uio
0000:00:00.1 'I350 Gigabit Network Connection 1521' if=eth1 drv=igb unused=igb_uio
0000:00:00.2 'I350 Gigabit Network Connection 1521' if=eth2 drv=igb unused=igb_uio
0000:00:00.3 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb' if=eth3 drv=ixgbe unused=igb_uio

Other Network devices
=====================
0000:00:02.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb' unused=igb_uio

No 'Crypto' devices detected
============================

No 'Eventdev' devices detected
==============================

No 'Mempool' devices detected
=============================

No 'Compress' devices detected
==============================
`

var bindOutShort = `Network devices using DPDK-compatible driver
============================================
0000:00:01.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb' drv=igb_uio unused=
`

var bindOutShort2 = `Network devices using DPDK-compatible driver
============================================
0000:00:01.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb' drv=igb_uio unused=igb_uio
`

var elaInterfacesMock = []elahelpers.NetworkDevice{
	{
		PCI:  "0000:00:01.0",
		Name: "",
	},
	{
		PCI:  "0000:00:00.0",
		Name: "eth0",
	},
	{
		PCI:  "0000:00:00.1",
		Name: "eth1",
	},
	{
		PCI:  "0000:00:00.2",
		Name: "eth2",
	},
	{
		PCI:  "0000:00:00.3",
		Name: "eth3",
	},
	{
		PCI:  "0000:00:02.0",
		Name: "",
	},
}

var strResultVsctl = `Bridge br-test
						datapath_type: netdev
						Port eth0
							Interface eth0
								type: dpdk
								options: {dpdk-devargs="0000:00:01.0"}`

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
	if debugMocks {
		fmt.Printf("MOCK [Vsctl received: ovs-vsctl %s]\n", args)
	}
	v.ReceivedArgs = append(v.ReceivedArgs, args)

	if len(v.VsctlResults) == 0 {
		return nil, errors.New("VsctlMock - results not set")
	}

	out, err := v.VsctlResults[0].ResultOutcome, v.VsctlResults[0].ResultError
	v.VsctlResults = v.VsctlResults[1:]
	if debugMocks {
		fmt.Printf("MOCK [Vsctl response: %s]\n", out)
	}
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

type devbindResult struct {
	// ResultOutcome is a string which will be provided as ovs-vsctl output
	resultOutcome string

	// ResultError is an error for simulating command's Run() errors
	resultError error
}

type DevbindMock struct {
	// ReceivedArgs stores received argument which would be passed to ovs-vsctl
	receivedArgs [][]string

	// VsctlResponses contain list of vsctl's exec results
	devbindResults []devbindResult
}

// Exec saves given args and returns output and error set by test
func (v *DevbindMock) Exec(args ...string) ([]byte, error) {
	if debugMocks {
		fmt.Printf("MOCK [Devind received: ./dpdk-devbind.py %s]\n", args)
	}
	v.receivedArgs = append(v.receivedArgs, args)

	if len(v.devbindResults) == 0 {
		return nil, errors.New("DevbindMock - results not set")
	}

	out, err := v.devbindResults[0].resultOutcome, v.devbindResults[0].resultError
	v.devbindResults = v.devbindResults[1:]
	if debugMocks {
		fmt.Printf("MOCK [Devind response: %s]\n", out)
	}
	return []byte(out), err
}

// Reset clears mock - Called flag and ReceivedArgs slice
func (v *DevbindMock) Reset() {
	v.receivedArgs = [][]string{}
}

// AddResult add next result for vsctl mock
func (v *DevbindMock) AddResult(outcome string, err error) {
	v.devbindResults = append(v.devbindResults, devbindResult{outcome, err})
}

func elaHelperKernelNetworkDevicesProvider() ([]elahelpers.NetworkDevice, error) {
	return elaInterfacesMock, nil
}

func get() (*pb.Ports, error) {
	conn, err := grpc.Dial(testEndpoint,
		grpc.WithTransportCredentials(transportCreds))
	Expect(err).NotTo(HaveOccurred())
	defer conn.Close()

	interfaceServiceClient := pb.NewInterfaceServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(),
		3*time.Second)
	defer cancel()

	return interfaceServiceClient.Get(ctx, &empty.Empty{},
		grpc.WaitForReady(true))
}

func attach(in *pb.Ports) error {
	conn, err := grpc.Dial(testEndpoint,
		grpc.WithTransportCredentials(transportCreds))
	Expect(err).NotTo(HaveOccurred())
	defer conn.Close()

	interfaceServiceClient := pb.NewInterfaceServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(),
		3*time.Second)
	defer cancel()

	_, err = interfaceServiceClient.Attach(ctx, in, grpc.WaitForReady(true))
	return err
}

func detach(in *pb.Ports) error {
	conn, err := grpc.Dial(testEndpoint,
		grpc.WithTransportCredentials(transportCreds))
	Expect(err).NotTo(HaveOccurred())
	defer conn.Close()

	interfaceServiceClient := pb.NewInterfaceServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(),
		3*time.Second)
	defer cancel()

	_, err = interfaceServiceClient.Detach(ctx, in, grpc.WaitForReady(true))
	return err
}

func prepareMocks() {
	vsctlMock = VsctlMock{}
	ifs.Vsctl = vsctlMock.Exec
	devbindMock = DevbindMock{}
	ifs.Devbind = devbindMock.Exec
	ifs.KernelNetworkDevicesProvider = elaHelperKernelNetworkDevicesProvider
}

func fakeKernelNetworkDevicesProvider() ([]elahelpers.NetworkDevice, error) {
	return elaInterfacesMock, errors.New("Failed to get NetworkDevices")
}

var _ = Describe("InterfaceService", func() {

	BeforeEach(func() {
		prepareMocks()
	})

	Describe("Get", func() {
		Context("no error occurred", func() {
			It("should return 6 interfaces:"+
				"1 dpdk, 4 kernel, 1 no driver attached", func() {

				devbindMock.AddResult(bindOut, nil)
				Expect(ifs.DpdkEnabled).To(Equal(true))
				// 13 times ovs-vsctl is called
				for i := 0; i < 13; i++ {
					vsctlMock.AddResult("", nil)
				}

				respPorts, err := get()

				Expect(err).ToNot(HaveOccurred())
				Expect(respPorts).ToNot(BeNil())

				Expect(respPorts.Ports).To(HaveLen(6))

				Expect(respPorts.Ports[0].GetPci()).To(Equal("0000:00:01.0"))
				Expect(respPorts.Ports[0].GetDriver()).To(Equal(pb.Port_USERSPACE))

				Expect(respPorts.Ports[1].GetPci()).To(Equal("0000:00:00.0"))
				Expect(respPorts.Ports[1].GetDriver()).To(Equal(pb.Port_KERNEL))

				Expect(respPorts.Ports[2].GetPci()).To(Equal("0000:00:00.1"))
				Expect(respPorts.Ports[2].GetDriver()).To(Equal(pb.Port_KERNEL))

				Expect(respPorts.Ports[3].GetPci()).To(Equal("0000:00:00.2"))
				Expect(respPorts.Ports[3].GetDriver()).To(Equal(pb.Port_KERNEL))

				Expect(respPorts.Ports[4].GetPci()).To(Equal("0000:00:00.3"))
				Expect(respPorts.Ports[4].GetDriver()).To(Equal(pb.Port_KERNEL))

				Expect(respPorts.Ports[5].GetPci()).To(Equal("0000:00:02.0"))
				Expect(respPorts.Ports[5].GetDriver()).To(Equal(pb.Port_NONE))
			})
		})
	})

	Describe("Attach", func() {
		Context("already attached 0000:00:00.0 to Port_KERNEL", func() {
			It("should return no error", func() {
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("already attached 0000:00:00.0 to Port_KERNEL", func() {
			It("should return no error", func() {
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("0000:00:00.0 to Port_USERSPACE", func() {
			It("should return no error", func() {

				str := `Bridge br-test
				datapath_type: netdev
				Port eth0
					Interface eth0
						type: dpdk
						options: {dpdk-devargs="0000:00:00.0"}`

				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("netdev", nil)
				vsctlMock.AddResult(str, nil)
				devbindMock.AddResult("2", nil)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_USERSPACE,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Detach", func() {
		Context("0000:00:01.0 to Port_KERNEL", func() {
			It("should return no error", func() {
				devbindMock.AddResult(bindOut, nil)

				vsctlMock.AddResult(strResultVsctl, nil) // resp for show
				vsctlMock.AddResult("", nil)             // resp for del-port
				devbindMock.AddResult("", nil)           // resp for bind

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := detach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:01.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})

				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Call uncovered functions", func() {
		Context("call getKernelNetworkDevices which is mocked in other tests", func() {
			It("should return no error", func() {
				ifsKernelNetworkDevicesProvider()
			})
			It("should return error", func() {
				fakeGetNetworkPCIs := func() ([]elahelpers.NetworkDevice, error) {
					return nil, errors.New("elahelpers.NetworkDevice errors")
				}

				GetNetworkPCIsPatch, err := monkey.PatchMethod(elahelpers.GetNetworkPCIs, fakeGetNetworkPCIs)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					pErr := GetNetworkPCIsPatch.Unpatch()
					Expect(pErr).NotTo(HaveOccurred())
				}()

				_, err = ifsKernelNetworkDevicesProvider()
				Expect(err).To(HaveOccurred())
			})
			It("should return no error", func() {

				// elahelpers.GetNetworkPCIs
				fakeGetNetworkPCIs := func() ([]elahelpers.NetworkDevice, error) {
					var ret []elahelpers.NetworkDevice
					return ret, nil
				}

				GetNetworkPCIsPatch, err := monkey.PatchMethod(elahelpers.GetNetworkPCIs, fakeGetNetworkPCIs)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					pErr := GetNetworkPCIsPatch.Unpatch()
					Expect(pErr).NotTo(HaveOccurred())
				}()

				// FillMACAddrForKernelDevs
				fakeFillMACAddrForKernelDevs := func([]elahelpers.NetworkDevice) error {
					return nil
				}

				FillMACAddrForKernelDevsPatch, err := monkey.PatchMethod(elahelpers.FillMACAddrForKernelDevs,
					fakeFillMACAddrForKernelDevs)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					pErr := FillMACAddrForKernelDevsPatch.Unpatch()
					Expect(pErr).NotTo(HaveOccurred())
				}()

				_, err = ifsKernelNetworkDevicesProvider()
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("call vsctl which is mocked in other tests", func() {
			It("should return no error", func() {
				originVsctl()
			})
		})

		Context("call devbind which is mocked in other tests", func() {
			It("should return no error", func() {
				originDevbind()
			})
		})

		Context("call Get()", func() {
			It("should return error as vsctl fails", func() {
				_, err := get()
				Expect(err).To(HaveOccurred())
			})
		})
		Context("call getKernelNetworkDevices", func() {
			It("interfaceservice.ReattachDpdkPorts detach error", func() {
				e := errors.New("Error attaching device")
				vsctlMock.AddResult("", nil) // resp for show

				err := ifsReattachDpdkPortsFunction()
				Expect(err).To(HaveOccurred())

				// resp for show
				vsctlMock.AddResult("", nil)
				// resp for list-br
				vsctlMock.AddResult("br-int\nbr-userspace", nil)
				// resp for get bridge br-int datapath_type - this will be skipped
				vsctlMock.AddResult("system", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("netdev", nil)
				// list-interfaces
				vsctlMock.AddResult("interface-ok\ninterface-error", nil)
				// no error for interface-ok
				vsctlMock.AddResult("", e)
				// error for interface-error
				vsctlMock.AddResult("Error attaching device 0000:00:00.1", nil)
				devbindMock.AddResult(
					"0000:00:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb'"+
						" if=eth1 drv=ixgbe unused=igb_uio", nil)

				err = ifsReattachDpdkPortsFunction()
				Expect(err).To(HaveOccurred())
			})

			It("interfaceservice.ReattachDpdkPorts attach error", func() {
				e := errors.New("Error attaching device")
				vsctlMock.AddResult("", nil) // resp for show

				err := ifsReattachDpdkPortsFunction()
				Expect(err).To(HaveOccurred())

				// resp for show
				vsctlMock.AddResult("", nil)
				// resp for list-br
				vsctlMock.AddResult("br-int\nbr-userspace", nil)
				// resp for get bridge br-int datapath_type - this will be skipped
				vsctlMock.AddResult("system", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("netdev", nil)
				// list-interfaces
				vsctlMock.AddResult("interface-ok\ninterface-error", nil)
				// no error for interface-ok
				vsctlMock.AddResult("", e)
				// error for interface-error
				vsctlMock.AddResult("Error attaching device 0000:00:00.1", nil)
				devbindMock.AddResult(
					"0000:00:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb'"+
						" if=eth1 drv=ixgbe unused=igb_uio", nil)
				// resp for del-port eth1
				vsctlMock.AddResult("", nil)

				err = ifsReattachDpdkPortsFunction()
				Expect(err).To(HaveOccurred())
			})

			It("interfaceservice.ReattachDpdkPorts attach error", func() {
				e := errors.New("Error attaching device")
				prepareMocks()
				vsctlMock.AddResult("", nil) // resp for show

				err := ifsReattachDpdkPortsFunction()
				Expect(err).To(HaveOccurred())

				// resp for show
				vsctlMock.AddResult("", nil)
				// resp for list-br
				vsctlMock.AddResult("br-int\nbr-userspace", nil)
				// resp for get bridge br-int datapath_type - this will be skipped
				vsctlMock.AddResult("system", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("netdev", nil)
				// list-interfaces
				vsctlMock.AddResult("interface-ok\ninterface-error", nil)
				// no error for interface-ok
				vsctlMock.AddResult("", e)
				// error for interface-error
				vsctlMock.AddResult("Error attaching device 0000:00:00.1", nil)
				devbindMock.AddResult(
					"0000:00:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb'"+
						" if=eth1 drv=ixgbe unused=igb_uio", nil)
				// resp for del-port eth1
				vsctlMock.AddResult("", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("", nil)

				err = ifsReattachDpdkPortsFunction()
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("0000:00:01.0 to Port_USERSPACE", func() {
			It("should return error", func() {
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("netdev", nil)
				vsctlMock.AddResult(strResultVsctl, nil)
				devbindMock.AddResult("2", nil)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:01.0",
							Driver: pb.Port_USERSPACE,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("attach with DpdkEnabled not set", func() {
			It("should not return error", func() {
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				oldDpdkEnabled := ifs.DpdkEnabled
				ifs.DpdkEnabled = false
				defer func() { ifs.DpdkEnabled = oldDpdkEnabled }()

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("attach with DpdkEnabled not set with Port_USERSPACE", func() {
			It("should return error", func() {
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				oldDpdkEnabled := ifs.DpdkEnabled
				ifs.DpdkEnabled = false
				defer func() { ifs.DpdkEnabled = oldDpdkEnabled }()

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_USERSPACE,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("attach with DpdkEnabled not set with Port_KERNEL", func() {
			It("should return no error", func() {
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				oldDpdkEnabled := ifs.DpdkEnabled
				ifs.DpdkEnabled = false
				defer func() { ifs.DpdkEnabled = oldDpdkEnabled }()

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("attach with no interface name", func() {
			It("should return error", func() {
				devbindMock.AddResult(bindOutShort, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("attach with invalid interface configuration", func() {
			It("should return error", func() {
				devbindMock.AddResult(bindOutShort, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				// Invalid PCI
				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:g0:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).To(HaveOccurred())

				// Invalid driver type
				err = attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_NONE,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).To(HaveOccurred())

				// Invalid bridge
				err = attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_USERSPACE,
							Bridge: "",
						},
					},
				})
				Expect(err).To(HaveOccurred())

			})
		})
	})

	Describe("Attach", func() {
		Context("attach with wrong bridge for Kernel", func() {
			It("should return error", func() {

				str := `Bridge br-test
				datapath_type: netdev
				Port eth0
					Interface eth0
						type: dpdk
						options: {dpdk-devargs="0000:00:00.0"}`

				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("netdev", nil)
				vsctlMock.AddResult(str, nil)
				devbindMock.AddResult("2", nil)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "netdev",
						},
					},
				})
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Detach", func() {
		Context("0000:00:05.0 to Port_KERNEL with no interface", func() {
			It("should return error", func() {
				devbindMock.AddResult(bindOutShort, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", nil)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := detach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:05.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})

				Expect(err).To(HaveOccurred())

				err = detach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:01.0",
							Driver: pb.Port_NONE,
							Bridge: "br-test",
						},
					},
				})

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Detach", func() {
		Context("with bind step failure", func() {
			It("should return error", func() {
				vsctlMock.AddResult(strResultVsctl, nil) // resp for show
				vsctlMock.AddResult("", nil)             // resp for del-port

				oldDpdkEnabled := ifs.DpdkEnabled
				ifs.DpdkEnabled = false
				defer func() { ifs.DpdkEnabled = oldDpdkEnabled }()

				err := detach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:01.0",
							Driver: pb.Port_USERSPACE,
							Bridge: "br-test",
						},
					},
				})

				Expect(err).To(HaveOccurred())

			})
		})
	})

	Describe("Detach", func() {
		Context("0000:00:01.0 to Port_KERNEL with not found", func() {
			It("should return error", func() {
				devbindMock.AddResult(bindOutShort2, nil)

				vsctlMock.AddResult(strResultVsctl, nil) // resp for show
				vsctlMock.AddResult("", nil)             // resp for del-port
				devbindMock.AddResult("", nil)           // resp for bind

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := detach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:01.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Attach", func() {
		Context("attach with vsctl error", func() {
			It("should return error", func() {
				var reterr = errors.New("vsctl failed")
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", reterr)

				Expect(ifs.DpdkEnabled).To(Equal(true))

				err := attach(&pb.Ports{
					Ports: []*pb.Port{
						{
							Pci:    "0000:00:00.0",
							Driver: pb.Port_KERNEL,
							Bridge: "br-test",
						},
					},
				})
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Get", func() {
		Context("port-to-br fails", func() {
			It("should not return error", func() {
				var reterr = errors.New("vsctl failed")
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", reterr)

				_, err := get()
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Get", func() {
		Context("fake KernelNetworkDevicesProvider", func() {
			It("should return error", func() {

				oldKernelNetworkDevicesProvider := ifs.KernelNetworkDevicesProvider
				ifs.KernelNetworkDevicesProvider = fakeKernelNetworkDevicesProvider
				defer func() { ifs.KernelNetworkDevicesProvider = oldKernelNetworkDevicesProvider }()

				var reterr = errors.New("vsctl failed")
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", reterr)

				_, err := get()
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Get", func() {
		Context("find matching port", func() {
			It("should not return error", func() {
				devbindMock.AddResult(bindOut, nil)
				Expect(ifs.DpdkEnabled).To(Equal(true))
				vsctlMock.AddResult(strResultVsctl, nil) // resp for show

				// 13 times ovs-vsctl is called
				for i := 0; i < 12; i++ {
					vsctlMock.AddResult("", nil)
				}

				_, err := get()
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Server bootup", func() {
		var (
			testEndpointFake = "localhost:22201"
			certsDirFake     string
			configFile       = "interfaceserviceFake.json"
			dpdkDevbindFake  = "dpdk-devbindFake.py"
			originConfigJSON []byte
		)

		BeforeEach(func() {
			// Generate certs
			var err error
			certsDirFake, err = ioutil.TempDir("", "elaCertsFake")
			Expect(err).NotTo(HaveOccurred())

			Expect(authtest.EnrollStub(certsDirFake)).ToNot(HaveOccurred())

			// Write ELA's config
			err = ioutil.WriteFile(configFile, []byte(fmt.Sprintf(`
			{
				"endpoint": "%s",
				"certsDirectory": "%s"
			}`, testEndpointFake, certsDirFake)), os.FileMode(0644))
			Expect(err).NotTo(HaveOccurred())

			originConfigJSON, err = json.Marshal(ifs.Config)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {

			err := json.Unmarshal(originConfigJSON, &ifs.Config)
			Expect(err).NotTo(HaveOccurred())

			os.RemoveAll(certsDirFake)
			os.Remove(configFile)
			os.Remove(dpdkDevbindFake)

			devbindMock.Reset()
			vsctlMock.Reset()
		})

		Context("call run with a damaged config file", func() {
			It("should return error", func() {

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				ifs.ReattachDpdkPorts = reatachPortsMock

				err := ioutil.WriteFile(configFile, []byte("damage date"), os.FileMode(0644))
				Expect(err).NotTo(HaveOccurred())

				err = ifs.Run(srvCtx, configFile)
				Expect(err).To(HaveOccurred())
				srvCancel()
			})
		})

		Context("call run with an incorrect endpoint", func() {
			It("should return error", func() {

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				ifs.ReattachDpdkPorts = reatachPortsMock

				// Write ELA's config
				err := ioutil.WriteFile(configFile, []byte(fmt.Sprintf(`
				{
					"endpoint": "%s",
					"certsDirectory": "%s"
				}`, "#@#@#@:9999999", certsDirFake)), os.FileMode(0644))
				Expect(err).NotTo(HaveOccurred())

				err = ifs.Run(srvCtx, configFile)
				Expect(err).To(HaveOccurred())
				srvCancel()
			})
		})

		Context("call run with nonexistent dpdk-devbind.py", func() {
			It("should return no error", func() {

				devbindMock.AddResult(bindOut, nil)
				Expect(ifs.DpdkEnabled).To(Equal(true))
				// 13 times ovs-vsctl is called
				for i := 0; i < 13; i++ {
					vsctlMock.AddResult("", nil)
				}

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				ifs.ReattachDpdkPorts = reatachPortsMock

				err := os.Remove("dpdk-devbind.py")
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					iErr := ioutil.WriteFile("./dpdk-devbind.py", []byte{}, os.ModePerm)
					Expect(iErr).NotTo(HaveOccurred())
					ifs.DpdkEnabled = true
				}()

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					ifs.Run(srvCtx, configFile)
					wg.Done()
				}()

				//waiting for interfaceservice.json
				for start := time.Now(); time.Since(start) < 3*time.Second; {
					if ifs.Config.Endpoint == testEndpointFake {
						break
					}
				}

				conn, err := grpc.Dial(testEndpointFake, grpc.WithTransportCredentials(transportCreds))
				Expect(err).NotTo(HaveOccurred())
				defer conn.Close()

				interfaceServiceClient := pb.NewInterfaceServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				_, err = interfaceServiceClient.Get(ctx, &empty.Empty{}, grpc.WaitForReady(true))
				Expect(err).NotTo(HaveOccurred())

				// confirm ifs.DpdkEnabled to be false
				Expect(ifs.DpdkEnabled).To(Equal(false))

				srvCancel()
				wg.Wait()
			})
		})

		Context("call run with a empty CertsDir path", func() {
			It("should return error", func() {

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				ifs.ReattachDpdkPorts = reatachPortsMock

				err := ioutil.WriteFile(configFile, []byte(fmt.Sprintf(`
				{
					"endpoint": "%s",
					"certsDirectory": "%s"
				}`, testEndpointFake, "")), os.FileMode(0644))
				Expect(err).NotTo(HaveOccurred())

				err = ifs.Run(srvCtx, configFile)
				Expect(err).To(HaveOccurred())
				srvCancel()
			})
		})

		Context("call run without root.pem file", func() {
			It("should return error", func() {

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				ifs.ReattachDpdkPorts = reatachPortsMock

				var configFake ifs.Configuration
				config.LoadJSONConfig(configFile, &configFake)

				caPath := filepath.Clean(filepath.Join(configFake.CertsDir, auth.CAPoolName))
				caPathBak := caPath + ".bak"
				err := os.Rename(caPath, caPathBak)
				Expect(err).NotTo(HaveOccurred())

				defer func() {
					err = os.Rename(caPathBak, caPath)
					Expect(err).NotTo(HaveOccurred())
				}()

				err = ifs.Run(srvCtx, configFile)
				Expect(err).To(HaveOccurred())
				srvCancel()
			})
		})

		Context("call run with incorrect root.pem file", func() {
			It("should return error", func() {

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				ifs.ReattachDpdkPorts = reatachPortsMock

				var configFake ifs.Configuration
				config.LoadJSONConfig(configFile, &configFake)

				caPath := filepath.Clean(filepath.Join(configFake.CertsDir, auth.CAPoolName))
				wf, wfErr := newWreckFile(caPath)
				Expect(wfErr).NotTo(HaveOccurred())

				wfErr = wf.wreckFile()
				Expect(wfErr).NotTo(HaveOccurred())

				defer func() {
					wfErr = wf.recoverFile()
					Expect(wfErr).NotTo(HaveOccurred())
				}()

				err := ifs.Run(srvCtx, configFile)
				Expect(err).To(HaveOccurred())
				srvCancel()
			})
		})

		Context("call run with failure on 'ovs-vsctl show'", func() {
			It("should panic", func() {
				ifs.ReattachDpdkPorts = ifsReattachDpdkPortsFunction
				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				fakeExit := func(int) {
					panic("os.Exit called")
				}
				patch, err := monkey.PatchMethod(os.Exit, fakeExit)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					pErr := patch.Unpatch()
					Expect(pErr).NotTo(HaveOccurred())
				}()

				Expect(func() { ifs.Run(srvCtx, configFile) }).Should(PanicWith("os.Exit called"))

				srvCancel()
			})
		})

		Context("call run with gRPC error", func() {
			var (
				buffer *gbytes.Buffer
			)

			BeforeEach(func() {
				var err error
				r, w, err := os.Pipe()
				Expect(err).NotTo(HaveOccurred())
				log.SetOutput(w)
				buffer = gbytes.BufferReader(r)
			})

			AfterEach(func() {
				os.Stdout.Write(buffer.Contents())
				log.SetOutput(GinkgoWriter)
			})

			It("should return error", func() {

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				ifs.ReattachDpdkPorts = reatachPortsMock

				grpcServer := grpc.NewServer()

				fakeRegisterPatch, irErr := monkey.PatchInstanceMethodByName(
					reflect.TypeOf(grpcServer), "RegisterService",
					func(s *grpc.Server, sd *grpc.ServiceDesc, ss interface{}) {
						log.Info("Fake RegisterService: ", sd.ServiceName)
					})
				Expect(irErr).NotTo(HaveOccurred())

				defer func() {
					uErr := fakeRegisterPatch.Unpatch()
					Expect(uErr).NotTo(HaveOccurred())
				}()

				fakeServerPatch, isErr := monkey.PatchInstanceMethodByName(
					reflect.TypeOf(grpcServer), "Serve",
					func(s *grpc.Server, lis net.Listener) error {
						lis.Close()
						return errors.New("Fake gRPC Error")
					})
				Expect(isErr).NotTo(HaveOccurred())

				defer func() {
					uErr := fakeServerPatch.Unpatch()
					Expect(uErr).NotTo(HaveOccurred())
				}()

				fakeNewServer := func(_ ...grpc.ServerOption) *grpc.Server {
					return grpcServer
				}

				patch, err := monkey.PatchMethod(grpc.NewServer, fakeNewServer)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					uErr := patch.Unpatch()
					Expect(uErr).NotTo(HaveOccurred())
				}()

				err = ifs.Run(srvCtx, configFile)
				Expect(err).To(MatchError("Fake gRPC Error"))

				duration := 1 * time.Second
				Eventually(buffer, duration).Should(
					gbytes.Say(`grpcServer.Serve error: Fake gRPC Error`))

				srvCancel()
			})
		})

		Context("test reattachDpdkPorts", func() {
			var (
				w      os.File
				buffer *gbytes.Buffer
			)

			BeforeEach(func() {
				var err error
				r, w, err := os.Pipe()
				Expect(err).NotTo(HaveOccurred())
				log.SetOutput(w)
				buffer = gbytes.BufferReader(r)
			})

			AfterEach(func() {
				os.Stdout.Write(buffer.Contents())
				log.SetOutput(GinkgoWriter)
			})

			It("should log 'detachPortFromOvs Error'", func() {

				ifs.ReattachDpdkPorts = ifsReattachDpdkPortsFunction

				// resp for show
				vsctlMock.AddResult("", nil)
				// resp for list-br
				vsctlMock.AddResult("br-int\nbr-userspace", nil)
				// resp for get bridge br-int datapath_type - this will be skipped
				vsctlMock.AddResult("system", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("netdev", nil)
				// list-interfaces
				vsctlMock.AddResult("interface-ok\ninterface-error", nil)
				// resp for get interface
				// error for interface-error
				vsctlMock.AddResult("Error attaching device 0000:00:00.1", nil)
				// resp for Devbind("--status") in updateDPDKDevbindOutput
				devbindMock.AddResult(
					"0000:00:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb'"+
						" if=eth1 drv=ixgbe unused=igb_uio", nil)

				e := errors.New("detachPortFromOvs Error")
				// resp for del-port eth1
				vsctlMock.AddResult("", e)

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				var wg sync.WaitGroup
				wg.Add(1)
				var err error
				go func() {
					err = ifs.Run(srvCtx, configFile)
					wg.Done()
				}()

				//waiting for interfaceservice.json
				for start := time.Now(); time.Since(start) < 3*time.Second; {
					if ifs.Config.Endpoint == testEndpointFake {
						break
					}
				}

				d := 5 * time.Second
				Eventually(buffer, d).Should(gbytes.Say(`detachPortFromOvs Error`))

				srvCancel()
				wg.Wait()
				Expect(err).Should(Succeed())
				w.Close()
			})

			It("should log 'attachPortFromOvs Error'", func() {

				ifs.ReattachDpdkPorts = ifsReattachDpdkPortsFunction

				// resp for show
				vsctlMock.AddResult("", nil)
				// resp for list-br
				vsctlMock.AddResult("br-int\nbr-userspace", nil)
				// resp for get bridge br-int datapath_type - this will be skipped
				vsctlMock.AddResult("system", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("netdev", nil)
				// list-interfaces
				vsctlMock.AddResult("interface-ok\ninterface-error", nil)
				// resp for get interface
				// error for interface-error
				vsctlMock.AddResult("Error attaching device 0000:00:00.1", nil)
				// resp for Devbind("--status") in updateDPDKDevbindOutput
				devbindMock.AddResult(
					"0000:00:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb'"+
						" if=eth1 drv=ixgbe unused=igb_uio", nil)

				ifs.KernelNetworkDevicesProvider = func() ([]elahelpers.NetworkDevice, error) {
					return nil, errors.New("attachPortFromOvs Error")
				}

				// resp for del-port eth1
				vsctlMock.AddResult("", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("netdev", nil)

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				var wg sync.WaitGroup
				wg.Add(1)
				var err error
				go func() {
					err = ifs.Run(srvCtx, configFile)
					wg.Done()
				}()

				//waiting for interfaceservice.json
				for start := time.Now(); time.Since(start) < 3*time.Second; {
					if ifs.Config.Endpoint == testEndpointFake {
						break
					}
				}

				d := 5 * time.Second
				Eventually(buffer, d).Should(gbytes.Say(`attachPortFromOvs Error`))

				srvCancel()
				wg.Wait()
				Expect(err).Should(Succeed())
				w.Close()
			})

			It("should log 'successfully reattached to bridge'", func() {

				ifs.ReattachDpdkPorts = ifsReattachDpdkPortsFunction

				// resp for show
				vsctlMock.AddResult("", nil)
				// resp for list-br
				vsctlMock.AddResult("br-int\nbr-userspace", nil)
				// resp for get bridge br-int datapath_type - this will be skipped
				vsctlMock.AddResult("system", nil)
				// resp for get bridge br-userspace datapath_type
				vsctlMock.AddResult("netdev", nil)
				// list-interfaces
				vsctlMock.AddResult("interface-ok\ninterface-error", nil)
				// resp for get interface
				// error for interface-error
				vsctlMock.AddResult("Error attaching device 0000:00:00.1", nil)
				// resp for Devbind("--status") in updateDPDKDevbindOutput
				devbindMock.AddResult(
					"0000:00:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection 10fb'"+
						" if=eth1 drv=ixgbe unused=igb_uio", nil)
				// resp for del-port eth1
				vsctlMock.AddResult("", nil)
				// resp for get bridge br-userspace datapath_type in attachPortToOvs
				vsctlMock.AddResult("netdev", nil)
				// resp for Devbind("-b", drv, port.Pci) in attachPortToOvs
				devbindMock.AddResult("", nil)
				// resp for --may-exist add-port in attachPortToOvs
				vsctlMock.AddResult("", nil)

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				var wg sync.WaitGroup
				wg.Add(1)
				var err error
				go func() {
					err = ifs.Run(srvCtx, configFile)
					wg.Done()
				}()

				//waiting for interfaceservice.json
				for start := time.Now(); time.Since(start) < 3*time.Second; {
					if ifs.Config.Endpoint == testEndpointFake {
						break
					}
				}

				d := 5 * time.Second
				Eventually(buffer, d).Should(gbytes.Say(`successfully reattached to bridge`))

				srvCancel()
				wg.Wait()
				Expect(err).Should(Succeed())
				w.Close()
			})
		})

		Context("confirm Heartbeat work", func() {
			var (
				w      os.File
				buffer *gbytes.Buffer
			)

			BeforeEach(func() {
				var err error
				r, w, err := os.Pipe()
				Expect(err).NotTo(HaveOccurred())
				log.SetOutput(w)
				buffer = gbytes.BufferReader(r)
			})

			AfterEach(func() {
				os.Stdout.Write(buffer.Contents())
				log.SetOutput(GinkgoWriter)
				os.Remove(configFile)
			})
			It("should log 'Heartbeat'", func() {

				devbindMock.AddResult(bindOut, nil)
				Expect(ifs.DpdkEnabled).To(Equal(true))
				// 13 times ovs-vsctl is called
				for i := 0; i < 13; i++ {
					vsctlMock.AddResult("", nil)
				}

				ifs.ReattachDpdkPorts = reatachPortsMock

				// Set up InterfaceService server
				srvCtx, srvCancel := context.WithCancel(context.Background())

				// set HeartbeatInterval
				period := "200ms"
				err := ioutil.WriteFile(configFile, []byte(fmt.Sprintf(`
				{
					"endpoint": "%s",
					"HeartbeatInterval": "%s",
					"certsDirectory": "%s"
				}`, testEndpointFake, period, certsDirFake)), os.FileMode(0644))
				Expect(err).NotTo(HaveOccurred())

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					ifs.Run(srvCtx, configFile)
					wg.Done()
				}()

				//waiting for interfaceservice.json
				for start := time.Now(); time.Since(start) < 3*time.Second; {
					if ifs.Config.Endpoint == testEndpointFake {
						break
					}
				}

				duration := 1 * time.Second
				Eventually(buffer, duration).Should(gbytes.Say(`Heartbeat`))

				srvCancel()
				wg.Wait()
				w.Close()
			})
		})
	})

	Describe("GET", func() {
		Context("make findDpdkPortName return an empty string", func() {
			It("should return error", func() {
				var strResultVsctl = `Bridge br-test options: {dpdk-devargs="0000:00:01.0"}
						datapath_type: netdev

							Interface eth0
								type: dpdk
								options: {dpdk-devargs="0000:00:01.0"}`

				devbindMock.AddResult("", nil)           // updateDPDKDevbindOutput - Devbind("--status")
				vsctlMock.AddResult(strResultVsctl, nil) // resp for port-to-br in Get - getBr
				vsctlMock.AddResult(strResultVsctl, nil) // resp for show in Get - getPorts - getDpdkPortName

				Expect(ifs.DpdkEnabled).To(Equal(true))

				_, err := get()
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

})
