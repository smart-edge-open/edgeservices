// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package interfaceservice_test

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	elahelpers "github.com/otcshare/edgenode/pkg/ela/helpers"
	ifs "github.com/otcshare/edgenode/pkg/interfaceservice"
	pb "github.com/otcshare/edgenode/pkg/interfaceservice/pb"
)

var (
	vsctlMock   VsctlMock
	devbindMock DevbindMock
	debugMocks  = true

	// store function pointers from interfaceservice pkg
	// to be able to call them if ifs.ReattachDpdkPorts & ifs.KernelNetworkDevicesProvider
	// are overritetten by mocks
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
				str := `Bridge br-test
						datapath_type: netdev
						Port eth0
							Interface eth0
								type: dpdk
								options: {dpdk-devargs="0000:00:01.0"}`

				devbindMock.AddResult(bindOut, nil)

				vsctlMock.AddResult(str, nil)  // resp for show
				vsctlMock.AddResult("", nil)   // respo for del-port
				devbindMock.AddResult("", nil) // resp for bind

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
		})
		Context("call Get()", func() {
			It("should return error as vsctl fails", func() {
				_, err := get()
				Expect(err).To(HaveOccurred())
			})
		})
		Context("call getKernelNetworkDevices", func() {
			It("iterfaceservice.ReattachDpdkPorts deattach error", func() {
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

			It("iterfaceservice.ReattachDpdkPorts attach error", func() {
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

			It("iterfaceservice.ReattachDpdkPorts attach error", func() {
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

				str := `Bridge br-test
					datapath_type: netdev
					Port eth0
						Interface eth0
							type: dpdk
							options: {dpdk-devargs="0000:00:01.0"}`

				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("netdev", nil)
				vsctlMock.AddResult(str, nil)
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

				str := `Bridge br-test
						datapath_type: netdev
						Port eth0
							Interface eth0
								type: dpdk
								options: {dpdk-devargs="0000:00:01.0"}`

				vsctlMock.AddResult(str, nil) // resp for show
				vsctlMock.AddResult("", nil)  // respo for del-port

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
				str := `Bridge br-test
							datapath_type: netdev
							Port eth0
								Interface eth0
									type: dpdk
									options: {dpdk-devargs="0000:00:01.0"}`

				devbindMock.AddResult(bindOutShort2, nil)

				vsctlMock.AddResult(str, nil)  // resp for show
				vsctlMock.AddResult("", nil)   // respo for del-port
				devbindMock.AddResult("", nil) // resp for bind

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
				var ret_err error
				ret_err = errors.New("vsctl failed")
				devbindMock.AddResult(bindOut, nil)
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", ret_err)

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
				var ret_err error
				ret_err = errors.New("vsctl failed")
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", ret_err)

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

				var ret_err error
				ret_err = errors.New("vsctl failed")
				vsctlMock.AddResult("", nil)
				vsctlMock.AddResult("", ret_err)

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

				str := `Bridge br-test
						datapath_type: netdev
						Port eth0
							Interface eth0
								type: dpdk
								options: {dpdk-devargs="0000:00:01.0"}`

				vsctlMock.AddResult(str, nil) // resp for show

				// 13 times ovs-vsctl is called
				for i := 0; i < 12; i++ {
					vsctlMock.AddResult("", nil)
				}

				_, err := get()
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
})
