// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package main_test

import (
	"errors"
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cli "github.com/otcshare/edgecontroller/cmd/interfaceservicecli"
	pb "github.com/otcshare/edgecontroller/pb/interfaceservice"
)

var _ = Describe("CLI tests", func() {

	BeforeEach(func() {
		cli.Cfg.Endpoint = ""
		cli.Cfg.ServiceName = ""
		cli.Cfg.Cmd = ""
		cli.Cfg.Pci = ""
		cli.Cfg.Brg = ""
		cli.Cfg.Drv = ""
		cli.Cfg.CertsDir = "./certs"
	})

	AfterEach(func() {
		Iserv.getReturnNi = nil
		Iserv.getReturnErr = nil
		Iserv.attachReturnErr = nil
		Iserv.detachReturnErr = nil
	})

	Context("start Cli without command", func() {
		It("should return help print", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			Expect(outString).To(Equal(HelpOut))
		})
	})

	Context("'help' command", func() {
		It("should return help print", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			cli.Cfg.Cmd = "help"
			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			Expect(outString).To(Equal(HelpOut))
		})
	})

	Context("unrecognized command", func() {
		It("should return 'Unrecognized action' + help print", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			cli.Cfg.Cmd = "test123"
			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			Expect(outString).To(Equal(WarningOut))
		})
	})

	Context("'attach' command on existing interface", func() {
		It("should call 'Attach'", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "attach"
			cli.Cfg.Pci = "5201:54:00.0"
			cli.Cfg.Brg = "br-local"
			cli.Cfg.Drv = "kernel"

			Ni := &pb.Port{
				Driver:     0,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' DPDK interface", func() {
		It("should call 'Attach'", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "attach"
			cli.Cfg.Pci = "5201:54:00.0"
			cli.Cfg.Brg = "br-dpdk"
			cli.Cfg.Drv = "dpdk"

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' command on unknown interface", func() {
		It("should dont call 'Attach'", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "attach"
			cli.Cfg.Pci = "5222:54:00.0"
			cli.Cfg.Brg = "br-local"
			cli.Cfg.Drv = "kernel"

			Ni := &pb.Port{
				Driver:     0,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' command on invalid interface", func() {
		It("should dont call 'Attach'", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "attach"
			cli.Cfg.Pci = "123:123:00"
			cli.Cfg.Brg = "br-local"
			cli.Cfg.Drv = "kernel"

			Ni := &pb.Port{
				Driver:     0,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' command on unknown OVS bridge", func() {
		It("should dont call 'Attach'", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "attach"
			cli.Cfg.Pci = "5201:54:00.0"
			cli.Cfg.Brg = "br-unknown"
			cli.Cfg.Drv = "kernel"

			Iserv.attachReturnErr = errors.New("")

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			err := cli.StartCli()
			Expect(err)
		})
	})

	Context("'attach' command with get error", func() {
		It("should dont call 'Attach'", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "attach"
			cli.Cfg.Pci = "5201:54:00.0"
			cli.Cfg.Brg = "br-unknown"
			cli.Cfg.Drv = "kernel"

			Iserv.attachReturnErr = errors.New("")

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			Iserv.getReturnErr = errors.New("")

			err := cli.StartCli()
			Expect(err)
		})
	})

	Context("'detach' command on existing interface", func() {
		It("should call 'Detach'", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "detach"
			cli.Cfg.Pci = "5201:54:00.0"

			Ni := &pb.Port{
				Driver:     1,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'get' command", func() {
		It("should return interfaces", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "get"

			Ni := &pb.Port{
				Driver:     0,
				Pci:        "5200:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Ni2 := &pb.Port{
				Driver:     1,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Ni3 := &pb.Port{
				Driver:     2,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-dpdk",
			}

			Ni4 := &pb.Port{
				Driver:     1,
				Pci:        "5201:54:00.1",
				MacAddress: "aa:bb:cc:dd:ee:gg",
				Bridge:     "",
			}

			Ni5 := &pb.Port{
				Driver:     2,
				Pci:        "5201:54:00.2",
				MacAddress: "aa:bb:cc:dd:ee:hh",
				Bridge:     "",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni, Ni2, Ni3, Ni4, Ni5},
			}

			err := cli.StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'get' command with no interfaces", func() {
		It("should return error", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "get"

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			err := cli.StartCli()
			Expect(err)
		})
	})

	Context("'get' command with 'Get' error", func() {
		It("should return error", func() {
			cli.Cfg.Endpoint = Iserv.Endpoint
			cli.Cfg.ServiceName = "localhost"

			cli.Cfg.Cmd = "get"

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			Iserv.getReturnErr = errors.New("")

			err := cli.StartCli()
			Expect(err)
		})
	})
})
