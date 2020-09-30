// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package main

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	pb "github.com/open-ness/edgenode/edgecontroller/pb/interfaceservice"
	monkey "github.com/undefinedlabs/go-mpatch"
)

var _ = Describe("CLI tests", func() {

	BeforeEach(func() {
		Cfg.Endpoint = ""
		Cfg.ServiceName = ""
		Cfg.Cmd = ""
		Cfg.Pci = ""
		Cfg.Brg = ""
		Cfg.Drv = ""
		Cfg.CertsDir = "./certs"
	})

	AfterEach(func() {
		Iserv.getReturnNi = nil
		Iserv.getReturnErr = nil
		Iserv.attachReturnErr = nil
		Iserv.detachReturnErr = nil

		Cfg.Endpoint = ""
		Cfg.ServiceName = ""
		Cfg.Cmd = ""
		Cfg.Pci = ""
		Cfg.Brg = ""
		Cfg.Drv = ""
		Cfg.CertsDir = "./certs"
		Cfg.Timeout = 20
	})

	Context("start Cli without command", func() {
		It("should return help print", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			err := StartCli()
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

			Cfg.Cmd = "help"
			err := StartCli()
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

			Cfg.Cmd = "test123"
			err := StartCli()
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
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "attach"
			Cfg.Pci = "5201:54:00.0"
			Cfg.Brg = "br-local"
			Cfg.Drv = "kernel"

			Ni := &pb.Port{
				Driver:     0,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' DPDK interface", func() {
		It("should call 'Attach'", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "attach"
			Cfg.Pci = "5201:54:00.0"
			Cfg.Brg = "br-dpdk"
			Cfg.Drv = "dpdk"

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			err := StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' command on unknown interface", func() {
		It("should dont call 'Attach'", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "attach"
			Cfg.Pci = "5222:54:00.0"
			Cfg.Brg = "br-local"
			Cfg.Drv = "kernel"

			Ni := &pb.Port{
				Driver:     0,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' command on invalid interface", func() {
		It("should dont call 'Attach'", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "attach"
			Cfg.Pci = "123:123:00"
			Cfg.Brg = "br-local"
			Cfg.Drv = "kernel"

			Ni := &pb.Port{
				Driver:     0,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "br-local",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'attach' command on unknown OVS bridge", func() {
		It("should dont call 'Attach'", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "attach"
			Cfg.Pci = "5201:54:00.0"
			Cfg.Brg = "br-unknown"
			Cfg.Drv = "kernel"

			Iserv.attachReturnErr = errors.New("")

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			err := StartCli()
			Expect(err)
		})
	})

	Context("'attach' command with get error", func() {
		It("should dont call 'Attach'", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "attach"
			Cfg.Pci = "5201:54:00.0"
			Cfg.Brg = "br-unknown"
			Cfg.Drv = "kernel"

			Iserv.attachReturnErr = errors.New("")

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			Iserv.getReturnErr = errors.New("")

			err := StartCli()
			Expect(err)
		})
	})

	Context("'detach' command on existing interface", func() {
		It("should call 'Detach'", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "detach"
			Cfg.Pci = "5201:54:00.0"

			Ni := &pb.Port{
				Driver:     1,
				Pci:        "5201:54:00.0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				Bridge:     "",
			}

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{Ni},
			}

			err := StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'get' command", func() {
		It("should return interfaces", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "get"

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

			err := StartCli()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("'get' command with no interfaces", func() {
		It("should return error", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "get"

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			err := StartCli()
			Expect(err)
		})
	})

	Context("'get' command with 'Get' error", func() {
		It("should return error", func() {
			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "get"

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			Iserv.getReturnErr = errors.New("")

			err := StartCli()
			Expect(err)
		})
	})

	Context("'get' command with empty Cfg.CertsDir path", func() {
		It("should panic", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "get"
			Cfg.CertsDir = ""

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			fakeExit := func(int) {
				panic("os.Exit called")
			}
			patch, err := monkey.PatchMethod(os.Exit, fakeExit)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				pErr := patch.Unpatch()
				Expect(pErr).NotTo(HaveOccurred())
			}()
			Expect(func() {
				cErr := StartCli()
				Expect(cErr).NotTo(HaveOccurred())
			}).Should(PanicWith("os.Exit called"))

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			ErrorOut := "Error when creating transport credentials: open cert.pem: no such file or directory\n"
			Expect(outString).To(Equal(ErrorOut))
		})
	})

	Context("'get' command without root.pem file", func() {
		It("should panic", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "get"

			caPath := filepath.Clean(filepath.Join(Cfg.CertsDir, "root.pem"))
			caPathBak := caPath + ".bak"
			err := os.Rename(caPath, caPathBak)
			Expect(err).NotTo(HaveOccurred())

			defer func() {
				err = os.Rename(caPathBak, caPath)
				Expect(err).NotTo(HaveOccurred())
			}()

			fakeExit := func(int) {
				panic("os.Exit called")
			}
			patch, err := monkey.PatchMethod(os.Exit, fakeExit)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				pErr := patch.Unpatch()
				Expect(pErr).NotTo(HaveOccurred())
			}()
			Expect(func() {
				cErr := StartCli()
				Expect(cErr).NotTo(HaveOccurred())
			}).Should(PanicWith("os.Exit called"))

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			ErrorOut := "Error when creating transport credentials: open certs/root.pem: no such file or directory\n"
			Expect(outString).To(Equal(ErrorOut))
		})
	})

	Context("'get' command with incorrect root.pem file", func() {
		It("should panic", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			Cfg.Endpoint = Iserv.Endpoint
			Cfg.ServiceName = "localhost"

			Cfg.Cmd = "get"

			caPath := filepath.Clean(filepath.Join(Cfg.CertsDir, "root.pem"))

			wf, wfErr := newWreckFile(caPath)
			Expect(wfErr).NotTo(HaveOccurred())

			wfErr = wf.wreckFile()
			Expect(wfErr).NotTo(HaveOccurred())

			defer func() {
				wfErr = wf.recoverFile()
				Expect(wfErr).NotTo(HaveOccurred())
			}()

			fakeExit := func(int) {
				panic("os.Exit called")
			}
			patch, err := monkey.PatchMethod(os.Exit, fakeExit)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				pErr := patch.Unpatch()
				Expect(pErr).NotTo(HaveOccurred())
			}()
			Expect(func() {
				cErr := StartCli()
				Expect(cErr).NotTo(HaveOccurred())
			}).Should(PanicWith("os.Exit called"))

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			ErrorOut := "Error when creating transport credentials: Failed append CA certs from certs/root.pem\n"
			Expect(outString).To(Equal(ErrorOut))
		})
	})

	Context("'get' command with incorrect gRPC server address", func() {
		It("should panic", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			Cfg.ServiceName = "wreckhost"
			originTimeout := Cfg.Timeout
			Cfg.Timeout = 1
			defer func() {
				Cfg.Timeout = originTimeout
			}()

			Cfg.Cmd = "get"

			fakeExit := func(int) {
				panic("os.Exit called")
			}
			patch, err := monkey.PatchMethod(os.Exit, fakeExit)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				pErr := patch.Unpatch()
				Expect(pErr).NotTo(HaveOccurred())
			}()
			Expect(func() {
				cErr := StartCli()
				Expect(cErr).NotTo(HaveOccurred())
			}).Should(PanicWith("os.Exit called"))

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			ErrorOut := "Error when dialing:  err:context deadline exceeded\n"
			Expect(outString).To(Equal(ErrorOut))
		})
	})

	Context("'get' command with no interfaces", func() {
		It("should panic", func() {
			saveStd := os.Stdout
			read, write, _ := os.Pipe()
			os.Stdout = write

			Cfg.ServiceName = "localhost"
			Cfg.Endpoint = Iserv.Endpoint
			originTimeout := Cfg.Timeout

			Iserv.getReturnNi = &pb.Ports{
				Ports: []*pb.Port{},
			}

			Cfg.Timeout = 1
			defer func() {
				Cfg.Timeout = originTimeout
			}()

			Cfg.Cmd = "get"

			fakeExit := func(int) {
				panic("os.Exit called")
			}
			patch, err := monkey.PatchMethod(os.Exit, fakeExit)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				pErr := patch.Unpatch()
				Expect(pErr).NotTo(HaveOccurred())
			}()
			Expect(func() {
				main()
			}).Should(PanicWith("os.Exit called"))

			write.Close()
			out, _ := ioutil.ReadAll(read)
			os.Stdout = saveStd
			outString := string(out[:])
			ErrorOut := `@@@ 'Get' from GRPC server @@@
Error when executing command: [get] err: No interfaces found on node
`
			Expect(outString).To(Equal(ErrorOut))
		})
	})
})
