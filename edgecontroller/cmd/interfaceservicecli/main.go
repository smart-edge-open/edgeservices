// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/open-ness/edgenode/edgecontroller/pb/interfaceservice"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const defaultBridge = "br-local"
const defaultDriver = pb.Port_KERNEL

type cliFlags struct {
	CertsDir    string
	Endpoint    string
	ServiceName string
	Timeout     int
	Cmd         string
	Pci         string
	Brg         string
	Drv         string
}

// Cfg stores flags passed to CLI
var Cfg cliFlags

func init() {
	flag.StringVar(&Cfg.Endpoint, "endpoint", "", "Interface service endpoint")
	flag.StringVar(&Cfg.ServiceName, "servicename", "interfaceservice.openness", "Name of server in certificate")
	flag.StringVar(&Cfg.Cmd, "cmd", "help", "Interface service command")
	flag.StringVar(&Cfg.Pci, "pci", "", "List of network interfaces PCI addresses")
	flag.StringVar(&Cfg.Brg, "brg", "", "OVS bridge an interface would be attached to")
	flag.StringVar(&Cfg.Drv, "drv", "", "Driver to be used")
	flag.StringVar(&Cfg.CertsDir, "certsdir", "./certs/client/interfaceservice", "Directory of key and certificate")
	flag.IntVar(&Cfg.Timeout, "timeout", 20, "Timeout value for grpc call (in seconds)")
}

func getTransportCredentials() (*credentials.TransportCredentials, error) {
	crtPath := filepath.Clean(filepath.Join(Cfg.CertsDir, "cert.pem"))
	keyPath := filepath.Clean(filepath.Join(Cfg.CertsDir, "key.pem"))
	caPath := filepath.Clean(filepath.Join(Cfg.CertsDir, "root.pem"))

	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.Errorf("Failed append CA certs from %s", caPath)
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		ServerName:   Cfg.ServiceName,
	})

	return &creds, nil
}

func createConnection(ctx context.Context) *grpc.ClientConn {
	tc, err := getTransportCredentials()
	if err != nil {
		fmt.Println("Error when creating transport credentials: " + err.Error())
		os.Exit(1)
	}

	conn, err := grpc.DialContext(ctx, Cfg.Endpoint,
		grpc.WithTransportCredentials(*tc), grpc.WithBlock())

	if err != nil {
		fmt.Println("Error when dialing: " + Cfg.Endpoint + " err:" + err.Error())
		os.Exit(1)
	}

	return conn
}

func printHelp() {
	fmt.Print(`
    Get or attach/detach network interfaces to OVS on remote edge node

    -endpoint      Endpoint to be requested
    -servicename   Name to be used as server name for TLS handshake
    -cmd           Supported commands: get, attach, detach
    -pci           PCI address for attach and detach commands. Multiple addresses can be passed
                   and must be separated by commas: -pci=0000:00:00.0,0000:00:00.1
    -brg           OVS bridge an interface would be attached to: -brg=br-local
    -drv           Driver that would be used: -drv=kernel
    -certsdir      Directory where cert.pem and key.pem for client and root.pem for CA resides   
    -timeout       Timeout value [s] for grpc requests

	`)
}

func splitAndValidatePCIFormat(val string) []string {
	devs := strings.Split(val, ",")
	var validPCIs []string

	// 0000:00:00.0
	for _, dev := range devs {
		s := strings.Split(dev, ":")
		if len(s) == 3 && len(s[0]) == 4 && len(s[1]) == 2 && len(s[2]) == 4 {
			validPCIs = append(validPCIs, dev)
		} else {
			fmt.Println("Invalid PCI address: " + dev + ". Skipping...")
		}
	}
	return validPCIs
}

func updateInterfaces(command, pcis, bridge string, driver pb.Port_InterfaceDriver) error {

	if bridge == "" {
		bridge = defaultBridge
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Cfg.Timeout)*time.Second)
	defer cancel()

	conn := createConnection(ctx)
	defer conn.Close()

	client := pb.NewInterfaceServiceClient(conn)

	var reqPorts []*pb.Port

	nodePorts, err := client.Get(ctx, &empty.Empty{})
	if err != nil {
		return err
	}

	addr := splitAndValidatePCIFormat(pcis)
	for _, a := range addr {
		found := false
		for _, p := range nodePorts.GetPorts() {
			if p.GetPci() == a {
				p.Driver = driver
				p.Bridge = bridge
				reqPorts = append(reqPorts, p)
				found = true
			}
		}

		if !found {
			fmt.Println("Interface: " + a + " not found. Skipping...")
		}
	}

	if command == "attach" {
		_, err = client.Attach(ctx, &pb.Ports{
			Ports: reqPorts,
		})
	} else {
		_, err = client.Detach(ctx, &pb.Ports{
			Ports: reqPorts,
		})
	}

	if err != nil {
		return err
	}

	for _, p := range reqPorts {
		fmt.Println("Interface: " + p.GetPci() + " successfully " + command + "ed")
	}

	return nil
}

func createInterfaceGroups(ports []*pb.Port) ([]*pb.Port, []*pb.Port, []*pb.Port) {
	var kernelPorts, dpdkPorts, otherPorts []*pb.Port
	for _, port := range ports {
		if port.Driver == pb.Port_KERNEL {
			kernelPorts = append(kernelPorts, port)
		} else if port.Driver == pb.Port_USERSPACE {
			dpdkPorts = append(dpdkPorts, port)
		} else {
			otherPorts = append(otherPorts, port)
		}
	}
	return kernelPorts, dpdkPorts, otherPorts
}

func printInterfaces() error {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Cfg.Timeout)*time.Second)
	defer cancel()

	conn := createConnection(ctx)
	defer conn.Close()

	client := pb.NewInterfaceServiceClient(conn)

	var err error
	ports, err := client.Get(ctx, &empty.Empty{})
	if err != nil {
		return err
	}

	allPorts := ports.GetPorts()

	if len(allPorts) == 0 {
		return errors.Errorf("No interfaces found on node")
	}

	kernelPorts, dpdkPorts, otherPorts := createInterfaceGroups(allPorts)

	if len(kernelPorts) > 0 {
		fmt.Printf("\nKernel interfaces:\n")
		for _, port := range kernelPorts {
			if port.GetBridge() != "" {
				fmt.Printf("\t%s  |  %s  |  attached  | %s\n", port.GetPci(), port.GetMacAddress(), port.GetBridge())
			} else {
				fmt.Printf("\t%s  |  %s  |  detached\n", port.GetPci(), port.GetMacAddress())
			}
		}
		fmt.Println()
	}

	if len(dpdkPorts) > 0 {
		fmt.Printf("DPDK interfaces:\n")
		for _, port := range dpdkPorts {
			if port.GetBridge() != "" {
				fmt.Printf("\t%s  |  attached  | %s\n", port.GetPci(), port.GetBridge())
			} else {
				fmt.Printf("\t%s  |  detached\n", port.GetPci())
			}
		}
		fmt.Println()
	}

	if len(otherPorts) > 0 {
		fmt.Printf("Other interfaces:\n")
		for _, port := range otherPorts {
			fmt.Printf("\t%s\n", port.GetPci())
		}
		fmt.Println()
	}

	return nil
}

func main() {
	flag.Parse()

	if err := StartCli(); err != nil {
		fmt.Println("Error when executing command: [" + Cfg.Cmd + "] err: " + err.Error())
		os.Exit(1)
	}
}

// StartCli handles command and arguments to call corresponding CLI function
func StartCli() error {
	var err error

	driver := defaultDriver
	if Cfg.Drv == "dpdk" {
		driver = pb.Port_USERSPACE
	}

	switch Cfg.Cmd {
	case "attach":
		fallthrough
	case "detach":
		err = updateInterfaces(Cfg.Cmd, Cfg.Pci, Cfg.Brg, driver)
	case "get":
		err = printInterfaces()
	case "help", "h", "":
		printHelp()
	default:
		fmt.Println("Unrecognized action: " + Cfg.Cmd)
		printHelp()
	}

	return err
}
