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

package kubeovn

import (
	"bytes"
	"context"
	"os/exec"
	"strings"

	"github.com/otcshare/edgenode/pkg/ela/helpers"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/otcshare/common/log"
	pb "github.com/otcshare/edgenode/pkg/ela/pb"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// kubeOvnBridge is name of kube-ovn's bridge
	kubeOvnBridge = "br-int"
)

var (
	// KernelNetworkDevicesProvider stores function providing
	// functionality to get network interfaces
	KernelNetworkDevicesProvider = getKernelNetworkDevices

	// Vsctl stores function which executes ovs-vsctl command with given args
	Vsctl = vsctl
)

// InterfaceService provides service for managing physical
// network interfaces in kube-ovn mode.
// It exposes Get and GetAll methods which provide information about interfaces.
// It also exposes Update and BulkUpdate methods which can be used
// to configure those interfaces.
type InterfaceService struct{}

// Update configures single network interface.
func (*InterfaceService) Update(ctx context.Context,
	networkInterface *pb.NetworkInterface) (*empty.Empty, error) {
	log.Info("InterfaceService Update: received request")

	if err := validateInterface(networkInterface); err != nil {
		return nil, err
	}

	if err := updatePortsConfiguration(&pb.NetworkInterfaces{
		NetworkInterfaces: []*pb.NetworkInterface{networkInterface},
	}); err != nil {
		return nil, errors.Wrap(err, "failed to Update")
	}

	return &empty.Empty{}, nil
}

// BulkUpdate configures several network interfaces.
func (*InterfaceService) BulkUpdate(ctx context.Context,
	networkInterfaces *pb.NetworkInterfaces) (*empty.Empty, error) {
	log.Info("InterfaceService BulkUpdate: received request")

	if err := validateInterfaces(networkInterfaces); err != nil {
		return nil, err
	}

	if err := updatePortsConfiguration(networkInterfaces); err != nil {
		return nil, errors.Wrap(err, "failed to BulkUpdate")
	}

	return &empty.Empty{}, nil
}

// GetAll provides information for all physical network interfaces.
func (*InterfaceService) GetAll(context.Context,
	*empty.Empty) (*pb.NetworkInterfaces, error) {
	log.Info("InterfaceService GetAll: received request")

	ifs, err := getNetworkInterfaces()
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return ifs, nil
}

// Get provides information for network interface identified by given PCI.
func (*InterfaceService) Get(ctx context.Context,
	id *pb.InterfaceID) (*pb.NetworkInterface, error) {
	log.Info("InterfaceService Get: received request")

	if id.Id == "" {
		log.Errf("InterfaceService Get: empty id")
		return nil,
			status.Error(codes.InvalidArgument, "empty id")
	}

	ifs, err := getNetworkInterfaces()
	if err != nil {
		log.Errf("InterfaceService Get: getNetworkInterfaces() failed: %+v",
			err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	for _, networkInterface := range ifs.NetworkInterfaces {
		if networkInterface.Id == id.Id {
			return networkInterface, nil
		}
	}

	log.Infof("InterfaceService Get: interface with ID=%s not found", id.Id)
	return nil, status.Error(codes.NotFound, "interface not found")
}

// validateInterfaces iterates over interfaces and validates them
func validateInterfaces(ifaces *pb.NetworkInterfaces) error {
	if ifaces == nil {
		return errors.New("NetworkInterfaces is nil")
	}

	for idx, iface := range ifaces.NetworkInterfaces {
		if err := validateInterface(iface); err != nil {
			return errors.Wrapf(err, "NetworkInterface[%d] is invalid", idx)
		}
	}
	return nil
}

// validateInterface checks if given NetworkInterface is valid
// Valid NetworkInterface is when:
//  - it's not nil,
//  - Driver is either KERNEL or USERSPACE
//  - Type is NONE
//  - Vlan is not set
//  - Zones are not set
//  - FallbackInterface
func validateInterface(iface *pb.NetworkInterface) error {
	if iface == nil {
		return errors.New("NetworkInterface is nil")
	}

	// mac address is not validated
	// controller sends one, but it does not matter for ovs

	if iface.Driver != pb.NetworkInterface_KERNEL &&
		iface.Driver != pb.NetworkInterface_USERSPACE {
		return errors.New("Driver is expected to be KERNEL or USERSPACE")
	}

	if iface.Type != pb.NetworkInterface_NONE {
		return errors.New("Type is expected to be NONE")
	}

	if iface.Vlan != 0 {
		return errors.New("Vlan is not supported")
	}

	if len(iface.Zones) != 0 {
		return errors.New("Zones are not supported")
	}

	if iface.FallbackInterface != "" {
		return errors.New("FallbackInterface is expected to be empty")
	}

	return nil
}

// getKernelNetworkDevices provides a list of network devices
// bound to kernel driver
func getKernelNetworkDevices() ([]helpers.NetworkDevice, error) {
	allDevs, err := helpers.GetNetworkPCIs()
	if err != nil {
		return nil, err
	}

	err = helpers.FillMACAddrForKernelDevs(allDevs)
	if err != nil {
		return nil, err
	}

	// At this point, only kernel ethernet devices should have MAC set up
	// Filter out devices without MAC (e.g. bound to DPDK)
	devs := make([]helpers.NetworkDevice, 0)
	for _, dev := range allDevs {
		if dev.MAC != "" {
			devs = append(devs, dev)
		}
	}

	return devs, nil
}

// vsctl executes ovs-vsctl with given args, it returnes combined output
func vsctl(args ...string) ([]byte, error) {
	// #nosec G204 - params are hardcoded
	return exec.Command("ovs-vsctl", args...).
		CombinedOutput()
}

// getOvnPorts returns list of all ports attached
// to kube-ovn's bridge
func getOvnPorts() ([]string, error) {
	output, err := Vsctl("list-ports", kubeOvnBridge)

	if err != nil {
		return nil, err
	}

	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return nil, nil
	}

	return strings.Split(string(output), "\n"), nil
}

// getNetworkDevices takes kernel devices and updates them if
// anyone is attached to OVS
func getNetworkDevices() ([]helpers.NetworkDevice, error) {
	devs, err := KernelNetworkDevicesProvider()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain kernel devices")
	}

	ovnPorts, err := getOvnPorts()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain OVN ports")
	}

	for devIdx := range devs {
		for _, ovnPort := range ovnPorts {
			if ovnPort == devs[devIdx].Name {
				devs[devIdx].Driver = pb.NetworkInterface_USERSPACE
			}
		}
	}

	return devs, nil
}

// getNetworkInterfaces provides network interfaces.
// Interfaces with driver set to USERSPACE are ports attached
// to kube-ovn's bridge
func getNetworkInterfaces() (*pb.NetworkInterfaces, error) {
	devs, err := getNetworkDevices()

	return helpers.ToNetworkInterfaces(devs), err
}

// attachPortToOVS adds given port to kube-ovn's bridge
func attachPortToOVS(port string) error {
	_, err := Vsctl("--may-exist", "add-port", kubeOvnBridge, port)
	return err
}

// detachPortFromOVS removes given port from kube-ovn's bridge
func detachPortFromOVS(port string) error {
	_, err := Vsctl("--if-exist", "del-port", kubeOvnBridge, port)
	return err
}

// updatePortsConfiguration attaches/detaches ports to/from kube-ovn switch
// based on received NetworkInterfaces
func updatePortsConfiguration(updatedIfs *pb.NetworkInterfaces) error {
	// get network devices because interface's name is required
	devs, err := getNetworkDevices()
	if err != nil {
		return errors.Wrap(err, "failed to obtain kernel devices")
	}

	for _, updatedIf := range updatedIfs.NetworkInterfaces {
		for _, dev := range devs {

			// match network devices and received request data
			if updatedIf.Id == dev.PCI {

				currentState := dev.Driver
				requestedState := updatedIf.Driver

				if currentState == requestedState {
					break // go to next interface from request
				}

				switch requestedState {
				case pb.NetworkInterface_KERNEL:
					if err := detachPortFromOVS(dev.Name); err != nil {
						return errors.Wrapf(err,
							"failed to detach interface %s (%s) from OVS",
							dev.PCI, dev.Name)
					}

				case pb.NetworkInterface_USERSPACE:
					if err := attachPortToOVS(dev.Name); err != nil {
						return errors.Wrapf(err,
							"failed to attach interface %s (%s) to OVS",
							dev.PCI, dev.Name)
					}
				}

				break // go to next interface from request
			}
		}
	}

	return nil
}
