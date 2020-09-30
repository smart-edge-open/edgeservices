// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package interfaceservice

import (
	"bytes"
	"strings"

	"github.com/open-ness/edgenode/pkg/ela/helpers"
	pb "github.com/open-ness/edgenode/pkg/interfaceservice/pb"
	"github.com/pkg/errors"
)

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

	return allDevs, nil
}

// getBr gets a bridge name for given port
func getBr(port string) string {
	br, err := Vsctl("port-to-br", port)
	if err != nil {
		log.Info(err.Error())
		return ""
	}
	return string(bytes.TrimSpace(br))
}

func findDpdkPortName(ovsShowOutput string, pciLine string) string {
	const portPrefix = "Port "
	var revShowOutputLines []string
	ovsShowOutputLines := strings.Split(ovsShowOutput, "\n")
	for i := range ovsShowOutputLines {
		outputLine := strings.TrimSpace(ovsShowOutputLines[i])
		revShowOutputLines = append([]string{outputLine}, revShowOutputLines...)
		if outputLine == pciLine {
			break
		}
	}
	for i := range revShowOutputLines {
		if strings.HasPrefix(revShowOutputLines[i], portPrefix) {
			return strings.Trim(revShowOutputLines[i][len(portPrefix):], "\"")
		}
	}
	return ""
}
func getDpdkPortName(PCI, ovsShowOutput string) (string, error) {
	if ovsShowOutput == "" {
		showData, err := Vsctl("show")
		if err != nil {
			return "", errors.Wrapf(err, "ovs-vsctl show failed %s", err.Error())
		}
		ovsShowOutput = string(bytes.TrimSpace(showData))
	}

	dpdkDevsrgsPCIOption := "options: {dpdk-devargs=\"" + PCI + "\"}"
	if strings.Contains(ovsShowOutput, dpdkDevsrgsPCIOption) {
		return findDpdkPortName(ovsShowOutput, dpdkDevsrgsPCIOption), nil
	}
	return "", nil
}

// getPorts takes kernel devices and updates them if attached to OVS bridge
func getPorts() ([]*pb.Port, []string, error) {
	var (
		ports     []*pb.Port
		logOutput []string
	)
	netDevs, err := KernelNetworkDevicesProvider()
	if err != nil {
		return nil, []string{}, errors.Wrap(err, "failed to obtain kernel devices")
	}

	showData, err := Vsctl("show")
	if err != nil {
		return nil, []string{}, errors.Wrap(err, "failed to ovs-vsctl show")
	}
	ovsShowOutput := string(bytes.TrimSpace(showData))

	for _, netDev := range netDevs {
		var port pb.Port
		port.Pci = netDev.PCI
		port.MacAddress = netDev.MAC
		port.Bridge = getBr(netDev.Name)
		portName, err := getDpdkPortName(port.Pci, ovsShowOutput)
		if err != nil {
			return []*pb.Port{}, []string{},
				errors.Wrapf(err, "Failed to get ports %s", err.Error())
		}
		if portName != "" {
			port.Bridge = getBr(portName)
		}
		currentDriver, _ := getPortDrivers(port.Pci)
		if currentDriver == defaultDpdkDriver {
			port.Driver = pb.Port_USERSPACE
		} else if currentDriver == "" {
			port.Driver = pb.Port_NONE
		} else {
			port.Driver = pb.Port_KERNEL
		}
		ports = append(ports, &port)
		logOutput = append(logOutput, strings.Join([]string{port.Pci,
			pb.Port_InterfaceDriver_name[int32(port.Driver)], netDev.Name,
			port.MacAddress, port.Bridge}, " | "))
	}
	return ports, logOutput, nil
}
