// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package interfaceservice

import (
	pb "github.com/open-ness/edgenode/pkg/interfaceservice/pb"
	"github.com/pkg/errors"
)

// attachPortToOvs attaches given port to kube-ovn's bridge
func attachPortToOvs(port pb.Port) error {

	if err := validatePortToAttach(port); err != nil {
		return err
	}

	name, err := getPortName(port.Pci)

	if err != nil {
		return errors.Wrapf(err, "Failed to find port's name")
	}

	if err = bindDriver(port); err != nil {
		return errors.Wrapf(err, "Failed to bind port to driver")
	}

	var output []byte
	if port.Driver == pb.Port_KERNEL {
		output, err = Vsctl("--may-exist", "add-port", port.Bridge, name)
		if err == nil {
			log.Info("Added OVS kernel port ", port.Pci, " - name: ", name, " bridge: ", port.Bridge)
		}
	} else {
		output, err = Vsctl("--may-exist", "add-port", port.Bridge, name, "--", "set", "Interface", name,
			"type=dpdk", "options:dpdk-devargs="+port.Pci)
		if err == nil {
			log.Info("Added OVS DPDK port ", port.Pci, " - name: ", name, " bridge: ", port.Bridge)
		}
	}

	if err != nil {
		return errors.Wrapf(err, string(output))
	}

	return nil
}

func validatePortToAttach(port pb.Port) error {
	if !DpdkEnabled && port.Driver == pb.Port_USERSPACE {
		return errors.New("Port " + port.Pci + " cannot use DPDK enabled driver - node does not support DPDK")
	}

	bridgeType, err := getOvsBridgeType(port.Bridge)
	if err != nil {
		return err
	}

	if port.Driver == pb.Port_USERSPACE && bridgeType != netdevBridgeOption {
		return errors.New("Cannot attach DPDK port to non-DPDK bridge " + port.Bridge)
	} else if port.Driver == pb.Port_KERNEL && bridgeType == netdevBridgeOption {
		return errors.New("Cannot attach non-DPDK port to DPDK bridge " + port.Bridge)
	}
	return nil
}
