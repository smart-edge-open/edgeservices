// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela

import (
	"context"

	"github.com/pkg/errors"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/open-ness/edgenode/pkg/ela/helpers"
	"github.com/open-ness/edgenode/pkg/ela/ini"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// GetInterfaces stores gets Interfaces functionality
	GetInterfaces func() (*pb.NetworkInterfaces, error) = getNetworkInterfaces

	// NTSConfigurationHandler is a NTS configuration handler
	NTSConfigurationHandler = configureNTS
)

// InterfaceService is a service interface
type InterfaceService struct{}

// Update do the update
func (*InterfaceService) Update(context.Context,
	*pb.NetworkInterface) (*empty.Empty, error) {

	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

// BulkUpdate do the Bulk Update
func (*InterfaceService) BulkUpdate(ctx context.Context,
	networkInterfaces *pb.NetworkInterfaces) (*empty.Empty, error) {
	log.Info("InterfaceService BulkUpdate: received request")

	if err := helpers.ValidateNetworkInterfaces(networkInterfaces); err != nil {
		log.Errf("InterfaceService BulkUpdate: invalid NetworkInterface: %v",
			err)

		return nil, err
	}

	InterfaceConfigurationData.NetworkInterfaces = networkInterfaces

	if err := NTSConfigurationHandler(ctx); err != nil {
		log.Errf("InterfaceService BulkUpdate: Failed to configure NTS: %+v",
			err)
		return nil, errors.Wrap(err, "failed to configure NTS")
	}

	return &empty.Empty{}, nil
}

// GetAll gets all service interfaces
func (*InterfaceService) GetAll(context.Context,
	*empty.Empty) (*pb.NetworkInterfaces, error) {
	log.Info("InterfaceService GetAll: received request")

	nis, err := GetInterfaces()
	if err != nil {
		log.Errf("InterfaceService GetAll: GetInterfaces() failed: %+v", err)
		return nil, errors.Wrap(err, "failed to obtain network interfaces")
	}

	return nis, nil
}

// Get gets interfaces
func (*InterfaceService) Get(ctx context.Context,
	id *pb.InterfaceID) (*pb.NetworkInterface, error) {
	log.Info("InterfaceService Get: received request")

	if id.Id == "" {
		log.Errf("InterfaceService Get: empty id")
		return nil,
			status.Error(codes.InvalidArgument, "empty id")
	}

	nis, err := GetInterfaces()
	if err != nil {
		log.Errf("InterfaceService Get: GetInterfaces() failed: %+v", err)
		return nil, errors.Wrap(err, "failed to obtain network interfaces")
	}

	for _, networkInterface := range nis.NetworkInterfaces {
		if networkInterface.Id == id.Id {
			return networkInterface, nil
		}
	}

	log.Infof("InterfaceService Get: Interface with ID=%s not found", id.Id)
	return nil, status.Error(codes.NotFound, "interface not found")
}

// IsPCIportBlacklisted checks if a pci port is blacklisted and cannot be used
// by controller to set up connection.
func IsPCIportBlacklisted(pci string) bool {
	for _, port := range Config.PCIBlacklist {
		if port == pci {
			return true
		}
	}
	return false
}

// getNetworkDevices provides a list of network devices
// including those bound to DPDK driver
func getNetworkDevices() ([]helpers.NetworkDevice, error) {
	devs, err := helpers.GetNetworkPCIs()
	if err != nil {
		return nil, err
	}

	err = fillMACAddrForDPDKDevs(devs)
	if err != nil {
		return nil, err
	}

	err = helpers.FillMACAddrForKernelDevs(devs)
	if err != nil {
		return nil, err
	}

	return devs, nil
}

func fillMACAddrForDPDKDevs(devs []helpers.NetworkDevice) error {
	ntsCfg, err := ini.NtsConfigFromFile(Config.NtsConfigPath)

	if err != nil {
		return errors.Wrap(err, "failed to read NTS config")
	}

	for _, port := range ntsCfg.Ports {
		for idx := range devs {
			if devs[idx].PCI == port.PciAddress {
				devs[idx].MAC = port.MAC
				devs[idx].Description = port.Description
				devs[idx].FallbackInterface = port.EgressPortID

				dir, _ := ini.InterfaceTypeFromTrafficDirection(
					port.TrafficDirection)

				devs[idx].Direction = dir
				devs[idx].Driver = pb.NetworkInterface_USERSPACE
			}
		}
	}

	return nil
}

func getNetworkInterfaces() (*pb.NetworkInterfaces, error) {
	devs, err := getNetworkDevices()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain network devices")
	}

	filteredDevices := make([]helpers.NetworkDevice, 0)
	for _, dev := range devs {
		if !IsPCIportBlacklisted(dev.PCI) {
			filteredDevices = append(filteredDevices, dev)
		}
	}

	return helpers.ToNetworkInterfaces(filteredDevices), nil
}
