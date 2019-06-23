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

package ela

import (
	"context"

	"github.com/pkg/errors"

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	GetInterfaces func() (*pb.NetworkInterfaces, error) = GetNetworkInterfaces

	NTSConfigurationHandler = configureNTS
)

func checkForNotAllowedChanges(
	networkInterfaces *pb.NetworkInterfaces) error {

	nis, err := GetInterfaces()
	if err != nil {
		return err
	}

	for _, ifaceUpdate := range networkInterfaces.NetworkInterfaces {
		for _, ifaceCurrent := range nis.NetworkInterfaces {
			if ifaceUpdate.Id == ifaceCurrent.Id {
				if ifaceUpdate.Driver == pb.NetworkInterface_KERNEL &&
					ifaceCurrent.Driver == pb.NetworkInterface_USERSPACE {
					return errors.Errorf("Device %s: "+
						"Changing from USERSPACE to KERNEL driver "+
						"is not supported", ifaceUpdate.Id)
				}
			}
		}
	}

	return nil
}

type InterfaceService struct{}

func (*InterfaceService) Update(context.Context,
	*pb.NetworkInterface) (*empty.Empty, error) {

	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

func (*InterfaceService) BulkUpdate(ctx context.Context,
	networkInterfaces *pb.NetworkInterfaces) (*empty.Empty, error) {
	log.Info("InterfaceService BulkUpdate: received request")

	if err := checkForNotAllowedChanges(networkInterfaces); err != nil {
		log.Errf("InterfaceService BulkUpdate: unsupported action: %v", err)

		return nil, err
	}

	newInterfaces := new(pb.NetworkInterfaces)

	for _, ifaceUpdate := range networkInterfaces.NetworkInterfaces {
		if ifaceUpdate.Driver == pb.NetworkInterface_USERSPACE {
			newInterfaces.NetworkInterfaces =
				append(newInterfaces.NetworkInterfaces, ifaceUpdate)
		}
	}

	if err := ValidateNetworkInterfaces(newInterfaces); err != nil {
		log.Errf("InterfaceService BulkUpdate: invalid NetworkInterface: %v",
			err)

		return nil, err
	}

	InterfaceConfigurationData.NetworkInterfaces = newInterfaces

	if err := NTSConfigurationHandler(ctx); err != nil {
		log.Errf("InterfaceService BulkUpdate: Failed to configure NTS: %+v",
			err)
		return nil, errors.Wrap(err, "failed to configure NTS")
	}

	return &empty.Empty{}, nil
}

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
