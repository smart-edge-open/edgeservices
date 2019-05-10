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
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	GetInterfaces func() (*pb.NetworkInterfaces, error) = GetNetworkInterfaces
)

type InterfaceService struct{}

func (*InterfaceService) Update(context.Context,
	*pb.NetworkInterface) (*empty.Empty, error) {

	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

func (*InterfaceService) BulkUpdate(context.Context,
	*pb.NetworkInterfaces) (*empty.Empty, error) {

	return nil, status.Errorf(codes.Unimplemented, "not implemented")
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

func (*InterfaceService) Get(context.Context,
	*pb.InterfaceID) (*pb.NetworkInterface, error) {

	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
