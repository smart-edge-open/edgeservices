// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/open-ness/edgenode/pkg/ela/helpers"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
)

// InterfacePolicyService describes interface policy service
type InterfacePolicyService struct{}

// Set stores received TrafficPolicy to be later used
// when InterfacePolicy/BulkUpdate request is received
func (*InterfacePolicyService) Set(ctx context.Context,
	tp *pb.TrafficPolicy) (*empty.Empty, error) {

	log.Info("InterfacePolicyService Set: received request")

	if err := helpers.VerifyTrafficPolicy(tp); err != nil {
		return nil, err
	}

	InterfaceConfigurationData.TrafficPolicies[tp.Id] = tp

	return &empty.Empty{}, nil
}
