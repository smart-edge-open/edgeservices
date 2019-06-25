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

	"github.com/golang/protobuf/ptypes/empty"
	pb "github.com/smartedgemec/appliance-ce/pkg/ela/pb"
)

// InterfacePolicyService describes interface policy service
type InterfacePolicyService struct{}

// Set stores received TrafficPolicy to be later used
// when InterfacePolicy/BulkUpdate request is received
func (*InterfacePolicyService) Set(ctx context.Context,
	tp *pb.TrafficPolicy) (*empty.Empty, error) {

	if err := VerifyTrafficPolicy(tp); err != nil {
		return nil, err
	}

	InterfaceConfigurationData.TrafficPolicies =
		append(InterfaceConfigurationData.TrafficPolicies, tp)

	return &empty.Empty{}, nil
}
