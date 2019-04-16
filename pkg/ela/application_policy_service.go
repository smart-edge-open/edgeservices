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
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// EDA is an object that communicates with EDA endpoint
	EDA EDAClient = &edaClient{}

	// MACFetcher is an object that gets a MAC for application
	MACFetcher MACAddressProvider = &MACFetcherImpl{}
)

// MACAddressProvider is an interface for objects that can provide MAC address
// from application ID
type MACAddressProvider interface {
	GetMacAddress(ctx context.Context, applicationID string) (string, error)
}

// EDAClient is an interface for calling EDA agent
type EDAClient interface {
	Set(context.Context, *pb.TrafficPolicy) (*empty.Empty, error)
	Get(context.Context, *pb.ApplicationID) (*pb.TrafficPolicy, error)
}

type edaClient struct{}

func (*edaClient) Set(context.Context,
	*pb.TrafficPolicy) (*empty.Empty, error) {

	// TODO: Pass request to EDA
	return &empty.Empty{},
		status.Error(codes.Unimplemented, "not yet implemented")
}

func (*edaClient) Get(context.Context,
	*pb.ApplicationID) (*pb.TrafficPolicy, error) {

	// TODO: Pass request to EDA
	return &pb.TrafficPolicy{},
		status.Error(codes.Unimplemented, "not yet implemented")
}

type ApplicationPolicyServiceServerImpl struct{}

func (srv *ApplicationPolicyServiceServerImpl) Set(ctx context.Context,
	trafficPolicy *pb.TrafficPolicy) (*empty.Empty, error) {
	log.Info("ApplicationPolicyService Set: Received request")

	if err := VerifyTrafficPolicy(trafficPolicy); err != nil {
		log.Errorf("ApplicationPolicyService Set: Invalid TrafficPolicy: %v",
			err)
		return nil,
			status.Errorf(codes.InvalidArgument, err.Error())
	}

	destMacAddress, err := MACFetcher.GetMacAddress(ctx, trafficPolicy.Id)
	if err != nil {
		log.Errorf("ApplicationPolicyService Set: "+
			"MAC not found for '%v' because: %v", trafficPolicy.Id, err)

		return nil,
			status.Errorf(codes.NotFound, "ApplicationPolicyService Set: "+
				"MAC not found for '%v' because: %v", trafficPolicy.Id, err)
	}

	log.Infof("Found MAC '%s' for application '%s'",
		destMacAddress, trafficPolicy.Id)

	if err := VerifyMACAddress(destMacAddress); err != nil {
		log.Errorf("ApplicationPolicyService Set: "+
			"Obtained MAC '%s' format is incorrect because: %v",
			destMacAddress, err)

		return nil,
			status.Errorf(codes.NotFound, "ApplicationPolicyService Set: "+
				"MAC '%s' format is incorrect because: %v",
				destMacAddress, err)
	}

	for _, trafficRule := range trafficPolicy.GetTrafficRules() {
		trafficRule.Target.Mac = &pb.MACModifier{MacAddress: destMacAddress}
	}

	return EDA.Set(ctx, trafficPolicy)
}

func (srv *ApplicationPolicyServiceServerImpl) Get(ctx context.Context,
	appID *pb.ApplicationID) (*pb.TrafficPolicy, error) {

	log.Info("ApplicationPolicyService Get: Received request")
	// TODO: Check if application is deployed

	return EDA.Get(ctx, appID)
}
