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
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	pb "github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const edaDialerTimeout = 10 * time.Second

var (
	// DialEDASet is function implementing gRPC dial to EDA
	DialEDASet = func(ctx context.Context,
		policy *pb.TrafficPolicy, endpoint string) (*empty.Empty, error) {

		ctx, cancel := context.WithTimeout(ctx,
			edaDialerTimeout)
		defer cancel()
		conn, err := grpc.DialContext(ctx,
			endpoint, grpc.WithInsecure())
		if err != nil {
			return nil, errors.Wrapf(err,
				"Failed to create a connection to %s", endpoint)
		}
		defer conn.Close()

		policyCLI := pb.NewApplicationPolicyServiceClient(conn)

		return policyCLI.Set(ctx, policy, grpc.WaitForReady(true))
	}

	// MACFetcher is an object that gets a MAC for application
	MACFetcher MACAddressProvider = &MACFetcherImpl{}
)

// MACAddressProvider is an interface for objects that can provide MAC address
// from application ID
type MACAddressProvider interface {
	GetMacAddress(ctx context.Context, applicationID string) (string, error)
}

type ApplicationPolicyServiceServerImpl struct{}

func (srv *ApplicationPolicyServiceServerImpl) Set(ctx context.Context,
	trafficPolicy *pb.TrafficPolicy) (*empty.Empty, error) {
	log.Info("ApplicationPolicyService Set: Received request")

	if err := VerifyTrafficPolicy(trafficPolicy); err != nil {
		log.Errf("ApplicationPolicyService Set: Invalid TrafficPolicy: %v",
			err)
		return nil,
			status.Errorf(codes.InvalidArgument, err.Error())
	}

	destMacAddress, err := MACFetcher.GetMacAddress(ctx, trafficPolicy.Id)
	if err != nil {
		log.Errf("ApplicationPolicyService Set: "+
			"MAC not found for '%v' because: %v", trafficPolicy.Id, err)

		return nil,
			status.Errorf(codes.NotFound, "ApplicationPolicyService Set: "+
				"MAC not found for '%v' because: %v", trafficPolicy.Id, err)
	}

	log.Infof("Found MAC '%s' for application '%s'",
		destMacAddress, trafficPolicy.Id)

	if err := VerifyMACAddress(destMacAddress); err != nil {
		log.Errf("ApplicationPolicyService Set: "+
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

	return DialEDASet(ctx, trafficPolicy, Config.EDAEndpoint)
}
