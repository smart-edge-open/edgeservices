// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ela

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/open-ness/edgenode/pkg/ela/helpers"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"github.com/pkg/errors"
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
		defer func() {
			if err1 := conn.Close(); err1 != nil {
				log.Errf("Failed to close connection: %v", err1)
			}
		}()

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

// ApplicationPolicyServiceServerImpl empty struct
type ApplicationPolicyServiceServerImpl struct{}

// Set sets traffic policy
func (srv *ApplicationPolicyServiceServerImpl) Set(ctx context.Context,
	trafficPolicy *pb.TrafficPolicy) (*empty.Empty, error) {
	log.Info("ApplicationPolicyService Set: Received request")

	if err := helpers.VerifyTrafficPolicy(trafficPolicy); err != nil {
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

	if err := helpers.VerifyMACAddress(destMacAddress); err != nil {
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
