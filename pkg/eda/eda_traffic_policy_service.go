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

package eda

import (
	"context"
	"net"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/smartedgemec/appliance-ce/pkg/ela/ini"
	pb "github.com/smartedgemec/appliance-ce/pkg/ela/pb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var NewConnFn = func() (NtsConnectionInt, error) {

	return NewNtsConnection()
}

type NtsConnectionInt interface {
	RouteRemove(lookupKeys string) error
	RouteAdd(macAddr net.HardwareAddr, lookupKeys string) error
	Disconnect() error
}

type edaTrafficPolicyServerImpl struct{}

type AppTrafficPolicy struct {
	Policy          pb.TrafficPolicy
	NtsTrafficRules []TrafficRuleParsed
}

type TrafficRuleParsed struct {
	LookupKeys string
	Mac        net.HardwareAddr
}

var AppTrafficPolicies map[string]*AppTrafficPolicy

func RemoveRules(appID string, conn NtsConnectionInt) error {

	log.Info("Removing Traffic Rules for App ID: " + appID)

	if _, present := AppTrafficPolicies[appID]; !present {
		log.Info("Traffic Policy does not exist for AppID: " + appID)
		return nil
	}

	if conn == nil {
		log.Errf("Not connected to NTS")
		return status.Errorf(codes.Internal, "Not connected to NTS")
	}
	// With every loop iteration a traffic rule at index 0 is removed
	// from NTS route table, then it is removed from IDA slice holding all
	// traffic rules per app ID by being replaced by the traffic rule
	// stored at its last position.
	// If the attempt to remove a traffic rule from NTS ends with an error,
	// the error is logged, the traffic rule is still removed from EDA memory
	// - the loop continues until there is no
	// traffic rules left in AppTrafficPolicies[appID].NtsTrafficRules
	for range AppTrafficPolicies[appID].NtsTrafficRules {

		log.Infof("Removing Traffic Rule %v",
			AppTrafficPolicies[appID].NtsTrafficRules[0].LookupKeys)
		// Remove traffic rule at index 0 from NTS
		err := conn.RouteRemove(AppTrafficPolicies[appID].
			NtsTrafficRules[0].LookupKeys)
		if err != nil {
			log.Errf("Failed at removing Traffic Rule %s for AppID %v."+
				" See logs to verify that the rule exists on NTS."+
				" Error: %v", AppTrafficPolicies[appID].NtsTrafficRules[0].
				LookupKeys, appID, err)
		}
		// Always remove the rule at index 0 by replacing it
		// with the traffic rule at the last position in the slice
		AppTrafficPolicies[appID].NtsTrafficRules[0] =
			AppTrafficPolicies[appID].NtsTrafficRules[len(
				AppTrafficPolicies[appID].NtsTrafficRules)-1]
		// The last entry in the slice is replaced with an empty struct
		AppTrafficPolicies[appID].NtsTrafficRules[len(
			AppTrafficPolicies[appID].NtsTrafficRules)-1] =
			TrafficRuleParsed{}
		// NtsTrafficRules slice is overriten with a new slice
		// including all the same entries except the last one - the empty one
		AppTrafficPolicies[appID].NtsTrafficRules =
			AppTrafficPolicies[appID].NtsTrafficRules[:len(
				AppTrafficPolicies[appID].NtsTrafficRules)-1]

	}

	// Once all traffic rules per app ID are removed
	// delete the map entry for appID from AppTrafficPolicies
	delete(AppTrafficPolicies, appID)

	return nil
}

func DisconnectNTS(conn NtsConnectionInt) {

	err := conn.Disconnect()
	if err != nil {
		log.Errf("Error while disconnecting from NTS: %v", err)
	}
	log.Info("Connection to NTS closed")
}

func ValidateTrafficRules(tp *pb.TrafficPolicy) (*[]TrafficRuleParsed, error) {

	var netMacAddr net.HardwareAddr
	var tempAppTrafficRules []TrafficRuleParsed

	for _, rule := range tp.TrafficRules {
		log.Info("Validating Traffic Rule: " + rule.Description)
		trString, err := ini.TrafficRuleProtoToString(rule)
		if err != nil {
			log.Errf("Error while parsing Traffic Rule to string: %v", err)
			return nil, status.Errorf(codes.Internal,
				"Error while parsing Traffic Rule to string %v", err)
		}

		if nil == rule.Target || nil == rule.Target.Mac {
			log.Errf("Failed to retrieve mac address for rule %s",
				trString)
			return nil, status.Errorf(codes.InvalidArgument,
				"Failed to retrieve mac address for rule %s",
				trString)
		}

		netMacAddr, err = net.ParseMAC(rule.Target.Mac.MacAddress)
		if err != nil {
			log.Errf("Error while parsing mac address: %s. Error: %v",
				rule.Target.Mac.MacAddress, err)
			return nil, status.Errorf(codes.InvalidArgument,
				"Error while parsing mac address: %v", err)
		}

		trafficRuleParsed := TrafficRuleParsed{
			LookupKeys: trString,
			Mac:        netMacAddr,
		}

		tempAppTrafficRules = append(tempAppTrafficRules, trafficRuleParsed)

	}
	return &tempAppTrafficRules, nil
}

func AddRequest(conn NtsConnectionInt, tp *pb.TrafficPolicy) error {

	parsedTrafficRules, err := ValidateTrafficRules(tp)
	if err != nil {
		log.Errf("Validation of traffic rules finished with error: %v", err)
		st, _ := status.FromError(err)
		return status.Errorf(st.Code(), "Validation of traffic rules "+
			"finished with error: %v", err)
	}

	appTrafficPolicy := AppTrafficPolicy{Policy: *tp}
	AppTrafficPolicies[tp.Id] = &appTrafficPolicy

	for _, rule := range *parsedTrafficRules {

		err = conn.RouteAdd(rule.Mac, rule.LookupKeys)
		if err != nil {
			log.Errf("Failed to add Traffic Rule: %s to mac addr"+
				" %s. Error: %v.", rule.LookupKeys,
				rule.Mac.String(), err)
			err = RemoveRules(tp.Id, conn)
			if err != nil {
				return status.Errorf(codes.Unknown,
					"Failed to clean traffic rules on error "+
						"from RouteAdd(). Error: %v", err)
			}

			return status.Errorf(codes.Unknown,
				"Traffic Rule %s can't be set for mac "+
					"address %s", rule.LookupKeys,
				rule.Mac.String())
		}
		tr := TrafficRuleParsed{
			Mac:        rule.Mac,
			LookupKeys: rule.LookupKeys,
		}

		log.Info("Traffic Rule " + tr.LookupKeys +
			" added for mac address: " + tr.Mac.String())

		appTrafficPolicy.NtsTrafficRules =
			append(appTrafficPolicy.NtsTrafficRules, tr)
	}

	return nil
}

func (s *edaTrafficPolicyServerImpl) Set(ctx context.Context,
	tp *pb.TrafficPolicy) (*empty.Empty, error) {

	if tp.Id == "" {
		log.Errf("Traffic Policy ID is empty")
		return &empty.Empty{}, errors.New("Traffic Policy ID is empty")
	}

	log.Info("Received SET request for Application Traffic " +
		"Policy ID: " + tp.Id)

	conn, err := NewConnFn()
	if err != nil {
		log.Errf("Connection to NTS failed %v", err)
		return &empty.Empty{}, err
	}
	log.Info("EDA connected to NTS")
	defer DisconnectNTS(conn)

	err = RemoveRules(tp.Id, conn)
	if err != nil {
		st, _ := status.FromError(err)
		return &empty.Empty{}, status.Errorf(st.Code(),
			"Attempt to remove Traffic Rules for Traffic Policy ID "+
				"%s finished with error: %v", tp.Id, err)
	}

	if tp.TrafficRules != nil {

		return &empty.Empty{}, AddRequest(conn, tp)
	}

	return &empty.Empty{}, nil
}
