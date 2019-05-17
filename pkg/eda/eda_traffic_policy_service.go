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
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/smartedgemec/appliance-ce/pkg/ela/ini"
	"github.com/smartedgemec/appliance-ce/pkg/ela/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
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

	for i, rule := range AppTrafficPolicies[appID].NtsTrafficRules {

		err := conn.RouteRemove(rule.LookupKeys)
		if err != nil {
			log.Errf("Failed at removing Traffic Rule %s for AppID %v."+
				" See logs to verify that the rule exists on NTS."+
				" Error: %v", rule.LookupKeys, appID, err)
		}

		AppTrafficPolicies[appID].NtsTrafficRules[i] =
			AppTrafficPolicies[appID].NtsTrafficRules[len(
				AppTrafficPolicies[appID].NtsTrafficRules)-1]

		AppTrafficPolicies[appID].NtsTrafficRules[len(
			AppTrafficPolicies[appID].NtsTrafficRules)-1] =
			TrafficRuleParsed{}

		AppTrafficPolicies[appID].NtsTrafficRules =
			AppTrafficPolicies[appID].NtsTrafficRules[:len(
				AppTrafficPolicies[appID].NtsTrafficRules)-1]

		log.Infof("Removed Traffic Rule %v,", rule.LookupKeys)

	}
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

	log.Info("Received SET request for adding Application Traffic " +
		"Policy ID: " + tp.Id)

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
					"Failed to clean traffic routs on error "+
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

	if tp == nil {
		log.Errf("Traffic Policy pointer is nil")
		return &empty.Empty{}, errors.New("Traffic Policy pointer is nil")
	}

	if tp.Id == "" {
		log.Errf("Traffic Policy ID is empty")
		return &empty.Empty{}, errors.New("Traffic Policy ID is empty")
	}

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
