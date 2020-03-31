// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eda

import (
	"context"
	"net"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/open-ness/edgenode/pkg/edants"
	"github.com/open-ness/edgenode/pkg/ela/ini"
	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"github.com/pkg/errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewConnFn is a fun to new Connection
var NewConnFn = func() (NtsConnectionInt, error) {
	return edants.NewNtsConnection()
}

// NtsConnectionInt interface representing nts connection
type NtsConnectionInt interface {
	RouteRemove(lookupKeys string) error
	RouteAdd(macAddr net.HardwareAddr, lookupKeys string) error
	Disconnect() error
}

type edaTrafficPolicyServerImpl struct{}

// AppTrafficPolicy represents app traffic policy
type AppTrafficPolicy struct {
	Policy          pb.TrafficPolicy
	NtsTrafficRules []TrafficRuleParsed
}

// TrafficRuleParsed represents traffic rule parsed
type TrafficRuleParsed struct {
	LookupKeys string
	Mac        net.HardwareAddr
}

// AppTrafficPolicies represents app traffic policies
var AppTrafficPolicies map[string]*AppTrafficPolicy

// RemoveRules removes rules
func RemoveRules(appID string, conn NtsConnectionInt) error {

	log.Infof("Removing existing traffic policy for application ID " + appID)

	if _, present := AppTrafficPolicies[appID]; !present {
		log.Infof("Traffic policy for application ID %v "+
			"not found in EDA memory.",
			appID)
		return nil
	}

	if conn == nil {
		log.Errf("Not connected to NTS")
		return status.Errorf(codes.Internal, "Not connected to NTS")
	}
	// With every loop iteration a traffic rule at index 0 is removed
	// from NTS route table, then it is removed from EDA slice holding all
	// traffic rules per app ID by being replaced by the traffic rule
	// stored at its last position.
	// If the attempt to remove a traffic rule from NTS ends with an error,
	// the error is logged, the traffic rule is still removed from EDA memory
	// - the loop continues until there is no
	// traffic rules left in AppTrafficPolicies[appID].NtsTrafficRules
	for range AppTrafficPolicies[appID].NtsTrafficRules {

		log.Debugf("Removing traffic rule %v",
			AppTrafficPolicies[appID].NtsTrafficRules[0].LookupKeys)
		// Remove traffic rule at index 0 from NTS
		err := conn.RouteRemove(AppTrafficPolicies[appID].
			NtsTrafficRules[0].LookupKeys)
		if err != nil {
			log.Errf("Failed to remove traffic rule %s for AppID %v."+
				" Check logs to verify that the rule exists on NTS."+
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

	log.Debugf("Successfully removed traffic rules for application ID %v "+
		"from NTS and EDA memory", appID)

	return nil
}

// DisconnectNTS disonnects nts connection
func DisconnectNTS(conn NtsConnectionInt) {

	err := conn.Disconnect()
	if err != nil {
		log.Errf("Error while disconnecting from NTS: %v", err)
	}
	log.Debugf("Connection to NTS closed")
}

// ValidateTrafficRules validates traffic rules
func ValidateTrafficRules(tp *pb.TrafficPolicy) (*[]TrafficRuleParsed, error) {

	var netMacAddr net.HardwareAddr
	var tempAppTrafficRules []TrafficRuleParsed

	log.Infof("Validating traffic rules for App ID " + tp.Id)

	for _, rule := range tp.TrafficRules {
		log.Debugf("Validating traffic rule: " + rule.Description)
		trString, err := ini.TrafficRuleProtoToString(rule)
		if err != nil {
			log.Errf("Error while parsing traffic rule to string: %v", err)
			return nil, status.Errorf(codes.Internal,
				"Error while parsing traffic rule to string %v", err)
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
	log.Debugf("Successfully validated traffic rules for application ID %v",
		tp.Id)
	return &tempAppTrafficRules, nil
}

// AddRequest adds a request
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

	log.Infof("Adding traffic rules for application ID " + tp.Id)

	for _, rule := range *parsedTrafficRules {

		err = conn.RouteAdd(rule.Mac, rule.LookupKeys)
		if err != nil {
			log.Errf("Failed to add traffic rule: %s for mac addr:"+
				" %s. Error: %v.", rule.LookupKeys,
				rule.Mac.String(), err)
			err = RemoveRules(tp.Id, conn)
			if err != nil {
				return status.Errorf(codes.Unknown,
					"Failed to clean traffic rules on error "+
						"in RouteAdd(). Error: %v", err)
			}

			return status.Errorf(codes.Unknown, "Failed to add "+
				"traffic rule: %s for mac addr: "+
				"%s.", rule.LookupKeys, rule.Mac.String())
		}
		tr := TrafficRuleParsed{
			Mac:        rule.Mac,
			LookupKeys: rule.LookupKeys,
		}

		log.Debugf("Successfully added traffic rule: %v for "+
			"mac address: %v", tr.LookupKeys, tr.Mac.String())

		appTrafficPolicy.NtsTrafficRules =
			append(appTrafficPolicy.NtsTrafficRules, tr)
	}

	log.Debugf("Successfully added all traffic rules for application "+
		"ID %v to NTS", tp.Id)

	return nil
}

func (s *edaTrafficPolicyServerImpl) Set(ctx context.Context,
	tp *pb.TrafficPolicy) (*empty.Empty, error) {

	if tp.Id == "" {
		log.Errf("Traffic policy ID is empty")
		return &empty.Empty{}, errors.New("Application traffic " +
			"policy ID is empty")
	}

	log.Info("Received new SET request for application traffic " +
		"policy ID " + tp.Id)

	conn, err := NewConnFn()
	if err != nil {
		log.Errf("Connection to NTS failed %v", err)
		return &empty.Empty{}, err
	}
	log.Debug("EDA started connection with NTS")
	defer DisconnectNTS(conn)

	err = RemoveRules(tp.Id, conn)
	if err != nil {
		st, _ := status.FromError(err)
		return &empty.Empty{}, status.Errorf(st.Code(),
			"Attempt to remove traffic rules for traffic policy ID "+
				"%s finished with error: %v", tp.Id, err)
	}

	if tp.TrafficRules != nil {

		return &empty.Empty{}, AddRequest(conn, tp)
	}

	return &empty.Empty{}, nil
}
