// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package helpers

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"

	pb "github.com/open-ness/edgenode/pkg/ela/pb"
)

// VerifyAddressMask verifies IP address and mask pair
func VerifyAddressMask(addr string, mask uint32) error {
	if mask == 0 {
		if addr != "" && addr != "0.0.0.0" {
			return errors.New("Invalid IP/Mask: " +
				"For Mask=0 only empty or 0.0.0.0 addresses are valid")
		}
	} else {
		if addr == "" {
			return errors.New("Invalid IP/Mask: " +
				"For empty IP only Mask=0 is valid")
		}

		ip := net.ParseIP(addr)
		if ip.To4() == nil {
			return errors.New("Invalid IP/Mask: " +
				"Given IP is not a valid IPv4 address")
		}

		if mask > 32 {
			return errors.New("Invalid IP/Mask: " +
				"Mask should be between 0 and 32")
		}

	}

	return nil
}

// VerifyIPFilter checks if IPFilter is correct
func VerifyIPFilter(ip *pb.IPFilter) error {
	if err := VerifyAddressMask(ip.Address, ip.Mask); err != nil {
		return errors.New("IPFilter: " + err.Error())
	}

	if ip.BeginPort > ip.EndPort {
		return errors.New("IPFilter: BeginPort greater than EndPort")
	}

	if ip.Protocol != "" {
		return errors.New("IPFilter: Protocol field is not supported")
	}

	return nil
}

// VerifyGTPFilter checks if GTPFilter is correct
func VerifyGTPFilter(gtp *pb.GTPFilter) error {
	if err := VerifyAddressMask(gtp.Address, gtp.Mask); err != nil {
		return errors.New("GTPFilter: " + err.Error())
	}

	if len(gtp.Imsis) > 0 {
		return errors.New("GTPFilter: Imsis is not supported")
	}

	return nil
}

// VerifyTrafficSelector checks if TrafficSelector is correct
func VerifyTrafficSelector(ts *pb.TrafficSelector) error {
	if ts.Macs != nil {
		return errors.New("TrafficSelector.Mac is set but not supported")
	}

	if ts.Ip == nil && ts.Gtp == nil {
		return errors.New("TrafficSelector: Neither Ip nor Gtp is set")
	}

	if ts.Ip != nil {
		if err := VerifyIPFilter(ts.Ip); err != nil {
			return errors.New("TrafficSelector.Ip: " + err.Error())
		}
	}

	if ts.Gtp != nil {
		if err := VerifyGTPFilter(ts.Gtp); err != nil {
			return errors.New("TrafficSelector.Gtp: " + err.Error())
		}
	}

	return nil
}

// VerifyMACAddress checks if passed mac is valid
func VerifyMACAddress(mac string) error {
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}

	if len(hwAddr) != 6 {
		return errors.New(
			"MAC Address: Wrong length - only 6 bytes are supported")
	}

	if strings.Contains(mac, ".") || strings.Contains(mac, "-") {
		return errors.New("MAC Address: Wrong delimiter, only : is supported")
	}

	return nil
}

// VerifyTrafficTarget checks if traffic target is valid
func VerifyTrafficTarget(tt *pb.TrafficTarget) error {
	if tt == nil {
		return errors.New("TrafficTarget is nil")
	}

	if tt.Action != pb.TrafficTarget_ACCEPT {
		return errors.New("TrafficTarget.Action: Action not supported: " +
			tt.Action.String())
	}

	if tt.Ip != nil {
		return errors.New("TrafficTarget.Ip: modifier is not supported")
	}

	return nil
}

// VerifyTrafficRule checks if TrafficRule is valid
func VerifyTrafficRule(tr *pb.TrafficRule) error {
	if tr.Source == nil && tr.Destination == nil {
		return errors.New(
			"TrafficRule: Both source and destination selectors are nil")
	}

	if tr.Source != nil {
		if err := VerifyTrafficSelector(tr.Source); err != nil {
			return errors.New("TrafficRule.Source: " + err.Error())
		}
	}

	if tr.Destination != nil {
		if err := VerifyTrafficSelector(tr.Destination); err != nil {
			return errors.New("TrafficRule.Destination: " + err.Error())
		}
	}

	if err := VerifyTrafficTarget(tr.Target); err != nil {
		return errors.New("TrafficRule.Target: " + err.Error())
	}

	return nil
}

// VerifyTrafficPolicy checks if TrafficPolicy is valid
func VerifyTrafficPolicy(trafficPolicy *pb.TrafficPolicy) error {
	if trafficPolicy == nil {
		return errors.New("TrafficPolicy is nil")
	}

	if trafficPolicy.Id == "" {
		return errors.New("TrafficPolicy.Id is empty")
	}

	for idx, trafficRule := range trafficPolicy.GetTrafficRules() {
		if err := VerifyTrafficRule(trafficRule); err != nil {
			return fmt.Errorf("TrafficPolicy.TrafficRule[%v] is invalid: %s",
				idx, err.Error())
		}
	}

	return nil
}

// ValidateNetworkInterface validates network interface
func ValidateNetworkInterface(iface *pb.NetworkInterface) error {
	if iface == nil {
		return errors.New("NetworkInterface is nil")
	}

	if iface.Id == "" {
		return errors.New("Id is nil")
	}

	if iface.Driver == pb.NetworkInterface_KERNEL {
		// Do not validate interfaces with KERNEL driver
		return nil
	}

	if iface.Type == pb.NetworkInterface_NONE {
		return errors.New("type 'NONE' is not supported")
	}

	if iface.MacAddress != "" {
		if err := VerifyMACAddress(iface.MacAddress); err != nil {
			return err
		}
	}

	if iface.Vlan != 0 {
		return errors.New("Vlan is not supported")
	}

	if len(iface.Zones) != 0 {
		return errors.New("Zones are not supported")
	}

	if iface.FallbackInterface == "" {
		return errors.New("FallbackInterface is empty")
	}

	return nil
}

// ValidateNetworkInterfaces validates network interfaces
func ValidateNetworkInterfaces(interfaces *pb.NetworkInterfaces) error {
	if interfaces == nil {
		return errors.New("NetworkInterfaces is nil")
	}

	for idx, iface := range interfaces.NetworkInterfaces {
		if err := ValidateNetworkInterface(iface); err != nil {
			return errors.Wrapf(err, "NetworkInterface[%d] is invalid", idx)
		}
	}
	return nil
}
