// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ini

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	pb "github.com/open-ness/edgenode/pkg/ela/pb"
)

func gtpFilterToString(gtp *pb.GTPFilter, source bool) (string, error) {
	if gtp == nil {
		return "", errors.New("gtp is nil")
	}

	s := gtp.Address + "/" + strconv.FormatUint(uint64(gtp.Mask), 10)

	prefix := "epc"
	if source {
		prefix = "enb"
	}

	return fmt.Sprintf("%s_ip:%s", prefix, s), nil
}

func ipFilterToString(ip *pb.IPFilter, source bool) (string, error) {
	if ip == nil {
		return "", errors.New("ip is nil")
	}

	prefix := "srv"
	if source {
		prefix = "ue"
	}

	rule := fmt.Sprintf("%s_ip:%s/%s", prefix, ip.Address,
		strconv.FormatUint(uint64(ip.Mask), 10))

	if ip.BeginPort > ip.EndPort {
		return "",
			errors.Errorf("begin port %v should be >= than end port %v",
				ip.BeginPort, ip.EndPort)
	}

	if !(ip.BeginPort == 0 && ip.EndPort == 0) {
		rule = fmt.Sprintf("%s,%s_port:%s-%s", rule, prefix,
			strconv.FormatUint(uint64(ip.BeginPort), 10),
			strconv.FormatUint(uint64(ip.EndPort), 10))
	}

	return rule, nil
}

func trafficSelectorToString(ts *pb.TrafficSelector,
	source bool) (string, error) {

	if ts == nil {
		return "", errors.New("traffic selector is nil")
	}

	var gtp, ip string
	var err error
	if ts.Gtp != nil {
		gtp, err = gtpFilterToString(ts.Gtp, source)
		if err != nil {
			return "",
				errors.Wrap(err, "failed to convert gtp filter to string")
		}
	}

	if ts.Ip != nil {
		ip, err = ipFilterToString(ts.Ip, source)
		if err != nil {
			return "", errors.Wrap(err, "failed to convert ip filter to string")
		}
	}

	if gtp != "" && ip != "" {
		return fmt.Sprintf("%s,%s", gtp, ip), nil
	}

	return gtp + ip, nil
}

// TrafficRuleProtoToString to string function
func TrafficRuleProtoToString(rule *pb.TrafficRule) (string, error) {
	if rule == nil {
		return "", errors.New("traffic rule is nil")
	}

	s := "prio:" + strconv.FormatUint(uint64(rule.Priority), 10)

	if rule.Source != nil {
		if source, err :=
			trafficSelectorToString(rule.Source, true); err == nil {
			s += "," + source
		} else {
			return "", errors.Wrap(err,
				"failed to convert Source traffic selector to string")
		}
	}

	if rule.Destination != nil {
		if dest, err :=
			trafficSelectorToString(rule.Destination, false); err == nil {
			s += "," + dest
		} else {
			return "", errors.Wrap(err,
				"failed to convert Destination traffic selector to string")
		}
	}

	if !strings.Contains(s, "epc") && !strings.Contains(s, "enb") {
		s += ",encap_proto:noencap"
	}

	return s, nil
}

func setPriority(tr *pb.TrafficRule, val string) error {
	prioU64, err := strconv.ParseUint(val, 10, 32)

	if err != nil {
		return errors.Errorf("failed to parse '%s' to uint", val)
	}

	tr.Priority = uint32(prioU64)
	return nil
}

func setIPAddrMask(s string, ip *pb.IPFilter) error {
	addrMask := strings.Split(s, "/")
	ip.Address = addrMask[0]

	if len(addrMask) == 2 {
		maskU64, err := strconv.ParseUint(addrMask[1], 10, 32)
		if err != nil {
			return errors.Errorf("failed to parse '%s' to uint", addrMask[1])
		}
		ip.Mask = uint32(maskU64)
	} else if len(addrMask) > 2 {
		return errors.Errorf("string '%s' contains too many "+
			"fields delimited by /, expected 2", s)
	}

	return nil
}

func parseGTPFilter(s string) (*pb.GTPFilter, error) {
	addrMask := strings.Split(s, "/")
	filter := &pb.GTPFilter{Address: addrMask[0]}

	if len(addrMask) == 2 {
		maskU64, err := strconv.ParseUint(addrMask[1], 10, 32)
		if err != nil {
			return nil,
				errors.Errorf("failed to parse '%s' to uint", addrMask[1])
		}
		filter.Mask = uint32(maskU64)
	} else if len(addrMask) > 2 {
		return nil, errors.Errorf("string '%s' contains too many "+
			"fields delimited by /, expected 2", s)
	}

	return filter, nil
}

func setIPPorts(s string, ip *pb.IPFilter) error {
	ports := strings.Split(s, "-")

	min, err := strconv.ParseUint(ports[0], 10, 32)
	if err != nil {
		return errors.Errorf("failed to parse '%s' to uint", ports[0])
	}
	ip.BeginPort = uint32(min)

	if len(ports) == 2 {
		max, err := strconv.ParseUint(ports[1], 10, 32)
		if err != nil {
			return errors.Errorf("failed to parse '%s' to uint", ports[1])
		}
		ip.EndPort = uint32(max)

	} else if len(ports) > 2 {
		return errors.Errorf("string '%s' contains too many "+
			"fields delimited by -, expected 2", s)
	}

	return nil
}

func createSourceSelectorIfNil(tr *pb.TrafficRule) {
	if tr.Source == nil {
		tr.Source = &pb.TrafficSelector{}
	}
}

func createDestinationSelectorIfNil(tr *pb.TrafficRule) {
	if tr.Destination == nil {
		tr.Destination = &pb.TrafficSelector{}
	}
}

func createSourceSelectorAndIPFilterIfNil(tr *pb.TrafficRule) {
	createSourceSelectorIfNil(tr)
	if tr.Source.Ip == nil {
		tr.Source.Ip = &pb.IPFilter{}
	}
}

func createDestinationSelectorAndIPFilterIfNil(tr *pb.TrafficRule) {
	createDestinationSelectorIfNil(tr)
	if tr.Destination.Ip == nil {
		tr.Destination.Ip = &pb.IPFilter{}
	}
}

func setUEIP(tr *pb.TrafficRule, val string) error {
	if val == "" {
		return errors.New("given string is empty")
	}

	createSourceSelectorAndIPFilterIfNil(tr)
	return setIPAddrMask(val, tr.Source.Ip)
}

func setUEPort(tr *pb.TrafficRule, val string) error {
	if val == "" {
		return errors.New("given string is empty")
	}

	createSourceSelectorAndIPFilterIfNil(tr)
	return setIPPorts(val, tr.Source.Ip)
}

func setSrvIP(tr *pb.TrafficRule, val string) error {
	if val == "" {
		return errors.New("given string is empty")
	}

	createDestinationSelectorAndIPFilterIfNil(tr)
	return setIPAddrMask(val, tr.Destination.Ip)
}

func setSrvPort(tr *pb.TrafficRule, val string) error {
	if val == "" {
		return errors.New("given string is empty")
	}

	createDestinationSelectorAndIPFilterIfNil(tr)
	return setIPPorts(val, tr.Destination.Ip)
}

func setEnbIP(tr *pb.TrafficRule, val string) error {
	if val == "" {
		return errors.New("given string is empty")
	}

	createSourceSelectorIfNil(tr)

	gtp, err := parseGTPFilter(val)
	if err != nil {
		return errors.Wrap(err, "failed to parse gtp filter")
	}

	tr.Source.Gtp = gtp
	return nil
}

func setEpcIP(tr *pb.TrafficRule, val string) error {
	if val == "" {
		return errors.New("given string is empty")
	}

	createDestinationSelectorIfNil(tr)

	gtp, err := parseGTPFilter(val)
	if err != nil {
		return errors.Wrap(err, "failed to parse gtp filter")
	}

	tr.Destination.Gtp = gtp
	return nil
}

func encapNoop(*pb.TrafficRule, string) error {
	return nil
}

var parsers = map[string]func(*pb.TrafficRule, string) error{
	"prio":        setPriority,
	"ue_ip":       setUEIP,
	"srv_ip":      setSrvIP,
	"enb_ip":      setEnbIP,
	"epc_ip":      setEpcIP,
	"ue_port":     setUEPort,
	"srv_port":    setSrvPort,
	"encap_proto": encapNoop,
}

// TrafficRuleStringToProto parses traffic rule string to proto
func TrafficRuleStringToProto(s string) (*pb.TrafficRule, error) {
	tr := &pb.TrafficRule{}

	fields := strings.Split(s, ",")
	for _, field := range fields {
		parts := strings.Split(field, ":")
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]

		if f, ok := parsers[key]; ok {
			err := f(tr, value)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse %s's value:'%s'",
					key, value)
			}
		} else {
			return nil, errors.Errorf("parser not found for '%s'", key)
		}
	}

	return tr, nil
}
