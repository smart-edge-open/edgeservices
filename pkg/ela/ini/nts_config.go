// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package ini

import (
	"bytes"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	pb "github.com/open-ness/edgenode/pkg/ela/pb"

	"gopkg.in/ini.v1"
)

func init() {
	ini.PrettyFormat = false
	ini.PrettyEqual = true
	ini.PrettySection = true
}

// KNI is a struct storing config regarding DPDK's Kernel Network Interface
type KNI struct {
	Max int `ini:"max"`
}

// VMCommon is a struct storing config regarding VMs
type VMCommon struct {
	Max      int    `ini:"max"`
	Number   int    `ini:"number"`
	VHostDev string `ini:"vhost-dev"`
}

// NtsServer is a struct storing config regarding NtsServer
type NtsServer struct {
	ControlSocket string `ini:"ctrl_socket"`
}

// NtsConfig is a struct representing nes.cfg file.
// It stores config for ports, VMs and Nts server.
type NtsConfig struct {
	VMCommon  VMCommon  `ini:"VM common"`
	NtsServer NtsServer `ini:"NES_SERVER"`
	KNI       KNI       `ini:"KNI"`
	Ports     []Port    `ini:"-"`
}

// SaveToFile saves data to a file
func (nts *NtsConfig) SaveToFile(filePath string) error {
	buf, err := nts.WriteToBuffer()

	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, buf.Bytes(), 0644)
}

// WriteToBuffer writes NtsConfig to buffer
func (nts *NtsConfig) WriteToBuffer() (*bytes.Buffer, error) {
	iniFile := ini.Empty()

	for idx, port := range nts.Ports {
		sectionName := "PORT" + strconv.Itoa(idx)

		section, err := iniFile.NewSection(sectionName)
		if err != nil {
			return nil,
				errors.Wrapf(err, "Failed to create %s section", sectionName)
		}

		err = section.ReflectFrom(&port)
		if err != nil {
			return nil,
				errors.Wrapf(err, "Failed to Reflect port %+v", port)
		}
	}

	err := ini.ReflectFrom(iniFile, nts)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = iniFile.WriteTo(buf)
	if err != nil {
		return nil, err
	}

	// Because ini library does not handle serializing shadow values
	// following hack is required
	// Overwrite `route = <r1>|<r2>` with:
	// route = <r1>
	// route = <r2>
	output := strings.Replace(buf.String(), "|", "\nroute = ", -1)

	// Because ini library errounously handles empty slices with shadow values
	// following hack is required. Removes line 'route = ' which is invalid.
	output = strings.Replace(output, "route = \n", "", -1)

	return bytes.NewBufferString(output), nil
}

// NtsConfigFromFile loads file to which path is given
// and parses it into NtsConfig struct
func NtsConfigFromFile(filePath string) (*NtsConfig, error) {
	c := new(NtsConfig)

	iniFile, err := ini.ShadowLoad(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to ShadowLoad file %s", filePath)
	}

	err = iniFile.MapTo(c)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to Map file %s", filePath)
	}

	for _, section := range iniFile.Sections() {
		if strings.Contains(section.Name(), "PORT") {

			var p Port
			err := section.StrictMapTo(&p)
			if err != nil {
				return nil, errors.Wrapf(err,
					"Failed to Map port from section %+v", section)
			}

			c.Ports = append(c.Ports, p)
		}
	}

	for idx, p := range c.Ports {
		if p.EgressPort > len(c.Ports) {
			return nil, errors.Errorf(
				"EgressPort %d greater than amount of Ports", p.EgressPort)
		}

		c.Ports[idx].EgressPortID = c.Ports[p.EgressPort].PciAddress
	}

	return c, nil
}

// AddNewPort adds given port to NtsConfig's slice of ports
func (nts *NtsConfig) AddNewPort(port Port) {
	nts.Ports = append(nts.Ports, port)
}

// RemovePort removes port with given pci from NtsConfig's slice of ports
func (nts *NtsConfig) RemovePort(pci string) {
	for idx, port := range nts.Ports {
		if port.PciAddress == pci {
			nts.Ports = append(nts.Ports[:idx], nts.Ports[idx+1:]...)
			return
		}
	}
}

// TrafficType is a enum typedef used for declaring traffic type
type TrafficType string

const (
	// IP traffic type
	IP TrafficType = "IP"
	// LTE traffic type
	LTE TrafficType = "LTE"
	// Mixed traffic type
	Mixed TrafficType = "mixed"
)

// TrafficDirection is a enum typedef used for declaring traffic direction
type TrafficDirection string

const (
	// Unknown traffic direction
	Unknown TrafficDirection = "unknown"
	// Upstream traffic direction
	Upstream TrafficDirection = "upstream"
	// Downstream traffic direction
	Downstream TrafficDirection = "downstream"
	// Both traffic direction
	Both TrafficDirection = "both"
	// LBP traffic direction
	LBP TrafficDirection = "lbp"
)

// Port struct represents configuration of a port for NTS
type Port struct {
	Name             string           `ini:"name"`
	Description      string           `ini:"description,omitempty"`
	PciAddress       string           `ini:"pci-address"`
	TrafficType      TrafficType      `ini:"traffic-type"`
	TrafficDirection TrafficDirection `ini:"traffic-direction"`
	EgressPort       int              `ini:"egress-port"`
	EgressPortID     string           `ini:"-"`
	MAC              string           `ini:"mac,omitempty"`
	LBPMAC           string           `ini:"lbp-mac,omitempty"`
	MTU              uint16           `ini:"MTU,omitempty"`

	Routes []string `ini:"route,omitempty,allowshadow" delim:"|"`
}

// TrafficDirectionFromInterfaceType find traffic direction
func TrafficDirectionFromInterfaceType(
	t pb.NetworkInterface_InterfaceType) (TrafficDirection, error) {

	switch t {
	case pb.NetworkInterface_UPSTREAM:
		return Upstream, nil
	case pb.NetworkInterface_DOWNSTREAM:
		return Downstream, nil
	case pb.NetworkInterface_BIDIRECTIONAL:
		return Both, nil
	case pb.NetworkInterface_BREAKOUT:
		return LBP, nil
	default:
		return Unknown,
			errors.Errorf("Network interface type %v is not supported", t)
	}
}

// InterfaceTypeFromTrafficDirection finds interface type
func InterfaceTypeFromTrafficDirection(
	t TrafficDirection) (pb.NetworkInterface_InterfaceType, error) {

	switch t {
	case Upstream:
		return pb.NetworkInterface_UPSTREAM, nil
	case Downstream:
		return pb.NetworkInterface_DOWNSTREAM, nil
	case Both:
		return pb.NetworkInterface_BIDIRECTIONAL, nil
	case LBP:
		return pb.NetworkInterface_BREAKOUT, nil
	default:
		return pb.NetworkInterface_NONE,
			errors.Errorf("Unknown TrafficDirection: %s", t)
	}
}

// Update do the update
func (nts *NtsConfig) Update() {
	for idx, p := range nts.Ports {
		if p.TrafficDirection != LBP {
			nts.Ports[idx].LBPMAC = ""
		}

		for idx2, p2 := range nts.Ports {
			if p.EgressPortID == p2.PciAddress {
				nts.Ports[idx].EgressPort = idx2
			}
		}
	}
}

// GetNetworkInterface gets network interface
func (p *Port) GetNetworkInterface() (*pb.NetworkInterface, error) {
	n := &pb.NetworkInterface{}

	n.Id = p.Name

	interfaceType, err := InterfaceTypeFromTrafficDirection(p.TrafficDirection)
	if err != nil {
		return nil, errors.Wrap(err,
			"failed to convert traffic direction to interface type")
	}

	n.Type = interfaceType
	n.FallbackInterface = p.EgressPortID
	n.Description = p.Description
	n.MacAddress = p.MAC

	return n, nil
}

// UpdateFromNetworkInterface updates from network interface
func (p *Port) UpdateFromNetworkInterface(n *pb.NetworkInterface) error {
	if p.PciAddress != "" && p.PciAddress != n.Id {
		return errors.Errorf(
			"PciAddress mismatched, Port: %s, NetworkInterface: %s",
			p.PciAddress, n.Id)
	}

	p.Name = n.Id
	p.PciAddress = n.Id

	direction, err := TrafficDirectionFromInterfaceType(n.Type)
	if err != nil {
		return errors.Wrap(err,
			"failed to convert interface type to traffic direction")
	}

	p.TrafficDirection = direction
	p.EgressPortID = n.FallbackInterface
	p.Description = n.Description
	p.MAC = n.MacAddress

	return nil
}

func (p *Port) setTrafficType(gtpTraffic, ipTraffic bool) {
	if gtpTraffic && ipTraffic {
		p.TrafficType = Mixed
	} else if gtpTraffic {
		p.TrafficType = LTE
	} else {
		p.TrafficType = IP
	}
}

func (p *Port) setLBPMAC(tr *pb.TrafficRule) {
	if p.LBPMAC == "" &&
		tr.Target != nil &&
		tr.Target.Mac != nil &&
		tr.Target.Mac.MacAddress != "" {

		p.LBPMAC = tr.Target.Mac.MacAddress
	}
}

// UpdateFromTrafficPolicy updates from traffic policy
func (p *Port) UpdateFromTrafficPolicy(tp *pb.TrafficPolicy) error {
	if p.PciAddress != "" && p.PciAddress != tp.Id {
		return errors.Errorf(
			"PciAddress mismatched, Port: %s, TrafficPolicy: %s",
			p.PciAddress, tp.Id)
	}

	p.Name = tp.Id
	p.PciAddress = tp.Id

	gtpTraffic := false
	ipTraffic := false

	for _, tr := range tp.TrafficRules {
		if route,
			err := TrafficRuleProtoToString(tr); err == nil &&
			route != "" {

			p.Routes = append(p.Routes, route)
		}

		p.setLBPMAC(tr)

		gtpFilterPresent := (tr.Source != nil && tr.Source.Gtp != nil) ||
			(tr.Destination != nil && tr.Destination.Gtp != nil)

		if gtpFilterPresent {
			gtpTraffic = true
		} else {
			ipTraffic = true
		}
	}

	p.setTrafficType(gtpTraffic, ipTraffic)

	return nil
}
