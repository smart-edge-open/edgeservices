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
	"bytes"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kata-containers/runtime/virtcontainers/pkg/nsenter"

	"github.com/otcshare/edgenode/pkg/ela/ini"
	pb "github.com/otcshare/edgenode/pkg/ela/pb"
	"github.com/pkg/errors"
)

// NetworkDevice contains data for network device
type NetworkDevice struct {
	PCI               string
	Manufacturer      string
	MAC               string
	Description       string
	FallbackInterface string
	Driver            pb.NetworkInterface_InterfaceDriver
	Direction         pb.NetworkInterface_InterfaceType
}

// IsPCIportBlacklisted check if a pci port is blacklisted and cannot be used
// by controller to set up connection.
func IsPCIportBlacklisted(pci string) bool {
	for _, port := range Config.PCIBlacklist {
		if port == pci {
			return true
		}
	}
	return false
}

func getNetworkPCIs() ([]NetworkDevice, error) {

	// #nosec G204 - called with lspci
	cmd := exec.Command("command", "-v", "lspci")
	if err := cmd.Run(); err != nil {
		return nil, errors.New("command `lspci` is not available")
	}

	// #nosec G204 - command is const
	cmd = exec.Command("bash", "-c",
		`lspci -Dmm | grep -i "Ethernet\|Network"`)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, errors.Errorf("Failed to exec lspci command: %s",
			err.Error())
	}

	csvReader := csv.NewReader(strings.NewReader(out.String()))
	csvReader.Comma = ' '
	csvReader.FieldsPerRecord = -1

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, errors.Errorf("Failed to parse CSV because: %v. Input: %s",
			err.Error(), out.String())
	}

	if len(records) == 0 {
		return nil, errors.New("No entries in CSV output from lspci")
	}

	devs := make([]NetworkDevice, 0)

	for _, rec := range records {
		if len(rec) >= 4 {
			pci, manufacturer, devName := rec[0], rec[2], rec[3]

			// do not use blacklisted network devices
			if IsPCIportBlacklisted(pci) {
				log.Infof("Skipping blacklisted interface %s", pci)
				continue
			}

			devs = append(devs, NetworkDevice{
				PCI:          pci,
				Manufacturer: manufacturer,
				Description:  devName,
			})
		}
	}

	return devs, nil
}

func fillMACAddrForKernelDevs(devs []NetworkDevice) error {
	var ifs []net.Interface
	var ifsErr error

	getIfs := func() error {
		ifs, ifsErr = net.Interfaces()
		return ifsErr
	}

	ns := []nsenter.Namespace{
		{Path: "/var/host_ns/net", Type: nsenter.NSTypeNet}}
	err := nsenter.NsEnter(ns, getIfs)

	if err != nil {
		return errors.Wrap(err, "failed to enter namespace")
	}

	if ifsErr != nil {
		return errors.Wrap(ifsErr, "failed to obtain interfaces")
	}

	pciRegexp := regexp.MustCompile(
		`([0-9]{0,4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]{1})`)

	for _, iface := range ifs {
		ueventPath := path.Join("/var/host_net_devices", iface.Name,
			"device/uevent")
		content, err := ioutil.ReadFile(filepath.Clean(ueventPath))
		if err != nil {
			if os.IsNotExist(err) {
				// "File not found" is expected
				continue
			}

			return errors.Wrapf(err, "Failed to load uevent file: %s",
				ueventPath)
		}

		pci := pciRegexp.FindString(string(content))

		for idx := range devs {
			if devs[idx].PCI == pci {
				devs[idx].MAC = iface.HardwareAddr.String()
				devs[idx].Description = fmt.Sprintf("[%s] %s", iface.Name,
					devs[idx].Description)
				devs[idx].Driver = pb.NetworkInterface_KERNEL
			}
		}
	}

	return nil
}

func fillMACAddrForDPDKDevs(devs []NetworkDevice) error {
	ntsCfg, err := ini.NtsConfigFromFile(Config.NtsConfigPath)

	if err != nil {
		return errors.Wrap(err, "failed to read NTS config")
	}

	for _, port := range ntsCfg.Ports {
		for idx := range devs {
			if devs[idx].PCI == port.PciAddress {
				devs[idx].MAC = port.MAC
				devs[idx].Description = port.Description
				devs[idx].FallbackInterface = port.EgressPortID

				dir, _ := ini.InterfaceTypeFromTrafficDirection(
					port.TrafficDirection)

				devs[idx].Direction = dir
				devs[idx].Driver = pb.NetworkInterface_USERSPACE
			}
		}
	}

	return nil
}

// GetNetworkDevices gets network devices
func GetNetworkDevices() ([]NetworkDevice, error) {
	devs, err := getNetworkPCIs()
	if err != nil {
		return nil, err
	}

	err = fillMACAddrForDPDKDevs(devs)
	if err != nil {
		return nil, err
	}

	err = fillMACAddrForKernelDevs(devs)
	if err != nil {
		return nil, err
	}

	return devs, nil
}

// ToNetworkInterface converts a device to an interface
func (dev *NetworkDevice) ToNetworkInterface() *pb.NetworkInterface {
	iface := &pb.NetworkInterface{}
	iface.Id = dev.PCI
	iface.Description = dev.Description
	iface.MacAddress = dev.MAC
	iface.Driver = dev.Driver
	iface.Type = dev.Direction
	iface.FallbackInterface = dev.FallbackInterface

	return iface
}

// GetNetworkInterfaces gets network interfaces
func GetNetworkInterfaces() (*pb.NetworkInterfaces, error) {
	devs, err := GetNetworkDevices()
	if err != nil {
		return nil, err
	}

	ifaces := &pb.NetworkInterfaces{}
	ifaces.NetworkInterfaces = make([]*pb.NetworkInterface, 0)

	for _, dev := range devs {
		ifaces.NetworkInterfaces = append(ifaces.NetworkInterfaces,
			dev.ToNetworkInterface())
	}

	return ifaces, nil
}
