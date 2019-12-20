// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package helpers

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

	pb "github.com/open-ness/edgenode/pkg/ela/pb"
	"github.com/pkg/errors"
)

// NetworkDevice contains data for network device
type NetworkDevice struct {
	PCI               string
	Name              string
	Manufacturer      string
	MAC               string
	Description       string
	FallbackInterface string
	Driver            pb.NetworkInterface_InterfaceDriver
	Direction         pb.NetworkInterface_InterfaceType
}

// GetNetworkPCIs returns slice of NetworkDevices with filled PCI,
// Manufacturer and Description
func GetNetworkPCIs() ([]NetworkDevice, error) {

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

			devs = append(devs, NetworkDevice{
				PCI:          pci,
				Manufacturer: manufacturer,
				Description:  devName,
			})
		}
	}

	return devs, nil
}

// FillMACAddrForKernelDevs updates network devices bound to kernel driver
// with MAC address
func FillMACAddrForKernelDevs(devs []NetworkDevice) error {
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
				devs[idx].Name = iface.Name
				devs[idx].Description = fmt.Sprintf("[%s] %s", iface.Name,
					devs[idx].Description)
				devs[idx].Driver = pb.NetworkInterface_KERNEL
			}
		}
	}

	return nil
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

// ToNetworkInterfaces transforms slice of NetworkDevice into NetworkInterfaces
func ToNetworkInterfaces(devs []NetworkDevice) *pb.NetworkInterfaces {
	ifaces := &pb.NetworkInterfaces{}
	ifaces.NetworkInterfaces = make([]*pb.NetworkInterface, 0)

	for _, dev := range devs {
		ifaces.NetworkInterfaces = append(ifaces.NetworkInterfaces,
			dev.ToNetworkInterface())
	}

	return ifaces
}
