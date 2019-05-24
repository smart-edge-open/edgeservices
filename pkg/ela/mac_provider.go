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
	"errors"
	"net"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	libvirt "github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"

	"github.com/containernetworking/plugins/pkg/ns"
)

// MACFetcherImpl is a MACAddressProvider which allows to get MAC of
// libvirt Domain's vHostUser interface or Docker container's KNI
type MACFetcherImpl struct{}

// GetMacAddress function tries to fetch a MAC for domain or container
// with given ID
func (*MACFetcherImpl) GetMacAddress(ctx context.Context,
	appID string) (string, error) {

	// TODO: Check app's metadata to decide which daemon should be asked for MAC

	log.Infof("GetMacAddress for: %s", appID)

	mac, err := getMACForVMvhostuser(appID)
	if err == nil {
		return mac, nil
	}
	log.Infof("GetMacAddress for: %s. VM error: %v", appID, err)

	mac, err = getMACForContainerKNI(ctx, appID)
	if err == nil {
		return mac, nil
	}
	log.Infof("GetMacAddress for: %s. Docker error: %v", appID, err)

	return "", errors.New("MAC address not found for: " + appID)
}

func getMACForVMvhostuser(appID string) (string, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	virtDomain, err := conn.LookupDomainByName(appID)
	if err != nil {
		return "", err
	}
	defer func() { _ = virtDomain.Free() }()

	xmlDump, err := virtDomain.GetXMLDesc(0)
	if err != nil {
		return "", err
	}

	domcfg := &libvirtxml.Domain{}
	err = domcfg.Unmarshal(xmlDump)
	if err != nil {
		return "", err
	}

	for _, iface := range domcfg.Devices.Interfaces {
		if iface.Source.VHostUser != nil {
			return iface.MAC.Address, nil
		}
	}

	return "", errors.New("Interface not found")
}

func getNetNamespaceForContainer(ctx context.Context,
	appName string) (string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return "", err
	}

	for _, c := range containers {
		if len(c.Names) == 0 {
			continue
		}

		name := c.Names[0][1:]
		if name == appName {
			cj, inspectErr := cli.ContainerInspect(ctx, c.ID)
			if inspectErr != nil {
				return "", errors.New("Failed to inspect the container: " +
					inspectErr.Error())
			}

			return cj.NetworkSettings.SandboxKey, nil
		}
	}

	return "", errors.New("Container not found")
}

func getMACForContainerKNI(ctx context.Context, appID string) (string, error) {
	nsPath, err := getNetNamespaceForContainer(ctx, appID)
	if err != nil {
		return "", err
	}

	netns, err := ns.GetNS(nsPath)
	if err != nil {
		return "", err
	}

	macAddr := ""

	var handler = func(hostNS ns.NetNS) error {
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}

		for _, iface := range ifaces {
			if strings.Contains(iface.Name, "vEth") {
				macAddr = iface.HardwareAddr.String()
				return nil
			}
		}

		return errors.New("vEth interface not found")
	}

	if err := netns.Do(handler); err != nil {
		return "", err
	}

	return macAddr, nil
}
