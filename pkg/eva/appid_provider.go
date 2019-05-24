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

package eva

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	libvirt "github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
	evapb "github.com/smartedgemec/appliance-ce/pkg/eva/pb"
)

type IPApplicationLookupServiceServerImpl struct{}

// GetApplicationByIP retreives application ID of instance owning
// IP address received in request
func (*IPApplicationLookupServiceServerImpl) GetApplicationByIP(
	ctx context.Context,
	ipAppLookupInfo *evapb.IPApplicationLookupInfo) (
	*evapb.IPApplicationLookupResult, error) {

	log.Info("IPApplicationLookupService GetApplicationByIP: Request for: " +
		ipAppLookupInfo.GetIpAddress())

	var result evapb.IPApplicationLookupResult
	name, err := lookupContainersByIP(ctx, ipAppLookupInfo.GetIpAddress())
	if err != nil {
		log.Errf("Failed to lookup container by IP: %v", err)
	}

	if name == "" {
		name, err = lookupDomainsByIP(ctx, ipAppLookupInfo.GetIpAddress())
		if err != nil {
			log.Errf("Failed to lookup domain by IP: %v", err)
		}
	}

	result.AppID = name
	return &result, err
}

func getDomMAC(d *libvirt.Domain) (string, error) {
	xmlDump, err := d.GetXMLDesc(0)
	if err != nil {
		return "", err
	}

	domcfg := &libvirtxml.Domain{}
	err = domcfg.Unmarshal(xmlDump)
	if err != nil {
		return "", err
	}

	for _, iface := range domcfg.Devices.Interfaces {
		if iface.Source.Network != nil {
			return iface.MAC.Address, nil
		}
	}

	return "", nil
}

func lookupDomainsByIP(ctx context.Context, addrIP string) (string, error) {

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	doms, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		return "", err
	}

	netDefault, err := conn.LookupNetworkByName("default")
	if err != nil {
		return "", err
	}

	leases, err := netDefault.GetDHCPLeases()
	if err != nil {
		return "", err
	}

	for _, dom := range doms {

		domName, err := dom.GetName()
		if err != nil {
			log.Errf("Failed to get name of domain")
			continue
		}

		domMAC, err := getDomMAC(&dom)
		if err != nil {
			log.Errf("Failed to get MAC for domain: %s error: %v", domName,
				err)
			continue
		}

		if domMAC == "" {
			continue
		}

		for _, lease := range leases {
			if lease.Mac == domMAC && lease.IPaddr == addrIP {
				_ = dom.Free()
				return domName, nil
			}
		}

		_ = dom.Free()
	}

	return "", nil
}

func lookupContainersByIP(ctx context.Context, addrIP string) (string, error) {

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

		cjson, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			log.Errf("Failed to inspect container: %s error: %v", name, err)
			continue
		}

		for _, n := range cjson.NetworkSettings.Networks {
			if n.IPAddress == addrIP {
				return name, nil
			}
		}
	}

	return "", nil
}
