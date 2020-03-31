// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package eva

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	libvirt "github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
	apppb "github.com/open-ness/edgenode/pkg/eva/internal_pb"
	pb "github.com/open-ness/edgenode/pkg/eva/pb"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// IPApplicationLookupServiceServerImpl describes
// IP Application Lookup Service Server Implementation
type IPApplicationLookupServiceServerImpl struct {
	cfg                  *Config
	transportCredentials credentials.TransportCredentials
}

// GetApplicationByIP retrieves application ID of instance owning
// IP address received in request
func (s *IPApplicationLookupServiceServerImpl) GetApplicationByIP(
	ctx context.Context,
	ipAppLookupInfo *apppb.IPApplicationLookupInfo) (
	*apppb.IPApplicationLookupResult, error) {

	log.Debug("IPApplicationLookupService GetApplicationByIP: Request for: " +
		ipAppLookupInfo.GetIpAddress())

	if s.cfg.KubernetesMode {
		return s.getK8sContainerByIP(ctx, ipAppLookupInfo,
			s.cfg.ControllerEndpoint)
	}

	// TODO: Do proper validation
	if s.cfg.UseCNI {
		return &apppb.IPApplicationLookupResult{AppID: "cni"}, nil
	}

	var result apppb.IPApplicationLookupResult
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

func (s *IPApplicationLookupServiceServerImpl) getK8sContainerByIP(
	ctx context.Context, ipAppLookupInfo *apppb.IPApplicationLookupInfo,
	endpoint string) (*apppb.IPApplicationLookupResult, error) {

	if s.transportCredentials == nil {
		return nil, errors.New(
			"getK8sContainerByIP: transport credentials not set")
	}

	conn, dialErr := grpc.DialContext(ctx, endpoint,
		grpc.WithTransportCredentials(s.transportCredentials))
	if dialErr != nil {
		return nil, errors.Wrapf(dialErr,
			"Failed to create a connection to %s", endpoint)
	}

	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Errf("Failed to close connection: %v", closeErr)
		}
	}()

	client := pb.NewControllerVirtualizationAgentClient(conn)
	containerInfo, err := client.GetContainerByIP(ctx,
		&pb.ContainerIP{Ip: ipAppLookupInfo.GetIpAddress()},
		grpc.WaitForReady(true))

	if err != nil {
		return nil, errors.Wrap(dialErr,
			"ControllerVirtualizationAgent/GetContainerByIP failed")
	}

	return &apppb.IPApplicationLookupResult{AppID: containerInfo.Id}, nil
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
	defer func() {
		if c, err1 := conn.Close(); err1 != nil || c < 0 {
			log.Errf("Failed to close libvirt connection: code: %v, error: %v",
				c, err1)
		}
	}()

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
	return searchDonamainByIP(doms, leases, addrIP)
}

func searchDonamainByIP(doms []libvirt.Domain,
	leases []libvirt.NetworkDHCPLease,
	addrIP string) (string, error) {
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
